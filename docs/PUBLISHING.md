# Publishing OrFS to crates.io

Status: **prepared, but blocked on one external dependency.** `cargo package`
succeeds and the crate name is free, but `cargo publish` cannot complete until
`ekbloom` is itself published to crates.io.

## What is already in place

* `Cargo.toml` carries the metadata crates.io expects: `description`, `license`
  (`MIT OR Apache-2.0`), `repository`, `homepage`, `documentation`, `readme`,
  `keywords` (≤5), and `categories` (`filesystem`, `os::unix-apis` — both valid
  crates.io slugs).
* `LICENSE-MIT` and `LICENSE-APACHE` are present.
* The `publish = false` guard has been removed, so the crate is publishable
  (subject to the dependency below).
* `exclude = ["/evidence", "/docs", "/scripts", "/research", "/mnt-scratch"]`
  keeps the package to source; `cargo package --list` yields 82 files
  (`src/`, `tests/`, `benches/`, `Cargo.toml`, `README.md`, the Dockerfiles,
  the toolchain pin, and the license files).
* The name `orfs` is **available** (crates.io returned `404 crate does not
  exist` on 2026-10-12).

## The blocker

crates.io requires that **every** dependency of a published crate is itself on
crates.io. OrFS consumes EKBLOOM as a rev-pinned **git** dependency:

```toml
ekbloom = { git = "https://github.com/infinityabundance/EKBLOOM", rev = "708c3491…", version = "=0.3.0" }
```

`ekbloom` is not published to crates.io (crates.io returned `404` on
2026-10-12), and the publish path resolves the declared `version = "=0.3.0"`
against the crates.io index rather than the git source. The failure is exact and
reproducible:

```
$ cargo publish --dry-run --no-verify
    Updating crates.io index
    Packaging orfs v0.1.0
    Updating crates.io index
error: failed to prepare local package for uploading
Caused by:
  no matching package named `ekbloom` found
  location searched: crates.io index
  required by package `orfs v0.1.0`
```

EKBLOOM's source must not be copied or vendored into OrFS (it is developed
separately and independently), so the fix is to publish EKBLOOM under its own
release process.

## Steps to complete the publication

1. **Publish EKBLOOM** as `ekbloom` 0.3.0 from the EKBLOOM repository (its own
   `cargo publish`). This is the one step that cannot be done from this
   repository.
2. **Switch OrFS to the registry dependency:**

   ```toml
   ekbloom = "=0.3.0"
   ```

   (Keeping the `=0.3.0` pin preserves reproducibility; the git `rev` pin is no
   longer needed once the exact version is on crates.io.)
3. **Publish OrFS** from the pinned container with a crates.io token:

   ```sh
   CARGO_REGISTRY_TOKEN=<token> sh scripts/container-publish.sh
   ```

   A `docker_run`-style wrapper (`scripts/container-publish.sh`) is **not yet
   added**: adding it wires a secret-bearing command line into the tooling, which
   is deferred until the dependency above is resolved. Until then, the equivalent
   container invocation is:

   ```sh
   sh -c '. scripts/lib.sh && docker_run cargo publish --allow-dirty'
   ```

   The token is read by cargo from `$CARGO_HOME/credentials.toml` or
   `CARGO_REGISTRY_TOKEN`. Never commit it.

## Notes

* crates.io's upload limit is 10 MB; the package is well under it because
  `evidence/`, `docs/`, and `scripts/` are excluded.
* The binary (`[[bin]] orfs`) and library (`[lib] orfs`) publish together under
  the one crate.
* `docs.rs` builds the library by default; the crate has no extra system
  requirements to *build* (FUSE/`io_uring` are used only at run time).
