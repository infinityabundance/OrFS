# Publishing OrFS to crates.io

Status: **published.** `orfs` v0.1.0 is live at <https://crates.io/crates/orfs>
(published 2026-10-12, crate checksum
`sha256:160aa0dd26fa9cb250544901377b1d9132d1590acba76f738d5618a4d4b38a62`; docs
at <https://docs.rs/orfs>). The authoritative record is
`evidence/receipts/crates-io.json`. crates.io versions are **immutable**, so any
source change requires a new version number — `0.1.0` cannot be replaced, only
yanked.

The sections below record what made the crate publishable and how to publish a
future version.

## What is in place

* `Cargo.toml` carries the metadata crates.io expects: `description`, `license`
  (`MIT OR Apache-2.0`), `repository`, `homepage`, `documentation`, `readme`,
  `keywords` (≤5), and `categories` (`filesystem`, `os::unix-apis` — both valid
  crates.io slugs).
* `LICENSE-MIT` and `LICENSE-APACHE` are present.
* The `publish = false` guard has been removed, so the crate is publishable.
* `exclude = ["/evidence", "/docs", "/scripts", "/research", "/mnt-scratch"]`
  keeps the package to source; `cargo package --list` yields 84 files
  (`src/`, `tests/`, `benches/`, `Cargo.toml`, `README.md`, the Dockerfiles,
  the toolchain pin, and the license files).
* The name `orfs` is **available** on crates.io (checked 2026-10-12).

## The dependency (resolved in Phase 35)

crates.io requires that **every** dependency of a published crate is itself on
crates.io. EKBLOOM is now published as `ekbloom` `0.3.0`, and OrFS depends on it
by exact version:

```toml
ekbloom = "=0.3.0"
```

The resolved source and checksum are recorded in `Cargo.lock`
(`registry+https://github.com/rust-lang/crates.io-index`,
`sha256:b02f89add93be1429809445c7570c1271a68957702728c95437887243bdcf2cf`) and
in `evidence/receipts/ekbloom.json`.

> Before Phase 35 the dependency was a rev-pinned **git** dependency on
> `https://github.com/infinityabundance/EKBLOOM` at rev `708c3491`. That form
> blocked publishing, because crates.io rejects git dependencies. The published
> `0.3.0` is newer than that revision (47 source files vs 30); the only consuming
> change was `OrMachine::init` now taking the core bytes and returning
> `Result<Snapshot>` (`src/readpath.rs::state_at`). The full test suite —
> including the manifested-vs-authoritative equivalence courts and the EKBLOOM
> roundtrip tests — passes against the published release. See
> `docs/LIMITATIONS.md` §1.

## Steps to publish

From the pinned container, with a crates.io token:

```sh
sh -c '. scripts/lib.sh && docker_run cargo publish'
```

The token is read by cargo from `$CARGO_HOME/credentials.toml` or
`CARGO_REGISTRY_TOKEN`. The container's `CARGO_HOME` is the project-local
`.cargo-home/` (gitignored), which does **not** contain the token by default;
supply it with `-e CARGO_REGISTRY_TOKEN=…` or place a `credentials.toml` there.
Never commit the token.

## Notes

* crates.io's upload limit is 10 MB; the package is well under it because
  `evidence/`, `docs/`, and `scripts/` are excluded.
* The binary (`[[bin]] orfs`) and library (`[lib] orfs`) publish together under
  the one crate.
* `docs.rs` builds the library by default; the crate has no extra system
  requirements to *build* (FUSE/`io_uring` are used only at run time).
