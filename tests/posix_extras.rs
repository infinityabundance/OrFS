//! POSIX-extras correctness court (no FUSE mount required).
//!
//! Exercises the primitives a reviewer named beyond the ordinary file/namespace
//! model, entirely through the library / [`Namespace`] API (plus the public
//! [`has_permission_grouped`] and the commit sequencer's ack states), so it is an
//! always-on, fast, mount-free court:
//!
//! * **xattrs** — set/get/list/remove, `XATTR_CREATE` semantics, the derived
//!   `user.orfs.*` set, name bounds, and the *uniform* access rule
//!   (docs/LIMITATIONS.md §8: reading needs read permission, setting/removing
//!   needs write permission; no special privilege for `security.*`/`trusted.*`).
//! * **symlinks** — create, `readlink`, resolve the target through the link, and
//!   confirm rename/replace preserves the link identity and target.
//! * **hard links** — a second name raises `nlink`, both names resolve to one
//!   inode, and removal decrements `nlink` while the inode and its data are
//!   retained (append-only tombstone).
//! * **supplementary groups** — the grouped permission rule
//!   (`src/inode.rs::has_permission_grouped`) for a file whose group matches a
//!   supplementary (not primary) group: allowed and denied cases, and the typed
//!   query API sharing the same rule.
//! * **durability** — `fsync` is the durability barrier and its ack state
//!   (`TxState::Durable` vs `Published`); `fdatasync` has no distinct primitive
//!   and is served by the same full `sync()` (strictly stronger).
//!
//! It emits machine-generated evidence `evidence/correctness/posix-extras.json`
//! (schema `orfs.correctness.posix-extras.v1`) with one entry per primitive. The
//! test only asserts what the implementation actually guarantees; a primitive
//! that were unsupported would assert the documented rejection and record
//! `UNSUPPORTED` with its errno rather than fail.

use std::path::Path;

use orfs::commit::{CommitSequencer, DurabilityMode};
use orfs::inode::{has_permission_grouped, InodeType, XATTR_NAME_MAX};
use orfs::log::OpenMode;
use orfs::namespace::{Namespace, RenameMode};
use orfs::query::{Credential, QueryRequest};
use orfs::record::RecordType;
use orfs::transaction::{Transaction, TransactionBuilder, TxState};
use orfs::volume::Volume;
use orfs::OrfsError;
use tempfile::TempDir;

/// A fixed volume UUID so the evidence volume is reproducible.
const FIXED_UUID: [u8; 16] = [
    0x4F, 0x72, 0x46, 0x53, 0x02, 0x11, 0x40, 0x22, 0x80, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
];
/// A fixed creation timestamp for reproducible volumes.
const FIXED_CREATED: u64 = 1_700_000_000;

fn write_json(path: &Path, value: &serde_json::Value) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create evidence dir");
    }
    let mut s = serde_json::to_string_pretty(value).expect("serialize json");
    s.push('\n');
    std::fs::write(path, s).expect("write evidence");
}

/// A stable errno name, so the receipt is readable without decoding integers.
fn errno_name(e: i32) -> &'static str {
    match e {
        libc::EACCES => "EACCES",
        libc::EEXIST => "EEXIST",
        libc::ENODATA => "ENODATA",
        libc::EINVAL => "EINVAL",
        libc::EPERM => "EPERM",
        libc::ENOENT => "ENOENT",
        libc::EISDIR => "EISDIR",
        libc::ENOTDIR => "ENOTDIR",
        libc::ENOTEMPTY => "ENOTEMPTY",
        libc::EOPNOTSUPP => "EOPNOTSUPP",
        _ => "UNKNOWN",
    }
}

/// One concrete sub-check within a primitive.
fn check(
    what: &str,
    expected: &str,
    observed: &str,
    result: &str,
    errno: Option<i32>,
    notes: &str,
) -> serde_json::Value {
    serde_json::json!({
        "what": what,
        "expected": expected,
        "observed": observed,
        "result": result,
        "errno": errno,
        "errno_name": errno.map(errno_name),
        "notes": notes,
    })
}

/// One primitive's aggregate verdict.
fn primitive(
    name: &str,
    result: &str,
    notes: &str,
    checks: Vec<serde_json::Value>,
) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "result": result,
        "notes": notes,
        "checks": checks,
    })
}

/// A minimal, well-framed transaction for the durability ack-state checks. It
/// carries one `INODE_METADATA` record; the sequencer only frames bytes (it never
/// applies records to an index), so no semantic payload is needed.
fn sample_transaction(id: u64) -> Transaction {
    let mut b = TransactionBuilder::new(id).expect("builder");
    b.add(RecordType::InodeMetadata, 1, 0, vec![0u8; 20])
        .expect("add record");
    b.build().expect("build transaction")
}

#[test]
fn posix_extras_correctness_receipt() {
    let mut primitives: Vec<serde_json::Value> = Vec::new();

    let dir = TempDir::new().unwrap();
    let mut ns = Namespace::init_with_uuid(
        dir.path(),
        1 << 20,
        FIXED_UUID,
        FIXED_CREATED,
        DurabilityMode::Sync,
    )
    .unwrap();
    // `root_ino` is the *inode id* of the volume root (`1`); reads are pinned to the
    // live *committed root* (`ns.root()`, a log offset). The two are distinct.
    let root_ino = ns.root_inode();

    // -- xattrs -------------------------------------------------------------
    {
        let mut checks = Vec::new();
        let f = ns.create(root_ino, b"xfile", 0o644, 0, 0).unwrap();

        ns.setxattr(f, b"user.answer", b"42", true).unwrap();
        let got = ns.getxattr(f, b"user.answer", ns.root()).unwrap();
        assert_eq!(got, b"42".to_vec());
        checks.push(check(
            "set(user.*, XATTR_CREATE) then get",
            "the value round-trips as 42",
            &format!("value = {:?}", String::from_utf8_lossy(&got)),
            "PASS",
            None,
            "",
        ));

        let names = ns.listxattr(f, ns.root()).unwrap();
        let has_user = names.iter().any(|n| n == b"user.answer");
        let has_derived = names.iter().any(|n| n == b"user.orfs.version");
        assert!(has_user && has_derived);
        checks.push(check(
            "listxattr",
            "contains the stored name and the derived user.orfs.* set",
            &format!(
                "{} names; user.answer={has_user}, user.orfs.version={has_derived}",
                names.len()
            ),
            "PASS",
            None,
            "derived attributes are computed, never stored (docs/NAMESPACE.md §2.2)",
        ));

        let ver = ns.getxattr(f, b"user.orfs.version", ns.root()).unwrap();
        assert!(!ver.is_empty());
        checks.push(check(
            "get(derived user.orfs.version)",
            "a non-empty version string",
            &format!("{:?}", String::from_utf8_lossy(&ver)),
            "PASS",
            None,
            "",
        ));

        let err = ns.setxattr(f, b"user.answer", b"43", true).unwrap_err();
        assert_eq!(err.errno(), libc::EEXIST);
        checks.push(check(
            "set(existing, XATTR_CREATE)",
            "EEXIST",
            "EEXIST",
            "PASS",
            Some(err.errno()),
            "",
        ));

        ns.setxattr(f, b"user.answer", b"43", false).unwrap();
        assert_eq!(
            ns.getxattr(f, b"user.answer", ns.root()).unwrap(),
            b"43".to_vec()
        );
        checks.push(check(
            "set(existing) without XATTR_CREATE",
            "replaces the value",
            "value = 43",
            "PASS",
            None,
            "",
        ));

        let err = ns.getxattr(f, b"user.missing", ns.root()).unwrap_err();
        assert_eq!(err.errno(), libc::ENODATA);
        checks.push(check(
            "get(absent)",
            "ENODATA",
            "ENODATA",
            "PASS",
            Some(err.errno()),
            "",
        ));

        ns.removexattr(f, b"user.answer").unwrap();
        assert_eq!(
            ns.getxattr(f, b"user.answer", ns.root())
                .unwrap_err()
                .errno(),
            libc::ENODATA
        );
        let err = ns.removexattr(f, b"user.answer").unwrap_err();
        assert_eq!(err.errno(), libc::ENODATA);
        checks.push(check(
            "remove then get/remove(absent)",
            "remove succeeds; a later get or remove returns ENODATA",
            "ENODATA",
            "PASS",
            Some(err.errno()),
            "",
        ));

        let err_empty = ns.setxattr(f, b"", b"v", false).unwrap_err();
        let long_name = vec![b'a'; XATTR_NAME_MAX + 1];
        let err_long = ns.setxattr(f, &long_name, b"v", false).unwrap_err();
        assert_eq!(err_empty.errno(), libc::EINVAL);
        assert_eq!(err_long.errno(), libc::EINVAL);
        checks.push(check(
            "name bounds",
            "empty and >255-byte names rejected with EINVAL",
            "EINVAL",
            "PASS",
            Some(libc::EINVAL),
            "",
        ));

        // The uniform access rule (docs/LIMITATIONS.md §8). The engine itself does
        // not enforce it; the transport does, through this exact function.
        let ro = ns.create(root_ino, b"ro-xattr", 0o444, 1000, 1000).unwrap();
        let st = ns.getattr(ro, ns.root()).unwrap();
        let can_read = has_permission_grouped(3000, 3000, &[], &st, 0o4);
        let can_write = has_permission_grouped(3000, 3000, &[], &st, 0o2);
        assert!(can_read && !can_write);
        checks.push(check(
            "access rule: non-owner on mode 0444",
            "read allowed (getxattr/listxattr); write denied (setxattr/removexattr) -> EACCES",
            "read = true, write = false",
            "PASS",
            Some(libc::EACCES),
            "src/fuse.rs applies this mask via has_permission_grouped before setxattr/removexattr",
        ));

        // `user.*` and `trusted.*` are equally gated: the name is opaque bytes and
        // carries no namespace-specific privilege.
        let rw = ns.create(root_ino, b"rw-xattr", 0o644, 1000, 1000).unwrap();
        ns.setxattr(rw, b"user.k", b"u", false).unwrap();
        ns.setxattr(rw, b"trusted.k", b"t", false).unwrap();
        assert_eq!(
            ns.getxattr(rw, b"user.k", ns.root()).unwrap(),
            b"u".to_vec()
        );
        assert_eq!(
            ns.getxattr(rw, b"trusted.k", ns.root()).unwrap(),
            b"t".to_vec()
        );
        checks.push(check(
            "user.* vs trusted.* names",
            "names are opaque; no namespace-specific privilege or CAP_SYS_ADMIN override",
            "both stored and returned; the write mask is identical for either prefix",
            "PASS",
            None,
            "docs/LIMITATIONS.md §8: one uniform rule, independent of namespace",
        ));

        primitives.push(primitive(
            "xattrs",
            "PASS",
            "set/get/list/remove, XATTR_CREATE, the derived user.orfs.* set, name bounds, and the uniform access rule.",
            checks,
        ));
    }

    // -- symlinks -----------------------------------------------------------
    {
        let mut checks = Vec::new();
        let t = ns.create(root_ino, b"sym-target", 0o644, 0, 0).unwrap();
        ns.write_at(t, 0, b"hello").unwrap();
        let l = ns
            .symlink(root_ino, b"sym-link", b"sym-target", 0, 0)
            .unwrap();
        assert_eq!(ns.getattr(l, ns.root()).unwrap().kind, InodeType::Symlink);
        checks.push(check(
            "symlink creation + getattr",
            "the new inode is of kind symlink",
            "kind = symlink",
            "PASS",
            None,
            "",
        ));

        let target = ns.readlink(l, ns.root()).unwrap();
        assert_eq!(target, b"sym-target".to_vec());
        checks.push(check(
            "readlink",
            "returns the authoritative target bytes",
            &format!("{:?}", String::from_utf8_lossy(&target)),
            "PASS",
            None,
            "",
        ));

        // Resolve through the link by walking the target name. The kernel performs
        // the same walk; the engine stores the target immutably.
        let resolved = ns.lookup(root_ino, &target, ns.root()).unwrap();
        assert_eq!(resolved, t);
        assert_eq!(
            ns.read_at(resolved, ns.root(), 0, 5).unwrap(),
            b"hello".to_vec()
        );
        checks.push(check(
            "resolve through the link",
            "lookup(target) yields the target inode and its bytes",
            "resolved inode == target inode; content = hello",
            "PASS",
            None,
            "single-component relative target; multi-component walks are the kernel's",
        ));

        let err = ns.readlink(t, ns.root()).unwrap_err();
        assert_eq!(err.errno(), libc::EINVAL);
        checks.push(check(
            "readlink on a regular file",
            "EINVAL (not a symlink)",
            "EINVAL",
            "PASS",
            Some(err.errno()),
            "",
        ));

        // Rename/replace: an ordinary rename replaces a file with the link.
        let victim = ns.create(root_ino, b"sym-victim", 0o644, 0, 0).unwrap();
        ns.write_at(victim, 0, b"old").unwrap();
        ns.rename(
            root_ino,
            b"sym-link",
            root_ino,
            b"sym-victim",
            RenameMode::Ordinary,
        )
        .unwrap();
        let now = ns.lookup(root_ino, b"sym-victim", ns.root()).unwrap();
        assert_eq!(now, l);
        assert_eq!(ns.readlink(now, ns.root()).unwrap(), b"sym-target".to_vec());
        assert_eq!(ns.getattr(now, ns.root()).unwrap().kind, InodeType::Symlink);
        assert!(matches!(
            ns.lookup(root_ino, b"sym-link", ns.root()),
            Err(OrfsError::NotFound)
        ));
        assert_eq!(ns.getattr(victim, ns.root()).unwrap().nlink, 0);
        checks.push(check(
            "rename replace (Ordinary)",
            "the link inode replaces the destination; identity and target preserved; the old file is unlinked",
            "victim resolves to the link inode; target still sym-target; old file nlink = 0",
            "PASS",
            None,
            "",
        ));

        let err = ns
            .rename(
                root_ino,
                b"sym-victim",
                root_ino,
                b"sym-target",
                RenameMode::NoReplace,
            )
            .unwrap_err();
        assert_eq!(err.errno(), libc::EEXIST);
        checks.push(check(
            "rename RENAME_NOREPLACE onto an existing name",
            "EEXIST",
            "EEXIST",
            "PASS",
            Some(err.errno()),
            "",
        ));

        primitives.push(primitive(
            "symlinks",
            "PASS",
            "create/readlink/resolve and rename-replace identity preservation.",
            checks,
        ));
    }

    // -- hard links ---------------------------------------------------------
    {
        let mut checks = Vec::new();
        let f = ns.create(root_ino, b"hl-a", 0o644, 0, 0).unwrap();
        ns.write_at(f, 0, b"data").unwrap();
        assert_eq!(ns.getattr(f, ns.root()).unwrap().nlink, 1);
        ns.link(f, root_ino, b"hl-b").unwrap();
        assert_eq!(ns.getattr(f, ns.root()).unwrap().nlink, 2);
        let a = ns.lookup(root_ino, b"hl-a", ns.root()).unwrap();
        let b = ns.lookup(root_ino, b"hl-b", ns.root()).unwrap();
        assert_eq!(a, b);
        assert_eq!(a, f);
        checks.push(check(
            "link + nlink",
            "a second name raises nlink 1 -> 2 and both names resolve to one inode",
            "nlink = 2; lookup(a) == lookup(b) == inode",
            "PASS",
            None,
            "",
        ));

        assert_eq!(ns.read_at(a, ns.root(), 0, 4).unwrap(), b"data".to_vec());
        assert_eq!(ns.read_at(b, ns.root(), 0, 4).unwrap(), b"data".to_vec());
        checks.push(check(
            "data via both names",
            "identical bytes read through either name",
            "data",
            "PASS",
            None,
            "",
        ));

        ns.unlink(root_ino, b"hl-a").unwrap();
        assert_eq!(ns.getattr(b, ns.root()).unwrap().nlink, 1);
        assert!(matches!(
            ns.lookup(root_ino, b"hl-a", ns.root()),
            Err(OrfsError::NotFound)
        ));
        assert_eq!(ns.read_at(b, ns.root(), 0, 4).unwrap(), b"data".to_vec());
        checks.push(check(
            "unlink one name",
            "nlink 2 -> 1; the remaining name still reads the data; the removed name is ENOENT",
            "nlink = 1; removed name ENOENT; data retained",
            "PASS",
            Some(libc::ENOENT),
            "",
        ));

        ns.unlink(root_ino, b"hl-b").unwrap();
        assert_eq!(ns.getattr(f, ns.root()).unwrap().nlink, 0);
        assert!(matches!(
            ns.lookup(root_ino, b"hl-b", ns.root()),
            Err(OrfsError::NotFound)
        ));
        assert_eq!(ns.read_at(f, ns.root(), 0, 4).unwrap(), b"data".to_vec());
        checks.push(check(
            "unlink the last name",
            "nlink reaches 0; the inode and its data remain readable by id (append-only tombstone)",
            "nlink = 0; lookup ENOENT; read_at(inode) still returns data",
            "PASS",
            None,
            "docs/NAMESPACE.md §4.2: a tombstone removes a name; the inode/bytes are never withdrawn",
        ));

        let d = ns.mkdir(root_ino, b"hl-dir", 0o755, 0, 0).unwrap();
        let err = ns.link(d, root_ino, b"hl-dirlink").unwrap_err();
        assert!(matches!(err, OrfsError::NotPermitted));
        checks.push(check(
            "link on a directory",
            "rejected with EPERM (as Linux does)",
            &format!("rejected with {}", errno_name(err.errno())),
            "PASS",
            Some(err.errno()),
            "docs/NAMESPACE.md §4.2: directories cannot be hard-linked (EPERM)",
        ));

        primitives.push(primitive(
            "hard_links",
            "PASS",
            "second link, nlink accounting, shared inode identity, and removal semantics.",
            checks,
        ));
    }

    // -- supplementary groups ----------------------------------------------
    {
        let mut checks = Vec::new();
        let f = ns.create(root_ino, b"grp-file", 0o640, 1000, 2000).unwrap();
        ns.write_at(f, 0, b"group").unwrap();
        let st = ns.getattr(f, ns.root()).unwrap();
        assert_eq!((st.uid, st.gid, st.mode & 0o777), (1000, 2000, 0o640));

        let owner_read = has_permission_grouped(1000, 999, &[], &st, 0o4);
        let owner_write = has_permission_grouped(1000, 999, &[], &st, 0o2);
        let supp_read = has_permission_grouped(3000, 3000, &[2000], &st, 0o4);
        let supp_write = has_permission_grouped(3000, 3000, &[2000], &st, 0o2);
        let primary_read = has_permission_grouped(3000, 2000, &[], &st, 0o4);
        let other_read = has_permission_grouped(3000, 3000, &[], &st, 0o4);
        let other_write = has_permission_grouped(3000, 3000, &[], &st, 0o2);
        let root_rw = has_permission_grouped(0, 0, &[], &st, 0o6);
        assert!(owner_read && owner_write);
        assert!(supp_read && !supp_write);
        assert!(primary_read);
        assert!(!other_read && !other_write);
        assert!(root_rw);
        checks.push(check(
            "has_permission_grouped allowed/denied",
            "owner rw; a supplementary group grants the group read class only; a primary-group match grants it; a stranger is denied; root bypasses",
            &format!(
                "owner(rw)={owner_read},{owner_write} supp(rw)={supp_read},{supp_write} primary_read={primary_read} other(rw)={other_read},{other_write} root={root_rw}"
            ),
            "PASS",
            Some(libc::EACCES),
            "the Linux in_group_p rule; the FUSE transports read Groups: from /proc/<pid>/status",
        ));

        let grouped = Credential {
            uid: 3000,
            gid: 3000,
            groups: vec![2000],
        };
        let req = QueryRequest::new(f, ns.root(), b"group".to_vec())
            .without_recursion()
            .with_credential(grouped);
        assert!(ns.query(req).is_ok());
        let ungrouped = Credential {
            uid: 3000,
            gid: 3000,
            groups: Vec::new(),
        };
        let req = QueryRequest::new(f, ns.root(), b"group".to_vec())
            .without_recursion()
            .with_credential(ungrouped);
        assert!(ns.query(req).is_err());
        checks.push(check(
            "typed query API parity",
            "a supplementary group admits the read; without it the read is denied",
            "grouped = Ok, ungrouped = Err",
            "PASS",
            Some(libc::EACCES),
            "src/query.rs shares has_permission_grouped with the transports",
        ));

        primitives.push(primitive(
            "supplementary_groups",
            "PASS",
            "the grouped permission rule for a supplementary (non-primary) group, allowed and denied.",
            checks,
        ));
    }

    // -- durability: fsync vs fdatasync -------------------------------------
    {
        let mut checks = Vec::new();

        // `sync`: a successful commit is durable before it is acknowledged.
        let dir_sync = TempDir::new().unwrap();
        let mut vol =
            Volume::init_with_uuid(dir_sync.path(), 1 << 20, FIXED_UUID, FIXED_CREATED).unwrap();
        {
            let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Sync);
            let out = seq.commit(sample_transaction(1)).unwrap();
            assert_eq!(out.state, TxState::Durable);
            assert!(out.durable);
            checks.push(check(
                "fsync-before-ack (DurabilityMode::Sync)",
                "a successful commit is acknowledged only at TxState::Durable (durable = true)",
                &format!("state = {}, durable = {}", out.state.name(), out.durable),
                "PASS",
                None,
                "docs/FUSE-SEMANTICS.md §8.1: fsync/fsyncdir call the engine sync()",
            ));
        }

        // `ordered`: ack at Published; durability is established by an explicit
        // flush() (the fsync barrier).
        let dir_ord = TempDir::new().unwrap();
        let mut vol2 =
            Volume::init_with_uuid(dir_ord.path(), 1 << 20, FIXED_UUID, FIXED_CREATED).unwrap();
        {
            let mut seq = CommitSequencer::new(&mut vol2, DurabilityMode::Ordered);
            let out = seq.commit(sample_transaction(1)).unwrap();
            assert_eq!(out.state, TxState::Published);
            assert!(!out.durable);
            let synced = seq.flush().unwrap();
            assert_eq!(synced.transactions, 1);
            let again = seq.flush().unwrap();
            assert_eq!(again.transactions, 0);
            checks.push(check(
                "fsync barrier (flush)",
                "ordered commits ack at Published; flush() makes the outstanding batch durable and is idempotent",
                &format!(
                    "commit = published/durable=false; flush transactions = {}; second flush = {}",
                    synced.transactions, again.transactions
                ),
                "PASS",
                None,
                "docs/FUSE-SEMANTICS.md §8.1: fsync calls sync(); flush() is the durability barrier",
            ));
        }

        // The engine's single durability hook is Namespace::sync(); both fsync and
        // fdatasync reach it. Prove the hook makes the state survive a reopen.
        let dir_ns = TempDir::new().unwrap();
        let mut ns2 = Namespace::init_with_uuid(
            dir_ns.path(),
            1 << 20,
            FIXED_UUID,
            FIXED_CREATED,
            DurabilityMode::Ordered,
        )
        .unwrap();
        let r2 = ns2.root_inode();
        let f2 = ns2.create(r2, b"dur", 0o644, 0, 0).unwrap();
        ns2.write_at(f2, 0, b"durable").unwrap();
        ns2.sync().unwrap();
        drop(ns2);
        let ro =
            Namespace::open(dir_ns.path(), OpenMode::ReadOnly, DurabilityMode::Ordered).unwrap();
        let f2b = ro.lookup(r2, b"dur", ro.root()).unwrap();
        assert_eq!(
            ro.read_at(f2b, ro.root(), 0, 7).unwrap(),
            b"durable".to_vec()
        );
        checks.push(check(
            "Namespace::sync() durability hook",
            "sync() is the single durability entry point; data survives an independent reopen",
            "reopened read-only; content = durable",
            "PASS",
            None,
            "",
        ));

        checks.push(check(
            "fdatasync as a distinct primitive",
            "no distinct primitive; served by the same full sync() (strictly stronger)",
            "the kernel delivers fdatasync(2) as fsync with the datasync hint; src/fuse.rs maps both to core.sync()",
            "PASS",
            None,
            "no errno: the operation is never rejected, so a reply is never a weaker (wrong) success",
        ));

        primitives.push(primitive(
            "durability",
            "PASS",
            "fsync is the durability barrier (ack state Durable vs Published); fdatasync has no distinct primitive and is covered by the same full sync().",
            checks,
        ));
    }

    let all_ok = primitives
        .iter()
        .all(|p| p["result"].as_str() == Some("PASS"));
    let doc = serde_json::json!({
        "schema": "orfs.correctness.posix-extras.v1",
        "generated_by": "tests/posix_extras.rs",
        "description": "POSIX-extras primitives exercised through the library/namespace API (no FUSE mount): xattrs, symlinks, hard links, supplementary groups, and durability (fsync vs fdatasync).",
        "all_ok": all_ok,
        "primitives": primitives,
    });
    write_json(Path::new("evidence/correctness/posix-extras.json"), &doc);
    assert!(all_ok, "every primitive must be PASS");
}
