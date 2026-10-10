//! Phase 3 namespace-model tests.
//!
//! A deterministic, independent **reference model** of the logical filesystem is
//! compared against the real OrFS namespace engine for every operation class:
//! create/open-for-read, arbitrary-offset writes, overwrite, sparse files,
//! beyond-EOF writes, truncate up/down, unlink, hard links, symlinks,
//! mkdir/rmdir, rename (ordinary / `NOREPLACE` / `EXCHANGE`, cross-directory,
//! cycle rejection), and extended attributes.
//!
//! It also proves the two structural properties of the derived index:
//!
//! * **rebuild equivalence** — an index rebuilt from the log equals the live
//!   index; and
//! * **log-wins** — a tampered persisted snapshot is rejected, and the live
//!   index always equals the log.
//!
//! Finally it exercises the two Phase-2 carry-over fixes: typed-bracket
//! validation on recovery (an inconsistent bracket is a hard error) and strictly
//! monotonic transaction-id allocation that never reuses an aborted id.

mod support;

use std::collections::{BTreeMap, HashMap};

use orfs::commit::{CommitSequencer, DurabilityMode};
use orfs::log::OpenMode;
use orfs::namespace::{Namespace, RenameMode, SetAttr};
use orfs::record::{Record, RecordType, FOOTER_LEN, HEADER_LEN};
use orfs::segment::segment_file_name;
use orfs::transaction::AbortReason;
use orfs::volume::Volume;
use proptest::prelude::*;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Reference model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    File,
    Dir,
    Symlink,
}

/// An independent, plain-data model of the logical filesystem. It derives link
/// counts from the tree (files: number of names; directories:
/// `2 + immediate subdirectories`), so it is a genuine oracle rather than a
/// restatement of the engine's bookkeeping.
#[derive(Debug, Clone, Default)]
struct Model {
    kinds: HashMap<u64, Kind>,
    content: HashMap<u64, Vec<u8>>,
    symlinks: HashMap<u64, Vec<u8>>,
    xattrs: HashMap<u64, BTreeMap<Vec<u8>, Vec<u8>>>,
    dentries: HashMap<(u64, Vec<u8>), u64>,
    dir_parent: HashMap<u64, u64>,
    next_inode: u64,
}

impl Model {
    fn new() -> Model {
        let mut m = Model::default();
        m.kinds.insert(1, Kind::Dir);
        m.dir_parent.insert(1, 1);
        m.xattrs.insert(1, BTreeMap::new());
        m.next_inode = 2;
        m
    }

    fn is_dir(&self, id: u64) -> bool {
        self.kinds.get(&id) == Some(&Kind::Dir)
    }

    /// Whether `id` is a directory still linked into the namespace: the root, or
    /// a directory that still has at least one name. A removed directory keeps
    /// its kind (so it is still compared) but is no longer live, and so cannot
    /// be the parent of a mutation.
    fn is_live_dir(&self, id: u64) -> bool {
        self.is_dir(id) && (id == 1 || self.dentries.values().any(|c| *c == id))
    }

    fn readdir(&self, dir: u64) -> Vec<(Vec<u8>, u64)> {
        let mut v: Vec<(Vec<u8>, u64)> = self
            .dentries
            .iter()
            .filter(|((p, _), _)| *p == dir)
            .map(|((_, n), c)| (n.clone(), *c))
            .collect();
        v.sort();
        v
    }

    fn live_nlink(&self, id: u64) -> u32 {
        match self.kinds.get(&id) {
            Some(Kind::Dir) => {
                let subdirs = self
                    .dentries
                    .iter()
                    .filter(|((p, _), c)| *p == id && self.is_dir(**c))
                    .count();
                if !self.dentries.values().any(|c| *c == id) && id != 1 {
                    // Removed directory: no names remain.
                    0
                } else {
                    2 + subdirs as u32
                }
            }
            _ => self.dentries.values().filter(|c| **c == id).count() as u32,
        }
    }

    fn is_ancestor(&self, ancestor: u64, node: u64) -> bool {
        if ancestor == node {
            return true;
        }
        let mut cur = node;
        loop {
            match self.dir_parent.get(&cur) {
                Some(&p) if p != cur => {
                    if p == ancestor {
                        return true;
                    }
                    cur = p;
                }
                _ => return false,
            }
        }
    }

    fn create(
        &mut self,
        parent: u64,
        name: &[u8],
        kind: Kind,
        target: Option<Vec<u8>>,
    ) -> Result<u64, ()> {
        if !self.is_live_dir(parent) || self.dentries.contains_key(&(parent, name.to_vec())) {
            return Err(());
        }
        let id = self.next_inode;
        self.next_inode += 1;
        self.kinds.insert(id, kind);
        self.xattrs.insert(id, BTreeMap::new());
        match kind {
            Kind::File => {
                self.content.insert(id, Vec::new());
            }
            Kind::Dir => {
                self.dir_parent.insert(id, parent);
            }
            Kind::Symlink => {
                self.symlinks.insert(id, target.unwrap_or_default());
            }
        }
        self.dentries.insert((parent, name.to_vec()), id);
        Ok(id)
    }

    fn write_at(&mut self, inode: u64, offset: u64, data: &[u8]) -> Result<(), ()> {
        if self.kinds.get(&inode) != Some(&Kind::File) {
            return Err(());
        }
        // A zero-length write succeeds but never changes the file (POSIX).
        if data.is_empty() {
            return Ok(());
        }
        let c = self.content.entry(inode).or_default();
        let end = offset as usize + data.len();
        if c.len() < end {
            c.resize(end, 0);
        }
        c[offset as usize..end].copy_from_slice(data);
        Ok(())
    }

    fn zero_range(&mut self, inode: u64, offset: u64, len: u64) -> Result<(), ()> {
        if self.kinds.get(&inode) != Some(&Kind::File) {
            return Err(());
        }
        if len == 0 {
            return Ok(());
        }
        let c = self.content.entry(inode).or_default();
        let end = (offset + len) as usize;
        if c.len() < end {
            c.resize(end, 0);
        }
        for b in &mut c[offset as usize..end] {
            *b = 0;
        }
        Ok(())
    }

    fn truncate(&mut self, inode: u64, size: u64) -> Result<(), ()> {
        if self.kinds.get(&inode) != Some(&Kind::File) {
            return Err(());
        }
        let c = self.content.entry(inode).or_default();
        c.resize(size as usize, 0);
        Ok(())
    }

    fn unlink(&mut self, parent: u64, name: &[u8]) -> Result<(), ()> {
        if !self.is_live_dir(parent) {
            return Err(());
        }
        let child = match self.dentries.get(&(parent, name.to_vec())) {
            Some(&c) => c,
            None => return Err(()),
        };
        if self.is_dir(child) {
            return Err(());
        }
        self.dentries.remove(&(parent, name.to_vec()));
        Ok(())
    }

    fn rmdir(&mut self, parent: u64, name: &[u8]) -> Result<(), ()> {
        if !self.is_live_dir(parent) {
            return Err(());
        }
        let child = match self.dentries.get(&(parent, name.to_vec())) {
            Some(&c) => c,
            None => return Err(()),
        };
        if !self.is_dir(child) || child == 1 || !self.readdir(child).is_empty() {
            return Err(());
        }
        self.dentries.remove(&(parent, name.to_vec()));
        self.dir_parent.remove(&child);
        Ok(())
    }

    fn link(&mut self, inode: u64, parent: u64, name: &[u8]) -> Result<(), ()> {
        if !matches!(
            self.kinds.get(&inode),
            Some(Kind::File) | Some(Kind::Symlink)
        ) {
            return Err(());
        }
        if !self.is_live_dir(parent) || self.dentries.contains_key(&(parent, name.to_vec())) {
            return Err(());
        }
        self.dentries.insert((parent, name.to_vec()), inode);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn rename(&mut self, op: u64, on: &[u8], np: u64, nn: &[u8], mode: u8) -> Result<(), ()> {
        if !self.is_live_dir(op) || !self.is_live_dir(np) {
            return Err(());
        }
        let src = match self.dentries.get(&(op, on.to_vec())) {
            Some(&s) => s,
            None => return Err(()),
        };
        if op == np && on == nn {
            return Ok(());
        }
        let dest = self.dentries.get(&(np, nn.to_vec())).copied();
        match mode {
            1 => {
                // NoReplace
                if dest.is_some() {
                    return Err(());
                }
                // Renaming a directory into itself or a descendant is a cycle.
                // OrFS rejects this (`DirectoryCycle`); the reference model must
                // too (the Ordinary branch below already does).
                if self.is_dir(src) && self.is_ancestor(src, np) {
                    return Err(());
                }
                self.move_entry(src, op, on, np, nn);
            }
            2 => {
                // Exchange
                let dest = match dest {
                    Some(d) => d,
                    None => return Err(()),
                };
                if dest == src {
                    return Ok(());
                }
                if self.is_dir(src)
                    && self.is_dir(dest)
                    && (self.is_ancestor(src, dest) || self.is_ancestor(dest, src))
                {
                    return Err(());
                }
                self.dentries.insert((op, on.to_vec()), dest);
                self.dentries.insert((np, nn.to_vec()), src);
                if self.is_dir(src) {
                    self.dir_parent.insert(src, np);
                }
                if self.is_dir(dest) {
                    self.dir_parent.insert(dest, op);
                }
            }
            _ => {
                // Ordinary
                if let Some(dest) = dest {
                    if self.is_dir(src) && !self.is_dir(dest) {
                        return Err(());
                    }
                    if !self.is_dir(src) && self.is_dir(dest) {
                        return Err(());
                    }
                    if self.is_dir(dest) && !self.readdir(dest).is_empty() {
                        return Err(());
                    }
                    self.dentries.remove(&(np, nn.to_vec()));
                    if self.is_dir(dest) {
                        self.dir_parent.remove(&dest);
                    }
                }
                if self.is_dir(src) && self.is_ancestor(src, np) {
                    return Err(());
                }
                self.move_entry(src, op, on, np, nn);
            }
        }
        Ok(())
    }

    fn move_entry(&mut self, src: u64, op: u64, on: &[u8], np: u64, nn: &[u8]) {
        self.dentries.remove(&(op, on.to_vec()));
        self.dentries.insert((np, nn.to_vec()), src);
        if self.is_dir(src) {
            self.dir_parent.insert(src, np);
        }
    }

    fn setxattr(&mut self, inode: u64, name: &[u8], value: &[u8], create: bool) -> Result<(), ()> {
        let x = self.xattrs.get_mut(&inode).ok_or(())?;
        if create && x.contains_key(name) {
            return Err(());
        }
        x.insert(name.to_vec(), value.to_vec());
        Ok(())
    }

    fn removexattr(&mut self, inode: u64, name: &[u8]) -> Result<(), ()> {
        let x = self.xattrs.get_mut(&inode).ok_or(())?;
        if x.remove(name).is_none() {
            return Err(());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Differential equivalence
// ---------------------------------------------------------------------------

fn assert_equivalent(ns: &Namespace, model: &Model) {
    let root = ns.root();
    for (&id, &kind) in &model.kinds {
        let stat = ns
            .getattr(id, root)
            .unwrap_or_else(|e| panic!("getattr {id}: {e}"));
        let expect_kind = match kind {
            Kind::File => "file",
            Kind::Dir => "directory",
            Kind::Symlink => "symlink",
        };
        assert_eq!(stat.kind.name(), expect_kind, "inode {id} kind");
        assert_eq!(
            stat.nlink,
            model.live_nlink(id),
            "inode {id} nlink (orfs vs model)"
        );
        match kind {
            Kind::File => {
                let content = &model.content[&id];
                assert_eq!(stat.size, content.len() as u64, "inode {id} size");
                let got = ns
                    .read_at(id, root, 0, stat.size as u32)
                    .unwrap_or_else(|e| panic!("read {id}: {e}"));
                assert_eq!(&got, content, "inode {id} content");
                // A clamped read near EOF returns a matching tail.
                if !content.is_empty() {
                    let off = (content.len() - 1) as u64;
                    let tail = ns.read_at(id, root, off, 4096).unwrap();
                    assert_eq!(tail, content[off as usize..].to_vec(), "inode {id} tail");
                }
            }
            Kind::Dir => {
                assert_eq!(
                    ns.readdir(id, root).unwrap(),
                    model.readdir(id),
                    "dir {id} children"
                );
            }
            Kind::Symlink => {
                assert_eq!(
                    ns.readlink(id, root).unwrap(),
                    model.symlinks[&id],
                    "symlink {id} target"
                );
            }
        }
        // Stored extended attributes must match exactly.
        for (name, value) in &model.xattrs[&id] {
            assert_eq!(&ns.getxattr(id, name, root).unwrap(), value, "xattr {id}");
        }
        let stored: Vec<Vec<u8>> = ns
            .listxattr(id, root)
            .unwrap()
            .into_iter()
            .filter(|n| !n.starts_with(b"user.orfs."))
            .collect();
        let expect: Vec<Vec<u8>> = model.xattrs[&id].keys().cloned().collect();
        assert_eq!(stored, expect, "xattr names {id}");
    }
    // Every directory entry resolves identically.
    for ((parent, name), child) in &model.dentries {
        assert_eq!(
            ns.lookup(*parent, name, root).unwrap(),
            *child,
            "lookup {parent}/{:?}",
            String::from_utf8_lossy(name)
        );
    }
}

// ---------------------------------------------------------------------------
// Payloads / helpers
// ---------------------------------------------------------------------------

fn data(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| seed.wrapping_add(i as u8)).collect()
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ---------------------------------------------------------------------------
// Deterministic scenarios
// ---------------------------------------------------------------------------

#[test]
fn deterministic_scenarios_match_reference_model() {
    let mut verdicts: Vec<serde_json::Value> = Vec::new();
    let mut record = |name: &str, ok: bool, detail: String| {
        verdicts.push(serde_json::json!({ "scenario": name, "ok": ok, "detail": detail }));
    };

    // -- arbitrary-offset, overwrite, sparse, beyond-EOF, truncate ------------
    {
        let td = TempDir::new().unwrap();
        let mut ns = support::init_namespace(td.path(), 1 << 20, DurabilityMode::Ordered);
        let mut m = Model::new();
        let root = ns.root_inode();
        let f = ns.create(root, b"f", 0o644, 0, 0).unwrap();
        m.create(root, b"f", Kind::File, None).unwrap();

        let ops: Vec<(&str, u64, Vec<u8>)> = vec![
            ("offset-zero", 0, data(8, 1)),
            ("middle", 3, data(2, 2)),
            ("eof", 8, data(4, 3)),
            ("beyond-eof", 20, data(5, 4)),
            ("overlap", 6, data(4, 5)),
        ];
        let mut ok = true;
        for (label, off, bytes) in ops {
            ns.write_at(f, off, &bytes).unwrap();
            m.write_at(f, off, &bytes).unwrap();
            assert_equivalent(&ns, &m);
            let _ = label;
        }
        // Explicit zero range (hole punch).
        ns.zero_range(f, 4, 6).unwrap();
        m.zero_range(f, 4, 6).unwrap();
        assert_equivalent(&ns, &m);
        // Truncate down then up must zero-fill, never resurrect.
        ns.truncate(f, 10).unwrap();
        m.truncate(f, 10).unwrap();
        assert_equivalent(&ns, &m);
        ns.truncate(f, 24).unwrap();
        m.truncate(f, 24).unwrap();
        assert_equivalent(&ns, &m);
        // Reopen: history retained, logical view identical.
        drop(ns);
        let ns = Namespace::open(td.path(), OpenMode::ReadWrite, DurabilityMode::Ordered).unwrap();
        assert_equivalent(&ns, &m);
        ok &= ns.index_matches_log().unwrap();
        record(
            "extents",
            ok,
            "offset-zero/middle/eof/beyond-eof/overlap/zero-range/truncate up+down match model"
                .into(),
        );
    }

    // -- unlink / hard links / symlink / mkdir / rmdir ------------------------
    {
        let td = TempDir::new().unwrap();
        let mut ns = support::init_namespace(td.path(), 1 << 20, DurabilityMode::Ordered);
        let mut m = Model::new();
        let root = ns.root_inode();
        let d = ns.mkdir(root, b"d", 0o755, 0, 0).unwrap();
        m.create(root, b"d", Kind::Dir, None).unwrap();
        assert_equivalent(&ns, &m);
        let f = ns.create(d, b"f", 0o644, 0, 0).unwrap();
        m.create(d, b"f", Kind::File, None).unwrap();
        ns.write_at(f, 0, &data(10, 7)).unwrap();
        m.write_at(f, 0, &data(10, 7)).unwrap();
        // rmdir on a non-empty directory is rejected by both.
        assert!(ns.rmdir(root, b"d").is_err());
        assert!(m.rmdir(root, b"d").is_err());
        // Hard link.
        ns.link(f, root, b"hard").unwrap();
        m.link(f, root, b"hard").unwrap();
        assert_equivalent(&ns, &m);
        // Unlink one name: data survives, nlink drops.
        ns.unlink(root, b"hard").unwrap();
        m.unlink(root, b"hard").unwrap();
        assert_equivalent(&ns, &m);
        // Unlink the last name: inode retained with nlink 0, data readable.
        ns.unlink(d, b"f").unwrap();
        m.unlink(d, b"f").unwrap();
        assert_equivalent(&ns, &m);
        assert_eq!(ns.getattr(f, ns.root()).unwrap().nlink, 0);
        // Symlink.
        let l = ns.symlink(root, b"link", b"../d/f", 0, 0).unwrap();
        m.create(root, b"link", Kind::Symlink, Some(b"../d/f".to_vec()))
            .unwrap();
        assert_equivalent(&ns, &m);
        assert_eq!(ns.readlink(l, ns.root()).unwrap(), b"../d/f");
        // rmdir the now-empty directory.
        ns.rmdir(root, b"d").unwrap();
        m.rmdir(root, b"d").unwrap();
        assert_equivalent(&ns, &m);
        assert!(ns.index_matches_log().unwrap());
        record(
            "namespace",
            true,
            "mkdir/rmdir(empty-only)/hardlink/unlink(last-name retains data)/symlink match model"
                .into(),
        );
    }

    // -- rename: ordinary, overwrite, NOREPLACE, EXCHANGE, cross-dir, cycle ---
    {
        let td = TempDir::new().unwrap();
        let mut ns = support::init_namespace(td.path(), 1 << 20, DurabilityMode::Ordered);
        let mut m = Model::new();
        let root = ns.root_inode();
        let a = ns.mkdir(root, b"a", 0o755, 0, 0).unwrap();
        m.create(root, b"a", Kind::Dir, None).unwrap();
        let b = ns.mkdir(root, b"b", 0o755, 0, 0).unwrap();
        m.create(root, b"b", Kind::Dir, None).unwrap();
        let x = ns.create(a, b"x", 0o644, 0, 0).unwrap();
        m.create(a, b"x", Kind::File, None).unwrap();
        ns.write_at(x, 0, &data(6, 3)).unwrap();
        m.write_at(x, 0, &data(6, 3)).unwrap();
        let y = ns.create(a, b"y", 0o644, 0, 0).unwrap();
        m.create(a, b"y", Kind::File, None).unwrap();
        ns.write_at(y, 0, &data(3, 9)).unwrap();
        m.write_at(y, 0, &data(3, 9)).unwrap();

        // Ordinary rename within a directory.
        ns.rename(a, b"x", a, b"z", RenameMode::Ordinary).unwrap();
        m.rename(a, b"x", a, b"z", 0).unwrap();
        assert_equivalent(&ns, &m);
        // Cross-directory rename.
        ns.rename(a, b"z", b, b"z", RenameMode::Ordinary).unwrap();
        m.rename(a, b"z", b, b"z", 0).unwrap();
        assert_equivalent(&ns, &m);
        // NOREPLACE onto an existing name is rejected.
        assert!(ns.rename(b, b"z", a, b"y", RenameMode::NoReplace).is_err());
        assert!(m.rename(b, b"z", a, b"y", 1).is_err());
        assert_equivalent(&ns, &m);
        // Ordinary overwrite replaces the destination.
        ns.rename(b, b"z", a, b"y", RenameMode::Ordinary).unwrap();
        m.rename(b, b"z", a, b"y", 0).unwrap();
        assert_equivalent(&ns, &m);
        // EXCHANGE swaps two names.
        let p = ns.create(a, b"p", 0o644, 0, 0).unwrap();
        m.create(a, b"p", Kind::File, None).unwrap();
        let q = ns.create(root, b"q", 0o644, 0, 0).unwrap();
        m.create(root, b"q", Kind::File, None).unwrap();
        ns.write_at(p, 0, &data(2, 1)).unwrap();
        m.write_at(p, 0, &data(2, 1)).unwrap();
        ns.write_at(q, 0, &data(2, 2)).unwrap();
        m.write_at(q, 0, &data(2, 2)).unwrap();
        ns.rename(a, b"p", root, b"q", RenameMode::Exchange)
            .unwrap();
        m.rename(a, b"p", root, b"q", 2).unwrap();
        assert_equivalent(&ns, &m);
        assert_eq!(ns.lookup(root, b"q", ns.root()).unwrap(), p);
        assert_eq!(ns.lookup(a, b"p", ns.root()).unwrap(), q);
        // Directory cycle is rejected.
        assert!(ns
            .rename(root, b"a", a, b"inner", RenameMode::Ordinary)
            .is_err());
        assert!(m.rename(root, b"a", a, b"inner", 0).is_err());
        assert_equivalent(&ns, &m);
        assert!(ns.index_matches_log().unwrap());
        record(
            "rename",
            true,
            "ordinary/overwrite/exchange/cross-directory match model; NOREPLACE and cycle rejected"
                .into(),
        );
    }

    // -- xattrs ---------------------------------------------------------------
    {
        let td = TempDir::new().unwrap();
        let mut ns = support::init_namespace(td.path(), 1 << 20, DurabilityMode::Ordered);
        let mut m = Model::new();
        let root = ns.root_inode();
        let f = ns.create(root, b"f", 0o644, 0, 0).unwrap();
        m.create(root, b"f", Kind::File, None).unwrap();
        ns.setxattr(f, b"user.a", b"1", false).unwrap();
        m.setxattr(f, b"user.a", b"1", false).unwrap();
        ns.setxattr(f, b"user.b", b"two", true).unwrap();
        m.setxattr(f, b"user.b", b"two", true).unwrap();
        assert_equivalent(&ns, &m);
        // XATTR_CREATE over an existing name is rejected.
        assert!(ns.setxattr(f, b"user.a", b"x", true).is_err());
        assert!(m.setxattr(f, b"user.a", b"x", true).is_err());
        // Overwrite.
        ns.setxattr(f, b"user.a", b"11", false).unwrap();
        m.setxattr(f, b"user.a", b"11", false).unwrap();
        assert_equivalent(&ns, &m);
        // Derived attributes are present.
        assert!(ns
            .listxattr(f, ns.root())
            .unwrap()
            .contains(&b"user.orfs.version".to_vec()));
        // Remove.
        ns.removexattr(f, b"user.b").unwrap();
        m.removexattr(f, b"user.b").unwrap();
        assert_equivalent(&ns, &m);
        assert!(ns.removexattr(f, b"user.b").is_err());
        record(
            "xattr",
            true,
            "set/overwrite/remove and XATTR_CREATE match model".into(),
        );
    }

    // -- setattr (mode/uid/gid/times/size) ------------------------------------
    {
        let td = TempDir::new().unwrap();
        let mut ns = support::init_namespace(td.path(), 1 << 20, DurabilityMode::Ordered);
        let root = ns.root_inode();
        let f = ns.create(root, b"f", 0o644, 0, 0).unwrap();
        ns.write_at(f, 0, &data(12, 5)).unwrap();
        let attrs = SetAttr {
            mode: Some(0o600),
            uid: Some(1000),
            gid: Some(1000),
            size: Some(4),
            ..Default::default()
        };
        ns.setattr(f, &attrs).unwrap();
        let st = ns.getattr(f, ns.root()).unwrap();
        assert_eq!(st.mode, 0o600);
        assert_eq!(st.uid, 1000);
        assert_eq!(st.gid, 1000);
        assert_eq!(st.size, 4);
        assert_eq!(
            ns.read_at(f, ns.root(), 0, 64).unwrap(),
            data(12, 5)[..4].to_vec()
        );
        assert!(ns.index_matches_log().unwrap());
        record(
            "setattr",
            true,
            "mode/uid/gid/size applied as a masked transition".into(),
        );
    }

    // Compose evidence.
    let all_ok = verdicts.iter().all(|v| v["ok"].as_bool().unwrap_or(false));
    let value = serde_json::json!({
        "schema": "orfs.evidence.inode-semantics.v1",
        "generator": "tests/namespace_model.rs",
        "all_ok": all_ok,
        "verdicts": verdicts,
    });
    support::write_json(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("evidence/correctness/inode-semantics.json")
            .as_path(),
        &value,
    );
    assert!(all_ok, "one or more model-vs-orfs scenarios disagreed");
}

#[test]
fn sparse_file_reads_zero_without_storing_zeros() {
    let td = TempDir::new().unwrap();
    let mut ns = support::init_namespace(td.path(), 1 << 20, DurabilityMode::Ordered);
    let root = ns.root_inode();
    let f = ns.create(root, b"sparse", 0o644, 0, 0).unwrap();
    // One byte at 1 MiB, leaving an enormous hole.
    ns.write_at(f, 1 << 20, b"Z").unwrap();
    let st = ns.getattr(f, ns.root()).unwrap();
    assert_eq!(st.size, (1 << 20) + 1);
    let hole = ns.read_at(f, ns.root(), 0, 4096).unwrap();
    assert_eq!(hole, vec![0u8; 4096]);
    let tail = ns.read_at(f, ns.root(), 1 << 20, 1).unwrap();
    assert_eq!(tail, b"Z");
    // The stored history is tiny relative to the logical hole.
    assert!(ns.volume().log.canonical_bytes() < (1 << 16));
    assert!(ns.index_matches_log().unwrap());
}

// ---------------------------------------------------------------------------
// Rebuild equivalence and log-wins
// ---------------------------------------------------------------------------

fn build_workload(ns: &mut Namespace, m: &mut Model) {
    let root = ns.root_inode();
    let a = ns.mkdir(root, b"a", 0o755, 0, 0).unwrap();
    m.create(root, b"a", Kind::Dir, None).unwrap();
    let b = ns.mkdir(a, b"b", 0o755, 0, 0).unwrap();
    m.create(a, b"b", Kind::Dir, None).unwrap();
    let f = ns.create(b, b"f", 0o644, 0, 0).unwrap();
    m.create(b, b"f", Kind::File, None).unwrap();
    ns.write_at(f, 0, &data(64, 1)).unwrap();
    m.write_at(f, 0, &data(64, 1)).unwrap();
    ns.write_at(f, 100, &data(16, 2)).unwrap();
    m.write_at(f, 100, &data(16, 2)).unwrap();
    ns.truncate(f, 90).unwrap();
    m.truncate(f, 90).unwrap();
    ns.link(f, root, b"hard").unwrap();
    m.link(f, root, b"hard").unwrap();
    let l = ns.symlink(root, b"l", b"a/b/f", 0, 0).unwrap();
    m.create(root, b"l", Kind::Symlink, Some(b"a/b/f".to_vec()))
        .unwrap();
    let _ = l;
    ns.setxattr(f, b"user.k", b"v", false).unwrap();
    m.setxattr(f, b"user.k", b"v", false).unwrap();
    ns.rename(a, b"b", root, b"b2", RenameMode::Ordinary)
        .unwrap();
    m.rename(a, b"b", root, b"b2", 0).unwrap();
}

#[test]
fn index_rebuild_equivalence_and_log_wins() {
    let td = TempDir::new().unwrap();
    let dir = td.path().to_path_buf();
    let mut ns = support::init_namespace(&dir, 1 << 20, DurabilityMode::Ordered);
    let mut m = Model::new();
    build_workload(&mut ns, &mut m);
    assert_equivalent(&ns, &m);

    // Rebuild from the log equals the live index.
    let rebuilt = ns.rebuild_index().unwrap();
    let live = ns.index().clone();
    let rebuild_equal = rebuilt == live;
    let digest_equal = rebuilt.canonical_digest() == live.canonical_digest();
    assert!(rebuild_equal, "rebuilt index must equal the live index");

    // Persist, then reload a valid snapshot.
    ns.persist_index_snapshot().unwrap();
    let root = ns.volume().log.committed_end_offset();
    let loaded = ns.load_persisted_index().unwrap();
    let snapshot_valid = loaded.as_ref().map(|i| i == &live).unwrap_or(false);
    assert!(
        snapshot_valid,
        "a freshly written snapshot must load and match"
    );

    // Tamper the persisted snapshot body (do not touch the digest).
    let path = ns.snapshot_path();
    let mut bytes = std::fs::read(&path).unwrap();
    if let Some(pos) = find_subslice(&bytes, b"\"nlink\"") {
        // Flip a digit in the first nlink value.
        let mut i = pos + 7;
        while i < bytes.len() && !bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i < bytes.len() {
            bytes[i] = if bytes[i] == b'9' { b'0' } else { bytes[i] + 1 };
        }
    }
    std::fs::write(&path, &bytes).unwrap();
    let tampered = ns.load_persisted_index().unwrap();
    let tamper_rejected = tampered.is_none();
    assert!(tamper_rejected, "a tampered snapshot must be rejected");

    // The log still wins: reopening yields an index equal to the log replay.
    drop(ns);
    let ns = Namespace::open(&dir, OpenMode::ReadWrite, DurabilityMode::Ordered).unwrap();
    assert_equivalent(&ns, &m);
    let after = ns.index().clone();
    let log_wins = ns.rebuild_index().unwrap() == after;
    assert!(log_wins);

    let value = serde_json::json!({
        "schema": "orfs.evidence.namespace-rebuild.v1",
        "generator": "tests/namespace_model.rs",
        "committed_root": root,
        "rebuild_equals_live": rebuild_equal,
        "digest_equals": digest_equal,
        "snapshot_valid_on_load": snapshot_valid,
        "tampered_snapshot_rejected": tamper_rejected,
        "log_wins_after_tamper": log_wins,
        "inode_count": live.inode_count(),
        "dentry_count": live.dentry_count(),
        "all_ok": rebuild_equal && digest_equal && snapshot_valid && tamper_rejected && log_wins,
    });
    support::write_json(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("evidence/correctness/namespace-rebuild.json")
            .as_path(),
        &value,
    );
    assert!(value["all_ok"].as_bool().unwrap());
}

#[test]
fn snapshots_and_checkpoints_are_logged_and_rebuilt() {
    let td = TempDir::new().unwrap();
    let mut ns = support::init_namespace(td.path(), 1 << 20, DurabilityMode::Ordered);
    let root = ns.root_inode();
    let f = ns.create(root, b"f", 0o644, 0, 0).unwrap();
    ns.write_at(f, 0, &data(8, 1)).unwrap();
    let pre_root = ns.root();
    let named = ns.publish_snapshot(b"v1").unwrap();
    assert_eq!(named, pre_root);
    ns.write_index_checkpoint().unwrap();
    let live = ns.index();
    assert_eq!(live.snapshot_roots().get(b"v1".as_slice()), Some(&pre_root));
    let checkpoints = live.checkpoints();
    assert_eq!(checkpoints.len(), 1);
    // The inode's version counts every authoritative record touching it:
    // INODE_CREATE, DENTRY_ADD, and DATA_EXTENT.
    let version = ns.getxattr(f, b"user.orfs.version", ns.root()).unwrap();
    assert_eq!(version, b"3");
    assert!(ns.index_matches_log().unwrap());
}

// ---------------------------------------------------------------------------
// Carry-over fix (a): typed-bracket validation on recovery
// ---------------------------------------------------------------------------

/// Overwrite a `TX_COMMIT` record's bracket checksum, keeping framing valid.
fn tamper_first_commit_bracket(dir: &std::path::Path) {
    let vol = Volume::open(dir, OpenMode::ReadOnly).expect("open valid volume");
    let canonical = vol.log.read_committed_bytes().unwrap();
    let extents = vol.log.extents().to_vec();
    let mut off = 0usize;
    let mut found = None;
    while off < canonical.len() {
        let (rec, used) = Record::decode(&canonical[off..]).unwrap();
        if rec.known_type().unwrap() == RecordType::TxCommit {
            found = Some((off as u64, used));
            break;
        }
        off += used;
    }
    let (logical, used) = found.expect("a committed TX_COMMIT exists");
    let seg = extents
        .iter()
        .find(|e| logical >= e.id && logical < e.id + e.valid_len)
        .expect("segment covering the commit");
    let phys = (logical - seg.id) as usize;
    let path = Volume::log_dir(dir).join(segment_file_name(seg.id).unwrap());
    let mut file = std::fs::read(&path).unwrap();
    {
        let rec = &mut file[phys..phys + used];
        let payload_len = u64::from_le_bytes(rec[12..20].try_into().unwrap()) as usize;
        let pstart = HEADER_LEN;
        // Flip one byte of the 32-byte bracket checksum (payload offset 40).
        rec[pstart + 40] ^= 0xFF;
        let pcrc = crc32c::crc32c(&rec[pstart..pstart + 68]);
        rec[pstart + 68..pstart + 72].copy_from_slice(&pcrc.to_le_bytes());
        let fstart = pstart + payload_len;
        let rcrc = crc32c::crc32c(&rec[..fstart]);
        rec[fstart + 8..fstart + 12].copy_from_slice(&rcrc.to_le_bytes());
        assert_eq!(fstart + FOOTER_LEN, used);
    }
    std::fs::write(&path, &file).unwrap();
}

#[test]
fn inconsistent_commit_bracket_is_a_hard_recovery_error() {
    let td = TempDir::new().unwrap();
    let dir = td.path().to_path_buf();
    {
        let mut ns = support::init_namespace(&dir, 1 << 20, DurabilityMode::Sync);
        let root = ns.root_inode();
        let f = ns.create(root, b"f", 0o644, 0, 0).unwrap();
        ns.write_at(f, 0, &data(32, 1)).unwrap();
        let g = ns.create(root, b"g", 0o644, 0, 0).unwrap();
        ns.write_at(g, 0, &data(16, 2)).unwrap();
        // The valid volume passes deep verification including bracket checks.
        let vol = Volume::open(&dir, OpenMode::ReadOnly).unwrap();
        let report = vol.verify(true).unwrap();
        assert!(report
            .checks
            .iter()
            .any(|c| c.name == "transaction_brackets" && c.ok));
    }
    tamper_first_commit_bracket(&dir);
    // Recovery/verification must refuse an inconsistent committed bracket.
    let res = Volume::open(&dir, OpenMode::ReadOnly);
    assert!(
        res.is_err(),
        "an inconsistent committed bracket must be refused"
    );
    let msg = res.err().unwrap().to_string();
    assert!(
        msg.contains("bracket") || msg.contains("corrupt"),
        "unexpected error: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Carry-over fix (b): monotonic, collision-free transaction ids
// ---------------------------------------------------------------------------

#[test]
fn transaction_ids_are_monotonic_and_never_reuse_aborted_ids() {
    let td = TempDir::new().unwrap();
    let dir = td.path().to_path_buf();
    {
        let mut vol = support::init_volume(&dir, 1 << 20);
        let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Ordered);
        let id1 = seq.peek_transaction_id();
        seq.commit(support::build_transaction(id1, 2)).unwrap();
        // Abort a transaction: its id must never be reused.
        let aborted_id = seq.peek_transaction_id();
        let tx = seq.begin().unwrap().build().unwrap();
        seq.abort(tx, AbortReason::UserRequested, "carry-over (b)")
            .unwrap();
        let id3 = seq.peek_transaction_id();
        seq.commit(support::build_transaction(id3, 2)).unwrap();
        assert_eq!(id1, 1);
        assert_eq!(aborted_id, 2);
        assert_eq!(id3, 3);
    }
    // Reopen read-write: the next allocated id must exceed every id ever used,
    // including the aborted id 2 (the Phase-2 bug would reissue 2).
    let mut vol = Volume::open(&dir, OpenMode::ReadWrite).unwrap();
    assert_eq!(vol.log.max_transaction_id(), 3);
    let next = vol.log.next_transaction_id().unwrap();
    assert!(
        next > 3,
        "next id {next} must exceed all previously used ids"
    );
    let seq = CommitSequencer::from_log(&mut vol.log, DurabilityMode::Ordered);
    assert!(
        seq.peek_transaction_id() > 2,
        "sequencer must not reissue the aborted id 2"
    );
    assert_eq!(seq.peek_transaction_id(), 4);
}

// ---------------------------------------------------------------------------
// Randomized differential testing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Op {
    Create(u64, u8),
    Mkdir(u64, u8),
    Symlink(u64, u8, Vec<u8>),
    Write(u64, u64, Vec<u8>),
    ZeroRange(u64, u64, u64),
    Truncate(u64, u64),
    Unlink(u64, u8),
    Rmdir(u64, u8),
    Link(u64, u64, u8),
    Rename(u64, u8, u64, u8, u8),
    SetXattr(u64, u8, u8),
    RemoveXattr(u64, u8),
}

fn name_of(n: u8) -> Vec<u8> {
    vec![b'a' + (n % 5)]
}

fn apply_model(m: &mut Model, op: &Op) -> Result<(), ()> {
    match op {
        Op::Create(p, n) => m.create(*p, &name_of(*n), Kind::File, None).map(|_| ()),
        Op::Mkdir(p, n) => m.create(*p, &name_of(*n), Kind::Dir, None).map(|_| ()),
        Op::Symlink(p, n, t) => m
            .create(*p, &name_of(*n), Kind::Symlink, Some(t.clone()))
            .map(|_| ()),
        Op::Write(i, o, d) => m.write_at(*i, *o, d),
        Op::ZeroRange(i, o, l) => m.zero_range(*i, *o, *l),
        Op::Truncate(i, s) => m.truncate(*i, *s),
        Op::Unlink(p, n) => m.unlink(*p, &name_of(*n)),
        Op::Rmdir(p, n) => m.rmdir(*p, &name_of(*n)),
        Op::Link(i, p, n) => m.link(*i, *p, &name_of(*n)),
        Op::Rename(op, on, np, nn, mode) => m.rename(*op, &name_of(*on), *np, &name_of(*nn), *mode),
        Op::SetXattr(i, _n, v) => m.setxattr(*i, b"k", &[b'0' + (v % 4)], false),
        Op::RemoveXattr(i, _n) => m.removexattr(*i, b"k"),
    }
}

fn apply_orfs(ns: &mut Namespace, op: &Op) -> Result<(), orfs::OrfsError> {
    match op {
        Op::Create(p, n) => ns.create(*p, &name_of(*n), 0o644, 0, 0).map(|_| ()),
        Op::Mkdir(p, n) => ns.mkdir(*p, &name_of(*n), 0o755, 0, 0).map(|_| ()),
        Op::Symlink(p, n, t) => ns.symlink(*p, &name_of(*n), t, 0, 0).map(|_| ()),
        Op::Write(i, o, d) => ns.write_at(*i, *o, d).map(|_| ()),
        Op::ZeroRange(i, o, l) => ns.zero_range(*i, *o, *l).map(|_| ()),
        Op::Truncate(i, s) => ns.truncate(*i, *s).map(|_| ()),
        Op::Unlink(p, n) => ns.unlink(*p, &name_of(*n)),
        Op::Rmdir(p, n) => ns.rmdir(*p, &name_of(*n)),
        Op::Link(i, p, n) => ns.link(*i, *p, &name_of(*n)),
        Op::Rename(op, on, np, nn, mode) => {
            let mode = match mode % 3 {
                1 => RenameMode::NoReplace,
                2 => RenameMode::Exchange,
                _ => RenameMode::Ordinary,
            };
            ns.rename(*op, &name_of(*on), *np, &name_of(*nn), mode)
        }
        Op::SetXattr(i, n, v) => {
            let _ = n;
            ns.setxattr(*i, b"k", &[b'0' + (v % 4)], false)
        }
        Op::RemoveXattr(i, n) => {
            let _ = n;
            ns.removexattr(*i, b"k")
        }
    }
}

fn op_strategy() -> impl Strategy<Value = Op> {
    let small = 1u64..7;
    prop_oneof![
        (small.clone(), 0u8..8).prop_map(|(p, n)| Op::Create(p, n)),
        (small.clone(), 0u8..8).prop_map(|(p, n)| Op::Mkdir(p, n)),
        (
            small.clone(),
            0u8..8,
            proptest::collection::vec(any::<u8>(), 1..4)
        )
            .prop_map(|(p, n, t)| Op::Symlink(p, n, t)),
        (
            small.clone(),
            0u64..64,
            proptest::collection::vec(any::<u8>(), 0..12)
        )
            .prop_map(|(i, o, d)| Op::Write(i, o, d)),
        (small.clone(), 0u64..48, 0u64..16).prop_map(|(i, o, l)| Op::ZeroRange(i, o, l)),
        (small.clone(), 0u64..48).prop_map(|(i, s)| Op::Truncate(i, s)),
        (small.clone(), 0u8..8).prop_map(|(p, n)| Op::Unlink(p, n)),
        (small.clone(), 0u8..8).prop_map(|(p, n)| Op::Rmdir(p, n)),
        (small.clone(), small.clone(), 0u8..8).prop_map(|(i, p, n)| Op::Link(i, p, n)),
        (small.clone(), 0u8..8, small.clone(), 0u8..8, 0u8..3)
            .prop_map(|(op, on, np, nn, mode)| Op::Rename(op, on, np, nn, mode)),
        (small.clone(), 0u8..3, 0u8..4).prop_map(|(i, n, v)| Op::SetXattr(i, n, v)),
        (small, 0u8..3).prop_map(|(i, n)| Op::RemoveXattr(i, n)),
    ]
}

// ---------------------------------------------------------------------------
// Regression: a removed directory is not a mutable parent
// ---------------------------------------------------------------------------

/// Regression (hardening). The differential property test shrank a failure to
/// `[Mkdir(1, 2), Rmdir(1, 2), Mkdir(2, 0)]`: creating an entry inside an
/// already-removed directory succeeded and bumped that directory's link count
/// from `0` to `1`, disagreeing with the reference model and with the documented
/// derivation (`docs/NAMESPACE.md` §4.1: a directory has `0` links once removed).
///
/// A directory that has been fully removed is retained and readable by id, but
/// it is no longer addressable, so it must not accept a new entry.
#[test]
fn removed_directory_is_not_a_mutable_parent() {
    let td = TempDir::new().unwrap();
    let mut ns = support::init_namespace(td.path(), 1 << 20, DurabilityMode::Ordered);
    let mut m = Model::new();
    let root_inode = ns.root_inode();

    // Mkdir(1, 2), Rmdir(1, 2), Mkdir(2, 0) — the shrunk failing sequence.
    let d = ns.mkdir(root_inode, &name_of(2), 0o755, 0, 0).unwrap();
    m.create(root_inode, &name_of(2), Kind::Dir, None).unwrap();
    ns.rmdir(root_inode, &name_of(2)).unwrap();
    m.rmdir(root_inode, &name_of(2)).unwrap();
    assert_eq!(ns.getattr(d, ns.root()).unwrap().nlink, 0);
    assert_eq!(m.live_nlink(d), 0);
    assert_equivalent(&ns, &m);

    // Neither engine accepts a new entry under the removed directory...
    assert!(ns.mkdir(d, &name_of(0), 0o755, 0, 0).is_err());
    assert!(m.create(d, &name_of(0), Kind::Dir, None).is_err());
    // ...and the removed directory's link count stays `0`.
    assert_eq!(ns.getattr(d, ns.root()).unwrap().nlink, 0);
    assert_equivalent(&ns, &m);
    assert!(ns.index_matches_log().unwrap());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Any random sequence of namespace operations: OrFS and the reference model
    /// must agree on success/failure, and on every observable, after each step.
    #[test]
    fn random_namespace_ops_match_reference_model(ops in proptest::collection::vec(op_strategy(), 1..24)) {
        let td = TempDir::new().unwrap();
        let mut ns = support::init_namespace(td.path(), 1 << 20, DurabilityMode::Ordered);
        let mut m = Model::new();
        for op in &ops {
            let mo = apply_model(&mut m, op);
            let oo = apply_orfs(&mut ns, op);
            prop_assert_eq!(mo.is_ok(), oo.is_ok(), "op {:?}: model {:?} vs orfs {:?}", op, mo.is_ok(), oo);
            if mo.is_ok() {
                assert_equivalent(&ns, &m);
            }
        }
        prop_assert!(ns.index_matches_log().unwrap());
    }
}
