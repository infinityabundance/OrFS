//! A persistent (path-copying) **segmented page tree** for `u64` keys.
//!
//! The byte-radix prototype ([`crate::radix::RadixMap`]) is a faithful
//! persistent radix, but the layout court (`tests/index_layout.rs`) measures it
//! *losing* on the inode-id domain: inode ids are allocated monotonically, so they
//! are **dense and sequential**, and a trie over their bytes cannot accumulate a
//! dense leaf page — it pushes the split all the way to the least-significant
//! byte and ends with roughly one entry per node. Dense sequential keys are the
//! adversarial case for any radix.
//!
//! This module keeps the reviewer's *shape* (a tree of contiguous, copy-on-write
//! **pages**: node capacity is a count, not a digit fan-out) but splits pages by
//! **count** and routes internal nodes by **separator key**, which is what makes
//! dense keys page-dense:
//!
//! * Entries live in sorted leaf pages of up to [`LEAF_CAP`] `(key, value)`
//!   pairs; a full page splits into two half pages, so a sequential build keeps
//!   pages ~half to full rather than one entry each.
//! * Internal pages hold up to [`INNER_CAP`] `(min_key, child)` routes and split
//!   the same way, so tree depth is `~log_INNER(N / LEAF_CAP)`.
//! * Every page is behind an `Arc`, so `Clone` is a single pointer copy and a
//!   mutation path-copies only the `O(depth)` pages on the root-to-leaf path —
//!   every other page is shared with every other version. Publishing a new root
//!   at a commit is `O(1)` and every old root stays reachable.
//!
//! Like [`crate::persistent::PMap`], this is a court candidate; it is only
//! adopted into the production index if the court shows a clear win that does not
//! regress publication or mutation.

use std::sync::Arc;

/// Entries per leaf page before it splits.
pub const LEAF_CAP: usize = 64;
/// Child routes per internal page before it splits.
pub const INNER_CAP: usize = 64;

enum Node<V> {
    /// A sorted run of `(key, value)` pairs.
    Leaf(Vec<(u64, V)>),
    /// A sorted run of `(min_key_of_subtree, child)` routes.
    Internal(Vec<(u64, Arc<Node<V>>)>),
}

/// A page that overflowed: the new right sibling and its minimum key.
type Split<V> = Option<(u64, Arc<Node<V>>)>;

/// A persistent ordered map from `u64` keys to `V`, stored as pages.
pub struct PageTree<V> {
    root: Option<Arc<Node<V>>>,
    len: usize,
}

impl<V> Clone for PageTree<V> {
    #[inline]
    fn clone(&self) -> Self {
        PageTree {
            root: self.root.clone(),
            len: self.len,
        }
    }
}

impl<V> Default for PageTree<V> {
    fn default() -> Self {
        PageTree { root: None, len: 0 }
    }
}

impl<V> std::fmt::Debug for PageTree<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PageTree").field("len", &self.len).finish()
    }
}

impl<V: PartialEq> PartialEq for PageTree<V> {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len && self.iter().eq(other.iter())
    }
}

impl<V: Eq> Eq for PageTree<V> {}

fn min_key<V>(node: &Node<V>) -> u64 {
    let mut cur = node;
    loop {
        match cur {
            Node::Leaf(entries) => return entries.first().map(|(k, _)| *k).unwrap_or(u64::MAX),
            Node::Internal(children) => match children.first() {
                Some((_, c)) => cur = c,
                None => return u64::MAX,
            },
        }
    }
}

impl<V> PageTree<V> {
    /// An empty tree.
    pub fn new() -> Self {
        PageTree::default()
    }

    /// The number of entries.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the tree is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Look up `key`. `O(depth)` page hops, each a binary search.
    pub fn get(&self, key: &u64) -> Option<&V> {
        let mut cur = self.root.as_deref()?;
        loop {
            match cur {
                Node::Leaf(entries) => {
                    return entries
                        .binary_search_by_key(key, |(k, _)| *k)
                        .ok()
                        .map(|i| &entries[i].1);
                }
                Node::Internal(children) => {
                    let i = children
                        .partition_point(|(m, _)| m <= key)
                        .saturating_sub(1);
                    cur = children.get(i)?.1.as_ref();
                }
            }
        }
    }

    /// Whether `key` is present.
    pub fn contains_key(&self, key: &u64) -> bool {
        self.get(key).is_some()
    }

    /// Iterate in ascending key order.
    pub fn iter(&self) -> Iter<'_, V> {
        Iter::new(self.root.as_ref(), 0, None)
    }

    /// Iterate the entries with keys in `[start, end)`, in ascending order.
    pub fn range(&self, start: u64, end: u64) -> Iter<'_, V> {
        Iter::new(self.root.as_ref(), start, Some(end))
    }

    /// Iterate the keys in ascending order.
    pub fn keys(&self) -> impl Iterator<Item = &u64> {
        self.iter().map(|(k, _)| k)
    }

    /// Iterate the values in ascending key order.
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.iter().map(|(_, v)| v)
    }

    /// The smallest entry whose key is `>= key`.
    pub fn successor(&self, key: &u64) -> Option<(&u64, &V)> {
        self.range(*key, u64::MAX).next()
    }

    /// The smallest entry whose key is strictly greater than `key`.
    pub fn successor_strict(&self, key: &u64) -> Option<(&u64, &V)> {
        if *key == u64::MAX {
            return None;
        }
        self.range(key.wrapping_add(1), u64::MAX).next()
    }

    /// The largest entry whose key is `<= key`.
    pub fn predecessor(&self, key: &u64) -> Option<(&u64, &V)> {
        let mut cur = self.root.as_deref()?;
        let mut best: Option<(&u64, &V)> = None;
        loop {
            match cur {
                Node::Leaf(entries) => {
                    let i = entries.partition_point(|(k, _)| *k <= *key);
                    if i > 0 {
                        let e = &entries[i - 1];
                        best = Some((&e.0, &e.1));
                    }
                    return best;
                }
                Node::Internal(children) => {
                    let i = children
                        .partition_point(|(m, _)| m <= key)
                        .saturating_sub(1);
                    if i > 0 {
                        if let Some(last) = rightmost(&children[i - 1].1) {
                            best = Some(last);
                        }
                    }
                    cur = children.get(i)?.1.as_ref();
                }
            }
        }
    }

    /// `(internal_pages, leaf_pages, leaf_entries, max_depth)`.
    pub fn layout_stats(&self) -> (usize, usize, usize, u32) {
        let mut acc = (0usize, 0usize, 0usize, 0u32);
        let mut stack: Vec<(&Node<V>, u32)> = Vec::new();
        if let Some(r) = self.root.as_deref() {
            stack.push((r, 1));
        }
        while let Some((n, d)) = stack.pop() {
            acc.3 = acc.3.max(d);
            match n {
                Node::Leaf(entries) => {
                    acc.1 += 1;
                    acc.2 += entries.len();
                }
                Node::Internal(children) => {
                    acc.0 += 1;
                    for (_, c) in children {
                        stack.push((c, d + 1));
                    }
                }
            }
        }
        acc
    }

    /// The number of allocated pages.
    pub fn node_count(&self) -> usize {
        let (i, l, _, _) = self.layout_stats();
        i + l
    }

    /// An estimate of the bytes the page structure occupies (page `Arc`
    /// allocations plus their buffer capacities; excludes allocator slop).
    pub fn mem_bytes(&self) -> usize {
        let arc_header = 2 * std::mem::size_of::<usize>();
        let node_size = std::mem::size_of::<Node<V>>();
        let rc_size = std::mem::size_of::<(u64, Arc<Node<V>>)>();
        let entry_size = std::mem::size_of::<(u64, V)>();
        let mut bytes = 0usize;
        let mut stack: Vec<&Node<V>> = Vec::new();
        if let Some(r) = self.root.as_deref() {
            stack.push(r);
        }
        while let Some(n) = stack.pop() {
            bytes += node_size + arc_header;
            match n {
                Node::Leaf(entries) => bytes += entries.capacity() * entry_size,
                Node::Internal(children) => {
                    bytes += children.capacity() * rc_size;
                    for (_, c) in children {
                        stack.push(c);
                    }
                }
            }
        }
        bytes
    }
}

impl<V: Clone> PageTree<V> {
    /// Return a new tree with `key` bound to `value`. `self` is unchanged.
    pub fn insert(&self, key: u64, value: V) -> PageTree<V> {
        let existed = self.get(&key).is_some();
        let root = match self.root.as_ref() {
            None => Arc::new(Node::Leaf(vec![(key, value)])),
            Some(r) => {
                let (new_root, split) = insert_rec(r, key, value);
                match split {
                    None => new_root,
                    Some((sep, right)) => {
                        let left_min = min_key(&new_root);
                        Arc::new(Node::Internal(vec![(left_min, new_root), (sep, right)]))
                    }
                }
            }
        };
        PageTree {
            root: Some(root),
            len: self.len + usize::from(!existed),
        }
    }

    /// Return a new tree without `key`. `self` is unchanged.
    pub fn remove(&self, key: &u64) -> PageTree<V> {
        if !self.contains_key(key) {
            return self.clone();
        }
        let root = remove_rec(self.root.as_ref(), *key);
        PageTree {
            root,
            len: self.len - 1,
        }
    }

    /// Build a tree from an iterator of pairs. Later duplicates win.
    pub fn from_pairs<I: IntoIterator<Item = (u64, V)>>(pairs: I) -> PageTree<V> {
        let mut t = PageTree::new();
        for (k, v) in pairs {
            t = t.insert(k, v);
        }
        t
    }
}

/// Insert into `node`; on overflow return `(new_right_page, min_key_of_right)`
/// for the caller to splice in.
fn insert_rec<V: Clone>(node: &Arc<Node<V>>, key: u64, val: V) -> (Arc<Node<V>>, Split<V>) {
    match &**node {
        Node::Leaf(entries) => {
            let pos = entries.partition_point(|(k, _)| *k < key);
            if pos < entries.len() && entries[pos].0 == key {
                let mut e = entries.clone();
                e[pos].1 = val;
                return (Arc::new(Node::Leaf(e)), None);
            }
            let mut e = entries.clone();
            e.insert(pos, (key, val));
            if e.len() <= LEAF_CAP {
                (Arc::new(Node::Leaf(e)), None)
            } else {
                let right = e.split_off(e.len() / 2);
                let sep = right[0].0;
                (
                    Arc::new(Node::Leaf(e)),
                    Some((sep, Arc::new(Node::Leaf(right)))),
                )
            }
        }
        Node::Internal(children) => {
            let i = children
                .partition_point(|(m, _)| *m <= key)
                .saturating_sub(1);
            let mut ch = children.clone();
            let (new_child, split) = insert_rec(&ch[i].1, key, val);
            ch[i].1 = new_child;
            if i == 0 {
                ch[0].0 = ch[0].0.min(key);
            }
            if let Some((sep, right)) = split {
                ch.insert(i + 1, (sep, right));
            }
            if ch.len() <= INNER_CAP {
                (Arc::new(Node::Internal(ch)), None)
            } else {
                let right = ch.split_off(ch.len() / 2);
                let sep = right[0].0;
                (
                    Arc::new(Node::Internal(ch)),
                    Some((sep, Arc::new(Node::Internal(right)))),
                )
            }
        }
    }
}

fn remove_rec<V: Clone>(node: Option<&Arc<Node<V>>>, key: u64) -> Option<Arc<Node<V>>> {
    let n = node?;
    match &**n {
        Node::Leaf(entries) => {
            let Ok(pos) = entries.binary_search_by_key(&key, |(k, _)| *k) else {
                return Some(n.clone());
            };
            let mut e = entries.clone();
            e.remove(pos);
            if e.is_empty() {
                None
            } else {
                Some(Arc::new(Node::Leaf(e)))
            }
        }
        Node::Internal(children) => {
            let i = children
                .partition_point(|(m, _)| *m <= key)
                .saturating_sub(1);
            let mut ch = children.clone();
            match remove_rec(Some(&ch[i].1), key) {
                Some(c) => ch[i].1 = c,
                None => {
                    ch.remove(i);
                }
            }
            if ch.is_empty() {
                None
            } else {
                if i == 0 {
                    ch[0].0 = min_key(&ch[0].1);
                }
                Some(Arc::new(Node::Internal(ch)))
            }
        }
    }
}

fn rightmost<V>(node: &Node<V>) -> Option<(&u64, &V)> {
    let mut cur = node;
    loop {
        match cur {
            Node::Leaf(entries) => {
                let e = entries.last()?;
                return Some((&e.0, &e.1));
            }
            Node::Internal(children) => {
                cur = &children.last()?.1;
            }
        }
    }
}

/// One frame of the in-order page walk.
enum Frame<'a, V> {
    Internal {
        children: &'a [(u64, Arc<Node<V>>)],
        idx: usize,
    },
    Leaf {
        entries: &'a [(u64, V)],
        idx: usize,
    },
}

/// In-order iterator over a [`PageTree`], optionally bounded by an exclusive end.
pub struct Iter<'a, V> {
    stack: Vec<Frame<'a, V>>,
    end: Option<u64>,
}

impl<'a, V> Iter<'a, V> {
    fn new(root: Option<&'a Arc<Node<V>>>, start: u64, end: Option<u64>) -> Iter<'a, V> {
        let mut stack = Vec::new();
        if let Some(r) = root {
            push_seek(r, start, &mut stack);
        }
        Iter { stack, end }
    }
}

fn push_seek<'a, V>(node: &'a Arc<Node<V>>, start: u64, out: &mut Vec<Frame<'a, V>>) {
    let mut cur = node;
    loop {
        match &**cur {
            Node::Leaf(entries) => {
                let i = entries.partition_point(|(k, _)| *k < start);
                out.push(Frame::Leaf { entries, idx: i });
                return;
            }
            Node::Internal(children) => {
                let i = children
                    .partition_point(|(m, _)| *m <= start)
                    .saturating_sub(1);
                out.push(Frame::Internal {
                    children,
                    idx: i + 1,
                });
                cur = match children.get(i) {
                    Some((_, c)) => c,
                    None => return,
                };
            }
        }
    }
}

enum Action<'a, V> {
    Yield(&'a u64, &'a V),
    PushInternal(&'a [(u64, Arc<Node<V>>)]),
    PushLeaf(&'a [(u64, V)]),
    Pop,
}

impl<'a, V> Iterator for Iter<'a, V> {
    type Item = (&'a u64, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let action = match self.stack.last_mut() {
                None => return None,
                Some(Frame::Leaf { entries, idx }) => {
                    let entries: &[(u64, V)] = entries;
                    if *idx < entries.len() {
                        let e = &entries[*idx];
                        *idx += 1;
                        Action::Yield(&e.0, &e.1)
                    } else {
                        Action::Pop
                    }
                }
                Some(Frame::Internal { children, idx }) => {
                    let children: &[(u64, Arc<Node<V>>)] = children;
                    if *idx < children.len() {
                        let child = &children[*idx].1;
                        *idx += 1;
                        match &**child {
                            Node::Internal(c) => Action::PushInternal(c),
                            Node::Leaf(e) => Action::PushLeaf(e),
                        }
                    } else {
                        Action::Pop
                    }
                }
            };
            match action {
                Action::Yield(k, v) => {
                    if let Some(end) = self.end {
                        if *k >= end {
                            self.stack.clear();
                            return None;
                        }
                    }
                    return Some((k, v));
                }
                Action::PushInternal(c) => self.stack.push(Frame::Internal {
                    children: c,
                    idx: 0,
                }),
                Action::PushLeaf(e) => self.stack.push(Frame::Leaf { entries: e, idx: 0 }),
                Action::Pop => {
                    self.stack.pop();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn insert_get_remove_and_share() {
        let base: PageTree<u64> = PageTree::new();
        let mut versions = vec![base.clone()];
        for i in 0..2000u64 {
            let next = versions.last().unwrap().insert(i, i * 10);
            versions.push(next);
        }
        for (v, m) in versions.iter().enumerate() {
            assert_eq!(m.len(), v);
            for i in 0..v as u64 {
                assert_eq!(m.get(&i), Some(&(i * 10)));
            }
            assert_eq!(m.get(&(v as u64)), None);
        }
        let full = versions.last().unwrap().clone();
        let removed = full.remove(&500);
        assert_eq!(removed.len(), 1999);
        assert_eq!(removed.get(&500), None);
        assert_eq!(full.get(&500), Some(&5000));
        assert!(full.iter().map(|(k, _)| *k).eq(0..2000));
    }

    #[test]
    fn matches_btreemap_for_shuffled_keys() {
        let keys: Vec<u64> = (0..5000u64)
            .map(|i| i.wrapping_mul(0x9E37_79B9_7F4A_7C15))
            .chain([0, u64::MAX])
            .collect();
        let mut t = PageTree::new();
        let mut model = BTreeMap::new();
        for (n, &k) in keys.iter().enumerate() {
            t = t.insert(k, n as u64);
            model.insert(k, n as u64);
        }
        assert_eq!(t.len(), model.len());
        assert_eq!(
            t.keys().copied().collect::<Vec<_>>(),
            model.keys().copied().collect::<Vec<_>>()
        );
        for (&k, &v) in &model {
            assert_eq!(t.get(&k), Some(&v));
        }
        assert_eq!(t.get(&123_456), None);
    }

    #[test]
    fn range_successor_predecessor_match_btreemap() {
        let keys: Vec<u64> = (0..3000u64).map(|i| i * 7 + 3).collect();
        let t = PageTree::from_pairs(keys.iter().map(|&k| (k, k)));
        let model: BTreeMap<u64, u64> = keys.iter().map(|&k| (k, k)).collect();

        for start in [0u64, 1, 3, 4, 100, 7001, 21_003, 21_004] {
            assert_eq!(
                t.range(start, start + 500)
                    .map(|(k, _)| *k)
                    .collect::<Vec<_>>(),
                model
                    .range(start..start + 500)
                    .map(|(k, _)| *k)
                    .collect::<Vec<_>>(),
                "range at {start}"
            );
        }
        for probe in [0u64, 2, 3, 4, 10, 7000, 7001, 7002, 21_004, 99_999] {
            assert_eq!(
                t.successor(&probe).map(|(k, _)| *k),
                model.range(probe..).next().map(|(k, _)| *k),
                "successor at {probe}"
            );
            assert_eq!(
                t.successor_strict(&probe).map(|(k, _)| *k),
                model.range((probe + 1)..).next().map(|(k, _)| *k),
                "successor_strict at {probe}"
            );
            assert_eq!(
                t.predecessor(&probe).map(|(k, _)| *k),
                model.range(..=probe).next_back().map(|(k, _)| *k),
                "predecessor at {probe}"
            );
        }
    }

    #[test]
    fn remove_shrinks_and_preserves_order() {
        let keys: Vec<u64> = (0..4000u64).map(|i| i * 3).collect();
        let mut t = PageTree::from_pairs(keys.iter().map(|&k| (k, k)));
        let mut model: BTreeMap<u64, u64> = keys.iter().map(|&k| (k, k)).collect();
        for (i, &k) in keys.iter().enumerate() {
            if i % 3 == 0 {
                t = t.remove(&k);
                model.remove(&k);
            }
        }
        assert_eq!(t.len(), model.len());
        assert_eq!(
            t.keys().copied().collect::<Vec<_>>(),
            model.keys().copied().collect::<Vec<_>>()
        );
        assert!(t.layout_stats().3 <= 8, "depth should stay small");
    }
}
