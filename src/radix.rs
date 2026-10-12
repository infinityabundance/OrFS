//! A persistent (path-copying) **segmented radix** ordered map for `u64` keys.
//!
//! Research programme §6 asks for a layout that beats a pointer-heavy ordered
//! indexing when the *key structure permits something better*. Inode ids are
//! `u64`s allocated **monotonically** by the writer, and they are looked up and
//! enumerated far more often than they are inserted. [`crate::persistent::PMap`]
//! (a treap) stores one heap-allocated `Node` per entry — high pointer-chase and
//! allocation density, and `O(log n)` node visits per lookup. This module keeps
//! the *same* persistence contract (immutable, path-copying, `Arc`-shared,
//! `O(1)` `Clone`) but a **radix-shaped** one:
//!
//! * Keys are routed by 8-bit digits, most-significant first, so tree depth is
//!   bounded by `8` regardless of entry count (the treap's depth grows with
//!   `log n`).
//! * Entries live in contiguous, sorted **leaf pages** ([`LEAF_CAP`] entries
//!   each), so a point lookup ends in one binary search over a cache-resident
//!   array rather than a pointer chase, and ordered enumeration walks pages in
//!   key order.
//! * A mutation path-copies only the `O(depth)` internal nodes on the root-to-
//!   leaf path plus the one leaf page it touches; every other page and subtree is
//!   shared with the previous version.
//!
//! ## Persistence contract (identical to [`PMap`](crate::persistent::PMap))
//!
//! * `Clone` is a single `Arc` bump — `O(1)`, never a deep copy. Publishing a new
//!   root at a commit therefore costs a constant number of pointer copies, and
//!   every previously published root stays alive and unchanged for readers.
//! * `insert`/`remove`/`get` leave the receiver untouched and return a new map
//!   sharing every untouched page with it.
//! * The observable sequence is the in-order traversal, so structural sharing
//!   changes neither equality nor any serialised projection.
//!
//! This is the "persistent segmented radix" candidate for the inode-id index in
//! the layout-competition court (`tests/index_layout.rs`); it is deliberately a
//! **separate** type so the production index is only switched to it if the court
//! shows a clear win that does not regress publication or mutation.

use std::sync::Arc;

/// Bits per radix digit. 8 bits → up to 256 children per internal node and a
/// maximum tree depth of `64 / 8 = 8`.
const DIGIT_BITS: u32 = 8;
/// Number of digits in a `u64` key.
const DIGITS: u32 = 64 / DIGIT_BITS;
/// Maximum entries in a leaf page before it splits into an internal node.
///
/// This is the cache-density / copy-cost knob: larger pages amortise the node
/// spine but copy more bytes per mutation. `32` keeps a page within half a
/// kilobyte of payload while still giving a shallow tree for dense inode ids.
pub const LEAF_CAP: usize = 32;

/// A node is either an internal router (sorted `(digit, child)` pairs) or a leaf
/// page (a sorted run of `(key, value)` entries).
enum Node<V> {
    Internal(Vec<(u8, Arc<Node<V>>)>),
    Leaf(Vec<(u64, V)>),
}

/// A persistent ordered map from `u64` keys to `V`.
pub struct RadixMap<V> {
    root: Option<Arc<Node<V>>>,
    len: usize,
}

impl<V> Clone for RadixMap<V> {
    #[inline]
    fn clone(&self) -> Self {
        RadixMap {
            root: self.root.clone(),
            len: self.len,
        }
    }
}

impl<V> Default for RadixMap<V> {
    fn default() -> Self {
        RadixMap { root: None, len: 0 }
    }
}

impl<V> std::fmt::Debug for RadixMap<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately non-recursive: a map may hold millions of entries.
        f.debug_struct("RadixMap").field("len", &self.len).finish()
    }
}

impl<V: PartialEq> PartialEq for RadixMap<V> {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len && self.iter().eq(other.iter())
    }
}

impl<V: Eq> Eq for RadixMap<V> {}

/// The digit of `key` at `depth` (0-based, most-significant first).
///
/// `depth` is only ever `< DIGITS` for an internal node; a leaf reached at
/// `depth == DIGITS` has already distinguished every key.
#[inline]
fn digit(key: u64, depth: u32) -> u8 {
    debug_assert!(depth < DIGITS);
    ((key >> (64 - DIGIT_BITS * (depth + 1))) & 0xff) as u8
}

impl<V> RadixMap<V> {
    /// An empty map.
    pub fn new() -> Self {
        RadixMap::default()
    }

    /// The number of entries.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the map is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Look up `key`. `O(depth)` ≈ `O(8)` worst case, plus one leaf binary search.
    pub fn get(&self, key: &u64) -> Option<&V> {
        get_node(self.root.as_ref(), *key, 0)
    }

    /// Whether `key` is present.
    pub fn contains_key(&self, key: &u64) -> bool {
        self.get(key).is_some()
    }

    /// Iterate in ascending key order.
    pub fn iter(&self) -> Iter<'_, V> {
        Iter::full(self.root.as_ref())
    }

    /// Iterate the entries with keys in `[start, end)`, in ascending order.
    pub fn range(&self, start: u64, end: u64) -> Iter<'_, V> {
        Iter::bounded(self.root.as_ref(), start, end)
    }

    /// Iterate the keys in ascending order.
    pub fn keys(&self) -> impl Iterator<Item = &u64> {
        self.iter().map(|(k, _)| k)
    }

    /// Iterate the values in ascending key order.
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.iter().map(|(_, v)| v)
    }

    /// The smallest entry whose key is `>= key` (a lower bound).
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

    /// The largest entry whose key is `<= key` (a floor).
    pub fn predecessor(&self, key: &u64) -> Option<(&u64, &V)> {
        predecessor_node(self.root.as_ref(), *key, 0)
    }

    /// Structural statistics for the layout court: `(nodes, leaves, entries in
    /// leaves, max depth)`.
    pub fn layout_stats(&self) -> (usize, usize, usize, u32) {
        let mut acc = (0usize, 0usize, 0usize, 0u32);
        if let Some(root) = self.root.as_ref() {
            layout_stats_node(root, 0, &mut acc);
        }
        acc
    }

    /// The number of allocated nodes (internal routers + leaf pages).
    pub fn node_count(&self) -> usize {
        let mut count = 0usize;
        let mut stack: Vec<&Node<V>> = Vec::new();
        if let Some(root) = self.root.as_ref() {
            stack.push(root);
        }
        while let Some(n) = stack.pop() {
            count += 1;
            if let Node::Internal(children) = n {
                for (_, c) in children {
                    stack.push(c);
                }
            }
        }
        count
    }

    /// An estimate of the bytes this map's structure occupies: one `Arc`
    /// allocation per node plus each node's heap-allocated child/entry buffer at
    /// its current capacity. Deterministic and comparable across layouts; it does
    /// not include allocator slop, so it is a lower bound.
    pub fn mem_bytes(&self) -> usize {
        let arc_header = 2 * std::mem::size_of::<usize>();
        let node_size = std::mem::size_of::<Node<V>>();
        let child_size = std::mem::size_of::<(u8, Arc<Node<V>>)>();
        let entry_size = std::mem::size_of::<(u64, V)>();
        let mut bytes = 0usize;
        let mut stack: Vec<&Node<V>> = Vec::new();
        if let Some(root) = self.root.as_ref() {
            stack.push(root);
        }
        while let Some(n) = stack.pop() {
            bytes += node_size + arc_header;
            match n {
                Node::Internal(children) => {
                    bytes += children.capacity() * child_size;
                    for (_, c) in children {
                        stack.push(c);
                    }
                }
                Node::Leaf(entries) => {
                    bytes += entries.capacity() * entry_size;
                }
            }
        }
        bytes
    }
}

impl<V: Clone> RadixMap<V> {
    /// Return a new map with `key` bound to `value`, sharing every untouched
    /// page with `self`. `self` is unchanged.
    pub fn insert(&self, key: u64, value: V) -> RadixMap<V> {
        let existed = self.get(&key).is_some();
        let root = insert_node(self.root.as_ref(), key, value, 0);
        RadixMap {
            root: Some(root),
            len: self.len + usize::from(!existed),
        }
    }

    /// Return a new map without `key`, sharing every untouched page with `self`.
    /// `self` is unchanged; a missing key returns an equal map.
    pub fn remove(&self, key: &u64) -> RadixMap<V> {
        if !self.contains_key(key) {
            return self.clone();
        }
        RadixMap {
            root: remove_node(self.root.as_ref(), *key, 0),
            len: self.len - 1,
        }
    }

    /// Build a map from an iterator of pairs. Later duplicates win.
    pub fn from_pairs<I: IntoIterator<Item = (u64, V)>>(pairs: I) -> RadixMap<V> {
        let mut m = RadixMap::new();
        for (k, v) in pairs {
            m = m.insert(k, v);
        }
        m
    }
}

fn get_node<V>(node: Option<&Arc<Node<V>>>, key: u64, depth: u32) -> Option<&V> {
    let n = node?;
    match &**n {
        Node::Leaf(entries) => entries
            .binary_search_by_key(&key, |(k, _)| *k)
            .ok()
            .map(|i| &entries[i].1),
        Node::Internal(children) => {
            let d = digit(key, depth);
            let pos = children.partition_point(|(cd, _)| *cd < d);
            if pos < children.len() && children[pos].0 == d {
                get_node(Some(&children[pos].1), key, depth + 1)
            } else {
                None
            }
        }
    }
}

fn insert_node<V: Clone>(
    node: Option<&Arc<Node<V>>>,
    key: u64,
    val: V,
    depth: u32,
) -> Arc<Node<V>> {
    match node {
        None => Arc::new(Node::Leaf(vec![(key, val)])),
        Some(n) => match &**n {
            Node::Leaf(entries) => match entries.binary_search_by_key(&key, |(k, _)| *k) {
                Ok(pos) => {
                    let mut e = entries.clone();
                    e[pos].1 = val;
                    Arc::new(Node::Leaf(e))
                }
                Err(pos) => {
                    let mut e = entries.clone();
                    e.insert(pos, (key, val));
                    if e.len() <= LEAF_CAP {
                        Arc::new(Node::Leaf(e))
                    } else {
                        build(e, depth)
                    }
                }
            },
            Node::Internal(children) => {
                let d = digit(key, depth);
                let pos = children.partition_point(|(cd, _)| *cd < d);
                let mut ch = children.clone();
                if pos < ch.len() && ch[pos].0 == d {
                    let new_child = insert_node(Some(&ch[pos].1), key, val, depth + 1);
                    ch[pos].1 = new_child;
                } else {
                    let child = insert_node(None, key, val, depth + 1);
                    ch.insert(pos, (d, child));
                }
                Arc::new(Node::Internal(ch))
            }
        },
    }
}

/// Build a node from a sorted run of entries that share `depth` leading digits.
///
/// Returns a leaf when the run fits, otherwise routes one digit deeper. Because
/// distinct `u64` keys differ in at least one of the [`DIGITS`] bytes, a group at
/// `depth == DIGITS - 1` can only ever be a single entry, so recursion always
/// terminates before [`digit`] would be called out of range.
fn build<V: Clone>(entries: Vec<(u64, V)>, depth: u32) -> Arc<Node<V>> {
    debug_assert!(!entries.is_empty());
    if entries.len() <= LEAF_CAP {
        return Arc::new(Node::Leaf(entries));
    }
    debug_assert!(depth < DIGITS);
    let mut groups: Vec<(u8, Vec<(u64, V)>)> = Vec::new();
    for (k, v) in entries {
        let d = digit(k, depth);
        match groups.last_mut() {
            Some((gd, es)) if *gd == d => es.push((k, v)),
            _ => groups.push((d, vec![(k, v)])),
        }
    }
    let children = groups
        .into_iter()
        .map(|(d, es)| (d, build(es, depth + 1)))
        .collect();
    Arc::new(Node::Internal(children))
}

fn remove_node<V: Clone>(
    node: Option<&Arc<Node<V>>>,
    key: u64,
    depth: u32,
) -> Option<Arc<Node<V>>> {
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
            let d = digit(key, depth);
            let pos = children.partition_point(|(cd, _)| *cd < d);
            if pos >= children.len() || children[pos].0 != d {
                return Some(n.clone());
            }
            let mut ch = children.clone();
            match remove_node(Some(&ch[pos].1), key, depth + 1) {
                Some(child) => ch[pos].1 = child,
                None => {
                    ch.remove(pos);
                }
            }
            if ch.is_empty() {
                None
            } else {
                Some(Arc::new(Node::Internal(ch)))
            }
        }
    }
}

fn predecessor_node<V>(node: Option<&Arc<Node<V>>>, key: u64, depth: u32) -> Option<(&u64, &V)> {
    let mut cur = node;
    let mut best: Option<(&u64, &V)> = None;
    let mut d = depth;
    while let Some(n) = cur {
        match &**n {
            Node::Leaf(entries) => {
                let i = entries.partition_point(|(k, _)| *k <= key);
                if i > 0 {
                    let e = &entries[i - 1];
                    best = Some((&e.0, &e.1));
                }
                break;
            }
            Node::Internal(children) => {
                let dd = digit(key, d);
                let i = children.partition_point(|(cd, _)| *cd < dd);
                // Every child before `i` lies entirely to the left of `key`.
                if i > 0 {
                    if let Some(last) = rightmost(&children[i - 1].1) {
                        best = Some(last);
                    }
                }
                if i < children.len() && children[i].0 == dd {
                    cur = Some(&children[i].1);
                    d += 1;
                } else {
                    break;
                }
            }
        }
    }
    best
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

fn layout_stats_node<V>(node: &Node<V>, depth: u32, acc: &mut (usize, usize, usize, u32)) {
    // Iterative to avoid any recursion-depth concern on pathological shapes.
    let mut stack: Vec<(&Node<V>, u32)> = vec![(node, depth)];
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
}

/// One frame of the in-order traversal stack.
enum Frame<'a, V> {
    Internal {
        children: &'a [(u8, Arc<Node<V>>)],
        idx: usize,
    },
    Leaf {
        entries: &'a [(u64, V)],
        idx: usize,
    },
}

/// In-order iterator over a [`RadixMap`] (optionally bounded by an exclusive end).
pub struct Iter<'a, V> {
    stack: Vec<Frame<'a, V>>,
    end: Option<u64>,
}

impl<'a, V> Iter<'a, V> {
    fn full(root: Option<&'a Arc<Node<V>>>) -> Iter<'a, V> {
        let mut stack = Vec::new();
        push_seek(root, 0, 0, &mut stack);
        Iter { stack, end: None }
    }

    fn bounded(root: Option<&'a Arc<Node<V>>>, start: u64, end: u64) -> Iter<'a, V> {
        if start >= end {
            return Iter {
                stack: Vec::new(),
                end: Some(end),
            };
        }
        let mut stack = Vec::new();
        push_seek(root, start, 0, &mut stack);
        Iter {
            stack,
            end: Some(end),
        }
    }
}

/// Push the frames that begin an in-order walk at the first key `>= start`.
fn push_seek<'a, V>(
    node: Option<&'a Arc<Node<V>>>,
    start: u64,
    depth: u32,
    out: &mut Vec<Frame<'a, V>>,
) {
    let Some(n) = node else { return };
    match &**n {
        Node::Leaf(entries) => {
            let i = entries.partition_point(|(k, _)| *k < start);
            out.push(Frame::Leaf { entries, idx: i });
        }
        Node::Internal(children) => {
            let d = digit(start, depth);
            let i = children.partition_point(|(cd, _)| *cd < d);
            if i < children.len() && children[i].0 == d {
                // Resume at the chosen child's siblings once its subtree is done.
                out.push(Frame::Internal {
                    children,
                    idx: i + 1,
                });
                push_seek(Some(&children[i].1), start, depth + 1, out);
            } else {
                // No child shares this digit: every remaining child is > start.
                out.push(Frame::Internal { children, idx: i });
            }
        }
    }
}

enum Action<'a, V> {
    Yield(&'a u64, &'a V),
    PushInternal(&'a [(u8, Arc<Node<V>>)]),
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
                    let children: &[(u8, Arc<Node<V>>)] = children;
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
        let base: RadixMap<u64> = RadixMap::new();
        let mut versions = vec![base.clone()];
        for i in 0..1000u64 {
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
        assert_eq!(removed.len(), 999);
        assert_eq!(removed.get(&500), None);
        assert_eq!(full.get(&500), Some(&5000));
        assert!(full.iter().map(|(k, _)| *k).eq(0..1000));
        assert!(removed.iter().map(|(k, _)| *k).ne(0..1000));
    }

    #[test]
    fn iter_order_is_sorted_for_shuffled_inserts() {
        let keys = [7u64, 3, 9, 1, 5, 8, 2, 6, 4, 0];
        let m = RadixMap::from_pairs(keys.into_iter().map(|k| (k, k)));
        assert!(m.iter().map(|(k, _)| *k).eq(0..10));
    }

    #[test]
    fn equality_is_structural_not_by_shape() {
        let a = RadixMap::from_pairs((0..64u64).map(|k| (k, k * 2)));
        let mut b = RadixMap::new();
        for k in (0..64u64).rev() {
            b = b.insert(k, k * 2);
        }
        assert_eq!(a, b);
    }

    #[test]
    fn spans_leaf_boundaries_and_large_gaps() {
        // Force internal nodes and many leaf pages, including sparse high keys.
        let keys: Vec<u64> = (0..5000u64)
            .map(|i| i.wrapping_mul(0x9E37_79B9_7F4A_7C15))
            .chain([0, 1, u64::MAX, u64::MAX - 1, 1 << 63])
            .collect();
        let mut m = RadixMap::new();
        let mut model = BTreeMap::new();
        for (n, &k) in keys.iter().enumerate() {
            m = m.insert(k, n as u64);
            model.insert(k, n as u64);
        }
        assert_eq!(m.len(), model.len());
        let got: Vec<u64> = m.keys().copied().collect();
        let want: Vec<u64> = model.keys().copied().collect();
        assert_eq!(got, want);
        for (&k, &v) in &model {
            assert_eq!(m.get(&k), Some(&v));
        }
        assert_eq!(m.get(&999_999), None);
    }

    #[test]
    fn range_successor_predecessor_match_btreemap() {
        let keys: Vec<u64> = (0..3000u64).map(|i| i * 7 + 3).collect();
        let m = RadixMap::from_pairs(keys.iter().map(|&k| (k, k)));
        let model: BTreeMap<u64, u64> = keys.iter().map(|&k| (k, k)).collect();

        for start in [0u64, 1, 3, 4, 100, 7001, 21_003, 21_004] {
            let got: Vec<u64> = m.range(start, start + 500).map(|(k, _)| *k).collect();
            let want: Vec<u64> = model.range(start..start + 500).map(|(k, _)| *k).collect();
            assert_eq!(got, want, "range at {start}");
        }

        for probe in [0u64, 2, 3, 4, 10, 7000, 7001, 7002, 21_004, 99_999] {
            assert_eq!(
                m.successor(&probe).map(|(k, _)| *k),
                model.range(probe..).next().map(|(k, _)| *k),
                "successor at {probe}"
            );
            assert_eq!(
                m.successor_strict(&probe).map(|(k, _)| *k),
                model.range((probe + 1)..).next().map(|(k, _)| *k),
                "successor_strict at {probe}"
            );
            assert_eq!(
                m.predecessor(&probe).map(|(k, _)| *k),
                model.range(..=probe).next_back().map(|(k, _)| *k),
                "predecessor at {probe}"
            );
        }
    }

    #[test]
    fn remove_shrinks_and_preserves_order() {
        let keys: Vec<u64> = (0..2000u64).map(|i| i * 3).collect();
        let mut m = RadixMap::from_pairs(keys.iter().map(|&k| (k, k)));
        let mut model: BTreeMap<u64, u64> = keys.iter().map(|&k| (k, k)).collect();
        for (i, &k) in keys.iter().enumerate() {
            if i % 3 == 0 {
                m = m.remove(&k);
                model.remove(&k);
            }
        }
        assert_eq!(m.len(), model.len());
        let got: Vec<u64> = m.keys().copied().collect();
        let want: Vec<u64> = model.keys().copied().collect();
        assert_eq!(got, want);
    }
}
