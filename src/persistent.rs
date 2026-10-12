//! Persistent, structurally-shared ordered maps (Phase 27).
//!
//! The derived index is published to readers as an immutable snapshot
//! ([`crate::namespace::ReadState`]) at every commit boundary. To keep that
//! publication proportional to the *affected* objects rather than to total
//! history, the index stores its spines in [`PMap`]: an immutable, path-copying
//! ordered map whose nodes are shared (via `Arc`) between every version of the
//! map.
//!
//! * Cloning a `PMap` is a single `Arc` pointer copy — `O(1)`, never a deep copy.
//! * `insert`/`remove`/`get` are expected `O(log n)` and copy only the `O(log n)`
//!   nodes along the root-to-key path; every untouched subtree is shared with the
//!   prior map.
//!
//! The implementation is a **treap**: an ordered binary tree whose nodes carry a
//! deterministic priority derived from the key's hash. Priorities fix the shape
//! for a given key set, so the structure is fully reproducible (no RNG), while
//! still giving the expected `O(log n)` depth of a random treap. Because a map's
//! observable sequence is its *in-order* traversal, structural sharing changes
//! neither equality nor any serialised projection.
//!
//! This is the "persistent (path-copying) map" that `docs/CONCURRENCY.md` §4.1
//! previously deferred.

use std::borrow::Borrow;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

/// A persistent ordered map from `K` to `V`.
///
/// `Clone` is `O(1)`; every mutating operation returns a new map and leaves the
/// receiver (and every other map sharing its nodes) unchanged.
pub struct PMap<K, V> {
    root: Option<Arc<Node<K, V>>>,
    len: usize,
}

struct Node<K, V> {
    key: K,
    val: V,
    prio: u64,
    left: Option<Arc<Node<K, V>>>,
    right: Option<Arc<Node<K, V>>>,
}

impl<K, V> Clone for PMap<K, V> {
    #[inline]
    fn clone(&self) -> Self {
        PMap {
            root: self.root.clone(),
            len: self.len,
        }
    }
}

impl<K, V> Drop for PMap<K, V> {
    fn drop(&mut self) {
        // Drop iteratively: a treap's depth is expected `O(log n)`, but a
        // structurally-shared map can in principle be deep, and recursing per
        // level would risk the stack. Shared subtrees still referenced by another
        // map are left to that owner.
        let mut stack: Vec<Arc<Node<K, V>>> = Vec::new();
        if let Some(root) = self.root.take() {
            stack.push(root);
        }
        while let Some(node) = stack.pop() {
            if let Ok(mut node) = Arc::try_unwrap(node) {
                if let Some(l) = node.left.take() {
                    stack.push(l);
                }
                if let Some(r) = node.right.take() {
                    stack.push(r);
                }
            }
        }
    }
}

impl<K, V> Default for PMap<K, V> {
    fn default() -> Self {
        PMap { root: None, len: 0 }
    }
}

impl<K, V> std::fmt::Debug for PMap<K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately non-recursive: a `PMap` may hold millions of nodes.
        f.debug_struct("PMap").field("len", &self.len).finish()
    }
}

impl<K: PartialEq, V: PartialEq> PartialEq for PMap<K, V> {
    fn eq(&self, other: &Self) -> bool {
        if self.len != other.len {
            return false;
        }
        self.iter().eq(other.iter())
    }
}

impl<K: Eq, V: Eq> Eq for PMap<K, V> {}

/// A deterministic 64-bit priority for `key`.
///
/// `FxHasher` is used for speed and reproducibility, then split-mixed so the
/// resulting bits are well distributed for tree balancing. Ties are benign: the
/// heap property uses a strict comparison, and any key set still yields a valid
/// BST.
fn priority<K: Hash + ?Sized>(key: &K) -> u64 {
    let mut h = rustc_hash::FxHasher::default();
    key.hash(&mut h);
    let mut x = h.finish();
    // splitmix64 finalizer.
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

impl<K, V> PMap<K, V> {
    /// An empty map.
    pub fn new() -> Self {
        PMap::default()
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

    /// Look up `key`. Expected `O(log n)`.
    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q> + Ord,
        Q: Ord + ?Sized,
    {
        let mut cur = self.root.as_deref();
        while let Some(n) = cur {
            match key.cmp(n.key.borrow()) {
                std::cmp::Ordering::Less => cur = n.left.as_deref(),
                std::cmp::Ordering::Greater => cur = n.right.as_deref(),
                std::cmp::Ordering::Equal => return Some(&n.val),
            }
        }
        None
    }

    /// Whether `key` is present.
    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q> + Ord,
        Q: Ord + ?Sized,
    {
        self.get(key).is_some()
    }

    /// Iterate in ascending key order.
    pub fn iter(&self) -> Iter<'_, K, V> {
        Iter {
            stack: leftmost(self.root.as_deref()),
        }
    }

    /// Iterate the keys in ascending order.
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.iter().map(|(k, _)| k)
    }

    /// Iterate the values in ascending key order.
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.iter().map(|(_, v)| v)
    }

    /// The number of allocated nodes reachable from this map.
    pub fn node_count(&self) -> usize {
        let mut count = 0usize;
        let mut stack: Vec<&Node<K, V>> = Vec::new();
        if let Some(root) = self.root.as_deref() {
            stack.push(root);
        }
        while let Some(n) = stack.pop() {
            count += 1;
            if let Some(l) = n.left.as_deref() {
                stack.push(l);
            }
            if let Some(r) = n.right.as_deref() {
                stack.push(r);
            }
        }
        count
    }

    /// An estimate of the bytes this map's structure occupies: one `Arc`
    /// allocation (header + `Node`) per node. Deterministic and comparable
    /// against other layouts; it excludes allocator slop (a lower bound).
    pub fn mem_bytes(&self) -> usize {
        let per_node = std::mem::size_of::<Node<K, V>>() + 2 * std::mem::size_of::<usize>();
        self.node_count() * per_node
    }

    /// The smallest entry whose key is `>= key` (a lower bound). `O(log n)`.
    pub fn successor<Q>(&self, key: &Q) -> Option<(&K, &V)>
    where
        K: Borrow<Q> + Ord,
        Q: Ord + ?Sized,
    {
        let mut best = None;
        let mut cur = self.root.as_deref();
        while let Some(n) = cur {
            if n.key.borrow() < key {
                cur = n.right.as_deref();
            } else {
                best = Some((&n.key, &n.val));
                cur = n.left.as_deref();
            }
        }
        best
    }

    /// The smallest entry whose key is strictly greater than `key`. `O(log n)`.
    pub fn successor_strict<Q>(&self, key: &Q) -> Option<(&K, &V)>
    where
        K: Borrow<Q> + Ord,
        Q: Ord + ?Sized,
    {
        let mut best = None;
        let mut cur = self.root.as_deref();
        while let Some(n) = cur {
            if n.key.borrow() > key {
                best = Some((&n.key, &n.val));
                cur = n.left.as_deref();
            } else {
                cur = n.right.as_deref();
            }
        }
        best
    }

    /// The largest entry whose key is `<= key` (a floor). `O(log n)`.
    pub fn predecessor<Q>(&self, key: &Q) -> Option<(&K, &V)>
    where
        K: Borrow<Q> + Ord,
        Q: Ord + ?Sized,
    {
        let mut best = None;
        let mut cur = self.root.as_deref();
        while let Some(n) = cur {
            if n.key.borrow() > key {
                cur = n.left.as_deref();
            } else {
                best = Some((&n.key, &n.val));
                cur = n.right.as_deref();
            }
        }
        best
    }
}

fn leftmost<K, V>(mut node: Option<&Node<K, V>>) -> Vec<&Node<K, V>> {
    let mut stack = Vec::new();
    while let Some(n) = node {
        stack.push(n);
        node = n.left.as_deref();
    }
    stack
}

/// In-order iterator over a [`PMap`].
pub struct Iter<'a, K, V> {
    stack: Vec<&'a Node<K, V>>,
}

impl<'a, K, V> Iterator for Iter<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        let n = self.stack.pop()?;
        let mut cur = n.right.as_deref();
        while let Some(c) = cur {
            self.stack.push(c);
            cur = c.left.as_deref();
        }
        Some((&n.key, &n.val))
    }
}

/// In-order iterator over the `u64`-keyed entries of a [`PMap`] that lie in
/// `[start, end)`, positioned directly at the first qualifying key.
pub struct Range<'a, V> {
    stack: Vec<&'a Node<u64, V>>,
    end: u64,
}

impl<'a, V> Iterator for Range<'a, V> {
    type Item = (&'a u64, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        let n = self.stack.pop()?;
        if n.key >= self.end {
            self.stack.clear();
            return None;
        }
        let mut cur = n.right.as_deref();
        while let Some(c) = cur {
            self.stack.push(c);
            cur = c.left.as_deref();
        }
        Some((&n.key, &n.val))
    }
}

impl<V> PMap<u64, V> {
    /// Iterate the entries with keys in `[start, end)`, in ascending order, in
    /// `O(log n + k)` for `k` entries visited.
    pub fn range(&self, start: u64, end: u64) -> Range<'_, V> {
        let mut stack = Vec::new();
        let mut cur = self.root.as_deref();
        while let Some(n) = cur {
            if n.key < start {
                cur = n.right.as_deref();
            } else {
                stack.push(n);
                cur = n.left.as_deref();
            }
        }
        Range { stack, end }
    }
}

impl<K: Clone + Ord + Hash, V: Clone> PMap<K, V> {
    /// Return a new map with `key` bound to `value`, sharing every untouched
    /// subtree with `self`. Expected `O(log n)`; `self` is unchanged.
    pub fn insert(&self, key: K, value: V) -> PMap<K, V> {
        let existed = self.get::<K>(&key).is_some();
        let prio = priority(&key);
        let root = insert_node(self.root.as_ref(), key, value, prio);
        PMap {
            root: Some(root),
            len: self.len + usize::from(!existed),
        }
    }

    /// Return a new map without `key`, sharing every untouched subtree with
    /// `self`. Expected `O(log n)`; `self` is unchanged. A missing key returns an
    /// equal map.
    pub fn remove<Q>(&self, key: &Q) -> PMap<K, V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        if !self.contains_key(key) {
            return self.clone();
        }
        let root = remove_node(self.root.as_ref(), key);
        PMap {
            root,
            len: self.len - 1,
        }
    }

    /// Build a map from an iterator of pairs. Later duplicates win.
    pub fn from_pairs<I: IntoIterator<Item = (K, V)>>(pairs: I) -> PMap<K, V> {
        let mut m = PMap::new();
        for (k, v) in pairs {
            m = m.insert(k, v);
        }
        m
    }
}

fn insert_node<K: Clone + Ord, V: Clone>(
    node: Option<&Arc<Node<K, V>>>,
    key: K,
    val: V,
    prio: u64,
) -> Arc<Node<K, V>> {
    match node {
        None => Arc::new(Node {
            key,
            val,
            prio,
            left: None,
            right: None,
        }),
        Some(n) => {
            if key < n.key {
                let new_left = insert_node(n.left.as_ref(), key, val, prio);
                let nn = Arc::new(Node {
                    key: n.key.clone(),
                    val: n.val.clone(),
                    prio: n.prio,
                    left: Some(new_left),
                    right: n.right.clone(),
                });
                let unbalanced = nn.left.as_ref().map(|l| l.prio).unwrap_or(0) > nn.prio;
                if unbalanced {
                    rotate_right(&nn)
                } else {
                    nn
                }
            } else if key > n.key {
                let new_right = insert_node(n.right.as_ref(), key, val, prio);
                let nn = Arc::new(Node {
                    key: n.key.clone(),
                    val: n.val.clone(),
                    prio: n.prio,
                    left: n.left.clone(),
                    right: Some(new_right),
                });
                let unbalanced = nn.right.as_ref().map(|r| r.prio).unwrap_or(0) > nn.prio;
                if unbalanced {
                    rotate_left(&nn)
                } else {
                    nn
                }
            } else {
                Arc::new(Node {
                    key: n.key.clone(),
                    val,
                    prio: n.prio,
                    left: n.left.clone(),
                    right: n.right.clone(),
                })
            }
        }
    }
}

fn rotate_right<K: Clone, V: Clone>(nn: &Arc<Node<K, V>>) -> Arc<Node<K, V>> {
    let l = nn.left.clone().expect("rotate_right without left child");
    let new_nn = Arc::new(Node {
        key: nn.key.clone(),
        val: nn.val.clone(),
        prio: nn.prio,
        left: l.right.clone(),
        right: nn.right.clone(),
    });
    Arc::new(Node {
        key: l.key.clone(),
        val: l.val.clone(),
        prio: l.prio,
        left: l.left.clone(),
        right: Some(new_nn),
    })
}

fn rotate_left<K: Clone, V: Clone>(nn: &Arc<Node<K, V>>) -> Arc<Node<K, V>> {
    let r = nn.right.clone().expect("rotate_left without right child");
    let new_nn = Arc::new(Node {
        key: nn.key.clone(),
        val: nn.val.clone(),
        prio: nn.prio,
        left: nn.left.clone(),
        right: r.left.clone(),
    });
    Arc::new(Node {
        key: r.key.clone(),
        val: r.val.clone(),
        prio: r.prio,
        left: Some(new_nn),
        right: r.right.clone(),
    })
}

fn remove_node<K, V, Q>(node: Option<&Arc<Node<K, V>>>, key: &Q) -> Option<Arc<Node<K, V>>>
where
    K: Clone + Borrow<Q>,
    V: Clone,
    Q: Ord + ?Sized,
{
    let n = node?;
    match key.cmp(n.key.borrow()) {
        std::cmp::Ordering::Less => {
            let new_left = remove_node(n.left.as_ref(), key);
            Some(Arc::new(Node {
                key: n.key.clone(),
                val: n.val.clone(),
                prio: n.prio,
                left: new_left,
                right: n.right.clone(),
            }))
        }
        std::cmp::Ordering::Greater => {
            let new_right = remove_node(n.right.as_ref(), key);
            Some(Arc::new(Node {
                key: n.key.clone(),
                val: n.val.clone(),
                prio: n.prio,
                left: n.left.clone(),
                right: new_right,
            }))
        }
        std::cmp::Ordering::Equal => merge(n.left.clone(), n.right.clone()),
    }
}

fn merge<K: Clone, V: Clone>(
    left: Option<Arc<Node<K, V>>>,
    right: Option<Arc<Node<K, V>>>,
) -> Option<Arc<Node<K, V>>> {
    match (left, right) {
        (None, r) => r,
        (l, None) => l,
        (Some(l), Some(r)) => {
            if l.prio > r.prio {
                let new_right = merge(l.right.clone(), Some(r));
                Some(Arc::new(Node {
                    key: l.key.clone(),
                    val: l.val.clone(),
                    prio: l.prio,
                    left: l.left.clone(),
                    right: new_right,
                }))
            } else {
                let new_left = merge(Some(l), r.left.clone());
                Some(Arc::new(Node {
                    key: r.key.clone(),
                    val: r.val.clone(),
                    prio: r.prio,
                    left: new_left,
                    right: r.right.clone(),
                }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_get_remove_and_share() {
        let base: PMap<u64, u64> = PMap::new();
        let mut versions = vec![base.clone()];
        for i in 0..1000u64 {
            let next = versions.last().unwrap().insert(i, i * 10);
            versions.push(next);
        }
        // Every historical version is unchanged (structural sharing).
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
        let m = PMap::from_pairs(keys.into_iter().map(|k| (k, k)));
        assert!(m.iter().map(|(k, _)| *k).eq(0..10));
    }

    #[test]
    fn equality_is_structural_not_by_shape() {
        // Two different insertion orders produce the same logical map regardless
        // of the treap shape the priorities induce.
        let a = PMap::from_pairs((0..64u64).map(|k| (k, k * 2)));
        let mut b = PMap::new();
        for k in (0..64u64).rev() {
            b = b.insert(k, k * 2);
        }
        assert_eq!(a, b);
    }

    #[test]
    fn borrowed_lookup() {
        let m: PMap<Vec<u8>, u64> = PMap::new().insert(b"hello".to_vec(), 1);
        assert_eq!(m.get(b"hello".as_slice()), Some(&1));
        assert_eq!(m.get(b"nope".as_slice()), None);
    }
}
