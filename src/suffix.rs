//! Suffix-oriented substring structure (research §11.2) — a suffix automaton.
//!
//! A suffix automaton recognises every substring of a byte sequence with
//! `O(m)` transitions per query (m = pattern length), independent of source
//! length. It distinguishes the three research-§11.2 operations, which have
//! genuinely different costs:
//!
//! * **existence** — [`SuffixAutomaton::contains`]: `O(m)`, no output.
//! * **match count** — [`SuffixAutomaton::count`]: `O(m)`, no output (each state
//!   carries the size of its end-position set).
//! * **all match positions** — [`SuffixAutomaton::match_positions`]: `O(m + k)`
//!   to report `k` positions, by walking the suffix-link subtree of the matched
//!   state. Enumeration is *not* constant-time — a single existence answer may be
//!   cheap while enumerating every occurrence is proportional to the output.
//!
//! Construction is `O(n)` time and `O(n)` states (a suffix automaton has at most
//! `2n − 1` states). This module is dependency-free and self-contained; it is
//! the *measured* alternative to the positional trigram index of
//! `src/trigram.rs`. It intentionally does **not** change any query semantics:
//! the typed query API always verifies results against authoritative content.
//!
//! The distinction the research warns about is preserved here: a fast
//! substring-*existence* query does not automatically give constant-time
//! enumeration of every occurrence.

use std::collections::BTreeMap;

/// A suffix automaton over an immutable byte sequence.
pub struct SuffixAutomaton {
    /// Longest-string length of each state.
    len: Vec<u32>,
    /// Transitions per state (deterministic, so evidence is reproducible).
    next: Vec<BTreeMap<u8, u32>>,
    /// End position of a prefix state, or `-1` if the state is a clone.
    prefix_end: Vec<i32>,
    /// Suffix-link tree children (derived after construction).
    children: Vec<Vec<u32>>,
    /// End-position-set size per state (derived after construction).
    occ: Vec<u64>,
    /// The length of the source sequence.
    source_len: u64,
}

impl SuffixAutomaton {
    /// Build the automaton over `source` in `O(n)`.
    pub fn build(source: &[u8]) -> SuffixAutomaton {
        let mut len = vec![0u32];
        let mut link = vec![-1i32];
        let mut next: Vec<BTreeMap<u8, u32>> = vec![BTreeMap::new()];
        let mut prefix_end = vec![-1i32];
        let mut last = 0u32;

        for (i, &c) in source.iter().enumerate() {
            let cur = len.len() as u32;
            len.push(len[last as usize] + 1);
            link.push(0);
            next.push(BTreeMap::new());
            prefix_end.push(i as i32);

            let mut p = last as i32;
            while p != -1 && !next[p as usize].contains_key(&c) {
                next[p as usize].insert(c, cur);
                p = link[p as usize];
            }
            if p == -1 {
                link[cur as usize] = 0;
            } else {
                let q = next[p as usize][&c];
                if len[p as usize] + 1 == len[q as usize] {
                    link[cur as usize] = q as i32;
                } else {
                    let clone = len.len() as u32;
                    len.push(len[p as usize] + 1);
                    link.push(link[q as usize]);
                    next.push(next[q as usize].clone());
                    prefix_end.push(-1);
                    while p != -1 && next[p as usize].get(&c) == Some(&q) {
                        next[p as usize].insert(c, clone);
                        p = link[p as usize];
                    }
                    link[q as usize] = clone as i32;
                    link[cur as usize] = clone as i32;
                }
            }
            last = cur;
        }

        // End-position-set sizes: prefix states seed one, then propagate up the
        // suffix-link tree in decreasing `len` order (the standard linear pass).
        let n = len.len();
        let mut occ = vec![0u64; n];
        for (s, pe) in prefix_end.iter().enumerate() {
            if *pe >= 0 {
                occ[s] = 1;
            }
        }
        let mut order: Vec<u32> = (0..n as u32).collect();
        order.sort_by_key(|&s| std::cmp::Reverse(len[s as usize]));
        for &s in &order {
            let l = link[s as usize];
            if l >= 0 {
                occ[l as usize] += occ[s as usize];
            }
        }
        let mut children = vec![Vec::new(); n];
        for (s, &l) in link.iter().enumerate().skip(1) {
            children[l as usize].push(s as u32);
        }

        SuffixAutomaton {
            len,
            next,
            prefix_end,
            children,
            occ,
            source_len: source.len() as u64,
        }
    }

    /// The source length.
    pub fn source_len(&self) -> u64 {
        self.source_len
    }

    /// The number of automaton states (≤ `2n − 1`).
    pub fn state_count(&self) -> u64 {
        self.len.len() as u64
    }

    /// The number of stored transitions.
    pub fn transition_count(&self) -> u64 {
        self.next.iter().map(|m| m.len() as u64).sum()
    }

    /// An approximate in-memory footprint in bytes (for honest reporting).
    pub fn memory_bytes(&self) -> u64 {
        let states = self.len.len() as u64;
        let transitions = self.transition_count();
        // Per state: len(4) + link(4) + prefix_end(4) + Vec header (~24) +
        // occ(8) + children Vec (~24). Per transition: key(1) + value(4) +
        // BTreeMap node overhead (~24, approximate).
        states * 68 + transitions * 29
    }

    /// Walk the automaton, returning the state accepting `pattern`, if any.
    fn transition(&self, pattern: &[u8]) -> Option<u32> {
        let mut state = 0u32;
        for &c in pattern {
            state = *self.next[state as usize].get(&c)?;
        }
        Some(state)
    }

    /// Whether `pattern` occurs at least once. `O(m)`.
    pub fn contains(&self, pattern: &[u8]) -> bool {
        if pattern.is_empty() {
            return true;
        }
        self.transition(pattern).is_some()
    }

    /// The number of occurrences of `pattern`. `O(m)`.
    pub fn count(&self, pattern: &[u8]) -> u64 {
        if pattern.is_empty() {
            return self.source_len + 1;
        }
        match self.transition(pattern) {
            Some(s) => self.occ[s as usize],
            None => 0,
        }
    }

    /// Every start offset of `pattern`, ascending. `O(m + k)` in the number of
    /// occurrences `k` (enumeration is proportional to the output).
    pub fn match_positions(&self, pattern: &[u8]) -> Vec<u64> {
        let m = pattern.len();
        if m == 0 {
            return Vec::new();
        }
        let Some(state) = self.transition(pattern) else {
            return Vec::new();
        };
        let mut ends = Vec::new();
        self.collect_ends(state, &mut ends);
        let back = (m - 1) as i64;
        let mut starts: Vec<u64> = ends
            .into_iter()
            .map(|end| (end as i64 - back) as u64)
            .collect();
        starts.sort_unstable();
        starts
    }

    fn collect_ends(&self, state: u32, out: &mut Vec<u64>) {
        // Iterative post-order over the suffix-link subtree so a deeply nested
        // link tree (worst case `O(n)` deep) cannot overflow the call stack.
        let mut stack = vec![state];
        while let Some(s) = stack.pop() {
            let pe = self.prefix_end[s as usize];
            if pe >= 0 {
                out.push(pe as u64);
            }
            for &child in &self.children[s as usize] {
                stack.push(child);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existence_count_and_positions_agree() {
        let text = b"banana";
        let sam = SuffixAutomaton::build(text);
        assert!(sam.contains(b"ana"));
        assert!(!sam.contains(b"ann"));
        assert_eq!(sam.count(b"ana"), 2);
        assert_eq!(sam.count(b"na"), 2);
        assert_eq!(sam.count(b"a"), 3);
        assert_eq!(sam.count(b"banana"), 1);
        assert_eq!(sam.count(b"zzz"), 0);
        assert_eq!(sam.match_positions(b"ana"), vec![1, 3]);
        assert_eq!(sam.match_positions(b"na"), vec![2, 4]);
        assert_eq!(sam.match_positions(b"a"), vec![1, 3, 5]);
        assert!(sam.match_positions(b"ann").is_empty());
    }

    #[test]
    fn brute_force_parity_over_random_input() {
        // Deterministic LCG so the test is reproducible.
        let mut seed = 0x1234_5678_9abc_def0u64;
        let mut next = || {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            seed >> 33
        };
        for _ in 0..40 {
            let n = (next() % 200) as usize;
            let text: Vec<u8> = (0..n).map(|_| b"abcde"[(next() % 5) as usize]).collect();
            let sam = SuffixAutomaton::build(&text);
            for plen in 1..=4usize {
                for _ in 0..4 {
                    let pat: Vec<u8> = (0..plen).map(|_| b"abcde"[(next() % 5) as usize]).collect();
                    let mut expect: Vec<u64> = Vec::new();
                    for s in 0..=text.len().saturating_sub(plen) {
                        if &text[s..s + plen] == pat.as_slice() {
                            expect.push(s as u64);
                        }
                    }
                    assert_eq!(sam.contains(&pat), !expect.is_empty(), "contains {pat:?}");
                    assert_eq!(sam.count(&pat), expect.len() as u64, "count {pat:?}");
                    assert_eq!(sam.match_positions(&pat), expect, "positions {pat:?}");
                }
            }
        }
    }
}
