//! The typed query API (research §12) — byte-oriented search over the
//! authoritative logical view, accelerated by the concealed trigram index
//! (`src/trigram.rs`) when one is present and exactly compatible, and otherwise
//! by a full authoritative scan.
//!
//! The governing law is **parity**: a query produces the *same logical result*
//! whether or not a manifested index exists. The engine achieves this by
//!
//! * pinning one committed `root` and one `inode_version` per file for the whole
//!   run (the same consistency rule ordinary reads use), and
//! * **verifying every index candidate against the actual logical file content**
//!   before reporting it (`Namespace::read_extent` is the reference). The index
//!   can therefore only ever produce *false candidates*, never false matches; a
//!   false candidate is discarded by content verification.
//!
//! An absent, stale, partial, or corrupt index yields `Impossible`/`Unsupported`
//! plans or is rejected outright, and the affected file is served by an
//! authoritative full scan with byte-identical results.
//!
//! The API supports streaming match positions (a callback), result limits,
//! cancellation, and permission enforcement that reuses the transport's POSIX
//! rule ([`crate::inode::has_permission`]).
//!
//! **Benchmark honesty (research §12.1).** Ordinary `grep -r` reads file
//! contents through POSIX operations and does **not** invoke this index. Only
//! `orfs query` (and the library API here) uses it; speedups are measured
//! against the equivalent full-scan query, never attributed to plain POSIX reads.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::error::{OrfsError, Result};
use crate::index::Index;
use crate::inode::{has_permission_grouped, InodeStat};
use crate::namespace::Namespace;
use crate::searchdir::{DirectoryBuilder, DirectoryPlan};
use crate::trigram::{sketch_possible, CandidatePlan, TrigramIndex, TrigramState, MIN_PATTERN};

/// The result schema identifier for JSON output and evidence.
pub const QUERY_SCHEMA: &str = "orfs.query.v1";

/// The identity under which a query runs (used for permission enforcement).
///
/// The typed query API is not a POSIX request: it carries no caller pid, so the
/// caller supplies its supplementary groups explicitly (empty by default, in
/// which case the caller is classified by effective ids alone). The FUSE
/// transports, by contrast, read a request's supplementary groups from
/// `/proc/<pid>/status`. Both share the single [`has_permission_grouped`] rule.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Credential {
    pub uid: u32,
    pub gid: u32,
    /// Supplementary groups the caller belongs to (Linux `in_group_p`).
    #[serde(skip)]
    pub groups: Vec<u32>,
}

impl Credential {
    /// The root identity (bypasses read/write permission checks).
    pub fn root() -> Credential {
        Credential {
            uid: 0,
            gid: 0,
            groups: Vec::new(),
        }
    }

    /// Attach the caller's supplementary groups (chainable).
    pub fn with_groups(mut self, groups: Vec<u32>) -> Credential {
        self.groups = groups;
        self
    }
}

/// Whether `cred` may read `st` (the single read rule for the query API).
fn may_read(cred: &Credential, st: &InodeStat) -> bool {
    has_permission_grouped(cred.uid, cred.gid, &cred.groups, st, 0o4)
}

impl Default for Credential {
    fn default() -> Self {
        Credential::root()
    }
}

/// A typed query request (research §12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryRequest {
    /// The inode to search (a regular file, or a directory when recursing).
    pub inode: u64,
    /// The committed root the query is pinned to.
    pub root: u64,
    /// The literal byte pattern to find.
    pub pattern: Vec<u8>,
    /// The maximum number of matches to report (`None` = unbounded).
    pub limit: Option<u64>,
    /// Recurse into subdirectories when `inode` is a directory.
    pub recursive: bool,
    /// The caller identity for permission enforcement.
    pub credential: Credential,
}

impl QueryRequest {
    /// A recursive, root-credential request for `inode` at `root`.
    pub fn new(inode: u64, root: u64, pattern: impl Into<Vec<u8>>) -> QueryRequest {
        QueryRequest {
            inode,
            root,
            pattern: pattern.into(),
            limit: None,
            recursive: true,
            credential: Credential::root(),
        }
    }

    /// Set the match limit.
    pub fn with_limit(mut self, limit: u64) -> QueryRequest {
        self.limit = Some(limit);
        self
    }

    /// Set the caller credential.
    pub fn with_credential(mut self, credential: Credential) -> QueryRequest {
        self.credential = credential;
        self
    }

    /// Search a single object only (no recursion).
    pub fn without_recursion(mut self) -> QueryRequest {
        self.recursive = false;
        self
    }
}

/// One reported match: a byte offset within a specific inode version.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct QueryMatch {
    pub inode: u64,
    pub inode_version: u64,
    /// The byte offset at which the pattern begins.
    pub offset: u64,
}

/// Whether the caller wants the run to continue after a match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchFlow {
    Continue,
    Stop,
}

/// Truthful accounting of how a query was served.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct QueryStats {
    /// Regular files considered (indexed or scanned).
    pub files_considered: u64,
    /// Files skipped because the caller lacked read permission.
    pub files_skipped_unreadable: u64,
    /// Files served from a compatible trigram index.
    pub files_indexed: u64,
    /// Files served by an authoritative full scan.
    pub files_scanned: u64,
    /// Index plans that proved the pattern impossible without reading content.
    pub impossible_by_index: u64,
    /// Candidate positions obtained from indexes.
    pub indexed_candidates: u64,
    /// Candidates that verified against the actual content (true matches).
    pub verified_matches: u64,
    /// Candidates that failed verification (false candidates the index allowed).
    pub false_candidates: u64,
    /// Bytes of authoritative content read.
    pub content_bytes_read: u64,
    /// Files the global search directory (research §9) pruned without examining
    /// them. Zero when no complete directory was used.
    #[serde(default)]
    pub files_pruned_by_directory: u64,
    /// Whether the limit truncates the result set.
    pub limit_reached: bool,
    /// Whether the query was cancelled.
    pub canceled: bool,
}

/// The complete result of a query.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct QueryResult {
    pub schema: &'static str,
    pub root: u64,
    /// The pattern as lowercase hex.
    pub pattern_hex: String,
    pub pattern_len: u64,
    pub matches: Vec<QueryMatch>,
    pub stats: QueryStats,
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// The query engine over a [`Namespace`]. It never mutates authoritative state.
pub struct QueryEngine<'a> {
    ns: &'a Namespace,
    limit: Option<u64>,
}

impl<'a> QueryEngine<'a> {
    /// Bind an engine to a namespace (unbounded unless [`QueryEngine::with_limit`]).
    pub fn new(ns: &'a Namespace) -> QueryEngine<'a> {
        QueryEngine { ns, limit: None }
    }

    /// Bind an engine with a match limit.
    pub fn with_limit(ns: &'a Namespace, limit: Option<u64>) -> QueryEngine<'a> {
        QueryEngine { ns, limit }
    }

    /// Run a query, invoking `on_match` for each verified match in order
    /// (ascending inode id, then ascending offset).
    ///
    /// `cancel` is polled between files and within scans; cancellation returns
    /// the matches found so far with [`QueryStats::canceled`] set. The callback
    /// may also request an early stop via [`MatchFlow::Stop`].
    pub fn run<F>(
        &self,
        req: &QueryRequest,
        cancel: &AtomicBool,
        mut on_match: F,
    ) -> Result<QueryStats>
    where
        F: FnMut(&QueryMatch) -> MatchFlow,
    {
        if req.pattern.is_empty() {
            return Err(OrfsError::InvalidArgument(
                "query pattern must be non-empty".into(),
            ));
        }
        let mut stats = QueryStats::default();
        let trigram = self.ns.trigram_state();

        // --- global search directory (Phase 52, research §9) --------------------
        // A whole-tree recursive query whose object set is fully covered by the
        // derived directory can be answered from the candidate intersection alone,
        // never opening the pruned files. The directory is only consulted when it is
        // complete, root-qualified, and the request covers the whole tree, so it can
        // only ever remove files that provably cannot match.
        if let Some(dir) = trigram.as_ref().and_then(|s| s.cached_search_directory()) {
            if dir.root() == req.root
                && dir.complete()
                && req.recursive
                && req.inode == self.ns.root_inode()
            {
                match dir.candidates(&req.pattern) {
                    DirectoryPlan::Impossible => {
                        stats.files_pruned_by_directory = dir.objects();
                        return Ok(stats);
                    }
                    DirectoryPlan::Candidates(ids) => {
                        stats.files_pruned_by_directory =
                            dir.objects().saturating_sub(ids.len() as u64);
                        for inode in ids {
                            if cancel.load(Ordering::SeqCst) {
                                stats.canceled = true;
                                break;
                            }
                            if self.examine_file(
                                inode,
                                req,
                                &trigram,
                                cancel,
                                &mut stats,
                                &mut on_match,
                            )? {
                                break;
                            }
                        }
                        return Ok(stats);
                    }
                    DirectoryPlan::Unsupported => {}
                }
            }
        }

        // Discover the candidate files at the pinned root, in a deterministic
        // order (ascending inode id) so indexed and scan paths agree exactly.
        let files = self.candidate_files(req)?;

        'files: for inode in files {
            if cancel.load(Ordering::SeqCst) {
                stats.canceled = true;
                break;
            }
            if self.examine_file(inode, req, &trigram, cancel, &mut stats, &mut on_match)? {
                break 'files;
            }
        }
        Ok(stats)
    }

    /// Examine one file for matches, updating `stats`. Returns `true` when the run
    /// should stop (the match limit was reached, the callback asked to stop, or a
    /// scan was cancelled). Shared by the full walk and the directory fast path.
    fn examine_file<F>(
        &self,
        inode: u64,
        req: &QueryRequest,
        trigram: &Option<Arc<TrigramState>>,
        cancel: &AtomicBool,
        stats: &mut QueryStats,
        on_match: &mut F,
    ) -> Result<bool>
    where
        F: FnMut(&QueryMatch) -> MatchFlow,
    {
        let Some(ino) = self.ns.search_inode(inode, req.root)? else {
            return Ok(false);
        };
        if !ino.is_file() {
            return Ok(false);
        }
        let st = ino.stat();
        if !may_read(&req.credential, &st) {
            stats.files_skipped_unreadable += 1;
            return Ok(false);
        }
        stats.files_considered += 1;
        let size = st.size;
        if (size as usize) < req.pattern.len() {
            return Ok(false);
        }

        // A pattern shorter than a trigram cannot be accelerated; scan it.
        if req.pattern.len() < MIN_PATTERN {
            return self.scan_file(inode, st.version, size, req, cancel, stats, on_match);
        }

        // Try the concealed index for exactly this identity (I6). The compact
        // sketch in the manifest prunes files whose pattern trigrams are provably
        // absent, without loading their positional payload. Any rejection (absent,
        // stale, partial, corrupt) falls back to a scan.
        let mut handled_by_index = false;
        if let Some(state) = trigram.as_ref() {
            if let Some(manifest) = state.usable_for(inode, st.version, req.root, size) {
                if !sketch_possible(manifest.sketch_bits, &manifest.sketch, &req.pattern) {
                    stats.files_indexed += 1;
                    stats.impossible_by_index += 1;
                    handled_by_index = true;
                } else if let Ok(index) = state.store().load_index(&manifest) {
                    stats.files_indexed += 1;
                    match index.plan(&req.pattern) {
                        CandidatePlan::Impossible => {
                            stats.impossible_by_index += 1;
                        }
                        CandidatePlan::Unsupported => {
                            stats.files_indexed -= 1;
                            if self
                                .scan_file(inode, st.version, size, req, cancel, stats, on_match)?
                            {
                                return Ok(true);
                            }
                        }
                        CandidatePlan::Candidates(cands) => {
                            stats.indexed_candidates += cands.len() as u64;
                            if self.verify_candidates(
                                inode, st.version, size, &index, &cands, req, cancel, stats,
                                on_match,
                            )? {
                                return Ok(true);
                            }
                        }
                    }
                    handled_by_index = true;
                }
            }
        }
        if !handled_by_index
            && self.scan_file(inode, st.version, size, req, cancel, stats, on_match)?
        {
            return Ok(true);
        }
        Ok(false)
    }

    /// Read the whole content once, verify each candidate against it, and emit
    /// the verified matches. Returns `true` when the run should stop early
    /// (limit reached or callback stop).
    #[allow(clippy::too_many_arguments)]
    fn verify_candidates<F>(
        &self,
        inode: u64,
        version: u64,
        size: u64,
        index: &TrigramIndex,
        candidates: &[u64],
        req: &QueryRequest,
        cancel: &AtomicBool,
        stats: &mut QueryStats,
        on_match: &mut F,
    ) -> Result<bool>
    where
        F: FnMut(&QueryMatch) -> MatchFlow,
    {
        // Verification metadata: the loaded index must describe exactly this
        // source. The manifest already matched (inode, version, root, size).
        if index.logical_size() != size {
            // Structurally inconsistent: fall back to a full scan of this file.
            stats.files_indexed -= 1;
            return self.scan_file(inode, version, size, req, cancel, stats, on_match);
        }
        let content = self.ns.read_extent(inode, req.root, 0, size)?;
        stats.content_bytes_read += content.len() as u64;
        let plen = req.pattern.len();
        for &start in candidates {
            if cancel.load(Ordering::SeqCst) {
                stats.canceled = true;
                return Ok(true);
            }
            let s = start as usize;
            if s + plen > content.len() {
                continue;
            }
            if &content[s..s + plen] == req.pattern.as_slice() {
                stats.verified_matches += 1;
                if self.emit(stats, on_match, inode, version, start) {
                    return Ok(true);
                }
            } else {
                stats.false_candidates += 1;
            }
        }
        Ok(false)
    }

    /// Authoritative full scan of one file: find every (overlapping) occurrence.
    #[allow(clippy::too_many_arguments)]
    fn scan_file<F>(
        &self,
        inode: u64,
        version: u64,
        size: u64,
        req: &QueryRequest,
        cancel: &AtomicBool,
        stats: &mut QueryStats,
        on_match: &mut F,
    ) -> Result<bool>
    where
        F: FnMut(&QueryMatch) -> MatchFlow,
    {
        stats.files_scanned += 1;
        let content = self.ns.read_extent(inode, req.root, 0, size)?;
        stats.content_bytes_read += content.len() as u64;
        let plen = req.pattern.len();
        let mut i = 0usize;
        while i + plen <= content.len() {
            if cancel.load(Ordering::SeqCst) {
                stats.canceled = true;
                return Ok(true);
            }
            if &content[i..i + plen] == req.pattern.as_slice() {
                stats.verified_matches += 1;
                if self.emit(stats, on_match, inode, version, i as u64) {
                    return Ok(true);
                }
            }
            i += 1;
        }
        Ok(false)
    }

    /// Report a match, honouring the limit. Returns `true` to stop.
    fn emit<F>(
        &self,
        stats: &mut QueryStats,
        on_match: &mut F,
        inode: u64,
        inode_version: u64,
        offset: u64,
    ) -> bool
    where
        F: FnMut(&QueryMatch) -> MatchFlow,
    {
        let m = QueryMatch {
            inode,
            inode_version,
            offset,
        };
        if let MatchFlow::Stop = on_match(&m) {
            return true;
        }
        if let Some(limit) = self.limit {
            if stats.verified_matches >= limit {
                stats.limit_reached = true;
                return true;
            }
        }
        false
    }

    /// The files to search, discovered from the pinned view.
    fn candidate_files(&self, req: &QueryRequest) -> Result<Vec<u64>> {
        let view = self.ns.search_view(req.root)?;
        let Some(target) = view.inode(req.inode) else {
            return Err(OrfsError::NotFound);
        };
        let st = target.stat();
        if !may_read(&req.credential, &st) {
            // An explicitly requested object the caller may not read is an error;
            // within a recursion such files are skipped (counted separately).
            return Err(OrfsError::PermissionDenied);
        }
        if target.is_file() {
            return Ok(vec![req.inode]);
        }
        if !target.is_dir() {
            return Err(OrfsError::InvalidArgument(
                "query target must be a file or directory".into(),
            ));
        }
        let mut out = Vec::new();
        self.collect_dir(&view, req.inode, req.recursive, &mut out)?;
        out.sort_unstable();
        out.dedup();
        Ok(out)
    }

    fn collect_dir(
        &self,
        view: &Index,
        root_dir: u64,
        recursive: bool,
        out: &mut Vec<u64>,
    ) -> Result<()> {
        // Iterative traversal with an explicit worklist and a visited set. A
        // hostile committed namespace that (illegally) contains a directory cycle
        // must not drive call-stack recursion to overflow (research §28, no
        // uncontrolled recursion); the walk is bounded by the number of distinct
        // directories reachable from the target.
        let mut stack = vec![root_dir];
        let mut visited: HashSet<u64> = HashSet::new();
        while let Some(dir) = stack.pop() {
            if !visited.insert(dir) {
                continue;
            }
            for (_name, child) in view.readdir(dir).unwrap_or_default() {
                let Some(ino) = view.inode(child) else {
                    continue;
                };
                if ino.is_file() {
                    out.push(child);
                } else if ino.is_dir() && recursive && !visited.contains(&child) {
                    stack.push(child);
                }
            }
        }
        Ok(())
    }
}

impl Namespace {
    /// Run a query against this namespace, collecting every match (up to
    /// `request.limit`). The common library entry point.
    pub fn query(&self, request: QueryRequest) -> Result<QueryResult> {
        let limit = request.limit;
        let cancel = AtomicBool::new(false);
        let mut matches = Vec::new();
        let stats = QueryEngine::with_limit(self, limit).run(&request, &cancel, |m| {
            matches.push(m.clone());
            MatchFlow::Continue
        })?;
        Ok(QueryResult {
            schema: QUERY_SCHEMA,
            root: request.root,
            pattern_hex: hex(&request.pattern),
            pattern_len: request.pattern.len() as u64,
            matches,
            stats,
        })
    }

    /// Streaming query: `on_match` is invoked for each verified match in order.
    /// `cancel` may be set from another thread to stop promptly.
    pub fn query_stream<F>(
        &self,
        request: QueryRequest,
        cancel: &AtomicBool,
        on_match: F,
    ) -> Result<QueryStats>
    where
        F: FnMut(&QueryMatch) -> MatchFlow,
    {
        QueryEngine::with_limit(self, request.limit).run(&request, cancel, on_match)
    }

    /// Build and cache the derived **global search directory** (research §9) over
    /// every file at the current committed root, folding each file's committed
    /// positional index. Returns the number of objects folded. Derived and never
    /// authoritative: the query engine consults it only when it is `complete`, and
    /// every candidate is still verified against committed content.
    ///
    /// Requires the concealed search plane (`enable_trigram`).
    pub fn prime_search_directory(&self) -> Result<u64> {
        let state = self.trigram_state().ok_or_else(|| {
            OrfsError::Unsupported("the concealed search plane is not enabled".into())
        })?;
        let root = self.root();
        let view = self.search_view(root)?;
        let mut files: Vec<u64> = Vec::new();
        collect_all_files(&view, self.root_inode(), &mut files);
        files.sort_unstable();
        files.dedup();

        let mut b = DirectoryBuilder::new(root, state.uuid());
        for &inode in &files {
            let Some(ino) = view.inode(inode) else {
                b.mark_incomplete();
                continue;
            };
            if !ino.is_file() {
                continue;
            }
            let st = ino.stat();
            match state.usable_for(inode, st.version, root, st.size) {
                Some(m) if m.source_logical_size == st.size => match state.store().load_index(&m) {
                    Ok(index) if index.logical_size() == st.size => b.fold(inode, &index),
                    _ => b.mark_incomplete(),
                },
                _ => b.mark_incomplete(),
            }
        }
        state.store_search_directory(Arc::new(b.finish()));
        Ok(files.len() as u64)
    }
}

/// Collect every regular file reachable from `start` (iterative, cycle-safe).
fn collect_all_files(view: &Index, start: u64, out: &mut Vec<u64>) {
    let mut stack = vec![start];
    let mut visited: HashSet<u64> = HashSet::new();
    while let Some(dir) = stack.pop() {
        if !visited.insert(dir) {
            continue;
        }
        for (_name, child) in view.readdir(dir).unwrap_or_default() {
            let Some(ino) = view.inode(child) else {
                continue;
            };
            if ino.is_file() {
                out.push(child);
            } else if ino.is_dir() && !visited.contains(&child) {
                stack.push(child);
            }
        }
    }
}
