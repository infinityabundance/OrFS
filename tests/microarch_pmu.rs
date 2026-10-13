//! **Phase 50 — hardware performance counters (PMU), not a heuristic.**
//!
//! The project previously claimed "hardware performance counters are unavailable
//! (`perf_event_paranoid=2`), so there are no flamegraphs". That is wrong. On
//! Linux `perf_event_paranoid=2` denies only *kernel* profiling to an
//! unprivileged caller; a user-space, per-thread counter for our own process is
//! still permitted. The real blocker is the container's seccomp profile, which
//! denies `perf_event_open` with `EPERM` — exactly as the same default profile
//! denies `io_uring_setup`, which this project already bypasses with
//! `--security-opt seccomp=unconfined` (`scripts/container-pmu.sh` proves it).
//!
//! This court reads **real** counters for four components and, when a sampling
//! ring can be built, emits a flamegraph:
//!
//! * (a) `PMap` point lookup (`src/persistent.rs`).
//! * (b) the EKBLOOM manifested read path via the planner
//!   (`ReadPlanner::measure_paths` executes the manifested candidate structures).
//! * (c) the `ReadPlanner` steady-state selection (a hot certified read that
//!   walks the published ranking and executes the chosen path, taking no model
//!   write lock and sorting nothing).
//! * (d) a backing log segment read (`Log::read_range`).
//!
//! The flamegraph is a leaf-IP profile: a `PERF_SAMPLE_IP` sampling ring records
//! the interrupted instruction, which is symbolized with `addr2line` (DWARF)
//! against the test binary, falling back to `nm`, and is labelled by module (from
//! `/proc/self/maps`) for frames outside it. It is produced by `pmu_flamegraph`,
//! which is run in a **debug** build: LTO/codegen-unit merging in the release
//! profile folds distinct functions onto shared addresses, which makes leaf
//! attribution ambiguous.
//!
//! The always-on `pmu_smoke` runs a bounded version of the counters. The two
//! opt-in `ORFS_PMU=1` tests are `pmu_flamegraph` (debug, writes the `.folded`/
//! `.svg` and a sidecar) and `pmu_sweep` (release, writes
//! `evidence/performance/pmu.json`, schema `orfs.performance.pmu.v1`, embedding
//! the flamegraph sidecar). When the PMU is genuinely unavailable the court
//! records `available:false` **with the exact errno** and still reports software
//! (wall-clock) timings — no number is invented. `scripts/container-pmu.sh`
//! proves which container flags permit `perf_event_open` and runs all three.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use orfs::commit::{CommitSequencer, DurabilityMode};
use orfs::manifestation::{
    ekbloom_format_version, CertificationState, GenerationManifest, GenerationStore,
    ManifestationProfile, ManifestationState, MANIFEST_SCHEMA,
};
use orfs::persistent::PMap;
use orfs::readpath::{ReadPathKind, ReadPlanner, ReadPlannerConfig, ReadQuery};
use orfs::record::RecordType;
use orfs::transaction::TransactionBuilder;
use orfs::volume::Volume;
use serde_json::json;
use tempfile::TempDir;

#[path = "support/pmu.rs"]
mod pmu;

use pmu::{Counter, PmuGroup};

// ---------------------------------------------------------------------------
// Fixtures (the same manifested-read fixture the PMU-free court uses)
// ---------------------------------------------------------------------------

const UUID: [u8; 16] = [
    0x4F, 0x72, 0x46, 0x53, 0x43, 0x44, 0x40, 0x50, 0x83, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
];

const SRC_LEN: usize = 4096;
const READ_LEN: u64 = 64;
const SEGMENT_SIZE: u64 = 256 * 1024;

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 131 + 17) % 251) as u8).collect()
}

fn auth_slice(source: &[u8], offset: u64, length: u64) -> Vec<u8> {
    let n = source.len() as u64;
    let end = offset.saturating_add(length).min(n);
    if offset >= end {
        Vec::new()
    } else {
        source[offset as usize..end as usize].to_vec()
    }
}

fn publish_generation(
    store: &GenerationStore,
    inode: u64,
    version: u64,
    root: u64,
    source: &[u8],
    profile: ManifestationProfile,
) -> GenerationManifest {
    store.ensure_dirs().expect("ensure dirs");
    let generation = store.next_generation().expect("generation");
    let body = ekbloom::create(source, profile.to_ekbloom()).expect("create body");
    let path = store.payload_path(generation, inode, version, root);
    ekbloom::write_body(&path, &body).expect("write body");
    let payload = std::fs::read(&path).expect("read payload");
    let (interval, depth, region_bytes) = profile.params();
    let manifest = GenerationManifest {
        schema: MANIFEST_SCHEMA,
        generation,
        volume_uuid: UUID,
        inode,
        inode_version: version,
        root,
        backend: "ekbloom".to_string(),
        ekbloom_version: "0.3.0".to_string(),
        ekbloom_format: ekbloom_format_version(),
        profile: profile.label(),
        profile_kind: profile.kind_code(),
        logical_start: 0,
        logical_end: source.len() as u64,
        physical_start: 0,
        physical_end: payload.len() as u64,
        interval,
        depth,
        region_bytes,
        certification: CertificationState::Built,
        certification_method: "test".to_string(),
        payload_rel_path: store.payload_rel_path(generation, inode, version, root),
        ekbloom_object_id: Some(body.object_id),
        payload_blake3: *blake3::hash(&payload).as_bytes(),
        visible_bytes: source.len() as u64,
        physical_bytes: payload.len() as u64,
        concealed_bytes: (payload.len() as u64).saturating_sub(source.len() as u64),
        source_bytes: source.len() as u64,
        components: vec![],
        base_generation: None,
        base_manifest_blake3: None,
        overlay_depth: 0,
        regions: Vec::new(),
        manifest_blake3: [0u8; 32],
    }
    .sealed();
    store.publish(&manifest).expect("publish");
    manifest
}

fn planner_for(dir: &Path, source: &[u8]) -> ReadPlanner {
    let store = GenerationStore::new(dir);
    publish_generation(
        &store,
        1,
        1,
        1,
        source,
        ManifestationProfile::Path { depth: 4 },
    );
    let state =
        ManifestationState::recover(GenerationStore::new(dir), UUID).expect("recover state");
    ReadPlanner::new(state, ReadPlannerConfig::default())
}

fn query(logical_len: u64) -> ReadQuery {
    ReadQuery {
        inode: 1,
        inode_version: 1,
        root: 1,
        logical_len,
        offset: 0,
        length: READ_LEN,
    }
}

/// A steady-state certified read of the single manifested object.
fn hot_read(planner: &ReadPlanner, source: &[u8]) -> usize {
    let p = planner
        .read(&query(source.len() as u64), |o, l| {
            Ok(auth_slice(source, o, l))
        })
        .expect("read");
    p.bytes.len()
}

/// A tiny deterministic PRNG for reproducible lookup patterns.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 11
    }
}

fn tx_payload(seed: u64, salt: u8) -> Vec<u8> {
    (0..64)
        .map(|k| {
            ((seed as u8).wrapping_mul(31))
                .wrapping_add(salt)
                .wrapping_add(k as u8)
        })
        .collect()
}

/// A volume with a committed log, for the backing-segment-read component.
fn log_fixture() -> (TempDir, Volume, u64) {
    let td = TempDir::new().expect("tempdir");
    let mut vol =
        Volume::init_with_uuid(td.path(), SEGMENT_SIZE, UUID, 1_700_000_000).expect("init volume");
    let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Ordered);
    for i in 0..32u64 {
        let mut b = TransactionBuilder::new(seq.peek_transaction_id()).expect("builder");
        b.add(RecordType::InodeCreate, 1, 0, tx_payload(i, 1))
            .expect("add");
        b.add(RecordType::DataExtent, 1, 0, tx_payload(i, 2))
            .expect("add");
        seq.commit(b.build().expect("build")).expect("commit");
    }
    let len = vol.log.committed_end_offset();
    (td, vol, len)
}

// ---------------------------------------------------------------------------
// Measurement harness
// ---------------------------------------------------------------------------

/// The outcome of measuring one component: real counters (when the PMU granted
/// them) and always-on wall-clock timing.
struct Metrics {
    name: &'static str,
    ops: u64,
    wall_ns_per_op: f64,
    /// Total counter values over `ops` operations; `None` when no PMU.
    counters: Option<Vec<(Counter, u64)>>,
    /// Which paths the planner served (only meaningful for the read components).
    chosen: Vec<(ReadPathKind, u64)>,
    /// The manifested candidates the planner exercised (component (b)).
    paths: Vec<String>,
}

fn per_op(total: u64, ops: u64) -> f64 {
    total as f64 / ops.max(1) as f64
}

fn counter_of(counters: &[(Counter, u64)], c: Counter) -> Option<u64> {
    counters.iter().find(|(k, _)| *k == c).map(|(_, v)| *v)
}

/// Run `ops` iterations of `work`, capturing the hardware counters (if a group
/// was supplied) and the wall-clock time around the whole loop.
fn measure<F: FnMut()>(
    name: &'static str,
    mut group: Option<&mut PmuGroup>,
    ops: u64,
    mut work: F,
) -> Metrics {
    if let Some(g) = group.as_mut() {
        let _ = g.reset();
        let _ = g.enable();
    }
    let started = Instant::now();
    for _ in 0..ops {
        work();
    }
    let elapsed = started.elapsed();
    let counters = if let Some(g) = group.as_mut() {
        let _ = g.disable();
        Some(g.read_all())
    } else {
        None
    };
    Metrics {
        name,
        ops,
        wall_ns_per_op: elapsed.as_nanos() as f64 / ops.max(1) as f64,
        counters,
        chosen: Vec::new(),
        paths: Vec::new(),
    }
}

fn metrics_json(m: &Metrics) -> serde_json::Value {
    let mut per_op_map = serde_json::Map::new();
    if let Some(counters) = &m.counters {
        for (c, total) in counters {
            per_op_map.insert(c.name().to_string(), json!(per_op(*total, m.ops)));
        }
        let cycles = counter_of(counters, Counter::Cycles).unwrap_or(0);
        let instructions = counter_of(counters, Counter::Instructions).unwrap_or(0);
        let refs = counter_of(counters, Counter::CacheReferences).unwrap_or(0);
        let misses = counter_of(counters, Counter::CacheMisses).unwrap_or(0);
        let branch_misses = counter_of(counters, Counter::BranchMisses).unwrap_or(0);
        if cycles > 0 {
            per_op_map.insert(
                "ipc".to_string(),
                json!(instructions as f64 / cycles as f64),
            );
        }
        if refs > 0 {
            per_op_map.insert(
                "cache_miss_rate".to_string(),
                json!(misses as f64 / refs as f64),
            );
        }
        if instructions > 0 {
            per_op_map.insert(
                "branch_miss_rate".to_string(),
                json!(branch_misses as f64 / instructions as f64),
            );
        }
    }
    json!({
        "name": m.name,
        "ops": m.ops,
        "wall_ns_per_op": m.wall_ns_per_op,
        "per_op": per_op_map,
        "measured_paths": m.paths,
        "chosen": m
            .chosen
            .iter()
            .map(|(k, n)| json!({ "path": k.name(), "count": n }))
            .collect::<Vec<_>>(),
    })
}

// ---------------------------------------------------------------------------
// The four components
// ---------------------------------------------------------------------------

/// (a) `PMap` point lookup over a 64 Ki-entry treap.
fn pmap_component(group: Option<&mut PmuGroup>, ops: u64) -> Metrics {
    let n = 1usize << 16;
    let mut map: PMap<u64, u64> = PMap::new();
    for k in 0..n as u64 {
        map = map.insert(k, k);
    }
    let mask = (n as u64).next_power_of_two() - 1;
    let mut rng = Lcg(0x1234_5678_9abc_def0);
    let mut acc = 0u64;
    let m = measure("pmap_point_lookup", group, ops, || {
        let k = rng.next() & mask;
        if let Some(v) = map.get(&(k % n as u64)) {
            acc = acc.wrapping_add(*v);
        }
    });
    std::hint::black_box(acc);
    m
}

/// (b) the EKBLOOM manifested read path via the planner: `measure_paths`
/// executes each manifested candidate structure for the object.
fn manifested_component(group: Option<&mut PmuGroup>, ops: u64) -> Metrics {
    let td = TempDir::new().expect("tempdir");
    let source = pattern(SRC_LEN);
    let planner = planner_for(td.path(), &source);
    let q = query(source.len() as u64);

    // Warm pass: loads and validates the manifested body once.
    let mut warm = |o: u64, l: u64| -> orfs::Result<Vec<u8>> { Ok(auth_slice(&source, o, l)) };
    let warm_paths: Vec<String> = planner
        .measure_paths(&q, &mut warm, 1)
        .expect("measure paths")
        .iter()
        .map(|p| p.path.name().to_string())
        .collect();

    let mut m = measure("ekbloom_manifested_read", group, ops, || {
        let mut auth = |o: u64, l: u64| -> orfs::Result<Vec<u8>> { Ok(auth_slice(&source, o, l)) };
        std::hint::black_box(
            planner
                .measure_paths(&q, &mut auth, 1)
                .expect("measure paths"),
        );
    });
    m.paths = warm_paths;
    m
}

/// (c) the `ReadPlanner` steady-state selection: a hot certified read that walks
/// the published ranking and executes the chosen path.
fn selection_component(group: Option<&mut PmuGroup>, ops: u64) -> Metrics {
    let td = TempDir::new().expect("tempdir");
    let source = pattern(SRC_LEN);
    let planner = planner_for(td.path(), &source);
    for _ in 0..128 {
        std::hint::black_box(hot_read(&planner, &source));
    }
    let before = planner.stats();
    let mut m = measure("readplanner_steady_state_selection", group, ops, || {
        std::hint::black_box(hot_read(&planner, &source));
    });
    let after = planner.stats();
    assert_eq!(
        after.hot_reads - before.hot_reads,
        ops,
        "steady-state selection did not serve every read on the hot path"
    );
    assert_eq!(
        after.selection_sorts, before.selection_sorts,
        "steady-state selection sorted candidates"
    );
    assert_eq!(
        after.model_write_locks, before.model_write_locks,
        "steady-state selection took a model write lock"
    );
    m.chosen = planner.chosen_counts();
    m
}

/// (d) a backing log segment read (`Log::read_range`).
fn log_component(group: Option<&mut PmuGroup>, ops: u64) -> Metrics {
    let (_td, vol, len) = log_fixture();
    let read_len = 4096u64.min(len.max(1));
    // Warm pass: opens the segment reader and faults its pages in.
    let _ = vol.log.read_range(0, read_len).expect("warm read");
    measure("backing_log_segment_read", group, ops, || {
        std::hint::black_box(vol.log.read_range(0, read_len).expect("segment read"));
    })
}

// ---------------------------------------------------------------------------
// Flamegraph: a sampling profiler over a perf ring buffer
// ---------------------------------------------------------------------------

/// One executable mapping from `/proc/self/maps`.
struct Mapping {
    start: u64,
    end: u64,
    file_offset: u64,
    module: String,
    is_exe: bool,
}

struct Symbolizer {
    exe: std::path::PathBuf,
    maps: Vec<Mapping>,
    /// `nm` symbol table of the test binary, used as a fallback when the DWARF
    /// resolver is unavailable.
    syms: Vec<(u64, String)>,
}

impl Symbolizer {
    fn load() -> Symbolizer {
        let exe = std::env::current_exe().unwrap_or_default();
        Symbolizer {
            maps: parse_maps(&exe),
            syms: load_nm(&exe).unwrap_or_default(),
            exe,
        }
    }

    /// The mapping containing `ip`, and the offset into the ELF file it implies.
    fn classify(&self, ip: u64) -> (bool, u64, String) {
        match self
            .maps
            .iter()
            .filter(|m| ip >= m.start && ip < m.end)
            .max_by_key(|m| m.start)
        {
            Some(m) if m.is_exe => (true, ip - m.start + m.file_offset, String::new()),
            Some(m) => (false, 0, m.module.clone()),
            None => (false, 0, format!("[0x{ip:x}]")),
        }
    }

    /// Resolve a batch of sampled instruction pointers. Frames in the test binary
    /// are resolved with `addr2line` (DWARF: it names LTO-internalized functions
    /// that `nm` omits), falling back to `nm`; frames in any other module (libc,
    /// ld.so, …) are labelled with that module's file name.
    fn resolve_many(&self, ips: &[u64]) -> HashMap<u64, String> {
        let mut out: HashMap<u64, String> = HashMap::new();
        let mut exe_addrs: Vec<u64> = Vec::new();
        let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
        for &ip in ips {
            if out.contains_key(&ip) {
                continue;
            }
            let (is_exe, addr, module) = self.classify(ip);
            if is_exe {
                if seen.insert(addr) {
                    exe_addrs.push(addr);
                }
            } else {
                out.insert(ip, module);
            }
        }
        if !exe_addrs.is_empty() {
            let names = addr2line_batch(&self.exe, &exe_addrs)
                .unwrap_or_else(|| self.nm_resolve(&exe_addrs));
            for &ip in ips {
                if out.contains_key(&ip) {
                    continue;
                }
                let (is_exe, addr, _) = self.classify(ip);
                if is_exe {
                    out.insert(
                        ip,
                        names
                            .get(&addr)
                            .cloned()
                            .unwrap_or_else(|| format!("exe+0x{addr:x}")),
                    );
                }
            }
        }
        out
    }

    fn nm_resolve(&self, addrs: &[u64]) -> HashMap<u64, String> {
        addrs.iter().map(|&a| (a, self.symbol_at(a))).collect()
    }

    fn symbol_at(&self, addr: u64) -> String {
        match self.syms.binary_search_by(|(a, _)| a.cmp(&addr)) {
            Ok(i) => self.syms[i].1.clone(),
            Err(0) => format!("0x{addr:x}"),
            Err(i) => self.syms[i - 1].1.clone(),
        }
    }
}

/// Resolve ELF addresses to function names with `addr2line -f -C -e <exe>`,
/// feeding every address on stdin. Requires DWARF (`debug = 1`); returns `None`
/// if `addr2line` is missing or every address comes back unresolved.
fn addr2line_batch(exe: &Path, addrs: &[u64]) -> Option<HashMap<u64, String>> {
    use std::io::Write as _;
    let mut child = std::process::Command::new("addr2line")
        .args(["-f", "-C", "-e"])
        .arg(exe)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    {
        let stdin = child.stdin.as_mut()?;
        for a in addrs {
            writeln!(stdin, "{a:x}").ok()?;
        }
    }
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut lines = text.lines();
    let mut map = HashMap::new();
    let mut resolved = 0usize;
    for &a in addrs {
        let func = lines.next().unwrap_or("??").to_string();
        let _location = lines.next();
        if func != "??" {
            resolved += 1;
        }
        map.insert(a, func);
    }
    if resolved == 0 {
        return None;
    }
    Some(map)
}

/// Parse `/proc/self/maps` into executable mappings.
fn parse_maps(exe: &Path) -> Vec<Mapping> {
    let Ok(text) = std::fs::read_to_string("/proc/self/maps") else {
        return Vec::new();
    };
    let exe = exe.to_string_lossy();
    let mut out = Vec::new();
    for line in text.lines() {
        let mut f = line.split_whitespace();
        let Some(range) = f.next() else { continue };
        let _perms = f.next();
        let Some(offset) = f.next() else { continue };
        let _dev = f.next();
        let _inode = f.next();
        let path = f.collect::<Vec<_>>().join(" ");
        let path = path.trim_end_matches(" (deleted)");
        let Some((start_hex, end_hex)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (
            u64::from_str_radix(start_hex, 16),
            u64::from_str_radix(end_hex, 16),
        ) else {
            continue;
        };
        let Ok(file_offset) = u64::from_str_radix(offset, 16) else {
            continue;
        };
        let module = if path.is_empty() {
            "[anon]".to_string()
        } else {
            Path::new(path)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.to_string())
        };
        out.push(Mapping {
            start,
            end,
            file_offset,
            module,
            is_exe: path == exe,
        });
    }
    out
}

/// `nm -C --defined-only -n` on `exe`, sorted by address.
fn load_nm(exe: &Path) -> Option<Vec<(u64, String)>> {
    let out = std::process::Command::new("nm")
        .args(["-C", "--defined-only", "-n"])
        .arg(exe)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut syms: Vec<(u64, String)> = Vec::new();
    for line in text.lines() {
        let mut parts = line.splitn(3, ' ');
        let Some(addr_hex) = parts.next() else {
            continue;
        };
        let Some(_kind) = parts.next() else {
            continue;
        };
        let Some(name) = parts.next() else {
            continue;
        };
        if let Ok(addr) = u64::from_str_radix(addr_hex, 16) {
            syms.push((addr, name.to_string()));
        }
    }
    syms.sort_by_key(|(a, _)| *a);
    syms.dedup_by_key(|(a, _)| *a);
    Some(syms)
}

/// Aggregate samples into collapsed stacks. Sampling is leaf-only
/// (`PERF_SAMPLE_IP`), so each line is `leaf-symbol count` — a flat profile at
/// function granularity.
fn folded_stacks(samples: &[pmu::Sample], names: &HashMap<u64, String>) -> Vec<(String, u64)> {
    let mut counts: HashMap<String, u64> = HashMap::new();
    for s in samples {
        let name = names
            .get(&s.ip)
            .cloned()
            .unwrap_or_else(|| format!("0x{:x}", s.ip));
        *counts.entry(name).or_insert(0) += 1;
    }
    let mut v: Vec<(String, u64)> = counts.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v.truncate(200);
    v
}

struct FlameNode {
    name: String,
    count: u64,
    children: Vec<usize>,
}

struct Arena {
    nodes: Vec<FlameNode>,
}

impl Arena {
    fn new() -> Arena {
        Arena {
            nodes: vec![FlameNode {
                name: "all".to_string(),
                count: 0,
                children: Vec::new(),
            }],
        }
    }

    fn insert(&mut self, frames: &[&str], count: u64) {
        let mut cur = 0usize;
        self.nodes[cur].count += count;
        for &frame in frames {
            let next = match self.nodes[cur]
                .children
                .iter()
                .find(|&&i| self.nodes[i].name == frame)
                .copied()
            {
                Some(i) => i,
                None => {
                    let i = self.nodes.len();
                    self.nodes.push(FlameNode {
                        name: frame.to_string(),
                        count: 0,
                        children: Vec::new(),
                    });
                    self.nodes[cur].children.push(i);
                    i
                }
            };
            self.nodes[next].count += count;
            cur = next;
        }
    }

    fn max_depth(&self, node: usize) -> usize {
        self.nodes[node]
            .children
            .iter()
            .map(|&c| 1 + self.max_depth(c))
            .max()
            .unwrap_or(0)
    }
}

const SVG_W: f64 = 1200.0;
const SVG_ROW: f64 = 16.0;

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn fold_name(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('~');
        out
    }
}

fn render_node(arena: &Arena, node: usize, depth: usize, x: f64, w: f64, svg: &mut String) {
    if w < 0.4 {
        return;
    }
    let n = &arena.nodes[node];
    let y = depth as f64 * SVG_ROW;
    let hue = (depth * 47) % 360;
    svg.push_str(&format!(
        "<g><title>{} ({})</title><rect x=\"{x:.2}\" y=\"{y:.2}\" width=\"{w:.2}\" \
         height=\"{SVG_ROW}\" fill=\"hsl({hue},60%,72%)\" stroke=\"#ffffff\"/></g>\n",
        xml_escape(&n.name),
        n.count
    ));
    if w > 44.0 {
        let label = format!("{} ({})", n.name, n.count);
        let shown = fold_name(&label, (w / 6.2) as usize);
        svg.push_str(&format!(
            "<text x=\"{:.2}\" y=\"{:.2}\" fill=\"#111111\">{}</text>\n",
            x + 3.0,
            y + 12.0,
            xml_escape(&shown)
        ));
    }
    let mut cx = x;
    for &child in &arena.nodes[node].children {
        let cw = w * (arena.nodes[child].count as f64 / arena.nodes[node].count.max(1) as f64);
        render_node(arena, child, depth + 1, cx, cw, svg);
        cx += cw;
    }
}

fn render_svg(arena: &Arena) -> String {
    let total = arena.nodes[0].count.max(1) as f64;
    let depth = arena.max_depth(0);
    let height = (depth as f64 + 1.0) * SVG_ROW + 16.0;
    let mut svg = String::new();
    svg.push_str(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{SVG_W}\" height=\"{height}\" \
         font-family=\"monospace\" font-size=\"11\">\n"
    ));
    svg.push_str(&format!(
        "<rect width=\"{SVG_W}\" height=\"{height}\" fill=\"#f7f7f9\"/>\n"
    ));
    let mut x = 0.0;
    for &child in &arena.nodes[0].children {
        let w = SVG_W * (arena.nodes[child].count as f64 / total);
        render_node(arena, child, 1, x, w, &mut svg);
        x += w;
    }
    svg.push_str("</svg>\n");
    svg
}

#[derive(serde::Serialize)]
struct FlameOutcome {
    produced: bool,
    samples: u64,
    frames: u64,
    folded: Option<String>,
    svg: Option<String>,
    reason: Option<String>,
}

/// Write the flamegraph outcome sidecar (so the release sweep can embed it) and
/// return it.
fn emit_flamegraph(evidence_dir: &Path, outcome: FlameOutcome) -> FlameOutcome {
    if let Ok(mut s) = serde_json::to_string_pretty(&outcome) {
        s.push('\n');
        let _ = std::fs::write(evidence_dir.join("flamegraph-microarch.json"), s);
    }
    outcome
}

fn run_flamegraph(evidence_dir: &Path) -> FlameOutcome {
    let mut sampler = match pmu::Sampler::open(200_000) {
        Ok(s) => s,
        Err(e) => {
            return emit_flamegraph(
                evidence_dir,
                FlameOutcome {
                    produced: false,
                    samples: 0,
                    frames: 0,
                    folded: None,
                    svg: None,
                    reason: Some(format!("perf_event_open(sampling): {e}")),
                },
            )
        }
    };
    if let Err(e) = sampler.enable() {
        return emit_flamegraph(
            evidence_dir,
            FlameOutcome {
                produced: false,
                samples: 0,
                frames: 0,
                folded: None,
                svg: None,
                reason: Some(format!("PERF_EVENT_IOC_ENABLE: {e}")),
            },
        );
    }

    // Build the mixed workload (untimed): PMap lookups + manifested reads.
    let n = 1usize << 15;
    let mut map: PMap<u64, u64> = PMap::new();
    for k in 0..n as u64 {
        map = map.insert(k, k);
    }
    let mask = (n as u64).next_power_of_two() - 1;
    let td = TempDir::new().expect("tempdir");
    let source = pattern(SRC_LEN);
    let planner = planner_for(td.path(), &source);
    for _ in 0..256 {
        std::hint::black_box(hot_read(&planner, &source));
    }

    let started = Instant::now();
    let mut rng = Lcg(0xfeed_face_dead_beef);
    let mut acc = 0u64;
    let mut samples: Vec<pmu::Sample> = Vec::new();
    while started.elapsed() < Duration::from_millis(1200) {
        for _ in 0..2000 {
            let k = rng.next() & mask;
            if let Some(v) = map.get(&(k % n as u64)) {
                acc = acc.wrapping_add(*v);
            }
        }
        for _ in 0..500 {
            std::hint::black_box(hot_read(&planner, &source));
        }
        samples.extend(sampler.collect());
    }
    std::hint::black_box(acc);
    let _ = sampler.disable();
    samples.extend(sampler.collect());

    let syms = Symbolizer::load();
    let ips: Vec<u64> = samples.iter().map(|s| s.ip).collect();
    let names = syms.resolve_many(&ips);
    let folded = folded_stacks(&samples, &names);
    let frame_count = folded.len() as u64;

    std::fs::create_dir_all(evidence_dir).expect("evidence dir");
    let folded_path = evidence_dir.join("flamegraph-microarch.folded");
    let mut folded_text = String::new();
    for (stack, count) in &folded {
        folded_text.push_str(&format!("{stack} {count}\n"));
    }
    std::fs::write(&folded_path, folded_text).expect("write folded");

    let mut arena = Arena::new();
    for (stack, count) in &folded {
        let frames: Vec<&str> = stack.split(';').collect();
        arena.insert(&frames, *count);
    }
    let svg_path = evidence_dir.join("flamegraph-microarch.svg");
    std::fs::write(&svg_path, render_svg(&arena)).expect("write svg");

    emit_flamegraph(
        evidence_dir,
        FlameOutcome {
            produced: true,
            samples: samples.len() as u64,
            frames: frame_count,
            folded: Some(folded_path.display().to_string()),
            svg: Some(svg_path.display().to_string()),
            reason: None,
        },
    )
}

// ---------------------------------------------------------------------------
// The court
// ---------------------------------------------------------------------------

/// Open the PMU group, or `None` with the errno reported on stderr.
fn open_group() -> Option<PmuGroup> {
    match PmuGroup::open() {
        Ok(g) => {
            let missing: Vec<&str> = g.missing().iter().map(|c| c.name()).collect();
            eprintln!(
                "pmu: counters available: {:?} (missing: {:?})",
                g.counters().iter().map(|c| c.name()).collect::<Vec<_>>(),
                missing
            );
            Some(g)
        }
        Err(e) => {
            eprintln!("pmu: unavailable: {e}");
            None
        }
    }
}

fn report(m: &Metrics) {
    match &m.counters {
        Some(counters) => {
            let cycles = per_op(counter_of(counters, Counter::Cycles).unwrap_or(0), m.ops);
            let instr = per_op(
                counter_of(counters, Counter::Instructions).unwrap_or(0),
                m.ops,
            );
            let misses = per_op(
                counter_of(counters, Counter::CacheMisses).unwrap_or(0),
                m.ops,
            );
            let bmiss = per_op(
                counter_of(counters, Counter::BranchMisses).unwrap_or(0),
                m.ops,
            );
            let ipc = if cycles > 0.0 { instr / cycles } else { 0.0 };
            eprintln!(
                "{:>34}  wall={:>10.1}ns  cyc={:>8.1}  insn={:>8.1}  cmiss={:>7.2}  bmiss={:>7.3}  ipc={:.2}",
                m.name, m.wall_ns_per_op, cycles, instr, misses, bmiss, ipc
            );
        }
        None => eprintln!(
            "{:>34}  wall={:>10.1}ns  (no PMU counters)",
            m.name, m.wall_ns_per_op
        ),
    }
}

fn run_all(
    group: &mut Option<PmuGroup>,
    pmap_ops: u64,
    manifest_ops: u64,
    sel_ops: u64,
    log_ops: u64,
) -> Vec<Metrics> {
    let pmap = pmap_component(group.as_mut(), pmap_ops);
    let manifested = manifested_component(group.as_mut(), manifest_ops);
    let selection = selection_component(group.as_mut(), sel_ops);
    let log = log_component(group.as_mut(), log_ops);
    vec![pmap, manifested, selection, log]
}

/// The always-on smoke: a bounded run of every component that never requires
/// the PMU to be usable.
#[test]
fn pmu_smoke() {
    let mut group = open_group();
    let components = run_all(&mut group, 20_000, 2_000, 20_000, 5_000);
    for c in &components {
        report(c);
    }
    for c in &components {
        assert!(c.ops > 0);
        assert!(
            c.wall_ns_per_op > 0.0,
            "{} reported a non-positive wall time",
            c.name
        );
    }
    if let Some(g) = &group {
        // Real counters were granted: they must actually be nonzero.
        let counters = components[0].counters.as_ref().expect("counters");
        assert!(
            counter_of(counters, Counter::Cycles).unwrap_or(0) > 0,
            "cycles counter read zero despite a live group"
        );
        assert!(
            counter_of(counters, Counter::Instructions).unwrap_or(0) > 0,
            "instructions counter read zero despite a live group"
        );
        assert!(g.has(Counter::Instructions));
    } else {
        eprintln!(
            "pmu_smoke: PMU unavailable; software timings only (this is recorded, not hidden)."
        );
    }
}

/// Produce the flamegraph and its collapsed stacks (opt-in via `ORFS_PMU=1`).
///
/// Run this in a **debug** build: without optimisation the leaf symbols are
/// unambiguous (LTO/codegen-unit merging in the release profile folds distinct
/// functions onto shared addresses). The release `pmu_sweep` embeds the sidecar
/// this writes.
#[test]
fn pmu_flamegraph() {
    if std::env::var("ORFS_PMU").as_deref() != Ok("1") {
        eprintln!("pmu_flamegraph: skipped (set ORFS_PMU=1)");
        return;
    }
    let evidence_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("evidence/performance");
    let flame = run_flamegraph(&evidence_dir);
    if flame.produced {
        eprintln!(
            "flamegraph: {} samples, {} collapsed frames -> {}",
            flame.samples,
            flame.frames,
            flame.svg.as_deref().unwrap_or("(none)")
        );
    } else {
        eprintln!(
            "flamegraph: not produced: {}",
            flame.reason.as_deref().unwrap_or("unknown")
        );
    }
}

/// The full sweep (opt-in via `ORFS_PMU=1`): writes `evidence/performance/pmu.json`
/// (embedding the flamegraph sidecar written by `pmu_flamegraph`).
#[test]
fn pmu_sweep() {
    if std::env::var("ORFS_PMU").as_deref() != Ok("1") {
        eprintln!("pmu_sweep: skipped (set ORFS_PMU=1 to run the full sweep)");
        return;
    }

    let mut group = open_group();
    let probe_error = PmuGroup::open().err();
    let available = group.is_some();

    let components = run_all(&mut group, 500_000, 20_000, 500_000, 100_000);
    for c in &components {
        report(c);
    }

    let evidence_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("evidence/performance");
    // The flamegraph is produced by the separate `pmu_flamegraph` run (a debug
    // build, where symbols are unambiguous); embed its sidecar if present.
    let flame = std::fs::read_to_string(evidence_dir.join("flamegraph-microarch.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .unwrap_or_else(|| {
            json!({
                "produced": false,
                "reason": "run `ORFS_PMU=1 cargo test --test microarch_pmu pmu_flamegraph`",
            })
        });

    let environment = orfs::bench::Environment::capture(std::env::var("ORFS_IMAGE").ok());
    let counters = group
        .as_ref()
        .map(|g| g.counters().iter().map(|c| c.name()).collect::<Vec<_>>())
        .unwrap_or_default();
    let missing = group
        .as_ref()
        .map(|g| g.missing().iter().map(|c| c.name()).collect::<Vec<_>>())
        .unwrap_or_default();

    let doc = json!({
        "schema": "orfs.performance.pmu.v1",
        "generated_by": "tests/microarch_pmu.rs",
        "available": available,
        "probe": {
            "perf_event_paranoid": environment.perf_event_paranoid,
            "error": probe_error,
            "counters": counters,
            "missing_counters": missing,
            "note": "perf_event_paranoid=2 permits user-space per-thread counters; a \
                     seccomp profile that denies perf_event_open returns EPERM. The \
                     container flag that fixes it is proven by scripts/container-pmu.sh.",
        },
        "components": components.iter().map(metrics_json).collect::<Vec<_>>(),
        "flamegraph": flame,
        "environment": environment,
        "build": if cfg!(debug_assertions) { "debug" } else { "release" },
        "note": "Single run, single host, one thread. Per-op hardware counters over the \
                 measured loop (reset/enable around the loop, disable before reading). \
                 Absolute nanoseconds are host/load sensitive; the counters and the \
                 IPC / miss-rate ratios are the point.",
    });

    std::fs::create_dir_all(&evidence_dir).expect("evidence dir");
    let path = evidence_dir.join("pmu.json");
    let mut s = serde_json::to_string_pretty(&doc).expect("serialize");
    s.push('\n');
    std::fs::write(&path, s).expect("write evidence");
    eprintln!("pmu evidence written to {}", path.display());
}
