//! Shared leaf-IP flamegraph rendering (Phase 50/57, reused by Phase 83).
//!
//! A `PERF_SAMPLE_IP` sampling ring records the interrupted instruction pointer;
//! this module resolves each leaf to a function name and renders a self-contained
//! SVG. It is deliberately a **leaf-IP** profile, not a call-chain flamegraph:
//! frame-pointer stacks (`PERF_SAMPLE_CALLCHAIN`) were tried and the kernel
//! emitted context markers and unreliable stacks, so no full stack is claimed.
//! Because sampling is leaf-only, the SVG is a flat profile at function
//! granularity and the counter tables in the courts are the decisive evidence.
//!
//! Symbolisation: frames inside the test binary are resolved with `addr2line`
//! (DWARF, naming LTO-internalised functions that `nm` omits), falling back to
//! `nm`; frames in any other module (libc, ld.so, …) are labelled by the module
//! file name from `/proc/self/maps`.
//!
//! Both the microarchitecture court (`tests/microarch_pmu.rs`,
//! `flamegraph-microarch.*`) and the mounted hot-path court
//! (`tests/hotpath_counters.rs`, `flamegraph-hotpath.*`) include this module via
//! `#[path = "support/flamegraph.rs"]`.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// One executable mapping from `/proc/self/maps`.
struct Mapping {
    start: u64,
    end: u64,
    file_offset: u64,
    module: String,
    is_exe: bool,
}

/// Resolves sampled instruction pointers to function names.
pub struct Symbolizer {
    exe: PathBuf,
    maps: Vec<Mapping>,
    /// `nm` symbol table of the test binary, used as a fallback when the DWARF
    /// resolver is unavailable.
    syms: Vec<(u64, String)>,
}

impl Symbolizer {
    pub fn load() -> Symbolizer {
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

    /// Resolve a batch of sampled instruction pointers.
    pub fn resolve_many(&self, ips: &[u64]) -> HashMap<u64, String> {
        let mut out: HashMap<u64, String> = HashMap::new();
        let mut exe_addrs: Vec<u64> = Vec::new();
        let mut seen: HashSet<u64> = HashSet::new();
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

/// Aggregate leaf instruction pointers into collapsed stacks. Sampling is
/// leaf-only, so each line is `leaf-symbol count` — a flat profile at function
/// granularity. The list is capped at the 200 hottest leaves.
pub fn folded_stacks(ips: &[u64], names: &HashMap<u64, String>) -> Vec<(String, u64)> {
    let mut counts: HashMap<String, u64> = HashMap::new();
    for &ip in ips {
        let name = names
            .get(&ip)
            .cloned()
            .unwrap_or_else(|| format!("0x{ip:x}"));
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

/// The outcome of a flamegraph attempt; serialised as the `.json` sidecar so the
/// release sweep can embed it and a reader can see exactly why a graph is absent.
#[derive(serde::Serialize)]
pub struct FlameOutcome {
    pub produced: bool,
    pub samples: u64,
    pub frames: u64,
    pub folded: Option<String>,
    pub svg: Option<String>,
    pub sidecar: Option<String>,
    pub reason: Option<String>,
}

/// A non-produced outcome carrying the exact reason (e.g. the `perf_event_open`
/// errno), so an absent graph is never mistaken for a failing run.
pub fn failure(reason: String) -> FlameOutcome {
    FlameOutcome {
        produced: false,
        samples: 0,
        frames: 0,
        folded: None,
        svg: None,
        sidecar: None,
        reason: Some(reason),
    }
}

/// Write the outcome to `<stem>.json` (its sidecar) and return it.
pub fn emit(evidence_dir: &Path, stem: &str, mut outcome: FlameOutcome) -> FlameOutcome {
    let path = evidence_dir.join(format!("{stem}.json"));
    if let Ok(mut s) = serde_json::to_string_pretty(&outcome) {
        s.push('\n');
        let _ = std::fs::write(&path, s);
        outcome.sidecar = Some(path.display().to_string());
    }
    outcome
}

/// Symbolise `ips`, fold them, and write `<stem>.folded` and `<stem>.svg`.
pub fn render(evidence_dir: &Path, stem: &str, ips: &[u64]) -> FlameOutcome {
    let syms = Symbolizer::load();
    let names = syms.resolve_many(ips);
    let folded = folded_stacks(ips, &names);

    std::fs::create_dir_all(evidence_dir).expect("evidence dir");
    let folded_path = evidence_dir.join(format!("{stem}.folded"));
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
    let svg_path = evidence_dir.join(format!("{stem}.svg"));
    std::fs::write(&svg_path, render_svg(&arena)).expect("write svg");

    emit(
        evidence_dir,
        stem,
        FlameOutcome {
            produced: true,
            samples: ips.len() as u64,
            frames: folded.len() as u64,
            folded: Some(folded_path.display().to_string()),
            svg: Some(svg_path.display().to_string()),
            sidecar: None,
            reason: None,
        },
    )
}
