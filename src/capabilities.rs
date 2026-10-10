//! Kernel and container capability discovery.
//!
//! `doctor` and the transport layer need to know, truthfully, what the running
//! kernel actually supports. Nothing here mutates host state; it only reads.

use std::fs;
use std::path::Path;

/// A snapshot of the runtime capabilities relevant to OrFS.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Capabilities {
    /// `uname -r`.
    pub kernel_release: String,
    /// `uname -m`.
    pub machine: String,
    /// Whether `/dev/fuse` exists and is character-special.
    pub dev_fuse_present: bool,
    /// Value of `/proc/sys/kernel/io_uring_disabled` if readable.
    pub io_uring_disabled: Option<i32>,
    /// Whether the kernel was built with `CONFIG_FUSE_FS`.
    pub config_fuse_fs: Option<bool>,
    /// Whether the kernel was built with `CONFIG_FUSE_IO_URING`.
    pub config_fuse_io_uring: Option<bool>,
    /// Whether the kernel was built with `CONFIG_IO_URING`.
    pub config_io_uring: Option<bool>,
    /// Whether `CONFIG_IO_URING_ZCRX` is present (zero-copy receive).
    pub config_io_uring_zcrx: Option<bool>,
    /// Heuristic: are we likely running inside a container?
    pub likely_container: bool,
}

impl Capabilities {
    /// Whether the traditional `/dev/fuse` transport is plausibly usable.
    pub fn traditional_fuse_usable(&self) -> bool {
        self.dev_fuse_present && self.config_fuse_fs.unwrap_or(true)
    }

    /// Whether the kernel advertises the FUSE-over-`io_uring` UAPI *and* the
    /// sysctl does not disable io_uring. This is a necessary, not sufficient,
    /// condition; runtime negotiation is still required.
    pub fn fuse_over_io_uring_plausible(&self) -> bool {
        self.config_fuse_io_uring.unwrap_or(false)
            && self.io_uring_disabled.unwrap_or(0) == 0
            && self.config_io_uring.unwrap_or(false)
    }
}

fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn uname() -> (String, String) {
    // SAFETY: `uname` is a pure query filling a caller-owned struct; we pass a
    // valid, aligned, fully-owned `utsname`. No pointers are retained.
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::uname(&mut u) };
    if rc != 0 {
        return (String::from("unknown"), String::from("unknown"));
    }
    let to_string = |arr: &[libc::c_char]| {
        let bytes: Vec<u8> = arr
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect();
        String::from_utf8_lossy(&bytes).into_owned()
    };
    (to_string(&u.release), to_string(&u.machine))
}

/// Search the kernel config for a `CONFIG_...=y|m` key. Tries `/proc/config.gz`
/// via `zcat` is *not* available here, so we look for a plaintext config at the
/// usual locations. Returns `None` when no config is readable.
fn kernel_config_flag(key: &str) -> Option<bool> {
    let candidates = ["/boot/config", "/proc/config", "/lib/modules/config"];
    for p in candidates {
        if let Ok(text) = fs::read_to_string(p) {
            return Some(config_contains(&text, key));
        }
    }
    None
}

fn config_contains(text: &str, key: &str) -> bool {
    let y = format!("{key}=y");
    let m = format!("{key}=m");
    text.lines().any(|l| {
        let l = l.trim_end();
        l == y || l == m
    })
}

/// Probe the current runtime.
pub fn probe() -> Capabilities {
    let (kernel_release, machine) = uname();

    let dev_fuse_present = fs::metadata(Path::new("/dev/fuse"))
        .map(|m| {
            use std::os::unix::fs::FileTypeExt;
            m.file_type().is_char_device()
        })
        .unwrap_or(false);

    let io_uring_disabled =
        read_trimmed("/proc/sys/kernel/io_uring_disabled").and_then(|s| s.parse::<i32>().ok());

    let likely_container = Path::new("/.dockerenv").exists()
        || read_trimmed("/proc/1/cgroup")
            .map(|c| c.contains("docker") || c.contains("containerd") || c.contains("kubepods"))
            .unwrap_or(false);

    Capabilities {
        kernel_release,
        machine,
        dev_fuse_present,
        io_uring_disabled,
        config_fuse_fs: kernel_config_flag("CONFIG_FUSE_FS"),
        config_fuse_io_uring: kernel_config_flag("CONFIG_FUSE_IO_URING"),
        config_io_uring: kernel_config_flag("CONFIG_IO_URING"),
        config_io_uring_zcrx: kernel_config_flag("CONFIG_IO_URING_ZCRX"),
        likely_container,
    }
}
