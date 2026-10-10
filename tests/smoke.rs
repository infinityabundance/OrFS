//! Phase 0 smoke tests: the crate builds, the error model maps to errnos, the
//! capability probe is safe, and the EKBLOOM dependency is genuinely wired.

use orfs::{OrfsError, FORMAT_VERSION, VERSION};

#[test]
fn version_is_populated() {
    assert!(!VERSION.is_empty());
    assert_eq!(FORMAT_VERSION, 1);
}

#[test]
fn errno_mapping_is_stable() {
    assert_eq!(OrfsError::NotFound.errno(), libc::ENOENT);
    assert_eq!(OrfsError::AlreadyExists.errno(), libc::EEXIST);
    assert_eq!(OrfsError::DirectoryNotEmpty.errno(), libc::ENOTEMPTY);
    assert_eq!(OrfsError::DirectoryCycle.errno(), libc::EINVAL);
    assert_eq!(OrfsError::NoSpace("backing".into()).errno(), libc::ENOSPC);
    assert_eq!(OrfsError::Unsupported("x".into()).errno(), libc::EOPNOTSUPP);
    assert_eq!(OrfsError::Unimplemented("p").errno(), libc::ENOSYS);
}

#[test]
fn capabilities_probe_does_not_panic() {
    let caps = orfs::capabilities::probe();
    assert!(!caps.kernel_release.is_empty());
    assert!(!caps.machine.is_empty());
}

/// Proves EKBLOOM is consumed as a real dependency and its authoritative machine
/// is exactly invertible over arbitrary bytes.
#[test]
fn ekbloom_machine_roundtrip_is_wired() {
    use ekbloom::{OrMachine, NL2};
    for src in [&b""[..], &b"A"[..], &b"OrFS<->EKBLOOM"[..], &[0u8; 257][..]] {
        let core = NL2.encode(src).expect("encode");
        assert_eq!(
            core.len(),
            src.len(),
            "visible length equals logical length"
        );
        let out = NL2.decode(&core, src.len() as u64).expect("decode");
        assert_eq!(&out[..], src);
    }
}
