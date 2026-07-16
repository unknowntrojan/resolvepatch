 use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

use coolfindpattern::pattern;
use pelite::pe::Pe;
use simplelog::Config;
use windows_registry::{CURRENT_USER, LOCAL_MACHINE};

// ========================================================================
// v21 DIALOG BYPASS — the missing piece!
// ========================================================================
// In Resolve 21, Blackmagic added a new license-check chain function that
// shows the "License Key / Blackmagic Cloud ID" chooser dialog at startup.
// This function was discovered via Frida dynamic analysis. The original
// unknowntrojan Rust patcher doesn't know about it (designed for v20).
//
// The fix: find the function prologue + first JNE, and convert that JNE
// to an unconditional JMP so the function always takes the early-exit
// success path, never reaching the dialog construction code.
fn patch_v21_dialog(data: &mut [u8]) -> Result<(), PatchError> {
    // This is the "Beta 3" pattern from resolvepatch_v2.py which successfully
    // bypassed the license dialog in the current v21.0.0 build.
    // It has two extra bytes (33 C9 = xor ecx,ecx) compared to the original v21 pattern,
    // which shifts the JNE (0F 85) to offset 24 instead of 22.
    let searcher = coolfindpattern::PatternSearcher::new(
        &data,
        pattern!(
            0x48, 0x89, 0x5C, 0x24, 0x10, 0x57,
            0x48, 0x81, 0xEC, 0x80, 0x00, 0x00, 0x00,
            0x33, 0xDB, 0x33, 0xC9,
            0xE8, _, _, _, _,
            0x84, 0xC0,
            0x0F, 0x85, _, _, _, _
        ),
    );

    let occs: Vec<usize> = searcher.collect();

    match occs.len() {
        0 => {
            log::warn!("v21 dialog bypass: pattern not found (may already be patched)");
            return Ok(());
        }
        1 => {
            let addr = occs[0];
            // Replace bytes 24-25 (0F 85 = JNE) with (90 E9 = NOP + JMP)
            // Bytes 26-29 (the rel32 displacement) are left intact,
            // so the JMP lands exactly where the JNE would have.
            log::info!("v21 dialog bypass: patching at offset 0x{:08X}", addr);
            data[addr + 24] = 0x90; // NOP
            data[addr + 25] = 0xE9; // JMP rel32
            // bytes 26..30 stay as-is (original displacement)
            Ok(())
        }
        n => {
            log::warn!("v21 dialog bypass: pattern matched {} times — skipping", n);
            Err(PatchError::SignatureOccurrenceMismatch(n))
        }
    }
}

// ========================================================================
// patch_4func — Dolby Vision license validator
// ========================================================================
fn patch_4func(data: &mut [u8]) -> Result<(), PatchError> {
    let addr = {
        let searcher = coolfindpattern::PatternSearcher::new(
            &data,
            pattern!(
                0xE8, _, _, _, _, 0x88, 0x83, _, _, _, _, 0x48, 0x8D, 0x4C, 0x24, _, 0xFF, 0x15
            ),
        );

        let occs: Vec<usize> = searcher.collect();

        match occs.len() {
            1 => {}
            _ => return Err(PatchError::ComplexFuncPatchFailed),
        }

        let call_addr = occs.get(0).unwrap();

        // resolve relative call
        let bytes = [
            data[call_addr + 1],
            data[call_addr + 2],
            data[call_addr + 3],
            data[call_addr + 4],
        ];

        let offset = u32::from_le_bytes(bytes);

        let addr = call_addr + 5 + offset as usize;

        addr
    };

    // v21 FIX: In Resolve 21, Blackmagic added 3 extra Dolby Vision license
    // checks for inner1. Indices [0,1,2,3] all jump to the same fail-block.
    // Indices [4,5] are normal program logic — DO NOT touch.
    // Inner2 stays the same as v20: indices [0,1,2] are license checks,
    // index [3] has different context (0x48 prefix = different instruction).
    const LOCAL_PATCHES: &'static [(&'static [Option<u8>], &'static [u8], &'static [usize])] = &[
        (
            pattern!(0x84, 0xC0, 0x0F, 0x84),
            &[0x84, 0xC0, 0x0F, 0x85],
            &[0, 1, 2, 3],
        ),
        (
            pattern!(0x85, 0xDB, 0x0F, 0x84),
            &[0x85, 0xDB, 0x0F, 0x85],
            &[0, 1, 2],
        ),
    ];

    for (pat, repl, idxs) in LOCAL_PATCHES {
        let searcher = coolfindpattern::PatternSearcher::new(&data[addr..addr + 0x1000], pat);

        let occs: Vec<usize> = searcher.collect();

        for idx in *idxs {
            let Some(x) = occs.get(*idx) else {
                return Err(PatchError::ComplexFuncPatchFailed);
            };

            data[addr + x..addr + x + repl.len()].copy_from_slice(repl);
        }
    }

    Ok(())
}

// ========================================================================
// Patch tables (from unknowntrojan — render guards & timer mines)
// ========================================================================

const PATCHES_OLD: &'static [(&'static [Option<u8>], &'static [u8])] = &[
    (
        pattern!(
            0x0F, 0x84, _, _, _, _, 0xE8, _, _, _, _, 0x33, 0xD2, 0x48, 0x8B, 0xC8, 0xE8, _, _, _,
            _, 0x84, 0xC0, 0x0F, 0x85
        ),
        &[0x90, 0xE9],
    ),
    (
        pattern!(
            0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x89, 0x51, 0x20, 0x48, 0x8B, 0xD9, 0xC6, 0x41,
            0x24, 0x00, 0x83, 0xEA, 0x01, 0x74
        ),
        &[0xB0, 0x01, 0xC3],
    ),
];

const PATCHES_20: &'static [(&'static [Option<u8>], &'static [u8])] = &[
    (
        pattern!(
            0x74, _, 0x48, 0x8B, 0x44, 0x24, _, 0x8B, 0x4C, 0x24, _, 0x89, 0x48, _, 0x33, 0xC0,
            0xEB, _, 0x48, 0x8B, 0x44, 0x24
        ),
        &[0xEB],
    ),
    (
        pattern!(
            0x74, _, 0x48, 0x8B, 0x44, 0x24, _, 0x8B, 0x4C, 0x24, _, 0x89, 0x48, _, 0x33, 0xC0,
            0xEB, _, 0xB8, 0x01, 0x00, 0x00, 0x00
        ),
        &[0xEB],
    ),
    (
        // v21 FIX: Use NOP + JMP preserving original rel32 offset instead
        // of hardcoded 0xA4.
        pattern!(
            0x0F, 0x84, _, _, _, _, 0xFF, 0x15, _, _, _, _, 0x83, 0xF8, 0x02, 0x75
        ),
        &[0x90, 0xE9],
    ),
    (
        pattern!(
            0x84, 0xC0, 0x0F, 0x84, _, _, _, _, 0xE8, _, _, _, _, 0x48, 0x8B, 0xC8, 0xE8, _, _, _,
            _, 0x84, 0xC0, 0x0F, 0x85, _, _, _, _, 0xE8
        ),
        &[0xB0, 0x01],
    ),
    (
        pattern!(
            0x84, 0xC0, 0x0F, 0x85, _, _, _, _, 0xE8, _, _, _, _, 0x48, 0x8B, 0xD0, 0xC7, 0x44,
            0x24, _, 0x00, 0x00, 0x00, 0x00
        ),
        &[0xB0, 0x01],
    ),
];

/// `RLM_LICENSE=blackmagic.lic`
const LIC_FILE: &'static str = r#"LICENSE blackmagic davinciresolvestudio 999999 permanent uncounted
  hostid=ANY issuer=ANY customer=ANY issued=14-Aug-2025
  akey=0000-0000-0000-0000-0000 _ck=00 sig="00""#;

fn configure_license_file(path: &str) -> Result<(), PatchError> {
    let mut path = PathBuf::from_str(path).map_err(|_| PatchError::LicenseFileError)?;

    path.set_file_name("blackmagic.lic");

    std::fs::write(&path, LIC_FILE).map_err(|_| PatchError::LicenseFileError)?;

    let key = LOCAL_MACHINE
        .open(r#"System\CurrentControlSet\Control\Session Manager\Environment"#)
        .map_err(|e| {
            log::error!("failed to set global environment variable RLM_LICENSE=blackmagic.lic. please set manually!!! {e}");
            PatchError::LicenseFileError
        })?;

    key.set_string("RLM_LICENSE", "blackmagic.lic")
        .map_err(|e| {
            log::error!("failed to set global environment variable RLM_LICENSE=blackmagic.lic. please set manually!!! {e}");
            PatchError::LicenseFileError
        })?;

    Ok(())
}

#[derive(Debug, thiserror::Error)]
enum PatchError {
    #[error("Resolve could not be located.")]
    ResolveNotFound,
    #[error("A pattern that should only be present once was instead present {0} times.")]
    SignatureOccurrenceMismatch(usize),
    #[error("This version of Resolve is either not compatible or was already patched.")]
    NoSignatureFound,
    #[error("Unable to backup Resolve.exe.")]
    BackupFailed,
    #[error("Unable to write patched Resolve.exe back.")]
    WriteFailed,
    #[error("Failed to parse PE header for main executable.")]
    InvalidPE,
    #[error("Failed to configure license file")]
    LicenseFileError,
    #[error("Could not patch complex function.")]
    ComplexFuncPatchFailed,
}

fn determine_version(data: &[u8]) -> Result<(u16, u16, u16), PatchError> {
    let file = pelite::pe64::PeFile::from_bytes(data).map_err(|_| PatchError::InvalidPE)?;

    let version = file
        .resources()
        .map_err(|_| PatchError::InvalidPE)?
        .version_info()
        .map_err(|_| PatchError::InvalidPE)?
        .fixed()
        .ok_or(PatchError::InvalidPE)?
        .dwFileVersion;

    Ok((version.Major, version.Minor, version.Patch))
}

fn patch(resolve_path: &str) -> Result<(), PatchError> {
    let Ok(mut data) = std::fs::read(resolve_path) else {
        Err(PatchError::ResolveNotFound)?
    };

    let version = determine_version(&data)?;
    log::info!("detected version: {}.{}.{}", version.0, version.1, version.2);

    // STEP 1: v21 dialog bypass (new — not in original unknowntrojan code)
    if version.0 >= 21 {
        log::info!("applying v21 dialog bypass...");
        match patch_v21_dialog(&mut data) {
            Ok(_) => log::info!("v21 dialog bypass: OK"),
            Err(e) => log::warn!("v21 dialog bypass failed: {e} (continuing)"),
        }
    }

    // STEP 2: render guard patches (unknowntrojan's 5 signatures)
    let patches = match version.0 {
        0..18 => {
            log::warn!("version too old, attempting PATCHES_OLD");
            PATCHES_OLD
        }
        18 | 19 => {
            if version.0 == 18 && version.1 == 6 && version.2 > 2 {
                log::warn!("This version of Resolve is unsupported.")
            }
            PATCHES_OLD
        }
        20 => PATCHES_20,
        21..=u16::MAX => {
            log::info!("v21+: applying PATCHES_20 render guards");
            PATCHES_20
        }
    };

    let mut patched = false;

    for (i, (sig, replacement)) in patches.iter().enumerate() {
        let searcher = coolfindpattern::PatternSearcher::new(&data, sig);

        let occs: Vec<usize> = searcher.collect();

        match occs.len() {
            0 => {
                log::info!("patch[{}]: no match (may already be patched)", i);
            }
            1 => {
                let addr = occs[0];
                log::info!("patch[{}]: applying at offset 0x{:08X}", i, addr);
                data[addr..addr + replacement.len()].copy_from_slice(replacement);
                patched = true;
            }
            n => {
                log::warn!("patch[{}]: matched {} times — skipping", i, n);
            }
        }
    }

    // STEP 3: Dolby Vision fix (patch_4func)
    if version.0 >= 20 {
        log::info!("applying patch_4func (Dolby Vision)...");
        match patch_4func(&mut data) {
            Ok(_) => {
                log::info!("patch_4func: OK");
                patched = true;
            }
            Err(e) => log::warn!("patch_4func: {} (continuing)", e),
        }
    }

    if !patched {
        Err(PatchError::NoSignatureFound)?
    }

    let Ok(_) = std::fs::copy(resolve_path, &format!("{resolve_path}.bak")) else {
        Err(PatchError::BackupFailed)?
    };

    let Ok(_) = std::fs::write(resolve_path, data) else {
        Err(PatchError::WriteFailed)?
    };

    let _ = configure_license_file(resolve_path);

    Ok(())
}

fn main() {
    let _ = simplelog::SimpleLogger::init(log::LevelFilter::Info, Config::default());

    log::info!("attempting to patch resolve!");

    let Ok(path) = locate() else {
        log::error!("unable to find resolve....");
        return;
    };

    log::info!("target: {}", path);

    match patch(&path) {
        Ok(_) => {
            log::info!("successfully patched!");
        }
        Err(e) => {
            log::error!("failed to patch resolve: {e}")
        }
    }

    std::thread::sleep(std::time::Duration::from_secs(5));
}

fn path_from_shellopen() -> Option<String> {
    fn path_from_shellopen_internal(typ: &str) -> Option<String> {
        if let Ok(key) =
            CURRENT_USER.open(format!(r#"Software\Classes\{}\shell\open\command"#, typ))
            && let Ok(key) = key.get_string("")
            && let key = &key[1..key.len() - 6]
            && Path::new(key).exists()
        {
            Some(key.to_string())
        } else {
            None
        }
    }

    const EXT_TYPES: &'static [&'static str] = &[
        "ResolveBinFile",
        "ResolveDrpFile",
        "ResolveDBKeyFile",
        "ResolveTimelineFile",
        "ResolveTemplateBundle",
    ];

    EXT_TYPES
        .iter()
        .filter_map(|typ| path_from_shellopen_internal(typ))
        .next()
}

fn locate() -> Result<String, PatchError> {
    if let Some(path) = path_from_shellopen() {
        log::info!("Resolve found via regkey: {path}");
        Ok(path)
    } else {
        const DEFAULT_PATH: &'static str =
            r#"C:\Program Files\Blackmagic Design\DaVinci Resolve\Resolve.exe"#;

        if std::fs::exists(DEFAULT_PATH).is_ok_and(|x| x) {
            Ok(DEFAULT_PATH.to_string())
        } else {
            Err(PatchError::ResolveNotFound)
        }
    }
}
