use simplelog::Config;
use windows_registry::CURRENT_USER;

// Custom pattern search implementation
fn find_pattern(haystack: &[u8], needle: &[Option<u8>]) -> Vec<usize> {
    let mut matches = Vec::new();
    if needle.is_empty() {
        return matches;
    }

    for i in 0..haystack.len().saturating_sub(needle.len() - 1) {
        let mut found = true;
        for j in 0..needle.len() {
            if let Some(n_byte) = needle[j] {
                if haystack[i + j] != n_byte {
                    found = false;
                    break;
                }
            }
        }
        if found {
            matches.push(i);
        }
    }
    matches
}

const PATCHES: &'static [(&'static [Option<u8>], &'static [u8])] = &[
    (
        &[
            Some(0x48), Some(0x89), Some(0x5C), Some(0x24), None, Some(0x48), Some(0x89), Some(0x74), Some(0x24), None, Some(0x57), Some(0x48), Some(0x83), Some(0xEC), Some(0x60),
            Some(0x48), Some(0x8B), Some(0x05), None, None, None, None, Some(0x48), Some(0x33), Some(0xC4), Some(0x48), Some(0x89), Some(0x44), Some(0x24), None, Some(0x48), Some(0x8B),
            Some(0xF1), Some(0x89), Some(0x51)
        ],
        &[0x48, 0x31, 0xC0, 0x48, 0xFF, 0xC0, 0xC3],
    ),
    (
        &[
            Some(0x40), Some(0x53), Some(0x48), Some(0x83), Some(0xEC), Some(0x20), Some(0x89), Some(0x51), Some(0x20), Some(0x48), Some(0x8B), Some(0xD9), Some(0xC6), Some(0x41),
            Some(0x24), Some(0x00), Some(0x83), Some(0xEA), Some(0x01), Some(0x74)
        ],
        &[0xB0, 0x01, 0xC3],
    ),
];

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
}

fn patch() -> Result<(), PatchError> {
    // Use the hardcoded path provided by the user
    let resolve_path = r#"C:\Program Files\Blackmagic Design\DaVinci Resolve\Resolve.exe"#;

    let Ok(mut data) = std::fs::read(resolve_path) else {
        Err(PatchError::ResolveNotFound)?
    };

    let mut patches = false;

    for (sig, replacement) in PATCHES {
        let occs: Vec<usize> = find_pattern(&data, sig);

        match occs.len() {
            0 => {}
            1 => {
                let addr = occs[0];

                data[addr..addr + replacement.len()].copy_from_slice(replacement);

                patches = true;
            }
            _ => {
                Err(PatchError::SignatureOccurrenceMismatch(occs.len()))?
            }
        }
    }

    if !patches {
        Err(PatchError::NoSignatureFound)?
    }

    let Ok(_) = std::fs::copy(
        resolve_path,
        &format!("{resolve_path}.bak"),
    ) else {
        Err(PatchError::BackupFailed)?
    };

    let Ok(_) = std::fs::write(resolve_path, data) else {
        Err(PatchError::WriteFailed)?
    };

    Ok(())
}

fn main() {
    let _ = simplelog::SimpleLogger::init(log::LevelFilter::Info, Config::default());

    log::info!("attempting to patch resolve!");

    match patch() {
        Ok(_) => {
            log::info!("successfully patched!");
        }
        Err(e) => {
            log::error!("failed to patch resolve: {e}")
        }
    }

    std::thread::sleep(std::time::Duration::from_secs(5));
}
