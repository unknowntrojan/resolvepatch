use coolfindpattern::pattern;
use simplelog::{Config, SimpleLogger};
use windows_registry::{CURRENT_USER, LOCAL_MACHINE};
use std::{fs, path::Path, thread, time::Duration};
use log::{warn, info, error};

const PATCHES: &'static [(&'static [Option<u8>], &'static [u8])] = &[
    (
        pattern!(
            0x48, 0x89, 0x5C, 0x24, _, 0x48, 0x89, 0x74, 0x24, _, 0x57, 0x48, 0x83, 0xEC, 0x60,
            0x48, 0x8B, 0x05, _, _, _, _, 0x48, 0x33, 0xC4, 0x48, 0x89, 0x44, 0x24, _, 0x48, 0x8B,
            0xF1, 0x89, 0x51
        ),
        &[0x48, 0x31, 0xC0, 0x48, 0xFF, 0xC0, 0xC3],
    ),
    (
        pattern!(
            0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x89, 0x51, 0x20, 0x48, 0x8B, 0xD9, 0xC6, 0x41,
            0x24, 0x00, 0x83, 0xEA, 0x01, 0x74
        ),
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
    #[error("Unable to backup Resolve.")]
    BackupFailed,
    #[error("Unable to write patched Resolve back.")]
    WriteFailed,
}

fn extract_path(cmd: &str) -> Option<String> {
    if let Some(start) = cmd.find('"') {
        if let Some(end) = cmd[start + 1..].find('"') {
            let path = &cmd[start + 1..start + 1 + end];
            if path.to_lowercase().contains("resolve") {
                return Some(path.to_string());
            }
        }
    }
    
    let words: Vec<&str> = cmd.split_whitespace().collect();
    for word in words {
        if word.to_lowercase().contains("resolve") && word.contains(':') {
            return Some(word.to_string());
        }
    }
    None
}

fn check_associations() -> Option<String> {
    let exts = [".drp", ".drt", ".drb", ".drfx", ".braw"];
    for ext in &exts {
        if let Ok(key) = LOCAL_MACHINE.open(&format!("SOFTWARE\\Classes\\{}", ext)) {
            if let Ok(file_type) = key.get_string("") {
                let command_path = format!("SOFTWARE\\Classes\\{}\\shell\\open\\command", file_type);
                if let Ok(command_key) = LOCAL_MACHINE.open(&command_path) {
                    if let Ok(command) = command_key.get_string("") {
                        if let Some(path) = extract_path(&command) {
                            if Path::new(&path).exists() {
                                return Some(path);
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

fn check_uninstall() -> Option<String> {
    if let Ok(uninstall_key) = LOCAL_MACHINE.open("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall") {
        for i in 0..10000 {
            let key_name = format!("{:08X}-0000-0000-0000-000000000000", i);
            let guid_key = format!("{{{}}}", key_name);
            
            if let Ok(subkey) = uninstall_key.open(&guid_key) {
                if let Ok(display_name) = subkey.get_string("DisplayName") {
                    if display_name.to_lowercase().contains("resolve") {
                        if let Some(path) = try_extract_resolve_path(&subkey) {
                            return Some(path);
                        }
                    }
                }
            }
            
            if let Ok(subkey) = uninstall_key.open(&key_name) {
                if let Ok(display_name) = subkey.get_string("DisplayName") {
                    if display_name.to_lowercase().contains("resolve") {
                        if let Some(path) = try_extract_resolve_path(&subkey) {
                            return Some(path);
                        }
                    }
                }
            }
        }
    }
    None
}

fn try_extract_resolve_path(subkey: &windows_registry::Key) -> Option<String> {
    let keys_to_try = ["InstallLocation", "InstallDir", "UninstallString", "DisplayIcon"];
    
    for key_name in &keys_to_try {
        if let Ok(value) = subkey.get_string(key_name) {
            let directory = match *key_name {
                "UninstallString" => {
                    if let Some(start) = value.find('"') {
                        if let Some(end) = value[start + 1..].find('"') {
                            let exe_path = &value[start + 1..start + 1 + end];
                            Path::new(exe_path).parent()?.to_string_lossy().to_string()
                        } else { 
                            continue; 
                        }
                    } else { 
                        continue; 
                    }
                }
                "DisplayIcon" => {
                    Path::new(&value).parent()?.to_string_lossy().to_string()
                }
                _ => value
            };
            
            let resolve_exe = format!("{}\\Resolve.exe", directory);
            if Path::new(&resolve_exe).exists() {
                return Some(resolve_exe);
            }
        }
    }
    None
}

fn locate() -> Result<String, PatchError> {
    if let Ok(key) = CURRENT_USER.open(r#"Software\Classes\ResolveBinFile\shell\open\command"#) {
        if let Ok(command) = key.get_string("") {
            if let Some(space_pos) = command.rfind(' ') {
                let part = &command[..space_pos];
                if let Some(colon_pos) = part.rfind(':') {
                    let path = &part[colon_pos + 1..];
                    if Path::new(path).exists() {
                        return Ok(path.to_string());
                    }
                }
            }
        }
    }
    
    warn!("Registry key removed in newer versions, trying alternatives");
    
    if let Some(path) = check_associations() { 
        return Ok(path); 
    }
    
    if let Some(path) = check_uninstall() { 
        return Ok(path); 
    }
    
    Err(PatchError::ResolveNotFound)
}

fn patch() -> Result<(), PatchError> {
    let path = locate()?;
    info!("Found Resolve at: {}", path);
    
    let data = fs::read(&path).map_err(|_| PatchError::ResolveNotFound)?;
    let mut patched = data.clone();
    let mut applied = false;

    for (sig, replacement) in PATCHES {
        let searcher = coolfindpattern::PatternSearcher::new(&data, sig);
        let found: Vec<usize> = searcher.collect();
        
        match found.len() {
            1 => {
                let addr = found[0];
                let end = addr + replacement.len();
                if end > patched.len() {
                    return Err(PatchError::NoSignatureFound);
                }
                patched[addr..end].copy_from_slice(replacement);
                applied = true;
                info!("Applied patch at offset: 0x{:X}", addr);
            }
            0 => continue,
            _ => return Err(PatchError::SignatureOccurrenceMismatch(found.len())),
        }
    }

    if !applied {
        return Err(PatchError::NoSignatureFound);
    }

    fs::copy(&path, format!("{}.bak", path)).map_err(|_| PatchError::BackupFailed)?;
    fs::write(&path, &patched).map_err(|_| PatchError::WriteFailed)?;

    Ok(())
}

fn main() {
    let _ = SimpleLogger::init(log::LevelFilter::Info, Config::default());
    info!("starting patch process");
    match patch() {
        Ok(_) => info!("patch applied successfully"),
        Err(e) => error!("patch failed: {}", e),
    }
    thread::sleep(Duration::from_secs(3));
}
