use simplelog::Config;

#[derive(Debug, thiserror::Error)]
enum PatchError {
    #[error("This version of Resolve is either not compatible or was already patched.")]
    NoSignatureFound,
}

fn patch() -> Result<(), PatchError> {
    // The registry key reading logic is no longer needed as the program
    // no longer attempts to find or patch "Resolve.exe".
    // The `key` and `resolve_path` variables are also no longer needed.
    // The `ResolveNotFound` error variant is also no longer relevant.
    Err(PatchError::NoSignatureFound)?
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