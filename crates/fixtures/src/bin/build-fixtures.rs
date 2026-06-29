//! `cargo run -p fixtures --bin build-fixtures -- <out-dir>`
//!
//! Builds the synthetic, deliberately-vulnerable Electron fixture — a packed
//! `electron-sample.asar` and an `ElectronSample.app` bundle — into `<out-dir>`,
//! so a later CI job can run the analyzers against it as a fixed target.

use std::path::Path;
use std::process::ExitCode;

fn build(out: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(out)?;
    let asar = fixtures::write_asar(out)?;
    let app = fixtures::build_app(out)?;
    eprintln!("built {}", asar.display());
    eprintln!("built {}", app.display());
    Ok(())
}

fn main() -> ExitCode {
    let Some(out) = std::env::args_os().nth(1) else {
        eprintln!("usage: build-fixtures <out-dir>");
        return ExitCode::from(2);
    };
    match build(Path::new(&out)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("build failed: {e}");
            ExitCode::FAILURE
        }
    }
}
