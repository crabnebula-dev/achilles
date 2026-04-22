//! `cargo run -p static-scan --example static-scan -- <path>` where `<path>`
//! is an `app.asar` or a directory of renderer source.

use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(path) = std::env::args_os().nth(1).map(std::path::PathBuf::from) else {
        eprintln!("usage: static-scan <path-to-.asar-or-dir>");
        return ExitCode::from(2);
    };
    match static_scan::scan(&path) {
        Ok(report) => match serde_json::to_string_pretty(&report) {
            Ok(json) => {
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("serialize: {err}");
                ExitCode::FAILURE
            }
        },
        Err(err) => {
            eprintln!("scan failed: {err}");
            ExitCode::FAILURE
        }
    }
}
