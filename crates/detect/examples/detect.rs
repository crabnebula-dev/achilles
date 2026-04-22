//! `cargo run --example detect -- <path-to-.app-or-Contents-root>`
//!
//! Thin CLI wrapper for trying the detector against real bundles.

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(path) = std::env::args_os().nth(1).map(PathBuf::from) else {
        eprintln!("usage: detect <path-to-bundle>");
        return ExitCode::from(2);
    };

    match detect::detect(&path) {
        Ok(result) => match serde_json::to_string_pretty(&result) {
            Ok(json) => {
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("serialize error: {err}");
                ExitCode::FAILURE
            }
        },
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
