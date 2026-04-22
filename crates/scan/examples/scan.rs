//! `cargo run -p scan --example scan` — discover apps and stream detections.

use std::time::Instant;

use tokio::sync::mpsc;

#[tokio::main]
async fn main() {
    let start = Instant::now();
    let paths = match scan::discover_applications().await {
        Ok(p) => p,
        Err(err) => {
            eprintln!("discovery failed: {err}");
            std::process::exit(1);
        }
    };

    eprintln!(
        "discovered {} bundles in {:?}",
        paths.len(),
        start.elapsed()
    );

    let (tx, mut rx) = mpsc::channel(64);
    tokio::spawn(scan::scan(paths, 8, tx));

    while let Some(event) = rx.recv().await {
        match event {
            scan::ScanEvent::Started { total } => eprintln!("started: {total} bundles"),
            scan::ScanEvent::Detected(d) => {
                let v = &d.versions;
                println!(
                    "{:<8}  {:<6}  e={:<10}  cr={:<18}  n={:<10}  t={:<10}  {}",
                    format!("{:?}", d.framework).to_lowercase(),
                    format!("{:?}", d.confidence).to_lowercase(),
                    v.electron.as_deref().unwrap_or("-"),
                    v.chromium.as_deref().unwrap_or("-"),
                    v.node.as_deref().unwrap_or("-"),
                    v.tauri.as_deref().unwrap_or("-"),
                    d.display_name.as_deref().unwrap_or_else(
                        || d.bundle_id.as_deref().unwrap_or("?")
                    ),
                );
            }
            scan::ScanEvent::Error { path, message } => {
                eprintln!("error on {}: {message}", path.display());
            }
            scan::ScanEvent::Finished { count } => {
                eprintln!("finished: {count} bundles in {:?}", start.elapsed());
            }
        }
    }
}
