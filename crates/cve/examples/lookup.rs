//! `cargo run -p cve --example lookup -- electron 40.4.1`

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let name = args.next().expect("first arg = package name (e.g. electron)");
    let version = args.next().expect("second arg = version (e.g. 40.4.1)");
    let ecosystem = args.next().unwrap_or_else(|| "npm".into());

    let client = cve::OsvClient::new();
    match client.query(&ecosystem, &name, &version).await {
        Ok(advisories) => {
            println!("{} advisor{}:", advisories.len(), if advisories.len() == 1 { "y" } else { "ies" });
            for a in advisories {
                println!(
                    "  {} [{}] fixed_in={:?} — {}",
                    a.id,
                    a.severity
                        .map(|s| format!("{:?}", s).to_lowercase())
                        .unwrap_or_else(|| "-".into()),
                    a.fixed_in,
                    a.summary.lines().next().unwrap_or("")
                );
            }
        }
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(1);
        }
    }
}
