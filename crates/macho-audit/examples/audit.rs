//! `cargo run -p macho-audit --example audit -- <path-to-.app>`

#[tokio::main]
async fn main() {
    let path = std::env::args_os()
        .nth(1)
        .map(std::path::PathBuf::from)
        .expect("usage: audit <path-to-.app>");
    let audit = macho_audit::audit(&path).await.expect("audit failed");
    let json = serde_json::to_string_pretty(&audit).expect("serialize");
    println!("{json}");
}
