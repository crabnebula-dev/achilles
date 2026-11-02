//! Reproduce the "Jev in 25 lines" example, or classify your own text.
//!
//! ```sh
//! cargo run --release -p jev --example classify
//! cargo run --release -p jev --example classify -- "Email: Your invoice is attached." Legitimate Spam Phishing
//! ```

use std::time::Instant;

fn main() -> Result<(), jev::JevError> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (subject, choices): (String, Vec<String>) = match args.split_first() {
        Some((subject, choices)) if choices.len() >= 2 => (subject.clone(), choices.to_vec()),
        _ => (
            "Email: Payroll asks for your password on a non-company sign-in page.".into(),
            vec!["Legitimate".into(), "Spam".into(), "Phishing".into()],
        ),
    };
    let choices: Vec<&str> = choices.iter().map(String::as_str).collect();

    let t = Instant::now();
    let model = std::env::var("JEV_MODEL").unwrap_or_else(|_| jev::DEFAULT_MODEL.to_string());
    let files = jev::ModelFiles::fetch(&model)?;
    let mut jev = jev::Jev::load(&files)?;
    eprintln!("loaded {} in {:.2?}", files.model_id, t.elapsed());

    let t = Instant::now();
    let result = jev.classify("Choose one option.", &subject, &choices)?;
    eprintln!("classified in {:.2?}", t.elapsed());

    for (name, pick) in [
        ("Logits", (|s: &jev::Score| s.logit) as fn(&jev::Score) -> f32),
        ("Log probabilities", |s| s.logprob),
        ("Probabilities", |s| s.probability),
    ] {
        let row: Vec<String> = result
            .scores
            .iter()
            .map(|s| format!("'{}': {:.3}", s.choice, pick(s)))
            .collect();
        println!("{name}: {{{}}}", row.join(", "));
    }
    println!("→ {}", result.best().choice);
    Ok(())
}
