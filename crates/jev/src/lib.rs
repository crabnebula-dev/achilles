//! Jev — on-device constrained classification with a small language model.
//!
//! A Rust port of the NobodyWho "Jev in 25 lines" technique
//! (<https://www.nobodywho.ai/posts/jev-in-25-lines/>): instead of letting the
//! model *generate* an answer, present the choices as lettered options, run a
//! single forward pass over the prompt, and read the logits of just the label
//! tokens (`A`, `B`, `C`, …) at the last position. A log-softmax over those
//! logits gives a probability per choice — deterministic, one pass, and the
//! model can't answer anything but one of the options.
//!
//! Two prompt shapes share that readout:
//! * [`Jev::classify`] — the blog's free-text subject + choices.
//! * [`Jev::decide`] — SemIf/OpenJev's (<https://openjev.com>) typed decision:
//!   JSON evidence, one criterion, and described options (typically including
//!   an "insufficient evidence" escape). Put shared evidence first so many
//!   criteria can be asked about the same state.
//!
//! Everything runs locally through `tauri-plugin-llm`'s candle backends (Metal
//! on macOS), from BF16 safetensors or quantized GGUF. The only network access
//! is the one-time model download in [`ModelFiles::fetch`];
//! [`ModelFiles::cached`] never touches the network.
//!
//! ```no_run
//! # fn main() -> Result<(), jev::JevError> {
//! let files = jev::ModelFiles::fetch(&jev::DEFAULT_MODEL)?;
//! let mut jev = jev::Jev::load(&files)?;
//! let result = jev.classify(
//!     "Choose one option.",
//!     "Email: Payroll asks for your password on a non-company sign-in page.",
//!     &["Legitimate", "Spam", "Phishing"],
//! )?;
//! println!("{}", result.best().choice);
//! # Ok(())
//! # }
//! ```

pub mod watchdog;

use std::path::{Path, PathBuf};

use serde::Serialize;
use tauri_plugin_llm::backend::{
    create_backend_by_gguf_file, create_backend_by_model_file, create_backend_by_model_index_file, ModelBackend,
};
use tauri_plugin_llm::candle_core::{DType, Device, Tensor};
use tauri_plugin_llm::tokenizers::Tokenizer;

/// Where to get a model from Hugging Face.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelSource {
    /// BF16 safetensors (single file or sharded), e.g. `Qwen/Qwen3-0.6B`.
    Safetensors { repo: &'static str },
    /// One quantized GGUF file. GGUF repos rarely ship `tokenizer.json`, so
    /// it comes from the base model's repo.
    Gguf {
        repo: &'static str,
        file: &'static str,
        tokenizer_repo: &'static str,
    },
}

impl ModelSource {
    /// The id the plugin dispatches backends on (it matches family names).
    pub fn id(&self) -> &'static str {
        match self {
            Self::Safetensors { repo } | Self::Gguf { repo, .. } => repo,
        }
    }
}

/// The model the original Jev uses (as BF16 safetensors).
pub const DEFAULT_MODEL: ModelSource = ModelSource::Safetensors { repo: "Qwen/Qwen3-0.6B" };

const CONFIG_FILE: &str = "config.json";
const TOKENIZER_FILE: &str = "tokenizer.json";
const WEIGHTS_FILE: &str = "model.safetensors";
const WEIGHTS_INDEX_FILE: &str = "model.safetensors.index.json";

/// Option labels, in order. One letter per choice.
const LABELS: [&str; 26] = [
    "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S",
    "T", "U", "V", "W", "X", "Y", "Z",
];

/// SemIf's direct-decision instruction, verbatim.
pub const DECIDE_SYSTEM: &str = "Apply the supplied criterion to the supplied evidence. Choose exactly one listed option. Respond with only its uppercase letter, with no explanation or reasoning.";

#[derive(Debug, thiserror::Error)]
pub enum JevError {
    #[error("model download/cache: {0}")]
    Hub(#[from] hf_hub::HFError),
    #[error("model {0} is not in the local cache")]
    NotCached(String),
    #[error("model backend: {0}")]
    Backend(#[from] tauri_plugin_llm::Error),
    #[error("tensor: {0}")]
    Tensor(#[from] tauri_plugin_llm::candle_core::Error),
    #[error("tokenizer: {0}")]
    Tokenizer(String),
    #[error("need between 2 and {max} choices, got {0}", max = LABELS.len())]
    ChoiceCount(usize),
    #[error("weights index: {0}")]
    Index(String),
    #[error("{0} needs a config.json")]
    MissingConfig(String),
    #[error("label {0:?} is not a single token for this tokenizer")]
    LabelToken(String),
}

pub type Result<T> = std::result::Result<T, JevError>;

/// Where a model's weights live on disk.
#[derive(Debug, Clone)]
pub enum Weights {
    /// One `model.safetensors` (small models such as Qwen3-0.6B).
    Single(PathBuf),
    /// `model.safetensors.index.json` plus the shards it names, all in `dir`.
    Sharded { index: PathBuf, dir: PathBuf },
    /// A quantized `.gguf` (carries its own architecture config).
    Gguf(PathBuf),
}

/// Local paths to everything a model needs.
#[derive(Debug, Clone)]
pub struct ModelFiles {
    /// The plugin picks its backend by family name, so this must name it.
    pub model_id: String,
    /// `config.json` — required for safetensors, unused for GGUF.
    pub config: Option<PathBuf>,
    pub tokenizer: PathBuf,
    pub weights: Weights,
}

impl ModelFiles {
    /// Resolve the model from the Hugging Face cache, downloading what's missing.
    pub fn fetch(source: &ModelSource) -> Result<Self> {
        Self::resolve(source, false)
    }

    /// Resolve the model from the Hugging Face cache only — never touches the
    /// network. Fails with [`JevError::NotCached`] if anything is missing.
    pub fn cached(source: &ModelSource) -> Result<Self> {
        Self::resolve(source, true)
    }

    /// Use safetensors model files from a plain directory.
    pub fn from_dir(model_id: &str, dir: &Path) -> Self {
        let index = dir.join(WEIGHTS_INDEX_FILE);
        let weights = if index.exists() {
            Weights::Sharded { index, dir: dir.to_path_buf() }
        } else {
            Weights::Single(dir.join(WEIGHTS_FILE))
        };
        Self {
            model_id: model_id.to_string(),
            config: Some(dir.join(CONFIG_FILE)),
            tokenizer: dir.join(TOKENIZER_FILE),
            weights,
        }
    }

    fn resolve(source: &ModelSource, local_only: bool) -> Result<Self> {
        let client = hf_hub::HFClient::builder().build_sync()?;
        let get = |repo_id: &str, filename: &str| {
            let (owner, name) = hf_hub::split_id(repo_id);
            client
                .model(owner, name)
                .download_file()
                .filename(filename)
                .local_files_only(local_only)
                .send()
                .map_err(|e| match e {
                    hf_hub::HFError::LocalEntryNotFound { .. } => JevError::NotCached(source.id().to_string()),
                    e => JevError::Hub(e),
                })
        };
        match *source {
            ModelSource::Gguf {
                repo,
                file,
                tokenizer_repo,
            } => Ok(Self {
                model_id: repo.to_string(),
                config: None,
                tokenizer: get(tokenizer_repo, TOKENIZER_FILE)?,
                weights: Weights::Gguf(get(repo, file)?),
            }),
            ModelSource::Safetensors { repo } => {
                // Larger models ship sharded: prefer the index when the repo has one.
                let weights = match get(repo, WEIGHTS_INDEX_FILE) {
                    Ok(index) => {
                        for shard in shard_files(&index)? {
                            get(repo, &shard)?;
                        }
                        let dir = index.parent().map(Path::to_path_buf).unwrap_or_default();
                        Weights::Sharded { index, dir }
                    }
                    Err(JevError::Hub(hf_hub::HFError::EntryNotFound { .. })) | Err(JevError::NotCached(_)) => {
                        Weights::Single(get(repo, WEIGHTS_FILE)?)
                    }
                    Err(e) => return Err(e),
                };
                Ok(Self {
                    model_id: repo.to_string(),
                    config: Some(get(repo, CONFIG_FILE)?),
                    tokenizer: get(repo, TOKENIZER_FILE)?,
                    weights,
                })
            }
        }
    }
}

/// Distinct shard file names listed in a safetensors index.
fn shard_files(index: &Path) -> Result<Vec<String>> {
    let text = std::fs::read_to_string(index).map_err(|e| JevError::Index(e.to_string()))?;
    let json: serde_json::Value = serde_json::from_str(&text).map_err(|e| JevError::Index(e.to_string()))?;
    let mut files: Vec<String> = json["weight_map"]
        .as_object()
        .ok_or_else(|| JevError::Index("no weight_map".into()))?
        .values()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    files.sort();
    files.dedup();
    Ok(files)
}

/// One choice's score.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Score {
    pub label: String,
    /// The choice text ([`Jev::classify`]) or option id ([`Jev::decide`]).
    pub choice: String,
    /// Raw logit of the label token.
    pub logit: f32,
    /// Log-probability, normalised over the offered choices only.
    pub logprob: f32,
    pub probability: f32,
}

/// Per-choice probabilities, in the order the choices were given.
#[derive(Debug, Clone, Serialize)]
pub struct Classification {
    pub scores: Vec<Score>,
}

impl Classification {
    /// The most probable choice.
    pub fn best(&self) -> &Score {
        self.scores
            .iter()
            .max_by(|a, b| a.logit.total_cmp(&b.logit))
            .expect("a classification always has at least two choices")
    }

    /// Probability of the choice (or option id) with this exact text.
    pub fn probability(&self, choice: &str) -> Option<f32> {
        self.scores.iter().find(|s| s.choice == choice).map(|s| s.probability)
    }
}

/// A described option for [`Jev::decide`].
#[derive(Debug, Clone, Copy)]
pub struct Opt<'a> {
    pub id: &'a str,
    pub description: &'a str,
}

/// A loaded model, ready to classify. Loading is the expensive part — keep
/// one around while there's work, drop it when idle to free its memory.
pub struct Jev {
    backend: Box<dyn ModelBackend>,
    tokenizer: Tokenizer,
    device: Device,
    /// Hybrid-thinking Qwen3 models need an empty `<think>` block before the
    /// answer; the non-thinking Instruct-2507 releases don't use one.
    empty_think: bool,
}

impl Jev {
    /// Load on the best available device (Metal on macOS, else CPU).
    pub fn load(files: &ModelFiles) -> Result<Self> {
        Self::load_on(files, default_device())
    }

    pub fn load_on(files: &ModelFiles, device: Device) -> Result<Self> {
        let config = || files.config.as_ref().ok_or_else(|| JevError::MissingConfig(files.model_id.clone()));
        let backend = match &files.weights {
            Weights::Single(file) => create_backend_by_model_file(&files.model_id, &device, file, config()?)?,
            Weights::Sharded { index, dir } => {
                create_backend_by_model_index_file(&files.model_id, &device, index, dir, config()?)?
            }
            Weights::Gguf(file) => create_backend_by_gguf_file(&files.model_id, &device, file)?,
        };
        let tokenizer = Tokenizer::from_file(&files.tokenizer).map_err(|e| JevError::Tokenizer(e.to_string()))?;
        Ok(Self {
            backend,
            tokenizer,
            device,
            empty_think: !files.model_id.contains("Instruct-2507"),
        })
    }

    /// Score `choices` for `subject` under the `system` instruction.
    ///
    /// `subject` is the user turn's content before the options — include any
    /// framing (the original uses `"Email: …"`).
    pub fn classify(&mut self, system: &str, subject: &str, choices: &[&str]) -> Result<Classification> {
        let labels = labels_for(choices.len())?;
        let options = labels
            .iter()
            .zip(choices)
            .map(|(label, choice)| format!("{label}. {choice}"))
            .collect::<Vec<_>>()
            .join("\n");
        let prompt = chat_prompt(system, &format!("{subject}\n\n{options}"), self.empty_think);
        self.score(&prompt, labels, choices)
    }

    /// SemIf-style typed decision: does `criterion` hold for `evidence`?
    /// Scores are keyed by option id.
    pub fn decide(&mut self, evidence: &serde_json::Value, criterion: &str, options: &[Opt<'_>]) -> Result<Classification> {
        let labels = labels_for(options.len())?;
        let prompt = chat_prompt(DECIDE_SYSTEM, &decision_payload(evidence, criterion, labels, options), self.empty_think);
        let ids: Vec<&str> = options.iter().map(|o| o.id).collect();
        self.score(&prompt, labels, &ids)
    }

    /// One forward pass over `prompt`; softmax over the label tokens' logits.
    fn score(&mut self, prompt: &str, labels: &[&str], names: &[&str]) -> Result<Classification> {
        let label_ids = labels
            .iter()
            .map(|l| self.single_token(l))
            .collect::<Result<Vec<_>>>()?;
        // Special tokens (`<|im_start|>` …) are matched from the text itself;
        // Qwen has no BOS, so don't let the tokenizer add one.
        let ids = self
            .tokenizer
            .encode(prompt, false)
            .map_err(|e| JevError::Tokenizer(e.to_string()))?
            .get_ids()
            .to_vec();

        // Each call is an independent single pass from position 0.
        self.backend.clear_kv_cache();
        let input = Tensor::new(ids.as_slice(), &self.device)?.unsqueeze(0)?;
        let logits = self.backend.forward(&input, 0)?;
        self.backend.clear_kv_cache();
        // Backends return `[vocab]` or `[1, vocab]` depending on the model
        // (candle's Qwen3 already narrows to the last position); batch is 1.
        let logits: Vec<f32> = logits.flatten_all()?.to_dtype(DType::F32)?.to_vec1()?;

        let choice_logits: Vec<f32> = label_ids.iter().map(|&id| logits[id as usize]).collect();
        let logprobs = log_softmax(&choice_logits);
        let scores = labels
            .iter()
            .zip(names)
            .zip(choice_logits.iter().zip(&logprobs))
            .map(|((label, name), (&logit, &logprob))| Score {
                label: (*label).to_string(),
                choice: (*name).to_string(),
                logit,
                logprob,
                probability: logprob.exp(),
            })
            .collect();
        Ok(Classification { scores })
    }

    fn single_token(&self, text: &str) -> Result<u32> {
        let enc = self
            .tokenizer
            .encode(text, false)
            .map_err(|e| JevError::Tokenizer(e.to_string()))?;
        match enc.get_ids() {
            [id] => Ok(*id),
            _ => Err(JevError::LabelToken(text.to_string())),
        }
    }
}

fn labels_for(n: usize) -> Result<&'static [&'static str]> {
    if n < 2 || n > LABELS.len() {
        return Err(JevError::ChoiceCount(n));
    }
    Ok(&LABELS[..n])
}

/// The blog's prompt for [`Jev::classify`] (kept as a free function so the
/// byte-for-byte test can pin it).
pub fn build_prompt(system: &str, subject: &str, labels: &[&str], choices: &[&str], empty_think: bool) -> String {
    let options = labels
        .iter()
        .zip(choices)
        .map(|(label, choice)| format!("{label}. {choice}"))
        .collect::<Vec<_>>()
        .join("\n");
    chat_prompt(system, &format!("{subject}\n\n{options}"), empty_think)
}

/// SemIf's user turn: `{"evidence", "criterion", "options": [{letter, description}]}`.
/// Evidence comes first, so decisions over the same state share a prefix.
pub fn decision_payload(evidence: &serde_json::Value, criterion: &str, labels: &[&str], options: &[Opt<'_>]) -> String {
    // Built by hand to pin SemIf's key order (serde_json maps sort keys).
    let quote = |s: &str| serde_json::Value::String(s.to_string()).to_string();
    let options = labels
        .iter()
        .zip(options)
        .map(|(letter, o)| format!("{{\"letter\": {}, \"description\": {}}}", quote(letter), quote(o.description)))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{{\"evidence\": {evidence}, \"criterion\": {}, \"options\": [{options}]}}",
        quote(criterion)
    )
}

/// The Qwen3 chat prompt. With `empty_think`, an empty `<think>` block skips
/// the reasoning phase so the very next token is the answer letter.
fn chat_prompt(system: &str, user: &str, empty_think: bool) -> String {
    let think = if empty_think { "<think>\n\n</think>\n\n" } else { "" };
    format!("<|im_start|>system\n{system}<|im_end|>\n<|im_start|>user\n{user}<|im_end|>\n<|im_start|>assistant\n{think}")
}

/// Numerically stable log-softmax.
fn log_softmax(xs: &[f32]) -> Vec<f32> {
    let max = xs.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let log_sum = max + xs.iter().map(|x| (x - max).exp()).sum::<f32>().ln();
    xs.iter().map(|x| x - log_sum).collect()
}

fn default_device() -> Device {
    #[cfg(target_os = "macos")]
    if let Ok(device) = Device::new_metal(0) {
        return device;
    }
    Device::Cpu
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_matches_the_original() {
        // Byte-for-byte the Python f-string from the blog post.
        let expected = "<|im_start|>system\nChoose one option.<|im_end|>\n<|im_start|>user\nEmail: Payroll asks for your password on a non-company sign-in page.\n\nA. Legitimate\nB. Spam\nC. Phishing<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\n";
        let got = build_prompt(
            "Choose one option.",
            "Email: Payroll asks for your password on a non-company sign-in page.",
            &["A", "B", "C"],
            &["Legitimate", "Spam", "Phishing"],
            true,
        );
        assert_eq!(got, expected);
    }

    #[test]
    fn decision_payload_keeps_semif_key_order() {
        let got = decision_payload(
            &serde_json::json!("The deployment completed."),
            "Did it succeed?",
            &["A", "B"],
            &[
                Opt { id: "yes", description: "It succeeded." },
                Opt { id: "no", description: "It did not." },
            ],
        );
        assert_eq!(
            got,
            r#"{"evidence": "The deployment completed.", "criterion": "Did it succeed?", "options": [{"letter": "A", "description": "It succeeded."}, {"letter": "B", "description": "It did not."}]}"#
        );
    }

    #[test]
    fn log_softmax_matches_reference() {
        // The blog's logits → its published log-probabilities.
        let lp = log_softmax(&[26.254, 27.262, 29.614]);
        for (got, want) in lp.iter().zip([-3.482, -2.474, -0.122]) {
            assert!((got - want).abs() < 1e-3, "{got} vs {want}");
        }
        let total: f32 = lp.iter().map(|x| x.exp()).sum();
        assert!((total - 1.0).abs() < 1e-5);
    }

    #[test]
    fn log_softmax_is_stable_for_large_logits() {
        let lp = log_softmax(&[1000.0, 1000.0]);
        // f32 resolution near 1000 is ~6e-5.
        assert!(lp.iter().all(|x| (x - (-std::f32::consts::LN_2)).abs() < 1e-4));
    }
}
