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
//! Everything runs locally through `tauri-plugin-llm`'s candle backends (Metal
//! on macOS). The only network access is the one-time model download in
//! [`ModelFiles::fetch`]; [`ModelFiles::cached`] never touches the network.
//!
//! ```no_run
//! # fn main() -> Result<(), jev::JevError> {
//! let files = jev::ModelFiles::fetch(jev::DEFAULT_MODEL)?;
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

use std::path::{Path, PathBuf};

use serde::Serialize;
use tauri_plugin_llm::backend::{create_backend_by_model_file, ModelBackend};
use tauri_plugin_llm::candle_core::{DType, Device, Tensor};
use tauri_plugin_llm::tokenizers::Tokenizer;

/// The model the original Jev uses (as full-precision safetensors; the
/// plugin's candle backends don't load the blog's Q8_0 GGUF).
pub const DEFAULT_MODEL: &str = "Qwen/Qwen3-0.6B";

const CONFIG_FILE: &str = "config.json";
const TOKENIZER_FILE: &str = "tokenizer.json";
const WEIGHTS_FILE: &str = "model.safetensors";

/// Option labels, in order. One letter per choice.
const LABELS: [&str; 26] = [
    "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S",
    "T", "U", "V", "W", "X", "Y", "Z",
];

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
    #[error("label {0:?} is not a single token for this tokenizer")]
    LabelToken(String),
}

pub type Result<T> = std::result::Result<T, JevError>;

/// Local paths to the three files a Qwen3 safetensors model needs.
#[derive(Debug, Clone)]
pub struct ModelFiles {
    /// Hugging Face repo id, e.g. `Qwen/Qwen3-0.6B`. The plugin picks its
    /// backend by model family name, so this must name the family.
    pub model_id: String,
    pub config: PathBuf,
    pub tokenizer: PathBuf,
    pub weights: PathBuf,
}

impl ModelFiles {
    /// Resolve the model from the Hugging Face cache, downloading what's
    /// missing (~1.5 GB for Qwen3-0.6B on first use).
    pub fn fetch(model_id: &str) -> Result<Self> {
        Self::resolve(model_id, false)
    }

    /// Resolve the model from the Hugging Face cache only — never touches the
    /// network. Fails with [`JevError::NotCached`] if anything is missing.
    pub fn cached(model_id: &str) -> Result<Self> {
        Self::resolve(model_id, true)
    }

    /// Use model files from a plain directory (e.g. one shipped next to the app).
    pub fn from_dir(model_id: &str, dir: &Path) -> Self {
        Self {
            model_id: model_id.to_string(),
            config: dir.join(CONFIG_FILE),
            tokenizer: dir.join(TOKENIZER_FILE),
            weights: dir.join(WEIGHTS_FILE),
        }
    }

    fn resolve(model_id: &str, local_only: bool) -> Result<Self> {
        let client = hf_hub::HFClient::builder().build_sync()?;
        let (owner, name) = hf_hub::split_id(model_id);
        let repo = client.model(owner, name);
        let get = |filename: &str| {
            repo.download_file()
                .filename(filename)
                .local_files_only(local_only)
                .send()
                .map_err(|e| match e {
                    hf_hub::HFError::LocalEntryNotFound { .. } => JevError::NotCached(model_id.to_string()),
                    e => JevError::Hub(e),
                })
        };
        Ok(Self {
            model_id: model_id.to_string(),
            config: get(CONFIG_FILE)?,
            tokenizer: get(TOKENIZER_FILE)?,
            weights: get(WEIGHTS_FILE)?,
        })
    }
}

/// One choice's score.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Score {
    pub label: String,
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

    /// Probability of the choice with this exact text, if it was offered.
    pub fn probability(&self, choice: &str) -> Option<f32> {
        self.scores.iter().find(|s| s.choice == choice).map(|s| s.probability)
    }
}

/// A loaded model, ready to classify. Loading is the expensive part — keep
/// one around and call [`Jev::classify`] repeatedly.
pub struct Jev {
    backend: Box<dyn ModelBackend>,
    tokenizer: Tokenizer,
    device: Device,
}

impl Jev {
    /// Load on the best available device (Metal on macOS, else CPU).
    pub fn load(files: &ModelFiles) -> Result<Self> {
        Self::load_on(files, default_device())
    }

    pub fn load_on(files: &ModelFiles, device: Device) -> Result<Self> {
        let backend = create_backend_by_model_file(&files.model_id, &device, &files.weights, &files.config)?;
        let tokenizer = Tokenizer::from_file(&files.tokenizer).map_err(|e| JevError::Tokenizer(e.to_string()))?;
        Ok(Self {
            backend,
            tokenizer,
            device,
        })
    }

    /// Score `choices` for `subject` under the `system` instruction.
    ///
    /// `subject` is the user turn's content before the options — include any
    /// framing (the original uses `"Email: …"`).
    pub fn classify(&mut self, system: &str, subject: &str, choices: &[&str]) -> Result<Classification> {
        if choices.len() < 2 || choices.len() > LABELS.len() {
            return Err(JevError::ChoiceCount(choices.len()));
        }
        let labels = &LABELS[..choices.len()];
        let label_ids = labels
            .iter()
            .map(|l| self.single_token(l))
            .collect::<Result<Vec<_>>>()?;

        let prompt = build_prompt(system, subject, labels, choices);
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
            .zip(choices)
            .zip(choice_logits.iter().zip(&logprobs))
            .map(|((label, choice), (&logit, &logprob))| Score {
                label: (*label).to_string(),
                choice: (*choice).to_string(),
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

/// The Qwen3 chat prompt, with an empty `<think>` block so the very next token
/// is the answer letter.
pub fn build_prompt(system: &str, subject: &str, labels: &[&str], choices: &[&str]) -> String {
    let options = labels
        .iter()
        .zip(choices)
        .map(|(label, choice)| format!("{label}. {choice}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "<|im_start|>system\n{system}<|im_end|>\n<|im_start|>user\n{subject}\n\n{options}<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\n"
    )
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
        );
        assert_eq!(got, expected);
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
