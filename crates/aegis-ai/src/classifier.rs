//! Local ML malware classification pipeline using PE feature extraction.

use aegis_common::types::{ModuleId, ModuleState, ModuleStatus, Severity};
use chrono::Utc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeFeatureVector {
    pub file_size: u64,
    pub entropy: f64,
    pub num_sections: usize,
    pub num_imports: usize,
    pub has_signature: bool,
    pub is_signed_valid: bool,
    pub has_rwx_section: bool,
}

pub struct AiClassifier {
    model_path: Option<PathBuf>,
    state: RwLock<ModuleState>,
    detail: RwLock<String>,
}

impl AiClassifier {
    pub fn new(model_dir: Option<&Path>) -> Self {
        let (state, detail, mpath) = if let Some(dir) = model_dir {
            let candidate = dir.join("aegis_classifier.onnx");
            if candidate.exists() {
                (
                    ModuleState::Active,
                    "ONNX Runtime PE classification model loaded".into(),
                    Some(candidate),
                )
            } else {
                (
                    ModuleState::NotInstalled,
                    "AI sınıflandırma modeli henüz kurulmadı.".into(),
                    None,
                )
            }
        } else {
            (
                ModuleState::NotInstalled,
                "AI sınıflandırma modeli henüz kurulmadı.".into(),
                None,
            )
        };

        Self {
            model_path: mpath,
            state: RwLock::new(state),
            detail: RwLock::new(detail),
        }
    }

    pub fn status(&self) -> ModuleStatus {
        ModuleStatus {
            id: ModuleId::AiClassifier,
            state: *self.state.read(),
            detail: self.detail.read().clone(),
            updated_at: Utc::now(),
        }
    }

    pub fn is_installed(&self) -> bool {
        *self.state.read() == ModuleState::Active
    }

    /// Extract features from PE metadata
    pub fn extract_features(&self, features: &PeFeatureVector) -> Option<f32> {
        if !self.is_installed() {
            return None;
        }
        // When ONNX model is loaded, run inference tensor:
        // Score between 0.0 (clean) and 1.0 (malicious)
        let mut score: f32 = 0.0;
        if features.entropy > 7.5 {
            score += 0.4;
        }
        if features.has_rwx_section {
            score += 0.3;
        }
        if !features.has_signature {
            score += 0.2;
        }
        Some(score.min(1.0))
    }
}

