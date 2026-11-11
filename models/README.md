# AEGIS AI - Machine Learning Models & Specifications

This directory houses the offline neural network weights and machine learning models for AEGIS AI Security.

---

## 🧠 Model Architecture & Role

AEGIS incorporates a lightweight, privacy-preserving, local-first PE structural classifier designed to identify zero-day malware patterns without sending binary data or hashes to cloud services.

- **Model Format**: Open Neural Network Exchange (ONNX) - `aegis_pe_classifier.onnx`
- **Runtime**: Local ONNX Runtime (`ort` crate)
- **Execution Target**: CPU (zero GPU dependency, optimized for SSE4.2 / AVX2 on modern x86_64 CPUs)
- **Input Feature Vector**: 256-dimensional numerical vector extracted directly from the Portable Executable (PE) headers by `aegis-ai::PeFeatureExtractor`:
  - Overall binary Shannon entropy and per-section entropy distribution.
  - Section characteristics count (specifically checking for executable & writable `RWX` sections).
  - Import address table (IAT) hash and frequency of dangerous Win32 API imports (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `AdjustTokenPrivileges`).
  - Size of optional header, entry point section position, and code-to-data size ratios.
  - Authenticode digital signature presence and certificate validity flags.
  - Anomaly indicators (e.g. invalid subsystem, suspicious timestamp disparity).

---

## 🛡️ Honest Fallback Policy

AEGIS is strictly engineered never to deceive the user:
- If `aegis_pe_classifier.onnx` is absent from this directory or corrupted, the system **never invents synthetic probabilities or fake risk scores**.
- The classifier cleanly returns `SignatureStatus::Unsigned` and logs the accurate status:
  - **TR**: `"AI sınıflandırma modeli henüz kurulmadı."`
  - **EN**: `"AI classification model is not installed."`
- In this state, defensive protection continues without interruption via the YARA-X signature engine, PE structural heuristics, and behavioral shields.

---

## 🛠️ Model Training & Export Workflow

For defensive security researchers training updated detection weights:

1. **Dataset**: Clean Windows system binaries vs. verified malware samples in isolated sandboxes.
2. **Feature Extraction**: Run `aegis-ai --extract-features <path>` to output `.csv` or `.parquet` feature tables.
3. **Training**: Train a gradient boosted decision tree (LightGBM) or dense neural network in Python.
4. **ONNX Export**:
   ```python
   import onnxmltools
   from onnxmltools.convert.common.data_types import FloatTensorType

   initial_type = [('float_input', FloatTensorType([None, 256]))]
   onnx_model = onnxmltools.convert_lightgbm(model, initial_types=initial_type)
   with open("aegis_pe_classifier.onnx", "wb") as f:
       f.write(onnx_model.SerializeToString())
   ```
5. Place the generated `aegis_pe_classifier.onnx` into `models/`.

