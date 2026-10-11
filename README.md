# AI/ML Model Security Reconnaissance Toolkit

`aiml_model_security_reconnaissance.py` is a pentester-oriented reconnaissance utility for analyzing AI/ML model artifacts before deeper security testing.

It is designed for:

- security testers
- ML security engineers
- red teams
- product-security teams
- researchers
- AI assurance teams

The goal is to quickly answer questions such as:

- What exactly is this model artifact?
- What framework or format does it use?
- What inputs and outputs does it expose?
- What metadata, classes, dimensions, operators, and runtime assumptions can be identified?
- Does the artifact use potentially unsafe serialization?
- Are there external dependencies or companion files?
- Is the model quantized?
- Does it contain custom operators?
- What attack surfaces should be tested next?
- Does the deployed model differ from the approved model?
- Which model-family-specific tests should a pentester consider?

> The tool does **not** prove that a model is secure, safe, accurate, backdoor-free, or compliant with a standard. It performs reconnaissance and provides security-relevant information for the next stages of testing.

---

# Key Features

The toolkit provides:

- model artifact identification
- SHA-256 integrity fingerprinting
- model format detection
- model-family-aware reconnaissance
- ONNX graph inspection
- input/output tensor enumeration
- static vs dynamic dimension identification
- model metadata extraction
- operator inventory
- custom operator/domain detection
- parameter and tensor inventory
- weight statistics
- NaN / Infinity checks
- quantization hints
- external weight/dependency discovery
- PyTorch safe-loading checks
- Pickle / Joblib static safety analysis
- Safetensors inspection
- GGUF metadata inspection
- TensorFlow Lite interface inspection
- Keras / HDF5 inventory
- TensorFlow SavedModel inventory
- XGBoost JSON metadata inspection
- LightGBM text-model inspection
- Stable-Baselines ZIP inventory
- companion configuration discovery
- model-family-specific attack-surface guidance
- ONNX structural fingerprinting
- ONNX runtime profiling
- model-to-model comparison
- real-image ONNX computer-vision inference
- raw model-output inspection
- detector-output interpretation
- concise pentester-friendly console output
- detailed JSON evidence generation

---

# Supported Model Families and Formats

The toolkit supports reconnaissance across multiple AI/ML model families.

| Model Family | Typical Use Cases | Common Formats | Current Recon Depth |
|---|---|---|---|
| **Computer Vision** | Classification, object detection, segmentation, pose estimation, depth estimation, OCR, visual inspection | `.onnx`, `.pt`, `.pth`, `.safetensors`, `.tflite`, `.keras`, `.h5`, `.hdf5` | **Very Strong for ONNX** — graph, I/O, weights, metadata, runtime profiling, real-image inference and detector-output analysis |
| **Language / LLM** | LLMs, text generation, embeddings, text classification, transformer encoders | `.safetensors`, `.gguf`, `.pt`, `.pth`, `.onnx`, `.bin`, SavedModel | **Good** — architecture, metadata, tokenizer/config discovery, quantization and artifact trust-boundary analysis |
| **Audio / Speech** | ASR, speaker recognition, sound classification, TTS | `.onnx`, `.pt`, `.pth`, `.safetensors`, `.tflite`, `.keras`, `.h5`, `.hdf5` | **Good** — artifact/interface reconnaissance with audio-specific testing guidance |
| **Multimodal** | Vision-language, image-text, audio-text, video-language, sensor-language models | `.safetensors`, `.gguf`, `.pt`, `.pth`, `.onnx`, `.keras` | **Good** — artifact/config reconnaissance and cross-modal trust-boundary guidance |
| **Time-Series / Sequential** | Forecasting, anomaly detection, predictive maintenance, sensor analytics | `.onnx`, `.pt`, `.pth`, `.keras`, `.h5`, `.hdf5`, `.tflite`, `.pkl`, `.joblib` | **Good** — model/interface reconnaissance and sequence/data-pipeline attack guidance |
| **Tabular / Classical ML** | Random forest, SVM, regression, XGBoost, LightGBM, scikit-learn pipelines | `.onnx`, `.pkl`, `.pickle`, `.joblib`, `.json`, `.ubj`, `.txt`, `.model` | **Good** — static inspection, model metadata and unsafe-deserialization analysis |
| **Generative Models** | Diffusion, GAN, VAE, image/audio generation | `.safetensors`, `.pt`, `.pth`, `.onnx`, `.keras`, `.h5`, `.hdf5` | **Good** — artifact/tensor reconnaissance with scheduler, adapter and conditioning guidance |
| **Reinforcement Learning** | Policies, actor-critic, Q-networks, robotics-control policies | `.pt`, `.pth`, `.onnx`, `.zip`, `.pkl`, `.joblib` | **Moderate** — policy artifact inspection and observation/action/reward attack-surface guidance |
| **Graph Neural Networks** | Graph classification, molecular models, graph embeddings, network analysis | `.pt`, `.pth`, `.onnx`, `.safetensors` | **Moderate** — artifact/interface reconnaissance and graph-specific testing guidance |
| **Recommendation / Ranking** | Personalization, matching, recommendation engines, ranking | `.onnx`, `.pt`, `.pth`, `.keras`, `.h5`, `.hdf5`, `.pkl`, `.joblib` | **Moderate** — artifact reconnaissance and ranking/embedding attack-surface guidance |

> Format support does not imply complete semantic reconstruction of every framework, model type, or framework version. Some formats are intentionally inspected statically or conservatively for security reasons.

---

# Supported Artifact Formats

| Framework / Artifact | Extensions / Type | Reconnaissance |
|---|---|---|
| **ONNX** | `.onnx` | Graph, metadata, I/O, operators, weights, validation, quantization, runtime profiling and comparison |
| **PyTorch** | `.pt`, `.pth` | Safe checkpoint/tensor inspection using `weights_only=True` where supported |
| **Safetensors** | `.safetensors` | Tensor names, shapes, datatypes, metadata and statistics |
| **GGUF** | `.gguf` | LLM architecture, tokenizer, context, quantization and metadata inspection |
| **TensorFlow Lite** | `.tflite` | Input/output interface and quantization information |
| **Keras** | `.keras` | Archive/config and model metadata inspection |
| **Keras / HDF5** | `.h5`, `.hdf5` | Groups, datasets, attributes and tensor inventory |
| **Pickle** | `.pkl`, `.pickle` | Static opcode/security inspection without unsafe deserialization |
| **Joblib** | `.joblib` | Conservative serialization-risk and artifact inspection |
| **XGBoost** | `.json`, `.ubj` | Learner, objective, booster and model-parameter reconnaissance |
| **LightGBM** | `.txt`, `.model` | Header, features, objective and tree-model reconnaissance |
| **Stable-Baselines / ZIP** | `.zip` | Archive inventory and suspicious-path inspection |
| **TensorFlow SavedModel** | Directory | Static directory, assets and variable inventory |

---

# Prerequisites

## Python

Recommended:

```text
Python 3.10+
```

The toolkit uses the Python standard library for its core workflow, while format-specific analysis requires additional packages.

---

# Installation

Clone the repository:

```bash
git clone https://github.com/NaveenNguyen/AI-ML-Models-Reconnaissance.git
cd AI-ML-Models-Reconnaissance
```

Install the default dependencies:

```bash
pip install -r requirements.txt
```

The default requirements include:

```text
numpy>=1.26
onnx>=1.16
onnxruntime>=1.18
torch>=2.4
safetensors>=0.4.5
h5py>=3.11
pillow>=10.0
```

Then verify the tool:

```bash
python aiml_model_security_recon.py --help
```

List supported model families and formats:

```bash
python aiml_model_security_recon.py --list-model-types
```

---

# Optional TensorFlow / TFLite Support

TensorFlow is intentionally not installed by default because it is a heavier dependency.

Install full TensorFlow:

```bash
pip install tensorflow
```

Or, where supported:

```bash
pip install tflite-runtime
```

You do not need every optional dependency if you only work with specific model formats.

---

# Quick Usage

Basic syntax:

```bash
python aiml_model_security_recon.py <model> --model-type <model-family>
```

Examples:

| Scenario | Command |
|---|---|
| **ONNX Computer Vision** | `python aiml_model_security_recon.py model.onnx --model-type computer-vision` |
| **Deep ONNX reconnaissance** | `python aiml_model_security_recon.py model.onnx --model-type computer-vision --deep` |
| **CV model with real image** | `python aiml_model_security_recon.py best.onnx --model-type computer-vision --input-image stop.jpg` |
| **Save raw inference output** | `python aiml_model_security_recon.py best.onnx --model-type computer-vision --input-image stop.jpg --dump-raw-output raw_outputs.npz` |
| **LLM / GGUF** | `python aiml_model_security_recon.py model.gguf --model-type language-llm` |
| **LLM / Safetensors** | `python aiml_model_security_recon.py model.safetensors --model-type language-llm` |
| **Audio / Speech** | `python aiml_model_security_recon.py speech.onnx --model-type audio-speech` |
| **Multimodal** | `python aiml_model_security_recon.py model.safetensors --model-type multimodal` |
| **Time-Series** | `python aiml_model_security_recon.py anomaly_detector.onnx --model-type time-series` |
| **Pickle / Classical ML** | `python aiml_model_security_recon.py model.pkl --model-type tabular-classical` |
| **XGBoost** | `python aiml_model_security_recon.py model.json --model-type tabular-classical` |
| **LightGBM** | `python aiml_model_security_recon.py model.txt --model-type tabular-classical` |
| **Generative Model** | `python aiml_model_security_recon.py model.safetensors --model-type generative` |
| **Reinforcement Learning** | `python aiml_model_security_recon.py policy.zip --model-type reinforcement-learning` |
| **Graph Neural Network** | `python aiml_model_security_recon.py model.pt --model-type graph` |
| **Recommendation / Ranking** | `python aiml_model_security_recon.py ranking.onnx --model-type recommendation-ranking` |
| **Compare approved vs deployed model** | `python aiml_model_security_recon.py approved.onnx --model-type computer-vision --deep --compare deployed.onnx` |
| **Full raw console details** | `python aiml_model_security_recon.py model.onnx --model-type computer-vision --verbose` |

---

# Interactive Model-Family Selection

If `--model-type` is omitted in an interactive terminal:

```bash
python aiml_model_security_recon.py model.onnx
```

the tool prompts for a model family.

Example:

```text
Select model family:

1. Computer Vision
2. Language / LLM
3. Audio / Speech
4. Multimodal
5. Time-Series / Sequential
6. Tabular / Classical ML
7. Generative
8. Reinforcement Learning
9. Graph Neural Network
10. Recommendation / Ranking
11. Automatic / Generic

Selection:
```

---

# Console Output

The default terminal output is designed to highlight the most relevant information instead of dumping large Python dictionaries.

Example:

```text
================================================================================================
AI/ML MODEL SECURITY RECON — KEY FINDINGS
================================================================================================

[KEY] Artifact : best.onnx
[KEY] SHA-256  : c77fdf7e...
[KEY] Family   : computer-vision
[KEY] Format   : onnx
[PASS] Recon   : COMPLETE

Important model facts:
  [INFO] Model       : pytorch | ONNX opset 18
  [INFO] Task        : detect
  [INFO] Input       : images FLOAT [1, 3, 640, 640]
  [INFO] Output      : output0 FLOAT [1, 19, 8400]
  [INFO] Classes     : 15 classes
  [INFO] Graph       : 368 nodes | 223 initializers | 2,419,796 parameters
  [INFO] Postprocess : NMS external / not detected
  [INFO] Custom ops  : None
```

Security-relevant observations are highlighted separately:

```text
[PASS] ONNX structural checker passed.
[PASS] No custom ONNX operator domains detected.
[INFO] NMS appears external; decoder/NMS becomes a trust boundary.
[PASS] No NaN/Inf found in sampled weights.
[PASS] No external ONNX initializer files referenced.
[INFO] Input dimensions are static.
```

Large raw graph, metadata, weight and tensor structures are preserved in the JSON report.

Use:

```bash
python aiml_model_security_recon.py model.onnx \
  --model-type computer-vision \
  --verbose
```

to print the detailed structures in the console.

Disable ANSI highlighting with:

```bash
python aiml_model_security_recon.py model.onnx \
  --model-type computer-vision \
  --no-color
```

---

# Artifact Identity and Integrity

The toolkit records:

- filename
- path
- size
- extension
- SHA-256
- detected format
- selected model family

This can be used to:

- identify the exact model tested
- compare approved and deployed models
- detect unauthorized replacement
- support release traceability
- retain assessment evidence

---

# Recon Completeness

The report indicates whether reconnaissance was complete or partial.

Example:

```text
status: COMPLETE

completed:
  - Artifact identity
  - SHA-256
  - Format detection
  - Input/output interface
  - Graph/operator inventory
  - Weight/parameter inventory
  - ONNX structural validation

missing: <none>
warnings: <none>
```

If part of the analysis fails:

```text
status: PARTIAL
```

This helps prevent a partial inspection from being mistaken for a complete assessment.

---

# Robust Metadata Parsing

ONNX metadata may contain unusual values such as:

```text
08
09
2026-01-08
00123
```

The toolkit uses best-effort metadata parsing.

If a value cannot be safely interpreted as a Python literal, it is retained as its original string instead of causing the entire model analysis to fail.

The remaining reconnaissance continues normally.

---

# ONNX Model Reconnaissance

For ONNX models, the toolkit can inspect:

- IR version
- producer name
- producer version
- model version
- ONNX opset
- embedded metadata
- model inputs
- model outputs
- graph node count
- initializers
- operator histogram
- operator domains
- custom operator domains
- quantization operators
- external weights
- embedded Resize
- embedded NMS
- parameter estimates
- tensor types
- weight statistics
- ONNX checker result

---

# Input / Output Interface

Example:

```text
INPUT
name: images
dtype: FLOAT
shape: [1, 3, 640, 640]
dynamic: False

OUTPUT
name: output0
dtype: FLOAT
shape: [1, 19, 8400]
dynamic: False
```

The model interface defines an important security boundary.

Useful test cases include:

```text
wrong shape
wrong dtype
unexpected batch size
very large dimensions
very small dimensions
NaN
Infinity
zero input
random input
boundary values
```

---

# Static vs Dynamic Dimensions

Static example:

```text
[1, 3, 640, 640]
```

Dynamic example:

```text
[N, 3, H, W]
```

Dynamic dimensions can increase:

- resource-exhaustion exposure
- input-validation complexity
- runtime edge cases
- parser edge cases

They should be included in fuzzing and resilience testing.

---

# Graph and Operator Inventory

The toolkit enumerates ONNX operators.

Example:

```text
Conv: 102
Mul: 90
Sigmoid: 88
Concat: 23
Add: 22
Resize: 2
```

It also identifies:

- custom domains
- embedded Resize
- embedded NMS
- quantization operators

Custom operators are particularly important because they may rely on native runtime libraries or plugins.

---

# Parameter and Weight Information

Where supported, the toolkit reports:

- parameter count
- tensor count
- tensor dimensions
- tensor datatypes
- large tensors
- approximate weight size

This can help with:

- model fingerprinting
- integrity comparison
- version comparison
- quantization analysis
- corruption analysis

---

# Weight Statistics

The toolkit can calculate sampled tensor statistics such as:

```text
minimum
maximum
mean
standard deviation
zero fraction
NaN count
Infinity count
```

Unexpected numeric values may indicate:

- damaged artifacts
- conversion problems
- corrupted weights
- numerical instability

Normal statistics do **not** prove that a model is free from backdoors or poisoning.

---

# Quantization Detection

For ONNX models, the toolkit looks for operators such as:

```text
QuantizeLinear
DequantizeLinear
```

This helps identify likely:

```text
FP32
FP16
INT8
mixed precision
```

Quantized production models should be compared with reference models, especially around:

- low-confidence predictions
- small objects
- edge cases
- class-confusion boundaries
- adversarial examples

---

# Preprocessing Reconnaissance

For computer-vision models, preprocessing may exist outside the model artifact.

Important assumptions include:

```text
RGB vs BGR
NCHW vs NHWC
normalization
letterbox vs stretch
crop
orientation
interpolation method
```

If preprocessing is external, it becomes part of the assessment boundary.

---

# Postprocessing Reconnaissance

For object detectors, if NMS is not embedded in the graph, the real execution chain may look like:

```text
Model
  ↓
Decoder
  ↓
Confidence filtering
  ↓
NMS
  ↓
Class mapping
```

This means external postprocessing becomes part of the attack surface.

Useful tests include:

```text
threshold manipulation
IoU manipulation
candidate explosion
class-mapping mismatch
malformed output handling
```

---

# Real-Image Forward-Pass Reconnaissance

For ONNX computer-vision models, a tester can provide a real image:

```bash
python aiml_model_security_recon.py best.onnx \
  --model-type computer-vision \
  --input-image stop.jpg
```

The toolkit:

1. identifies the input shape and likely layout
2. loads the image
3. applies selected preprocessing assumptions
4. runs ONNX Runtime inference
5. records latency
6. records raw output shape and statistics
7. performs best-effort object-detector interpretation
8. shows top raw class candidates
9. optionally saves raw output tensors

Example:

```text
================================================================================================
REAL-IMAGE FORWARD PASS
================================================================================================

[PASS] Inference completed in 24.8 ms
[INFO] Image      : stop.jpg
[INFO] Preprocess : NCHW | RGB | scale=0-1 | letterbox

[WARN] Confirm preprocessing assumptions against the reference/production pipeline.

Output[0] shape=[1, 19, 8400] dtype=float32

[KEY] Heuristic detector decode: 8400 candidates, 15 classes

Top raw candidates:

#4162  Stop              raw_score=0.913421
#4161  Stop              raw_score=0.887031
#5200  Speed Limit 20    raw_score=0.072114
```

The value is deliberately called `raw_score`.

The toolkit does not automatically claim that a raw model value is a calibrated final detection confidence.

---

# Raw Output Dump

Save exact runtime outputs:

```bash
python aiml_model_security_recon.py best.onnx \
  --model-type computer-vision \
  --input-image stop.jpg \
  --dump-raw-output raw_outputs.npz
```

This can be useful for:

- decoder development
- reference-vs-production comparison
- PT-vs-ONNX equivalence testing
- regression testing
- adversarial-example comparison
- reproducing unusual detections

---

# Preprocessing Controls

The real-image helper supports:

```text
--resize-mode auto|stretch|letterbox
--channel-order rgb|bgr
--input-scale auto|0-1|0-255
```

Example:

```bash
python aiml_model_security_recon.py best.onnx \
  --model-type computer-vision \
  --input-image stop.jpg \
  --resize-mode letterbox \
  --channel-order rgb \
  --input-scale 0-1
```

`auto` uses a conservative heuristic.

For common Ultralytics detection metadata it prefers letterbox preprocessing.

> Always compare preprocessing assumptions with the original training/export code and production implementation before treating differences as model defects.

---

# Deep Mode

Deep mode is currently strongest for ONNX models.

Run:

```bash
python aiml_model_security_recon.py model.onnx \
  --model-type computer-vision \
  --deep
```

Deep mode adds:

- structural fingerprinting
- ONNX runtime profiling
- output range profiling
- latency profiling
- stronger model-comparison evidence

---

# Structural Fingerprint

The toolkit creates a graph-level structural fingerprint based on information such as:

```text
ONNX IR version
opset
inputs
outputs
node count
initializer count
operator histogram
operator domains
initializer structure
```

This is different from the normal file SHA-256.

Think of them as:

```text
File SHA-256
→ Is this exactly the same file?

Structural fingerprint
→ Does this model have the same structure/interface?
```

Both are useful during model-integrity assessment.

---

# Runtime Profiling

Deep mode can perform repeated synthetic inference runs.

Example:

```bash
python aiml_model_security_recon.py model.onnx \
  --model-type computer-vision \
  --deep \
  --profile-runs 25
```

The report can include:

```text
minimum latency
maximum latency
average latency
output minimum
output maximum
NaN count
Infinity count
```

This provides a baseline before:

- resource-exhaustion testing
- denial-of-service testing
- worst-case input testing
- target-hardware comparison

This is not an accuracy benchmark.

---

# Model Comparison

Compare two artifacts:

```bash
python aiml_model_security_recon.py approved.onnx \
  --model-type computer-vision \
  --deep \
  --compare deployed.onnx
```

ONNX comparison can include:

```text
file SHA-256
structural fingerprint
opset
input interface
output interface
operators
operator domains
node count
initializer count
```

Example:

```text
byte_identical: False
structurally_equivalent_summary: True
```

This means:

```text
The files differ,
but their structural summaries match.
```

Further investigation can then focus on:

- weight differences
- metadata
- serialization
- export changes

---

# PyTorch Safety

PyTorch `.pt` and `.pth` files may contain Python pickle objects.

Blindly loading an untrusted checkpoint can be unsafe.

The toolkit attempts:

```python
torch.load(..., weights_only=True)
```

where supported.

It intentionally does not fall back to unsafe pickle-enabled loading.

Recommended handling for unknown PyTorch artifacts:

- use an isolated VM or container
- avoid privileged execution
- do not use `weights_only=False`
- verify artifact provenance
- remove sensitive credentials from the environment

---

# Pickle / Joblib Security Inspection

Formats such as:

```text
.pkl
.pickle
.joblib
```

may execute code during deserialization.

The toolkit performs static analysis instead of blindly loading the artifact.

It looks for security-relevant pickle operations such as:

```text
GLOBAL
STACK_GLOBAL
REDUCE
BUILD
NEWOBJ
NEWOBJ_EX
PERSID
BINPERSID
```

These operations are not automatically malicious.

Their presence highlights why untrusted pickle-family artifacts should not be blindly deserialized.

---

# Safetensors Reconnaissance

Safetensors is designed for safer tensor serialization.

The toolkit can inspect:

- tensor names
- shapes
- datatypes
- parameter count
- metadata
- numeric statistics

This is useful for:

- LLMs
- diffusion models
- transformer models
- vision models

---

# GGUF / LLM Reconnaissance

For GGUF models, the toolkit attempts to extract information such as:

```text
architecture
model name
context length
embedding size
block count
attention configuration
tokenizer information
BOS/EOS tokens
RoPE settings
quantization/file type
```

Important LLM attack surfaces may include:

```text
tokenizer
context length
generation configuration
quantization
chat template
RAG
tools/functions
prompt hierarchy
```

The model artifact alone does not represent the entire LLM application.

---

# Companion Artifact Discovery

The toolkit can look for relevant configuration files near the model.

For LLMs and multimodal models:

```text
config.json
generation_config.json
tokenizer.json
tokenizer_config.json
special_tokens_map.json
processor_config.json
preprocessor_config.json
adapter_config.json
adapter_model.safetensors
```

For computer vision:

```text
classes.txt
labels.txt
config.json
preprocessor_config.json
*.yaml
*.yml
```

Companion files may define:

- tokenizer behavior
- architecture
- context length
- class mapping
- processor behavior
- adapters
- LoRA configuration
- feature schemas
- generation parameters

These files may therefore be part of the model's security boundary.

---

# Model-Family-Specific Security Guidance

The toolkit provides suggested next tests based on the selected model family.

| Model Family | Suggested Security Areas |
|---|---|
| **Computer Vision** | preprocessing equivalence, class mapping, adversarial images, adversarial patches, decoder/NMS abuse |
| **Language / LLM** | tokenizer mismatch, context-length abuse, prompt injection, system-prompt leakage, tool/function abuse, RAG boundaries |
| **Audio / Speech** | sample-rate mismatch, channel mismatch, malformed audio, adversarial audio, decoder/tokenizer manipulation |
| **Multimodal** | cross-modal injection, image-text injection, processor mismatch, modality confusion |
| **Time-Series** | sequence length, timestamp disorder, missing values, replay, drift, outlier handling |
| **Tabular / Classical ML** | feature order, feature type, NaN handling, out-of-range values, preprocessor mismatch |
| **Generative** | scheduler/config mismatch, conditioning manipulation, LoRA/model replacement, latent/input bounds |
| **Reinforcement Learning** | observation-space manipulation, action-boundary testing, reward manipulation, policy replacement, environment poisoning |
| **Graph Neural Networks** | node/edge extremes, malformed adjacency, feature mismatch, graph poisoning |
| **Recommendation / Ranking** | embedding mismatch, candidate explosion, ranking manipulation, profile poisoning |

---

# JSON Report

The toolkit automatically writes a JSON report.

Example:

```text
best.onnx.security-recon.json
```

Specify another location:

```bash
python aiml_model_security_recon.py best.onnx \
  --model-type computer-vision \
  --json reports/best_model.json
```

The JSON report can retain:

- artifact identity
- model metadata
- graph/operator inventory
- input/output interfaces
- parameter information
- tensor statistics
- preprocessing details
- raw output statistics
- security observations
- attack-surface recommendations
- comparison evidence

It is useful for:

- assessment evidence
- report generation
- automation
- CI/CD security checks
- later model comparison

---

# Recommended Pentester Workflow

```text
Receive model
     ↓
Preserve original artifact
     ↓
Calculate hash
     ↓
Select model family
     ↓
Run reconnaissance
     ↓
Review companion files
     ↓
Identify input/output boundaries
     ↓
Identify serialization/runtime risks
     ↓
Run deep mode where useful
     ↓
Run real-sample inference where useful
     ↓
Create attack-surface plan
     ↓
Perform security / robustness testing
     ↓
Compare deployed model later
```

---

# Security Considerations

Always treat unknown model artifacts as untrusted input.

Recommended practices:

- analyze in a VM or container
- do not run as administrator/root
- remove cloud/API credentials from the environment
- restrict network access where appropriate
- preserve the original artifact
- calculate hashes before analysis
- keep ML runtimes patched
- isolate parser/fuzzing activities
- avoid unsafe pickle-family deserialization

---

# Limitations

The toolkit does not automatically prove:

- model accuracy
- model safety
- training-data integrity
- absence of poisoning
- absence of backdoors
- secure deployment
- secure APIs
- secure RAG implementation
- secure tool/function calling
- secure sensor integration
- compliance with a standard

Model security usually involves more than the model file.

The complete trust boundary may include:

```text
data
training pipeline
model artifact
tokenizer
preprocessor
postprocessor
runtime
application
API
plugins
RAG
tools
sensors
network interfaces
deployment platform
updates
monitoring
```

---

# Suggested Evidence to Retain

For each model assessment, retain:

```text
model filename
model SHA-256
model version
selected model family
recon JSON
tool/runtime versions
test date
tester
reference documentation
approved artifact identity
comparison results
```

---

# Repository Structure

```text
AI-ML-Models-Reconnaissance/
│
├── aiml_model_security_recon.py
├── README.md
├── requirements.txt
├── LICENSE
├── examples/
│   ├── onnx/
│   ├── llm/
│   └── classical-ml/
└── docs/
    └── screenshots/
```

For the initial repository, these files are sufficient:

```text
aiml_model_security_recon.py
README.md
requirements.txt
```

---

# Disclaimer

This toolkit is intended for:

- authorized security testing
- defensive security analysis
- AI/ML assurance
- research
- vulnerability assessment

Only analyze systems and model artifacts that you are authorized to test.

The toolkit provides reconnaissance and testing guidance. It does not constitute certification or proof of compliance with any security, safety, or regulatory standard.

---

# Project Goal

> Give pentesters a fast way to understand an unfamiliar AI/ML model artifact and turn that reconnaissance into meaningful security tests.

Good AI/ML security testing starts by understanding:

- what the model is
- how it is serialized
- what it expects
- what surrounds it
- where its trust boundaries exist
- which parts require deeper testing
