# AI/ML Model Security Reconnaissance Toolkit

`aiml_model_security_recon.py` is a pentester-oriented reconnaissance utility for analyzing AI/ML model artifacts before deeper security testing.

It is designed for security testers, ML security engineers, red teams, product-security teams, and researchers who need a quick way to answer questions such as:

- What exactly is this model artifact?
- What format and framework does it use?
- What inputs and outputs does it expose?
- What metadata, classes, dimensions, operators, or runtime assumptions can be identified?
- Is the artifact using unsafe serialization?
- Are there external dependencies or companion files?
- Is the model quantized?
- Does it contain custom operators?
- What attack surfaces should be tested next?
- Does the deployed model differ from the approved model?
- Which model-family-specific tests should the pentester consider?

The tool does **not** attempt to prove that a model is secure, safe, accurate, backdoor-free, or standards-compliant. It performs reconnaissance and produces security-relevant guidance for the next stages of testing.

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
- companion config discovery
- model-family-specific attack-surface guidance
- optional ONNX deep mode
- ONNX structural fingerprinting
- ONNX runtime profiling
- model-to-model comparison
- JSON report generation

---

# Supported Model Families

The user can select one of the following model families.

## Computer Vision

Examples:

- image classification
- object detection
- segmentation
- pose estimation
- depth estimation
- OCR
- visual inspection

Typical formats:

```text
.onnx
.pt
.pth
.safetensors
.tflite
.keras
.h5
.hdf5
```

---

## Language / LLM

Examples:

- large language models
- text classification
- embedding models
- transformer encoders
- text-generation models

Typical formats:

```text
.safetensors
.gguf
.pt
.pth
.onnx
.bin
TensorFlow SavedModel
```

For LLMs, the tool also looks for common companion files such as:

```text
config.json
generation_config.json
tokenizer.json
tokenizer_config.json
special_tokens_map.json
adapter_config.json
preprocessor_config.json
processor_config.json
```

---

## Audio / Speech

Examples:

- automatic speech recognition
- speaker recognition
- sound classification
- text-to-speech

Typical formats:

```text
.onnx
.pt
.pth
.safetensors
.tflite
.keras
.h5
.hdf5
```

---

## Multimodal

Examples:

- vision-language models
- image + text models
- audio + text models
- video + language models
- sensor + language models

Typical formats:

```text
.safetensors
.gguf
.pt
.pth
.onnx
.keras
```

---

## Time-Series / Sequential

Examples:

- forecasting
- anomaly detection
- predictive maintenance
- sensor analytics

Typical formats:

```text
.onnx
.pt
.pth
.keras
.h5
.hdf5
.tflite
.pkl
.joblib
```

---

## Tabular / Classical ML

Examples:

- random forest
- gradient boosting
- SVM
- logistic regression
- regression models
- XGBoost
- LightGBM
- scikit-learn pipelines

Typical formats:

```text
.onnx
.pkl
.pickle
.joblib
.json
.ubj
.txt
.model
```

---

## Generative

Examples:

- diffusion models
- GANs
- VAEs
- image-generation models
- audio-generation models

Typical formats:

```text
.safetensors
.pt
.pth
.onnx
.keras
.h5
.hdf5
```

---

## Reinforcement Learning

Examples:

- policies
- actor-critic models
- Q-networks
- robotics-control policies

Typical formats:

```text
.pt
.pth
.onnx
.zip
.pkl
.joblib
```

---

## Graph Neural Networks

Examples:

- graph classification
- graph embeddings
- molecular models
- network-analysis models

Typical formats:

```text
.pt
.pth
.onnx
.safetensors
```

---

## Recommendation / Ranking

Examples:

- personalization
- ranking
- matching
- recommendation engines

Typical formats:

```text
.onnx
.pt
.pth
.keras
.h5
.hdf5
.pkl
.joblib
```

---

# Supported Artifact Formats

Current format support includes:

```text
ONNX                .onnx
PyTorch             .pt .pth
Safetensors         .safetensors
GGUF                .gguf
TensorFlow Lite     .tflite
Keras               .keras
Keras/HDF5          .h5 .hdf5
Pickle              .pkl .pickle
Joblib              .joblib
XGBoost             .json .ubj
LightGBM            .txt .model
Stable-Baselines    .zip
TensorFlow SavedModel directory
```

> Format support does not necessarily mean complete semantic reconstruction of every framework/version. Some formats are inspected statically or conservatively for security reasons.

---

# Prerequisites

## Python

Recommended:

```text
Python 3.10+
```

The toolkit uses the Python standard library for its core workflow, while format-specific analysis requires a small set of additional packages.

---

## Install Dependencies

The repository includes a `requirements.txt` file.

Recommended installation:

```bash
pip install -r requirements.txt
```

The current `requirements.txt` installs:

```text
numpy>=1.26
onnx>=1.16
onnxruntime>=1.18
torch>=2.4
safetensors>=0.4.5
h5py>=3.11
pillow>=10.0
```

These provide broad coverage for:

- ONNX static analysis
- ONNX deep-mode runtime profiling
- PyTorch checkpoint inspection
- Safetensors inspection
- Keras / HDF5 inspection
- numerical/tensor analysis

### Optional TensorFlow / TFLite Support

TensorFlow is intentionally **not** installed by default because it is a much heavier dependency.

If you need TensorFlow / TFLite support, install one of the following separately.

Full TensorFlow:

```bash
pip install tensorflow
```

Or, where available, the smaller TFLite runtime:

```bash
pip install tflite-runtime
```

You do **not** need every dependency if you only work with one model format.

---

# Installation

Clone the repository:

```bash
git clone https://github.com/<YOUR_GITHUB_USERNAME>/AI-ML-Model-Security-Recon.git
cd AI-ML-Model-Security-Recon
```

Install the default dependencies:

```bash
pip install -r requirements.txt
```

Then verify the tool:

```bash
python aiml_model_security_recon.py --help
```

And list supported model families and formats:

```bash
python aiml_model_security_recon.py --list-model-types
```

For TensorFlow / TFLite inspection, install the optional dependency separately:

```bash
pip install tensorflow
```

or:

```bash
pip install tflite-runtime
```

---

# Help Menu

Run:

```bash
python aiml_model_security_recon.py --help
```

Typical output:

```text
usage: aiml_model_security_recon.py [-h]
                                    [--model-type MODEL_TYPE]
                                    [--list-model-types]
                                    [--deep]
                                    [--profile-runs PROFILE_RUNS]
                                    [--compare OTHER_MODEL]
                                    [--json JSON_PATH]
                                    [model]

AI/ML Model Security Reconnaissance Toolkit v3.3

Pentester-oriented reconnaissance for AI/ML artifacts.

Use --list-model-types to see supported model families and formats.

Examples:
  aiml_model_security_recon.py model.onnx --model-type computer-vision --deep
  aiml_model_security_recon.py model.gguf --model-type language-llm
  aiml_model_security_recon.py model.safetensors --model-type generative
  aiml_model_security_recon.py model.pkl --model-type tabular-classical
  aiml_model_security_recon.py policy.zip --model-type reinforcement-learning
  aiml_model_security_recon.py approved.onnx --model-type computer-vision --deep --compare deployed.onnx
```

---

# List Supported Model Families and Formats

Run:

```bash
python aiml_model_security_recon.py --list-model-types
```

This prints:

- model-family names
- example use cases
- supported artifact formats

---

# Basic Usage

## Computer Vision

```bash
python aiml_model_security_recon.py model.onnx --model-type computer-vision
```

## Language / LLM

```bash
python aiml_model_security_recon.py model.gguf --model-type language-llm
```

## Generative Model

```bash
python aiml_model_security_recon.py model.safetensors --model-type generative
```

## Tabular Model

```bash
python aiml_model_security_recon.py model.pkl --model-type tabular-classical
```

## Reinforcement-Learning Policy

```bash
python aiml_model_security_recon.py policy.zip --model-type reinforcement-learning
```

---

# Interactive Model-Family Selection

If you do not specify `--model-type` in an interactive terminal:

```bash
python aiml_model_security_recon.py model.onnx
```

the tool prompts you to select the model family.

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

# What the Output Looks Like

For an ONNX computer-vision model:

```bash
python aiml_model_security_recon.py best.onnx \
  --model-type computer-vision \
  --deep
```

the output is organized into security-relevant sections.

Example:

```text
================================================================================================
1. ARTIFACT IDENTITY
================================================================================================
path: C:\models\best.onnx
name: best.onnx
kind: file
extension: .onnx
size_human: 10.71 MB
sha256: 8d74c8c9...
selected_model_type: computer-vision
detected_format: onnx
```

This establishes the exact artifact tested.

---

# Artifact Identity and Integrity

The tool reports:

- filename
- path
- file size
- extension
- SHA-256

Example:

```text
sha256: 8d74c8c9...
```

## Security Value

The file hash can be used to:

- identify the exact model tested
- compare approved vs deployed models
- detect unauthorized replacement
- support release traceability
- retain assessment evidence

Example:

```text
Approved model SHA-256:
ABC123...

Extracted production model SHA-256:
XYZ456...
```

A mismatch means the artifacts are not byte-for-byte identical.

---


## Robust Metadata Parsing and Recon Completeness

Version 3.2 hardens ONNX metadata handling.

A malformed or unusual metadata value must not stop the rest of the reconnaissance. For example, metadata values such as:

```text
08
09
2026-01-08
00123
```

may look numeric but are often identifiers or strings. The tool now uses best-effort parsing and falls back to the raw string if literal parsing is not safe.

Instead of aborting the ONNX analysis, the report records a metadata parsing warning and continues collecting:

- input/output interfaces
- graph/operator inventory
- parameter and tensor information
- ONNX checker result
- quantization indicators
- external initializers
- semantic metadata
- attack-surface guidance

The console and JSON report now also include a **Recon Completeness** status.

Example:

```text
1A. RECON COMPLETENESS

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

If part of the inspection fails, the tool reports `PARTIAL` rather than making the result look complete.

Example:

```text
status: PARTIAL

completed:
  - Artifact identity
  - SHA-256
  - Format detection
  - Input/output interface
  - Graph/operator inventory

warnings:
  - 1 metadata value retained as a raw string after safe parse fallback
```

This is useful during pentesting because a tester can immediately see which parts of the model were successfully inspected and which areas still require manual follow-up.


# ONNX Model Identity

For ONNX models, the tool can report:

- IR version
- producer
- producer version
- ONNX opset
- model version
- embedded metadata

Example:

```text
producer_name: pytorch
producer_version: 2.x
opset: 19
task: detect
imgsz: [640, 640]
stride: 32
```

## Pentest Use

This helps the tester:

- identify conversion/export history
- determine runtime compatibility
- detect unexpected exporter versions
- compare approved and deployed artifacts
- identify provenance inconsistencies

---

# Input / Output Interface

The tool reports model inputs and outputs.

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

## Security Value

The model interface defines a major attack surface.

Possible tests include:

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

Example static shape:

```text
[1, 3, 640, 640]
```

Example dynamic shape:

```text
[N, 3, H, W]
```

Dynamic dimensions can increase:

- resource-exhaustion exposure
- input-validation complexity
- parser/runtime edge cases

They should be included in fuzzing.

---

# Graph / Operator Inventory

For ONNX, the tool enumerates operators.

Example:

```text
Conv: 64
Concat: 20
Resize: 2
Sigmoid: 1
Reshape: 5
```

The tool also identifies:

- custom domains
- embedded Resize
- embedded NMS
- quantization operators

## Pentest Use

Operator information helps identify:

- custom runtime plugins
- unsupported operators
- parser attack surfaces
- supply-chain dependencies
- runtime differences

Custom operators are particularly important because they may be implemented in native libraries.

---

# Parameter and Weight Information

The tool can report:

- estimated parameter count
- tensor count
- tensor dimensions
- tensor datatypes
- largest tensors
- approximate weight size

This information helps with:

- model fingerprinting
- integrity comparison
- version comparison
- quantization identification
- corruption analysis

---

# Weight Statistics

Where safely supported, the tool can calculate sampled statistics:

```text
minimum
maximum
mean
standard deviation
zero fraction
NaN count
Infinity count
```

## Security Value

Unexpected numeric values can indicate:

- damaged artifacts
- conversion failures
- corrupted weights
- numerical instability

Normal statistics do **not** prove that a model is backdoor-free.

---

# NaN / Infinity Detection

The tool checks for:

```text
NaN
+Infinity
-Infinity
```

where practical.

These values may cause issues in:

- model inference
- postprocessing
- comparisons
- thresholds
- downstream decision logic

They are useful targets for resilience and fuzz testing.

---

# Quantization Detection

For ONNX, the tool looks for operators such as:

```text
QuantizeLinear
DequantizeLinear
```

This helps identify:

```text
FP32
FP16
INT8
mixed precision
```

## Pentest Use

Quantized production models should be compared with reference models, especially for:

- small objects
- low-confidence predictions
- edge cases
- class-confusion boundaries
- adversarial examples

---

# Embedded Resize / Preprocessing Clues

If the model graph contains Resize operators, some preprocessing may be embedded.

If not, resizing may happen externally.

External preprocessing should be tested for:

```text
RGB vs BGR
NCHW vs NHWC
normalization
letterbox vs stretch
crop
orientation
interpolation method
```

---

# Embedded NMS / Postprocessing Clues

For object detectors, if NMS is not embedded in the graph, the real execution chain may be:

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

This means the external decoder/postprocessing becomes part of the attack surface.

Useful tests include:

```text
threshold tampering
IoU manipulation
candidate explosion
class-mapping mismatch
malformed output handling
```

---

# PyTorch Safety

PyTorch `.pt` and `.pth` files may contain Python pickle objects.

Blindly loading an untrusted checkpoint can be unsafe.

The tool therefore attempts:

```python
torch.load(..., weights_only=True)
```

when supported.

It intentionally does not fall back to unsafe pickle-enabled loading.

## Tester Guidance

For unknown PyTorch artifacts:

- use an isolated VM or container
- avoid privileged execution
- do not use `weights_only=False`
- verify provenance
- keep sensitive credentials out of the environment

---

# Pickle / Joblib Security Inspection

Formats such as:

```text
.pkl
.pickle
.joblib
```

may execute code when deserialized.

The tool performs a static scan instead of loading the model.

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

These operations are not automatically malicious, but their presence reinforces why untrusted pickle artifacts must not be blindly loaded.

---

# Safetensors

Safetensors is designed for safer tensor serialization.

The tool can inspect:

- tensor names
- tensor shapes
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

For GGUF models, the tool attempts to extract metadata such as:

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

## Pentest Use

This helps identify important LLM testing boundaries such as:

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

The GGUF model alone does not represent the entire LLM application.

---

# Companion Artifact Discovery

For some model families, the tool searches the model directory for relevant configuration files.

For LLMs and multimodal models this can include:

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

For CV models:

```text
classes.txt
labels.txt
config.json
preprocessor_config.json
*.yaml
*.yml
```

## Security Value

Companion files may define:

- tokenizer behavior
- model architecture
- context length
- class mapping
- processor behavior
- adapters
- LoRA configuration
- feature schemas
- generation parameters

They must therefore be considered part of the security boundary.

---

# Model-Family-Specific Attack Guidance

One of the main goals of the tool is to convert reconnaissance into useful next tests.

## Computer Vision

Suggested areas:

```text
preprocessing equivalence
class mapping
adversarial images
adversarial patches
decoder/NMS abuse
```

## Language / LLM

Suggested areas:

```text
tokenizer mismatch
context-length abuse
prompt injection
system-prompt leakage
tool/function abuse
RAG boundary review
```

## Audio / Speech

Suggested areas:

```text
sample-rate mismatch
channel mismatch
malformed audio
adversarial audio
decoder/tokenizer manipulation
```

## Multimodal

Suggested areas:

```text
cross-modal prompt injection
image-text injection
processor mismatch
modality confusion
```

## Time-Series

Suggested areas:

```text
sequence length
timestamp disorder
missing values
replay
drift
outlier handling
```

## Tabular / Classical ML

Suggested areas:

```text
feature order
feature type
NaN / missing values
out-of-range values
preprocessor mismatch
```

## Generative

Suggested areas:

```text
scheduler/config mismatch
conditioning manipulation
LoRA/model replacement
latent/input bounds
```

## Reinforcement Learning

Suggested areas:

```text
observation-space manipulation
action-space boundary testing
reward manipulation
policy replacement
environment poisoning
```

## Graph Neural Networks

Suggested areas:

```text
node/edge count extremes
malformed adjacency
feature-dimension mismatch
graph poisoning
```

## Recommendation / Ranking

Suggested areas:

```text
feature/embedding mismatch
candidate explosion
ranking manipulation
profile poisoning
```

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

The script creates a graph-level structural SHA-256 fingerprint based on properties such as:

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
→ Is the model structure/interface equivalent?
```

Both are useful during model-integrity testing.

---

# ONNX Runtime Profiling

Deep mode can perform multiple synthetic inference runs.

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

This is useful as a baseline before:

- resource-exhaustion tests
- denial-of-service testing
- target-hardware performance comparison
- worst-case input testing

This is **not** an accuracy benchmark.

---

# Model Comparison

Compare two artifacts:

```bash
python aiml_model_security_recon.py approved.onnx \
  --model-type computer-vision \
  --deep \
  --compare deployed.onnx
```

For ONNX-to-ONNX comparison, the tool can compare:

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
the files differ
but
their structural summaries match
```

Further investigation may then focus on:

- weight differences
- metadata
- serialization
- export changes

---

# JSON Report

The tool automatically writes a JSON report.

Example:

```text
best.onnx.security-recon.json
```

You can specify your own path:

```bash
python aiml_model_security_recon.py best.onnx \
  --model-type computer-vision \
  --json reports/best_model.json
```

This is useful for:

- assessment evidence
- report generation
- automation
- CI/CD security checks
- later model comparison

---

# Recommended Pentester Workflow

A practical workflow is:

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
Identify inputs/outputs
     ↓
Identify serialization/runtime risk
     ↓
Run deep mode where useful
     ↓
Create attack-surface plan
     ↓
Perform functional/security testing
     ↓
Compare deployed model later
```

---

# Example: Computer-Vision Model

Suppose reconnaissance finds:

```text
Format: ONNX
Input: [1,3,640,640]
Output: [1,19,8400]
Classes: 15
NMS embedded: No
Resize embedded: No
```

A pentester can derive:

```text
Preprocessing is external
→ verify RGB/BGR
→ verify normalization
→ verify letterbox/stretch
→ verify NCHW/NHWC

Postprocessing is external
→ inspect decoder
→ inspect threshold
→ inspect NMS
→ test candidate explosion

Model input boundary
→ shape fuzzing
→ dtype fuzzing
→ NaN/Inf

Model security
→ adversarial inputs
→ targeted attacks
→ model replacement
```

---

# Example: LLM

Suppose reconnaissance identifies:

```text
Format: GGUF
Architecture: llama
Context length: 8192
Quantized: yes
Tokenizer metadata found
```

A pentester should not stop at the weight file.

Next test surfaces may include:

```text
tokenizer/config integrity
prompt injection
system prompt leakage
context-length abuse
generation configuration
RAG retrieval boundary
tool/function calling
model replacement
adapter/LoRA integrity
```

---

# Example: Tabular Model

Suppose the target is a Joblib model.

The tool does not blindly deserialize it.

Instead it identifies:

```text
format: joblib
unsafe deserialization risk: true
```

The pentester should then assess:

```text
artifact provenance
model-loading trust boundary
feature ordering
preprocessor integrity
NaN handling
out-of-range features
model replacement
```

---



# Version 3.3 – Real-Image Forward Pass and Pentester-Friendly Output

Version 3.3 integrates the second-stage forward-pass reconnaissance workflow into the main toolkit.

The default console output is now intentionally concise. Large raw dictionaries, weight tensor lists, and full metadata structures are still preserved in the JSON report and can be printed with:

```bash
python aiml_model_security_recon.py model.onnx \
  --model-type computer-vision \
  --verbose
```

The normal console view now prioritizes:

```text
[KEY]  model identity / SHA-256
[PASS] successful structural/security checks
[INFO] model facts and trust-boundary observations
[WARN] assumptions, external processing, or incomplete analysis
[FAIL] reconnaissance/runtime failures
```

When the terminal supports ANSI colors, the tags are highlighted automatically. Disable color with:

```bash
python aiml_model_security_recon.py model.onnx \
  --model-type computer-vision \
  --no-color
```

## Real-Image Forward-Pass Reconnaissance

For ONNX computer-vision models, a tester can now provide a real sample image:

```bash
python aiml_model_security_recon.py best.onnx \
  --model-type computer-vision \
  --input-image stop.jpg
```

The tool:

1. identifies the model input shape and layout
2. loads the image
3. applies the selected preprocessing assumptions
4. runs ONNX Runtime inference
5. records inference latency
6. reports raw output shape/range
7. performs a best-effort interpretation of common object-detector output
8. shows the top raw class candidates
9. optionally saves the complete raw output tensors

Example:

```text
REAL-IMAGE FORWARD PASS

[PASS] Inference completed in 24.8 ms
[INFO] Image      : stop.jpg
[INFO] Preprocess : NCHW | RGB | scale=0-1 | letterbox
[WARN] Confirm preprocessing assumptions against the reference/production pipeline.

Output[0] shape=[1, 19, 8400] dtype=float32

[KEY] Heuristic detector decode: 8400 candidates, 15 classes
[INFO] Assumption: first 4 channels are box values and the remaining 15 are class scores.

Top raw candidates:
  #4162  Stop                     raw_score=0.913421
  #4161  Stop                     raw_score=0.887031
  #5200  Speed Limit 20           raw_score=0.072114
```

The score is labelled `raw_score` deliberately. The tool does not claim that the value is a final calibrated detection confidence unless the model/export semantics are known.

## Raw Output Dump

Save the exact runtime outputs:

```bash
python aiml_model_security_recon.py best.onnx \
  --model-type computer-vision \
  --input-image stop.jpg \
  --dump-raw-output raw_outputs.npz
```

This is useful for:

- decoder development
- reference-vs-production comparison
- PT-vs-ONNX equivalence work
- regression testing
- adversarial-example comparison
- reproducing unusual detections

## Top Candidate Count

Control how many candidates are displayed:

```bash
python aiml_model_security_recon.py best.onnx \
  --model-type computer-vision \
  --input-image stop.jpg \
  --top-k 20
```

## Preprocessing Controls

The forward-pass helper supports:

```text
--resize-mode auto|stretch|letterbox
--channel-order rgb|bgr
--input-scale auto|0-1|0-255
```

Examples:

```bash
python aiml_model_security_recon.py best.onnx \
  --model-type computer-vision \
  --input-image stop.jpg \
  --resize-mode letterbox \
  --channel-order rgb \
  --input-scale 0-1
```

`auto` uses a conservative heuristic. For common Ultralytics detection metadata it prefers letterbox; otherwise it uses stretch resize.

> The preprocessing chosen by the tool is an assessment assumption. Always compare it with the original training/export code and the production implementation before treating output differences as model defects.

## Why Real-Sample Output Analysis Matters

Static reconnaissance answers:

```text
What is this model?
What does its interface look like?
What runtime/parser surfaces exist?
```

Real-sample forward-pass reconnaissance additionally answers:

```text
Can the model execute successfully?
What does the raw output actually look like?
Which candidates/classes receive the highest scores?
Does our decoder assumption make sense?
Does preprocessing materially change behavior?
```

This is particularly useful before:

- functional validation
- implementation equivalence testing
- adversarial ML testing
- output/postprocessing fuzzing
- deployed-runtime comparison

## Console vs JSON Evidence

The normal console output is optimized for a pentester making decisions quickly.

The JSON report keeps the detailed evidence, including:

- complete metadata
- graph/operator inventory
- parameter/tensor information
- weight statistics
- real-image preprocessing details
- raw output statistics
- heuristic interpretation
- security observations
- attack-surface recommendations

Use `--verbose` only when you want the full raw structures printed to the terminal.


# Security Considerations

Always treat unknown model artifacts as untrusted input.

Recommended practices:

- analyze in a VM/container
- do not run as administrator/root
- remove cloud/API credentials from the environment
- restrict network access where appropriate
- preserve the original artifact
- calculate hashes before analysis
- keep ML runtimes patched
- isolate parser/fuzzing activities
- avoid loading pickle-family artifacts directly

---

# Limitations

The tool does not automatically prove:

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

The full trust boundary may include:

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
tool version
runtime/library versions
test date
tester
reference documentation
approved artifact identity
comparison results
```

---

# Suggested Repository Structure

A clean GitHub repository could look like:

```text
AI-ML-Model-Security-Recon/
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

For the first release, the script and README alone are enough.

---

# Disclaimer

This tool is intended for authorized security testing, research, validation, and defensive analysis.

Only analyze systems and model artifacts that you are authorized to test.

The tool provides reconnaissance and testing guidance. It does not constitute a certification or proof of compliance with any security, safety, or regulatory standard.

---

# Project Goal

The goal of this project is simple:

> Give pentesters a fast way to understand an unfamiliar AI/ML model artifact and turn that reconnaissance into meaningful security tests.

Good AI/ML security testing starts by understanding what the model is, how it is serialized, what it expects, what surrounds it, and where its trust boundaries actually are.
