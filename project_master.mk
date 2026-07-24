# ScamShield AI — PROJECT_MASTER.md
## Current Source of Truth for Architecture, Scope, Constraints, and Development

> IMPORTANT:
> This document supersedes all previous ScamShield project-master documents
> based on the old Intel i5 / 8GB RAM laptop.
>
> The current repository is an existing working codebase being evolved.
> Do NOT rewrite working components without a demonstrated reason.
>
> Historical constraints such as:
> - 8GB RAM ceiling
> - <450MB ML memory limit
> - mandatory xlm-roberta-base
> - mandatory CPU inference
> - mandatory ONNX deployment
> - max_length=128
>
> are NO LONGER project requirements.


# 1. PROJECT OBJECTIVE

Project Name: ScamShield AI

Objective:
Build a portfolio-grade multilingual Indian scam-intelligence system capable
of analyzing suspicious text messages and mobile screenshots with high
detection accuracy, low user-visible latency, explainable results, and safe
handling of malicious URLs.

Primary priorities, in order:

1. Detection accuracy
2. Low user-visible latency
3. Reliability and graceful failure
4. Security and malicious-URL isolation
5. Evidence-grounded explainability
6. Maintainable architecture
7. Strong ML/cybersecurity portfolio value
8. Reasonable local resource consumption

This is NOT intended to be a production system serving millions of users.

Do not introduce enterprise-scale infrastructure unless measurements show
that it materially improves the project.


# 2. TARGET USERS AND LANGUAGE SCOPE

Primary context:
Indian scam messages received through channels such as:

- SMS
- WhatsApp
- messaging applications
- notification screenshots
- copied text

Supported language scope:

- English
- Hindi / Devanagari
- Hinglish / Romanized Hindi
- Mixed English + Hindi
- Mixed English + Hinglish

Marathi is OUTSIDE the intended classification/reporting scope.

Do not spend model capacity, dataset work, OCR optimization, or explanation
development specifically on Marathi.


# 3. CURRENT HARDWARE PROFILE

Development Machine:

- HP OMEN
- AMD Ryzen AI 7 350
- 8 CPU cores / 16 threads
- 24GB system RAM
- NVIDIA GeForce RTX 5050 Laptop GPU
- 8GB VRAM
- Radeon 860M integrated GPU
- AMD NPU available
- Windows
- Python 3.11.9

The RTX 5050 is the primary accelerator candidate for ML training and
accelerated inference.

The CPU remains appropriate for lightweight preprocessing, routing,
database work, regex/entity extraction, and other low-cost operations.

The Radeon iGPU and NPU must NOT be integrated merely because they exist.
Use them only if benchmarking demonstrates a meaningful advantage.


# 4. NEW PERFORMANCE PHILOSOPHY

The previous project was designed around:

"Make ScamShield fit inside an 8GB laptop."

That constraint is retired.

The current philosophy is:

"Build the highest-quality ScamShield system that achieves excellent
detection accuracy with the lowest practical user-visible latency on the
available hardware."

There is NO artificial <450MB ML memory requirement anymore.

There is NO requirement to use the smallest possible model.

There is also NO requirement to consume all available hardware.

Bigger models, more services, more APIs, more OCR passes, more caching
layers, or more concurrency are NOT automatically improvements.

Every significant optimization should improve at least one of:

- accuracy
- latency
- reliability
- security
- maintainability

without causing an unacceptable regression elsewhere.


# 5. LATENCY GOALS

Latency should be measured rather than assumed.

Target behavior:

TEXT SCAN:
Local analysis should feel near-instant where possible.

IMAGE SCAN:
OCR + local intelligence should remain responsive despite higher processing
cost.

CACHE HIT:
Target approximately <50ms application-level retrieval where practical.

REMOTE INTELLIGENCE:
External APIs must execute asynchronously and must not unnecessarily serialize
the pipeline.

AWS SANDBOX:
Must have a strict timeout and graceful degradation.

The previous "entire pipeline must always complete under 4 seconds" rule is
NOT a hard architectural constraint.

Instead measure:

- cache latency
- OCR latency
- ML latency
- API latency
- sandbox latency
- complete scan latency
- median latency
- p95 latency

Optimize the critical path based on measurements.


# 6. HIGH-LEVEL SYSTEM ARCHITECTURE

User
 |
 v
React Vite Frontend
 |
 v
FastAPI Backend
 |
 v
Input Validation / Scan Context
 |
 v
Text or Screenshot Processing
 |
 v
Normalization + Entity Extraction
 |
 v
SHA-256 Cache Gatekeeper
 |
 +---------- CACHE HIT ----------> Final Report
 |
 +---------- CACHE MISS
                  |
                  v
              URL Present?
               /       \
             YES        NO
              |          |
              v          v
       Parallel Tracks   ML / relevant
       A + B + C + D     local analysis
              |
              v
           Fan-In
              |
              v
       Risk Aggregation
              |
              v
       Explanation Engine
              |
              v
       PostgreSQL Persistence
              |
              v
          React UI


# 7. LAYER 1 — INPUT INGESTION

Technology:

React Vite
FastAPI

Supported input:

1. Raw/copied text
2. Mobile screenshot/image

Each request receives a unique scan_id.

Example:

scam_2026_x89

Responsibilities:

- validate request
- validate image type/size
- establish scan context
- record timing
- route input safely
- prevent malformed input from crashing downstream components

Do not perform expensive analysis directly inside routing code.


# 8. LAYER 2 — OCR, NORMALIZATION AND ENTITY EXTRACTION

## 8.1 Text Input

Copied text bypasses OCR.

Processing includes:

- Unicode-safe normalization
- whitespace normalization
- artifact cleanup where appropriate
- preservation of security-relevant characters
- entity extraction

Important:

Do NOT aggressively normalize text in ways that corrupt:

- URLs
- UPI IDs
- phone numbers
- OTP values
- currency amounts
- suspicious spelling
- Unicode homoglyph evidence


## 8.2 Screenshot Input

Current OCR implementation uses PaddleOCR with multilingual processing.

Current environment includes approximately:

- PaddleOCR 3.7.x
- PaddlePaddle 3.3.x
- OpenCV

Existing OCR architecture includes:

- image preprocessing
- dark/light image handling
- contrast enhancement
- OCR block extraction
- English OCR
- Hindi/Devanagari OCR
- bounding-box merging
- artifact filtering
- text reconstruction
- quality estimation

The existing pipeline currently performs substantial English and
Hindi/Devanagari OCR passes and merges their results.

THIS IS NOT YET THE FINAL OCR ARCHITECTURE.

Before changing OCR:

1. benchmark current accuracy
2. benchmark latency
3. measure entity preservation
4. identify failure categories
5. optimize based on evidence

Potential future optimizations include:

- conditional language routing
- stronger recognition models
- resolution changes
- selective preprocessing
- GPU acceleration if supported and beneficial
- avoiding unnecessary duplicate OCR passes

These are hypotheses, not requirements.


## 8.3 Tesseract

PyTesseract/Tesseract existed in the original architecture as a fallback.

Tesseract is NOT required to remain the primary OCR engine.

Do not install, remove, or redesign the fallback merely to preserve the old
architecture.

Its future role must be justified by benchmark results.


## 8.4 Entity Extraction

Extract structured entities such as:

- URLs
- domains
- phone numbers
- UPI IDs
- OTP-like values
- rupee/currency amounts
- bank/brand references where useful

Entity extraction must tolerate common scam formatting and OCR noise.

The result becomes a structured metadata packet for downstream analysis.


# 9. OCR QUALITY REQUIREMENTS

Normal CER/WER alone are insufficient for ScamShield.

A one-character OCR error inside a URL can materially alter cybersecurity
analysis.

OCR evaluation therefore includes:

- Character Error Rate (CER)
- Word Error Rate (WER)
- URL preservation
- domain preservation
- phone-number preservation
- UPI-ID preservation
- amount preservation
- OTP preservation
- bank/brand preservation
- semantic preservation
- OCR confidence
- latency

Benchmark screenshots should represent realistic Indian users:

- English SMS
- Hindi SMS
- Hinglish
- mixed English/Hindi
- WhatsApp
- Google Messages/SMS
- light mode
- dark mode
- notification screenshots
- small fonts
- compressed images
- long messages
- URLs
- UPI IDs
- ₹ amounts
- OTP language
- bank impersonation
- KYC scams
- delivery scams
- electricity scams


# 10. LAYER 3 — CACHE AND INTELLIGENT ROUTING

Technology:

- PostgreSQL
- SHA-256 hashing

Current cache TTL:

approximately 24 hours.

Flow:

Normalize/extract input
        |
        v
Generate stable cache identity
        |
        v
Query PostgreSQL
        |
     cache hit?
      /     \
    YES      NO
     |        |
     v        v
Return      Continue
cached      analysis
report


If no actionable URL is present:

Do NOT execute URL/domain/sandbox tracks unnecessarily.

Route primarily to text/ML analysis and other relevant local signals.

If URL is present:

Fan out appropriate independent intelligence operations concurrently.

Do NOT add Redis unless benchmarked workload demonstrates a real need.


# 11. LAYER 4 — TRACK A: URL INTELLIGENCE

Purpose:

Analyze URL-level static/reputation signals without requiring the local
machine to render the malicious website.

Components include:

- URL parsing
- domain extraction
- typo-squatting detection
- brand impersonation detection
- homoglyph detection
- suspicious structural features
- VirusTotal reputation lookup

Target Indian brands may include examples such as:

- SBI
- HDFC
- ICICI
- Axis
- Paytm
- PhonePe
- Amazon India
- India Post

Do not hard-code the system so narrowly that unseen brands automatically
appear safe.


# 12. LAYER 4 — TRACK B: DOMAIN INTELLIGENCE

Purpose:

Analyze domain-level evidence.

Potential evidence:

- registration age
- WHOIS information
- domain reputation
- TLS/certificate metadata where safe and appropriate

WhoisXML may provide domain-registration intelligence.

SECURITY REQUIREMENT:

Re-evaluate any direct local socket/TLS interaction with attacker-controlled
hosts.

The local Windows machine should NOT perform unnecessary active interaction
with malicious infrastructure.

Static/local parsing is acceptable.

Active hostile-site interaction belongs in the remote sandbox whenever
practical.


# 13. LAYER 4 — TRACK C: REMOTE AWS SANDBOX

Purpose:

Perform dangerous active URL inspection outside the local Windows machine.

Target architecture:

FastAPI
   |
   v
AWS ECS/Fargate
   |
   v
Ephemeral Docker Worker
   |
   v
Playwright Browser
   |
   v
Malicious/Suspicious URL

The worker should eventually collect structured evidence such as:

- redirect chain
- final destination URL
- DOM indicators
- password fields
- OTP fields
- payment forms
- suspicious authentication forms
- iframe indicators
- relevant network behavior where practical
- screenshot

The worker returns structured evidence to the backend.

The worker must be disposable.

The backend must handle:

- task startup failure
- timeout
- browser crash
- unreachable domain
- malformed result
- AWS failure

without hanging the scan.

IMPORTANT:

A sandbox timeout is UNKNOWN/UNAVAILABLE evidence.

Do NOT automatically interpret every timeout as proof of maliciousness.


# 14. LAYER 4 — TRACK D: MULTILINGUAL ML ENGINE

Current repository status:

NO final trained ScamShield transformer is currently deployed.

Existing heuristic/rule-based output is development fallback behavior and
must NOT be represented as genuine ML inference.


## Intended Architecture

Multi-Task Learning model:

                  Shared Multilingual Transformer
                           |
                +----------+----------+
                |                     |
                v                     v
         Social Engineering       Scam Intent
              Head                  Head


## Head 1 — Multi-Label Social Engineering

Initial target labels:

- urgency
- fear
- authority impersonation
- reward bait
- financial pressure

Activation/loss concept:

Sigmoid + Binary Cross Entropy


## Head 2 — Multi-Class Scam Intent

Target taxonomy should cover important Indian fraud categories such as:

- Fake KYC
- OTP / Credential Theft
- UPI / Payment Fraud
- Job Scam
- Delivery / Courier Fraud
- Electricity Bill Fraud
- Bank Account Freeze Scam
- Refund Scam
- Loan Scam
- SIM Swap Scam
- legitimate / benign class where appropriate

The FINAL taxonomy must be determined by dataset coverage and label quality.

Activation/loss concept:

Softmax + Cross Entropy


# 15. MODEL SELECTION POLICY

The old mandatory model:

xlm-roberta-base

is now only a BASELINE candidate.

Potential models may include stronger multilingual transformers.

Model selection must consider:

- English accuracy
- Hindi accuracy
- Hinglish/code-mixed accuracy
- macro F1
- per-class recall
- scam recall
- false-positive rate
- inference latency
- GPU/CPU memory
- export/deployment compatibility

Do NOT choose xlm-roberta-large merely because the new laptop can run it.

Train/evaluate a sensible baseline first.

Then compare stronger alternatives.

Dataset quality takes priority over model size.


# 16. TOKENIZATION

The historical max_length=128 restriction is retired.

Candidate lengths such as:

128
256

should be evaluated against actual scam-message length distributions.

Longer context should only be used if it materially improves classification.

Sliding windows may be used for unusually long messages if justified.


# 17. ML TRAINING HARDWARE

Primary training accelerator:

NVIDIA RTX 5050 Laptop GPU — 8GB VRAM.

Use PyTorch + NVIDIA CUDA where compatibility is validated.

Training configuration should exploit:

- mixed precision where stable
- GPU batching
- early stopping
- checkpointing
- reproducible seeds
- class weighting/focal strategies only when justified
- validation-driven model selection

Do NOT assume a batch size before measuring VRAM consumption.


# 18. ONNX AND INFERENCE POLICY

ONNX is NO LONGER a mandatory architectural requirement.

The trained model is the primary asset.

Possible inference runtimes include:

1. ONNX Runtime CUDA
2. PyTorch CUDA
3. ONNX Runtime CPU
4. other optimized runtimes only if justified

Important RTX 5050 / Blackwell rule:

Do NOT assume that merely seeing:

CUDAExecutionProvider

means ONNX inference is actually executing efficiently on the GPU.

When Track D exists, perform a dedicated inference benchmark.

Verify:

- actual execution provider
- fallback behavior
- warm-up latency
- median latency
- p95 latency
- GPU utilization
- VRAM usage
- numerical agreement
- CPU vs GPU performance

Avoid unofficial/community ONNX Runtime builds unless official runtimes
demonstrably fail and the alternative has been carefully validated.

Do NOT introduce DirectML or TensorRT prematurely.

If ONNX CUDA creates compatibility problems but PyTorch CUDA performs well,
PyTorch CUDA is an acceptable deployment runtime.


# 19. DATASET STRATEGY

Dataset quality is one of the highest-priority components of ScamShield.

Candidate dataset stack from previous research includes:

1. UCI SMS Spam Collection
2. Mendeley SMS Phishing / Smishing datasets
3. Indian multilingual scam-message datasets
4. OTP / OTP-intent phishing datasets
5. phishing/social-engineering datasets
6. Hindi/English SMS spam datasets

Dataset availability, licensing, actual label quality, and usefulness must be
verified before inclusion.

Do NOT blindly concatenate datasets.


# 20. TRAINING DATA CONTRACT

Canonical dataset concept:

- id
- text
- language
- source_dataset
- is_scam

Head 1:

- social_urgency
- social_fear
- social_authority_impersonation
- social_reward_bait
- social_financial_pressure

Head 2:

- intent_label
- intent_id

Useful metadata:

- has_url
- has_phone
- has_otp
- has_upi

Fields such as risk_score or reason_text should NOT automatically be used as
supervised targets unless their provenance and quality are trustworthy.


# 21. DATA QUALITY REQUIREMENTS

Before training:

1. normalize source schemas
2. verify labels
3. remove duplicates
4. detect near-duplicates
5. prevent train/test leakage
6. inspect class imbalance
7. inspect language distribution
8. inspect dataset-source bias
9. create deterministic splits
10. document dataset provenance

Synthetic augmentation may be used carefully for Indian scam variation.

Examples:

- bank-name mutation
- UPI/payment variation
- courier variation
- electricity-provider variation
- rupee amount variation
- Hinglish variation
- controlled obfuscation

Synthetic examples must NOT dominate evaluation data.

Validation/test sets should contain real or independently curated examples
where possible.


# 22. EXTERNAL INTELLIGENCE

Primary planned external services:

## VirusTotal

Purpose:

Historical URL reputation / security-engine verdicts.

Must handle:

- rate limiting
- timeout
- quota exhaustion
- unknown URL
- API failure

UNKNOWN must not equal SAFE.


## WhoisXML

Purpose:

Domain registration information / age.

Must handle:

- missing WHOIS
- privacy-protected records
- parsing errors
- quota exhaustion
- timeout

UNKNOWN must not automatically equal SAFE or MALICIOUS.


## AWS

boto3/ECS is used for remote sandbox orchestration.

Cloud interaction must fail gracefully.


# 23. LAYER 5 — FAN-IN / SYNCHRONIZATION

Independent intelligence tracks should execute concurrently where appropriate.

Use structured concurrency / asyncio patterns carefully.

One failed track must NOT destroy the entire scan.

Each track should return a structured status such as:

- completed
- unavailable
- timeout
- failed
- skipped

plus its evidence.

The aggregation engine must know which evidence was actually available.


# 24. LAYER 6 — RISK AGGREGATION

Historical architecture used approximately:

ML      = 40%
URL     = 25%
Domain  = 20%
Sandbox = 15%

These are INITIAL architecture weights, NOT scientifically calibrated final
weights.

Do NOT tune final scoring using simulated Track C or heuristic Track D output.

After real components exist:

1. collect validation scans
2. compare component signals
3. analyze false positives/negatives
4. calibrate weighting
5. validate thresholds

Missing evidence should be handled explicitly.

If a component is unavailable, redistribution may be applied to available
signals only when mathematically justified.

Do NOT treat missing evidence as zero-risk evidence.


# 25. RISK CATEGORIES

Historical categories:

0–30   Safe
31–60  Suspicious
61–100 High Risk

These thresholds are provisional.

Final thresholds should be calibrated against evaluation data.

UI terminology should avoid claiming absolute safety.

Prefer wording such as:

- Low Risk
- Suspicious
- High Risk

where appropriate.


# 26. LAYER 7 — EXPLANATION ENGINE

Generative AI is intentionally NOT part of the current explanation engine.

Use deterministic, evidence-grounded templates.

Supported reporting languages:

- English
- Hindi

Explanation generation must use ACTUAL evidence.

Example:

"The message creates urgency and impersonates SBI. The included domain is
recently registered and resembles the official SBI domain."

Do NOT generate claims such as:

"Sandbox detected password fields"

unless the sandbox actually returned that evidence.

The explanation layer must distinguish:

- detected
- not detected
- unavailable
- not analyzed


# 27. LAYER 8 — PERSISTENCE AND FRONTEND

PostgreSQL is the primary local persistence/cache database.

SQLite fallback currently exists.

Persist relevant structured scan information such as:

- scan identifier
- cache identity
- normalized text
- extracted entities
- component results
- risk result
- explanation
- timestamps
- sandbox screenshot/reference where appropriate

Avoid unnecessarily storing extremely large base64 payloads if a cleaner
storage/reference design becomes appropriate.

React Vite displays the final structured report.


# 28. CACHE STRATEGY

Current PostgreSQL cache is sufficient until measurements prove otherwise.

Do NOT introduce Redis simply because 24GB RAM is available.

If future testing demonstrates a meaningful bottleneck, Redis or an
in-process hot cache may be reconsidered.

Optimize actual bottlenecks, not hypothetical scale.


# 29. CONCURRENCY POLICY

Do NOT blindly increase concurrency to 8, 16, or higher based on CPU/RAM.

Concurrency must account for:

- OCR memory
- model VRAM
- PostgreSQL
- API rate limits
- VirusTotal quota
- WhoisXML quota
- AWS task limits

Measure memory and latency under concurrent scans before increasing limits.


# 30. SECURITY PRINCIPLES

1. Never trust user-provided URLs.
2. Avoid rendering suspicious sites locally.
3. Validate uploaded files.
4. Enforce request/image size limits.
5. Apply network timeouts.
6. Handle malformed external responses.
7. Never expose API secrets.
8. Keep .env outside Git.
9. Log safely without leaking secrets.
10. Isolate active malicious-site browsing remotely.
11. Treat external intelligence as evidence, not unquestionable truth.
12. Treat unavailable evidence explicitly.


# 31. CURRENT IMPLEMENTATION STATUS

SUBSTANTIALLY IMPLEMENTED:

- FastAPI backend
- /scan/text
- /scan/image
- normalization
- entity extraction
- PostgreSQL connection
- SHA-256 caching
- SQLite fallback
- asynchronous orchestration
- Track A structure
- Track B structure
- risk aggregation structure
- deterministic English/Hindi explanation engine
- persistence
- React frontend

PARTIALLY IMPLEMENTED / NEEDS VALIDATION:

- OCR pipeline
- real VirusTotal behavior
- real WhoisXML behavior
- security boundary of local domain/TLS inspection

NOT YET REAL:

- Track D trained ML model
- Track C real AWS sandbox result pipeline

Current Track D uses deterministic heuristic fallback because trained model
artifacts are absent.

Current Track C contains simulated/mock behavior.

Never describe those simulated outputs as real intelligence.


# 32. CURRENT DEVELOPMENT ENVIRONMENT

Known working backend environment:

backend/venv

Python:

3.11.9

Representative installed runtime components currently include:

- FastAPI
- SQLAlchemy
- asyncpg
- OpenCV
- PaddleOCR
- PaddlePaddle
- ONNX Runtime
- PyTesseract Python package

PostgreSQL 18 is installed locally.

Dependency declarations currently require cleanup so requirements.txt fully
represents the active runtime.

Do not repeatedly rebuild the environment unless an actual dependency problem
requires it.


# 33. DEVELOPMENT WORKFLOW

All development must be incremental.

For every meaningful task:

1. Inspect current implementation
2. Define one bounded objective
3. Propose changes
4. Review proposal
5. Implement
6. Test
7. Benchmark where relevant
8. Commit
9. Update project state
10. Continue

Do NOT allow AI coding agents to perform broad autonomous rewrites.


# 34. AI TOOL WORKFLOW

Antigravity IDE:

Primary implementation/coding agent.

ChatGPT:

- project management
- architecture
- ML strategy
- code/design review
- debugging strategy
- benchmark interpretation
- implementation planning

Claude / Gemini / other research tools:

- independent technical research
- compatibility research
- alternative architecture analysis
- code review

No AI recommendation automatically becomes a project decision.

Recommendations must be evaluated against:

- current repository
- current hardware
- project goal
- measurements
- implementation cost


# 35. CURRENT EXECUTION PLAN

PHASE 1 — OCR BASELINE
Create benchmark harness and measure current OCR.

PHASE 2 — OCR FINALIZATION
Optimize OCR architecture based on measured accuracy/latency.

PHASE 3 — DATA CONTRACT
Finalize scam taxonomy, social labels and canonical dataset schema.

PHASE 4 — DATASET PIPELINE
Acquire, verify, clean, normalize, deduplicate, label and split datasets.

PHASE 5 — BASELINE ML
Train first real multi-task multilingual model.

PHASE 6 — MODEL EXPERIMENTATION
Use RTX 5050 to compare justified model/configuration alternatives.

PHASE 7 — MODEL SELECTION
Select model based on accuracy + latency + reliability.

PHASE 8 — INFERENCE OPTIMIZATION
Evaluate PyTorch CUDA / ONNX CUDA / CPU fallback.

PHASE 9 — TRACK A/B FINALIZATION
Replace remaining simulations and validate external intelligence.

PHASE 10 — AWS SANDBOX
Implement real isolated Fargate/Playwright analysis and result retrieval.

PHASE 11 — RISK CALIBRATION
Calibrate weights and thresholds using real outputs.

PHASE 12 — FRONTEND FINALIZATION
Improve reporting UX and evidence presentation.

PHASE 13 — END-TO-END VALIDATION
Test normal, scam, malformed, timeout and component-failure scenarios.

PHASE 14 — PORTFOLIO PACKAGE
Prepare architecture diagrams, evaluation metrics, README, demo and technical
documentation.


# 36. CURRENT ACTIVE TASK

CURRENT TASK:

Benchmark the existing OCR pipeline BEFORE redesigning it.

The benchmark should measure per screenshot:

- extracted text
- cleaned text
- OCR confidence/quality
- processing latency
- OCR path
- extracted URLs
- phone numbers
- UPI IDs

When ground truth exists:

- CER
- WER

Aggregate:

- average latency
- median latency
- p95 latency
- failure count
- fallback count

Also evaluate security-critical entity preservation.

Production OCR behavior should remain unchanged until baseline measurements
exist.


# 37. DECISIONS THAT ARE CURRENTLY FROZEN

KEEP:

- React Vite frontend
- FastAPI backend
- PostgreSQL primary persistence
- asynchronous fan-out/fan-in concept
- remote isolation for active malicious URL browsing
- English/Hindi/Hinglish focus
- deterministic explanation architecture
- multi-task scam NLP concept

NOT FROZEN:

- exact transformer backbone
- ONNX requirement
- model precision
- tokenizer length
- OCR models
- OCR execution provider
- number of OCR passes
- Tesseract fallback
- risk weights
- risk thresholds
- PostgreSQL pool size
- concurrency limit


# 38. THINGS NOT TO ADD WITHOUT EVIDENCE

Do not automatically add:

- Redis
- vector databases
- LLM APIs
- microservices
- Kubernetes
- Kafka
- oversized PostgreSQL pools
- unofficial ONNX Runtime builds
- TensorRT
- DirectML
- NPU inference
- additional external APIs
- extra OCR engines

Every additional subsystem increases:

- latency
- dependency risk
- debugging complexity
- maintenance cost

Add one only when its measurable value exceeds that cost.


# 39. FINAL SUCCESS CRITERIA

The finished ScamShield should allow a user to submit suspicious text or a
mobile screenshot.

The system should:

1. accurately recover the message
2. understand English/Hindi/Hinglish semantics
3. identify scam intent
4. identify social-engineering tactics
5. extract security-relevant entities
6. analyze suspicious URLs
7. analyze domain intelligence
8. safely inspect suspicious websites remotely
9. combine available evidence intelligently
10. generate an evidence-grounded risk assessment
11. explain the result clearly in English/Hindi
12. return the result with low practical latency
13. gracefully survive unavailable components
14. cache repeated scans
15. expose enough metrics to demonstrate objectively that the system works

Portfolio evaluation should include measurable results such as:

- OCR CER/WER/entity accuracy
- ML precision/recall/F1
- per-class performance
- confusion matrix
- false-positive analysis
- inference latency
- OCR latency
- end-to-end latency
- cache latency
- graceful-failure demonstrations


# 40. FINAL ENGINEERING RULE

Do not optimize ScamShield for impressive technology names.

Optimize it for:

ACCURATE INPUT
        +
STRONG MULTILINGUAL UNDERSTANDING
        +
REAL CYBERSECURITY EVIDENCE
        +
SAFE EXECUTION
        +
CALIBRATED SCORING
        +
FAST USER EXPERIENCE
        +
DEFENSIBLE EVALUATION

When an old implementation decision conflicts with this goal, measure the
alternative and choose the better engineering solution.