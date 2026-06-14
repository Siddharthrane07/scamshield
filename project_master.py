# project_master_content = """# ScamShield AI: High-Performance Multilingual Scam Detection Architecture
# **PROJECT_MASTER.md** - Ultimate Source of Truth for Context & Scope

# ## 1. Project Scope
# **Objective:** Develop a portfolio-grade, high-performance, and high-accuracy scam detection engine optimized for speed and low resource consumption.
# **Timeline:** 2-week execution block.
# **Nature:** Local-first processing with selective asynchronous cloud offloading.
# **Target Audience / Focus:** Indian demographic (English, Hindi, Hinglish text/images). 

# ## 2. Core Constraints
# - **Hardware Profile:** 8GB RAM Local Environment Limit.
# - **Latency Target:** Sub 4-second total execution time for the synchronous pipeline.
# - **Cache Hit Latency:** Sub 50ms bypass.
# - **Model Size Limit:** < 450MB RAM allocation for the ML Engine (Must use ONNX).
# - **Sandbox Hard Ceiling:** 8-second timeout for AWS Fargate container, with a non-blocking graceful failure path.
# - **Strict Exclusion:** **Marathi language processing is strictly EXCLUDED** from text normalization, analysis, and reporting layers.
# - **Generative AI:** Strictly prohibited for Layer 7. Explanations must use a deterministic, scratch-built Algorithmic Structural Template Engine.

# ## 3. System Architecture (Layers 1 to 8)

# ### Layer 1: Entry Point & Input Ingestion
# - **Tech:** React Vite Frontend -> Local FastAPI Backend.
# - **Flow:** User uploads multi-part text string or mobile screenshot (English, Hindi, Hinglish).
# - **Action:** Intercept request, assign unique `scan_id` (e.g., scam_2026_x89), initiate global log.

# ### Layer 2: Local Detox & Pre-Processing
# - **Tech:** Local CPU Worker / Python / OpenCV / PyTesseract.
# - **Action 1 (Image):** OpenCV Adaptive Thresholding -> PyTesseract `image_to_string(img, lang='eng+hin')`.
# - **Action 2 (Text):** Strip trailing spaces, convert casing, extract structured arrays (URLs, phones, UPIs) via Regex.
# - **Output:** Clean JSON metadata packet with normalized strings.

# ### Layer 3: Intelligent Routing & Local DB Caching (Gatekeeper)
# - **Tech:** PostgreSQL, SHA-256 Hashing.
# - **Condition 1:** Check SHA-256 hash of extracted text/URL in DB. If <24hrs old -> Fast-forward to Layer 8 (<50ms).
# - **Condition 2:** If URL exists -> Fan-out to Tracks A, B, C, D. If NO URL -> Bypass A, B, C; Route only to Track D.

# ### Layer 4: Parallel Asynchronous Engine Tracks (Fan-Out)
# Executed via `asyncio.gather()`:
# - **Track A (URL Intelligence):** Custom Typo-Squatting/Homoglyph Python script + VirusTotal API check.
# - **Track B (Domain Intelligence):** WhoisXML API (domain age) + Custom low-level socket script for Port 443 TLS cert verification (flags Let's Encrypt/Cloudflare).
# - **Track C (AWS Sandbox):** Ephemeral Linux Docker container on AWS ECS Fargate. Uses Playwright-stealth to traverse redirects, scan DOM for auth inputs, capture full-page PNG.
# - **Track D (Multi-Task ML Engine):** Shared `xlm-roberta-base` ONNX model.
#     - *Head 1:* Social Engineering (Urgency, Fear, Authority, Reward, Financial Pressure).
#     - *Head 2:* Scam Intent (Fake KYC, OTP Theft, UPI Fraud, Job Scams, Delivery Scams).

# ### Layer 5: Synchronization Core (Fan-In)
# - **Tech:** FastAPI `asyncio.gather()` barrier.
# - **Logic:** Collect JSON packets. If Track C times out (>8s) or crashes, apply fallback penalty `{"sandbox_status": "hostile_timeout", "risk_weight": 40}` and proceed.

# ### Layer 6: Weighted Risk Score Computation
# - **Tech:** Local Aggregation Matrix.
# - **Weights:** ML Head (40%), URL Intel (25%), Domain Age+SSL (20%), Sandbox DOM (15%).
# - **Dynamic Override:** If Sandbox fails, 15% redistributes proportionally.
# - **Thresholds:** 0-30 Safe | 31-60 Suspicious | 61-100 High Risk.

# ### Layer 7: Explanation Engine
# - **Tech:** Local Algorithmic Structural Template Engine.
# - **Logic:** Maps math indicators to pre-defined localized templates (English, Hindi). Generates human-readable safety narratives. No GenAI.

# ### Layer 8: Final Reporting & Persistence
# - **Tech:** PostgreSQL -> React Vite UI.
# - **Logic:** Save consolidated scan metrics, explanation strings, and base64 screenshot into DB cache. Ship JSON to UI.

# ## 4. Datasets & Model Training Schema
# Mixed training stack required:
# 1. UCI SMS Spam Collection (baseline ham/spam).
# 2. Mendeley SMS Phishing Dataset (URL/email/phone features).
# 3. Indian Multilingual Scam Message Dataset (English/Hindi/Hinglish).
# 4. SMS-dataset-OTP-OTP_INTENT_Phishing (Indian OTP/intent patterns).
# 5. Zenodo phishing/social-engineering dataset.
# 6. Crowdsourced Hindi + English SMS spam dataset.

# **Training Schema (Shared XLM-R Backbone, 2 Heads):**
# - `id`, `text`, `language` (English, Hindi, Hinglish), `source_dataset`, `is_scam`
# - **Head 1 (Multi-label):** `social_urgency`, `social_fear`, `social_authority_impersonation`, `social_reward_bait`, `social_financial_pressure`
# - **Head 2 (Multi-class):** `intent_label`, `intent_id`
# - **Auxiliary:** `risk_score`, `reason_text`, `has_url`, `has_phone`, `has_otp`, `has_upi`

# ## 5. Required External APIs
# 1. **VirusTotal API:** Free Tier (4 req/min) - Historical AV verdicts.
# 2. **WhoisXML API:** Free Tier (500 req/month) - Domain registration age.
# 3. **AWS boto3:** ECS/Fargate management for ephemeral Playwright containers.

# ## 6. Target Folder Structure