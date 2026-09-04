import os
import sys
import re
import csv
import json
import random
import hashlib
from pathlib import Path
from collections import Counter, defaultdict

# Force UTF-8 for Windows console
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

random.seed(42)

# Paths
backend_dir = Path(__file__).resolve().parent.parent
raw_dir = backend_dir / "data" / "raw"
processed_dir = backend_dir / "data" / "processed"
scripts_dir = backend_dir / "scripts"
processed_dir.mkdir(parents=True, exist_ok=True)

# Regex Patterns
AADHAAR_RE = re.compile(r'\b\d{4}\s\d{4}\s\d{4}\b')
DEVANAGARI_RE = re.compile(r'[\u0900-\u097F]')
URL_RE = re.compile(r'https?://\S+|www\.\S+|[a-zA-Z0-9\-]+\.(?:com|org|net|in|xyz|me|online|top|site|live|co|info|biz|apk|app|page|tk|ml|ly|io)(?:/\S*)?', re.IGNORECASE)
PHONE_RE = re.compile(r'\b(?:\+91|91|0)?[6-9]\d{9}\b|\b\d{5}[-\s]?\d{5}\b')
OTP_RE = re.compile(r'\b(?:otp|one time password|verification code|pin|passcode|ओटीपी|पिन)\b', re.IGNORECASE)
UPI_RE = re.compile(r'\b[a-zA-Z0-9.\-_]+@[a-zA-Z]{2,}\b')
AMOUNT_RE = re.compile(r'(?:INR|Rs\.?|₹|rs\.?|\$|£)\s*(\d+(?:,\d+)*(?:\.\d{1,2})?)', re.IGNORECASE)

STRONG_INDIC_WORDS = {
    'aapka', 'aapke', 'aapko', 'apna', 'apne', 'apni', 'karein', 'kare', 'karo', 'karna',
    'kijiye', 'krwalo', 'kardo', 'turant', 'dhokhadhadi', 'bijli', 'challan', 'parivahan',
    'khata', 'khate', 'inaam', 'badhai', 'paise', 'paisa', 'rupaye', 'rupay', 'dhanyawad',
    'chahiye', 'chalega', 'adhikari', 'sambandhit', 'suvidha', 'bhugtan', 'mubarak',
    'yojana', 'sarkari', 'suchna', 'warna', 'varna', 'kripya', 'sahab', 'shulk', 'jama',
    'paayein', 'sampark', 'jaldi'
}

INDIC_GRAMMAR_PARTICLES = {
    'hai', 'hain', 'hoga', 'hogi', 'hoge', 'gaya', 'gayi', 'gaye', 'nahi', 'nahin', 'mat',
    'bheja', 'bheje', 'bhejo', 'raha', 'rahe', 'rahi', 'rha', 'rhi', 'mujhe', 'mera', 'meri',
    'mere', 'tera', 'teri', 'tere', 'humara', 'humare', 'bhai', 'beta', 'papa', 'pata',
    'baat', 'karta', 'karti', 'karte', 'liye', 'wala', 'wali', 'wale', 'hua', 'hui', 'hue'
}

def redact_aadhaar(text: str) -> str:
    return AADHAAR_RE.sub("[Aadhaar Redacted]", text)

def detect_language(text: str) -> str:
    if bool(DEVANAGARI_RE.search(text)):
        return "Hindi"
    
    tokens = set(w.lower().strip(".,!?:;\"'()[]{}<>-/\\#@$%^&*~`") for w in text.split())
    if not tokens:
        return "English"
    
    strong_hits = tokens & STRONG_INDIC_WORDS
    grammar_hits = tokens & INDIC_GRAMMAR_PARTICLES
    
    # Rule 1: At least 1 strong unambiguous Indic keyword
    if len(strong_hits) >= 1:
        return "Hinglish"
    
    # Rule 2: At least 2 distinct Indic grammatical particles
    if len(grammar_hits) >= 2:
        return "Hinglish"
        
    return "English"

def extract_social_engineering_tags(text: str, is_scam: int) -> dict:
    if not is_scam:
        return {
            "urgency": 0, "fear": 0, "authority_impersonation": 0,
            "reward_bait": 0, "financial_pressure": 0
        }
    
    text_lower = text.lower()
    
    urgency = int(any(w in text_lower for w in [
        'urgent', 'immediately', 'immediate', 'today', '24 hours', '24 ghante', 'turant', 'aaj raat',
        'expires', 'expire', 'hurry', 'limited time', 'limited period', 'last day', 'ends today', '12 hours',
        'तुरंत', 'आज रात', '२४ घंटे', 'अंतिम दिन', 'जल्दी', 'shighra'
    ]))
    
    fear = int(any(w in text_lower for w in [
        'block', 'blocked', 'suspend', 'suspended', 'freeze', 'arrest', 'police', 'cyber crime',
        'crime branch', 'jail', 'penalty', 'warning', 'virus', 'hacked', 'cancel', 'band ho', 'sthagit',
        'ब्लॉक', 'बंद', 'स्थगित', 'चेतावनी', 'वायरस', 'जुर्माना', 'कार्रवाई', 'गैर-जमानती'
    ]))
    
    authority = int(any(w in text_lower for w in [
        'sbi', 'hdfc', 'icici', 'axis', 'kotak', 'rbi', 'cert-in', 'cyber cell', 'police', 'customs',
        'income tax', 'india post', 'government', 'sarkari', 'telecom', 'department of telecom', 'trai',
        'parivahan', 'msedcl', 'bses', 'uppcl', 'bescom', 'tsspdcl',
        'भारतीय स्टेट बैंक', 'दूरसंचार विभाग', 'भारत सरकार', 'कस्टम्स', 'बिजली विभाग', 'यातायात पुलिस'
    ]))
    
    reward = int(any(w in text_lower for w in [
        'won', 'winner', 'congratulations', 'badhai', 'lottery', 'reward', 'free', 'cashback', 'bonus',
        'inaam', 'gift', 'discount', 'prize', 'claim', 'special offer', 'बधाई', 'इनाम', 'लॉटरी', 'कैशबैक'
    ]))
    
    financial = int(any(w in text_lower for w in [
        'loan', 'debit card', 'credit card', 'credited', 'debited', 'transfer', 'amount', 'rs.', 'inr',
        'rupees', 'emi', 'refund', 'duty charges', 'fee', 'shulk', 'bhugtan', 'balance', 'challan',
        'रुपये', 'भुगतान', 'शुल्क', 'चालान'
    ]))
    
    return {
        "urgency": urgency,
        "fear": fear,
        "authority_impersonation": authority,
        "reward_bait": reward,
        "financial_pressure": financial
    }

def classify_scam_intent(text: str, is_scam: int) -> str:
    if not is_scam:
        return "Legitimate / Benign"
    
    text_lower = text.lower()
    
    if any(k in text_lower for k in ['challan', 'parivahan', 'traffic police', 'यातायात पुलिस', 'चालान', 'vahan fine']):
        return "Traffic e-Challan"
    elif any(k in text_lower for k in ['electricity', 'power bill', 'light bill', 'bijli', 'बिजली बिल', 'बिजली कनेक्शन', 'msedcl', 'bses', 'uppcl', 'bescom']):
        return "Electricity Disconnection"
    elif any(k in text_lower for k in ['kyc', 'pan card', 'aadhaar', 'update your kyc', 'kyc suspend', 'केवाईसी', 'सत्यापन', 'e-kyc']):
        return "Fake KYC"
    elif any(k in text_lower for k in ['customs', 'parcel', 'courier', 'fedex', 'warehouse', 'delivery', 'पार्सल', 'कस्टम्स', 'india post', 'bluedart', 'delhivery']):
        return "Courier Scam"
    elif any(k in text_lower for k in ['lottery', 'winner', 'kbc', 'prize', 'inaam', 'लॉटरी', 'इनाम', 'बधाई', '7.5 lakh', '25 lakh', 'dhan yojana']):
        return "Lottery / Prize"
    elif any(k in text_lower for k in ['job', 'work from home', 'daily salary', 'part time job', 'घर बैठे कमाई', 'नौकरी', 'youtube like', 'hotel review']):
        return "Telegram Job"
    elif any(k in text_lower for k in ['upi', 'google pay', 'gpay', 'phonepe', 'paytm', 'cashback', 'collect request', 'कलेक्ट']):
        return "UPI Fraud"
    elif any(k in text_lower for k in ['account block', 'account suspended', 'account freeze', 'khata block', 'खाता ब्लॉक', 'खाता स्थगित', 'cbi', 'cyber cell', 'digital arrest', 'money laundering']):
        return "Bank Account Freeze"
    elif any(k in text_lower for k in ['otp', 'verification code', 'one time password', 'passcode', 'ओटीपी', 'पिन']):
        return "OTP / Credential Theft"
    elif any(k in text_lower for k in ['loan', 'personal loan', 'pre-approved loan', 'ऋण', 'लोन']):
        return "Loan Scam"
    else:
        return "General Spam / Telemarketing"

def build_record(text: str, is_scam: int, source: str, rec_id: str, split_group: str = None) -> dict:
    clean_text = redact_aadhaar(text.strip())
    lang = detect_language(clean_text)
    social_tags = extract_social_engineering_tags(clean_text, is_scam)
    intent = classify_scam_intent(clean_text, is_scam)
    
    return {
        "id": rec_id,
        "text": clean_text,
        "language": lang,
        "source_dataset": source,
        "is_scam": is_scam,
        "head1_social_engineering": social_tags,
        "head2_scam_intent": intent,
        "split_group": split_group if split_group else f"real_{source.lower().replace('/', '_')}",
        "metadata": {
            "has_url": bool(URL_RE.search(clean_text)),
            "has_phone": bool(PHONE_RE.search(clean_text)),
            "has_otp": bool(OTP_RE.search(clean_text)),
            "has_upi": bool(UPI_RE.search(clean_text)),
            "has_amount": bool(AMOUNT_RE.search(clean_text))
        }
    }

# ==========================================
# 1. INGEST ALL REAL DATA SOURCES
# ==========================================
print("=" * 60)
print("1. INGESTING ALL REAL DATA SOURCES")
print("=" * 60)

real_records = []
seen_hashes = set()

def add_real_record(text: str, is_scam: int, source: str):
    clean_text = text.strip()
    if not clean_text or len(clean_text) < 4:
        return
    norm_hash = hashlib.sha256(clean_text.lower().encode('utf-8')).hexdigest()
    if norm_hash in seen_hashes:
        return
    seen_hashes.add(norm_hash)
    
    rec_id = f"real_{len(real_records)+1:06d}"
    rec = build_record(clean_text, is_scam, source, rec_id)
    real_records.append(rec)

# 1. Ingest UCI
uci_path = raw_dir / "uci_sms_spam" / "SMSSpamCollection"
if uci_path.exists():
    with open(uci_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parts = line.strip().split("\t", 1)
            if len(parts) == 2:
                is_scam = 1 if parts[0].strip().lower() == "spam" else 0
                add_real_record(parts[1], is_scam, "UCI_SMS_Spam")
    print(f"Loaded UCI SMS Spam. Cumulative real records: {len(real_records)}")

# 2. Ingest Indian Telecom SMS
ind_path = raw_dir / "indian_sms" / "spam_ham_india.csv"
if ind_path.exists():
    with open(ind_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        next(reader, None)
        for row in reader:
            if len(row) >= 2:
                text = row[0].strip()
                is_scam = 1 if "spam" in row[1].strip().lower() else 0
                add_real_record(text, is_scam, "Indian_Telecom_SMS")
    print(f"Loaded Indian Telecom SMS. Cumulative real records: {len(real_records)}")

# 3. Ingest Smishing Dataset
smish_path = raw_dir / "smishing_dataset" / "Combined-Labeled-Dataset.csv"
if smish_path.exists():
    with open(smish_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        next(reader, None)
        for row in reader:
            if len(row) >= 2:
                text = row[0].strip()
                is_scam = 1 if row[1].strip() == "1" or "smish" in row[1].strip().lower() else 0
                add_real_record(text, is_scam, "Smishing_Dataset")
    print(f"Loaded Smishing Dataset. Cumulative real records: {len(real_records)}")

# 4. Ingest Tier A Real Data (Hinglish/Hindi)
tier_a_path = processed_dir / "tier_a_indian_filtered.jsonl"
if tier_a_path.exists():
    with open(tier_a_path, "r", encoding="utf-8") as f:
        for line in f:
            line_str = line.strip()
            if line_str:
                data = json.loads(line_str)
                is_scam = 1 if str(data.get("raw_label", "0")) in ["1", "scam"] else 0
                add_real_record(data["text"], is_scam, data.get("source_dataset", "ysangam/Indian_Cyber_Scam_Hinglish"))
    print(f"Loaded Tier A Indian Filtered Data. Cumulative real records: {len(real_records)}")

# 5. Ingest Curated Real Benchmark Ground Truth (Devanagari & Hinglish Real SMS)
gt_path = scripts_dir / "ground_truth.json"
if gt_path.exists():
    with open(gt_path, "r", encoding="utf-8") as f:
        gt_data = json.load(f)
        for img_name, text in gt_data.items():
            # Classify scam vs benign based on known ground truth categories
            text_lower = text.lower()
            is_scam = 1 if any(k in text_lower for k in ['scam', 'block', 'kyc', 'inaam', 'lottery', 'winner', 'loan', 'virus', 'apk', 'customs', 'duty']) else 0
            add_real_record(text, is_scam, "Benchmark_Ground_Truth")
    print(f"Loaded Real Benchmark Ground Truth. Cumulative real records: {len(real_records)}")

# 6. Ingest Kaggle Hindi Cleaned Data (Devanagari Hindi Ham & Scam)
kaggle_hindi_path = raw_dir / "kaggle_hindi_clean.jsonl"
if kaggle_hindi_path.exists():
    with open(kaggle_hindi_path, "r", encoding="utf-8") as f:
        for line in f:
            line_str = line.strip()
            if line_str:
                data = json.loads(line_str)
                add_real_record(data["text"], data["is_scam"], data.get("source_dataset", "Kaggle_Hindi_Merged"))
    print(f"Loaded Kaggle Hindi Cleaned Data. Cumulative real records: {len(real_records)}")


# ==========================================
# 2. STRATIFIED SPLITTING (REAL DATA ONLY)
# ==========================================
print("\n" + "=" * 60)
print("2. STRATIFIED SPLITTING (REAL DATA ONLY: 80% / 10% / 10%)")
print("=" * 60)

random.shuffle(real_records)

strata = defaultdict(list)
for r in real_records:
    strata[(r["language"], r["is_scam"])].append(r)

train_real, val_set, test_set = [], [], []

for key, items in strata.items():
    n = len(items)
    n_train = int(n * 0.80)
    n_val = int(n * 0.10)
    
    # Ensure at least 1 sample in test if n >= 2
    if n >= 2 and (n - n_train - n_val) == 0:
        n_train -= 1
        
    train_real.extend(items[:n_train])
    val_set.extend(items[n_train:n_train+n_val])
    test_set.extend(items[n_train+n_val:])

print(f"Real Data Splits:")
print(f"  - Train Real: {len(train_real)} samples")
print(f"  - Val Set   : {len(val_set)} samples")
print(f"  - Test Set  : {len(test_set)} samples")

# ==========================================
# 3. STRICT SYNTHETIC INJECTION (TRAIN ONLY)
# ==========================================
print("\n" + "=" * 60)
print("3. STRICT SYNTHETIC INJECTION (TRAIN ONLY)")
print("=" * 60)

synthetic_corpus_path = processed_dir / "synthetic_indian_corpus.jsonl"
synthetic_records = []

if synthetic_corpus_path.exists():
    with open(synthetic_corpus_path, "r", encoding="utf-8") as f:
        for line in f:
            line_str = line.strip()
            if line_str:
                synthetic_records.append(json.loads(line_str))
    print(f"Loaded {len(synthetic_records)} synthetic Indian records from {synthetic_corpus_path.name}")
else:
    print(f"WARNING: {synthetic_corpus_path} not found!")

# Final train set is train_real + synthetic_records
final_train = train_real + synthetic_records
random.shuffle(final_train)

# Strict Validation Assertions
assert all(r.get("source_dataset") != "Synthetic_Tier_C" for r in val_set), "LEAKAGE ERROR: Synthetic data found in val_set!"
assert all(r.get("source_dataset") != "Synthetic_Tier_C" for r in test_set), "LEAKAGE ERROR: Synthetic data found in test_set!"
print("Zero synthetic leakage assertion PASSED for val_set and test_set.")

# ==========================================
# 4. EXPORT STANDARDIZED JSONL DATASETS
# ==========================================
print("\n" + "=" * 60)
print("4. EXPORTING STANDARDIZED JSONL DATASETS")
print("=" * 60)

def save_jsonl(data, file_path):
    with open(file_path, "w", encoding="utf-8") as f:
        for r in data:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"Saved {len(data):6d} rows to {file_path.name}")

train_jsonl_path = processed_dir / "train.jsonl"
val_jsonl_path = processed_dir / "val.jsonl"
test_jsonl_path = processed_dir / "test.jsonl"

test_hindi_path = processed_dir / "test_hindi.jsonl"
test_hinglish_path = processed_dir / "test_hinglish.jsonl"
test_english_path = processed_dir / "test_english.jsonl"

save_jsonl(final_train, train_jsonl_path)
save_jsonl(val_set, val_jsonl_path)
save_jsonl(test_set, test_jsonl_path)

# Language-specific evaluation slices strictly from test.jsonl
test_hindi = [r for r in test_set if r["language"] == "Hindi"]
test_hinglish = [r for r in test_set if r["language"] == "Hinglish"]
test_english = [r for r in test_set if r["language"] == "English"]

save_jsonl(test_hindi, test_hindi_path)
save_jsonl(test_hinglish, test_hinglish_path)
save_jsonl(test_english, test_english_path)

# ==========================================
# 5. CLEAN UP LEGACY .JSON ARRAY FILES
# ==========================================
print("\n" + "=" * 60)
print("5. CLEANING UP LEGACY .JSON ARRAY FILES")
print("=" * 60)

legacy_json_files = [
    "scamshield_all_unified.json",
    "train.json",
    "val.json",
    "test.json",
    "test_english.json",
    "test_hindi.json",
    "test_hinglish.json"
]

for fname in legacy_json_files:
    fpath = processed_dir / fname
    if fpath.exists():
        fpath.unlink()
        print(f"Deleted legacy file: {fname}")

# ==========================================
# 6. FINAL SUMMARY TABLE
# ==========================================
print("\n" + "=" * 70)
print(f"{'OUTPUT DATASET FILE':<35} | {'RECORD COUNT':<15} | {'SYNTHETIC %':<12}")
print("=" * 70)

files_summary = [
    (train_jsonl_path, len(final_train), len(synthetic_records) / len(final_train) * 100),
    (val_jsonl_path, len(val_set), 0.0),
    (test_jsonl_path, len(test_set), 0.0),
    (test_english_path, len(test_english), 0.0),
    (test_hinglish_path, len(test_hinglish), 0.0),
    (test_hindi_path, len(test_hindi), 0.0)
]

for path, count, synth_pct in files_summary:
    print(f"{path.name:<35} | {count:<15} | {synth_pct:<10.2f}%")

print("=" * 70)
print("\nAll datasets assembled and saved in standardized JSONL format!")
