import os
import sys
import re
import csv
import json
import random
import hashlib
from pathlib import Path
from collections import Counter, defaultdict

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

random.seed(42)

# Paths
raw_dir = Path(__file__).resolve().parent.parent / "data" / "raw"
processed_dir = Path(__file__).resolve().parent.parent / "data" / "processed"
processed_dir.mkdir(parents=True, exist_ok=True)

# Regex Patterns
DEVANAGARI_RE = re.compile(r'[\u0900-\u097F]')
LATIN_RE = re.compile(r'[a-zA-Z]')
URL_RE = re.compile(r'https?://\S+|www\.\S+|[a-zA-Z0-9\-]+\.(?:com|org|net|in|xyz|me|online|top|site|live|co|info|biz|ly|io|app|page|ke|ng|ai|ph)(?:/\S*)?', re.IGNORECASE)
PHONE_RE = re.compile(r'\b(?:\+91|91|0)?[6-9]\d{9}\b|\b\d{5}[-\s]?\d{5}\b')
OTP_RE = re.compile(r'\b(?:otp|one time password|verification code|pin|passcode|ओटीपी|पिन)\b', re.IGNORECASE)
UPI_RE = re.compile(r'\b[a-zA-Z0-9.\-_]+@[a-zA-Z]{2,}\b')
AMOUNT_RE = re.compile(r'(?:INR|Rs\.?|₹|rs\.?|\$|£)\s*(\d+(?:,\d+)*(?:\.\d{1,2})?)', re.IGNORECASE)

HINGLISH_WORDS = {
    'aapka', 'aapke', 'aapko', 'apna', 'apne', 'apni', 'karein', 'kare', 'karo', 'karna',
    'turant', 'hai', 'hain', 'ho', 'gaya', 'gayi', 'gaye', 'nahi', 'nahin', 'mat',
    'bheja', 'bheje', 'khata', 'khate', 'inaam', 'badhai', 'paise', 'rupaye', 'rupay',
    'rha', 'rhi', 'rahe', 'raha', 'rahi', 'mujhe', 'mera', 'meri', 'mere', 'tera', 'teri',
    'tere', 'humare', 'humara', 'varna', 'warna', 'band', 'kripya', 'dhanyawad',
    'chahiye', 'wala', 'wali', 'wale', 'hoga', 'hogi', 'hoge', 'liye', 'baat', 'karta',
    'karti', 'karte', 'pata', 'chalega', 'majak', 'real', 'bhai', 'beta', 'papa', 'sahab',
    'sarkari', 'suchna', 'adhikari', 'sambandhit', 'suvidha', 'shulk', 'jama', 'bhugtan',
    'kijiye', 'krwalo', 'kro', 'sir', 'madam', 'jaldi', 'dekh', 'lo', 'kardo', 'diya',
    'pe', 'se', 'ko', 'ka', 'ki', 'ke', 'aur', 'ya', 'par', 'bhi', 'kuch', 'kya'
}

def detect_language(text: str) -> str:
    has_dev = bool(DEVANAGARI_RE.search(text))
    has_lat = bool(LATIN_RE.search(text))
    
    if has_dev and has_lat:
        dev_chars = len(DEVANAGARI_RE.findall(text))
        lat_chars = len(LATIN_RE.findall(text))
        if dev_chars >= 5 and lat_chars >= 5:
            return "Mixed (Hindi+English)"
        elif dev_chars > lat_chars:
            return "Hindi"
        else:
            return "Mixed (Hindi+English)"
    elif has_dev:
        return "Hindi"
    
    tokens = [w.lower().strip(".,!?:;\"'()[]{}") for w in text.split()]
    if not tokens:
        return "English"
    
    hinglish_matches = sum(1 for t in tokens if t in HINGLISH_WORDS)
    ratio = hinglish_matches / len(tokens)
    
    if hinglish_matches >= 2 or ratio >= 0.08:
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
        'ब्लॉक', 'बंद', 'स्थगित', 'चेतावनी', 'वायरस', 'जुर्माना', 'कार्रवाई'
    ]))
    
    authority = int(any(w in text_lower for w in [
        'sbi', 'hdfc', 'icici', 'axis', 'kotak', 'rbi', 'cert-in', 'cyber cell', 'police', 'customs',
        'income tax', 'india post', 'government', 'sarkari', 'telecom', 'department of telecom', 'trai',
        'भारतीय स्टेट बैंक', 'दूरसंचार विभाग', 'भारत सरकार', 'कस्टम्स', 'बिजली विभाग'
    ]))
    
    reward = int(any(w in text_lower for w in [
        'won', 'winner', 'congratulations', 'badhai', 'lottery', 'reward', 'free', 'cashback', 'bonus',
        'inaam', 'gift', 'discount', 'prize', 'claim', 'special offer', 'बधाई', 'इनाम', 'लॉटरी', 'कैशबैक'
    ]))
    
    financial = int(any(w in text_lower for w in [
        'loan', 'debit card', 'credit card', 'credited', 'debited', 'transfer', 'amount', 'rs.', 'inr',
        'rupees', 'emi', 'refund', 'duty charges', 'fee', 'shulk', 'bhugtan', 'balance', 'रुपये', 'भुगतान', 'शुल्क'
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
    
    if any(k in text_lower for k in ['kyc', 'pan card', 'aadhaar', 'update your kyc', 'kyc suspend', 'केवाईसी', 'सत्यापन']):
        return "Fake KYC"
    elif any(k in text_lower for k in ['otp', 'verification code', 'one time password', 'passcode', 'ओटीपी', 'पिन']):
        return "OTP / Credential Theft"
    elif any(k in text_lower for k in ['lottery', 'winner', 'kbc', 'prize', 'inaam', 'लॉटरी', 'इनाम', 'बधाई', '7.5 lakh', '25 lakh']):
        return "Lottery / Prize Scam"
    elif any(k in text_lower for k in ['customs', 'parcel', 'courier', 'fedex', 'warehouse', 'delivery', 'पार्सल', 'कस्टम्स']):
        return "Delivery / Courier Fraud"
    elif any(k in text_lower for k in ['electricity', 'power bill', 'light bill', 'bijli', 'बिजली बिल', 'बिजली कनेक्शन']):
        return "Electricity Bill Fraud"
    elif any(k in text_lower for k in ['account block', 'account suspended', 'account freeze', 'khata block', 'खाता ब्लॉक', 'खाता स्थगित', 'cbi', 'cyber cell']):
        return "Bank Account Freeze Scam"
    elif any(k in text_lower for k in ['loan', 'personal loan', 'pre-approved loan', 'ऋण', 'लोन', 'loan approve']):
        return "Loan Scam"
    elif any(k in text_lower for k in ['job', 'work from home', 'daily salary', 'part time job', 'घर बैठे कमाई', 'नौकरी']):
        return "Job Scam"
    elif any(k in text_lower for k in ['upi', 'google pay', 'gpay', 'phonepe', 'paytm', 'cashback', 'कलेक्ट']):
        return "UPI / Payment Fraud"
    else:
        return "General Spam / Telemarketing"

records = []
seen_hashes = set()

def add_record(text: str, is_scam: int, source: str, custom_intent: str = None):
    text_clean = text.strip()
    if not text_clean or len(text_clean) < 4:
        return
    
    norm_hash = hashlib.sha256(text_clean.lower().encode('utf-8')).hexdigest()
    if norm_hash in seen_hashes:
        return
    seen_hashes.add(norm_hash)
    
    lang = detect_language(text_clean)
    social_tags = extract_social_engineering_tags(text_clean, is_scam)
    intent = custom_intent if custom_intent else classify_scam_intent(text_clean, is_scam)
    
    record = {
        "id": f"scam_{len(records)+1:06d}",
        "text": text_clean,
        "language": lang,
        "source_dataset": source,
        "is_scam": is_scam,
        "head1_social_engineering": social_tags,
        "head2_scam_intent": intent,
        "metadata": {
            "has_url": bool(URL_RE.search(text_clean)),
            "has_phone": bool(PHONE_RE.search(text_clean)),
            "has_otp": bool(OTP_RE.search(text_clean)),
            "has_upi": bool(UPI_RE.search(text_clean)),
            "has_amount": bool(AMOUNT_RE.search(text_clean))
        }
    }
    records.append(record)

print("="*60)
print("1. LOADING PUBLIC BASELINE DATASETS")
print("="*60)

# 1. UCI Dataset
uci_path = raw_dir / "uci_sms_spam" / "SMSSpamCollection"
if uci_path.exists():
    with open(uci_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parts = line.strip().split("\t", 1)
            if len(parts) == 2:
                is_scam = 1 if parts[0].strip().lower() == "spam" else 0
                add_record(parts[1], is_scam, "UCI_SMS_Spam")

# 2. Indian Telecom Dataset
ind_path = raw_dir / "indian_sms" / "spam_ham_india.csv"
if ind_path.exists():
    with open(ind_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        next(reader, None)
        for row in reader:
            if len(row) >= 2:
                text = row[0].strip()
                is_scam = 1 if "spam" in row[1].strip().lower() else 0
                add_record(text, is_scam, "Indian_Telecom_SMS")

# 3. Smishing Dataset
smish_path = raw_dir / "smishing_dataset" / "Combined-Labeled-Dataset.csv"
if smish_path.exists():
    with open(smish_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        next(reader, None)
        for row in reader:
            if len(row) >= 2:
                text = row[0].strip()
                is_scam = 1 if row[1].strip() == "1" or "smish" in row[1].strip().lower() else 0
                add_record(text, is_scam, "Smishing_Dataset")

print(f"Loaded public datasets: {len(records)} records")

# 4. Large-Scale Authentic Multilingual Hindi & Hinglish Augmentation
print("\n" + "="*60)
print("2. GENERATING EXTENDED MULTILINGUAL HINDI & HINGLISH SAMPLES")
print("="*60)

hindi_hinglish_corpus = []

banks = ["SBI", "HDFC", "ICICI", "Axis", "PNB", "Kotak", "Bank of Baroda", "Canara Bank", "Union Bank", "IndusInd"]
banks_hi = ["भारतीय स्टेट बैंक", "एचडीएफसी बैंक", "आईसीआईसीआई बैंक", "एक्सिस बैंक", "पंजाब नेशनल बैंक", "कोटक बैंक", "बैंक ऑफ बड़ौदा"]
amounts = ["500", "1,200", "2,500", "5,000", "15,000", "25,000", "45,000", "75,000", "1,50,000", "2,50,000"]
providers = ["MSEB", "UPPCL", "DHBVN", "PSPCL", "BSES", "Tata Power", "TSSPDCL", "BESCOM", "WBSEDCL"]
couriers = ["India Post", "FedEx", "BlueDart", "Delhivery", "DTDC", "Ekart", "Shadowfax"]

# 1. Fake KYC Scams (Hindi, Hinglish, Mixed)
for b in banks:
    for a in amounts[:4]:
        dom = f"{b.lower()}-kyc-update.xyz"
        # Pure Devanagari Hindi
        hindi_hinglish_corpus.append((
            f"सावधान! आपका {b} बैंक खाता आज रात 12 बजे ब्लॉक कर दिया जाएगा। केवाईसी सत्यापन लंबित है। तुरंत अपना पैन और आधार लिंक करें: {dom}/login",
            1, "Fake KYC"
        ))
        hindi_hinglish_corpus.append((
            f"प्रिय ग्राहक, {b} बैंक में आपका खाता सुरक्षा कारणों से अस्थायी रूप से रोक दिया गया है। पुनः सक्रिय करने हेतु क्लिक करें: {dom}/verify",
            1, "Fake KYC"
        ))
        # Hinglish
        hindi_hinglish_corpus.append((
            f"Alert: Aapka {b} Bank account block hone wala hai kyunki KYC update nahi hua hai. Agar aapne Rs {a} ka transaction nahi kiya toh turant verify karein: {dom}",
            1, "Fake KYC"
        ))
        hindi_hinglish_corpus.append((
            f"Dear Customer, aapka {b} YONO / NetBanking access expire ho chuka hai. 24 ghante ke andar e-KYC update karein varna khata band kar diya jayega: {dom}",
            1, "Fake KYC"
        ))

# 2. Electricity Bill Scams (Hindi & Hinglish)
for prov in providers:
    for amt in ["850", "1,450", "2,800", "3,650"]:
        phone = f"98{random.randint(10000000, 99999999)}"
        hindi_hinglish_corpus.append((
            f"{prov} विद्युत विभाग: प्रिय उपभोक्ता, आपका बिजली कनेक्शन आज रात 9:30 बजे काट दिया जाएगा क्योंकि पिछले माह का बिल ₹{amt} अपडेट नहीं हुआ है। संपर्क करें: {phone}",
            1, "Electricity Bill Fraud"
        ))
        hindi_hinglish_corpus.append((
            f"{prov} Power Notice: Dear Consumer, aapka power connection tonight 9:30 PM cut ho jayega unpaid bill Rs {amt} ki wajah se. Call Electricity Officer: {phone}",
            1, "Electricity Bill Fraud"
        ))

# 3. Delivery & Customs Scams (Hindi & Hinglish)
for cou in couriers:
    for fee in ["35", "45", "75", "99"]:
        dom = f"{cou.lower().replace(' ', '')}-india-track.xyz"
        hindi_hinglish_corpus.append((
            f"अलर्ट: आपका {cou} पार्सल वेयरहाउस में अटका है क्योंकि पता अधूरा है। ₹{fee} सीमा शुल्क देकर तुरंत पता सही करें: {dom}/pay",
            1, "Delivery / Courier Fraud"
        ))
        hindi_hinglish_corpus.append((
            f"Important Notice: Aapka {cou} courier incomplete address ki wajah se hold par hai. Delivery confirm karne ke liye Rs {fee} pay karein: {dom}",
            1, "Delivery / Courier Fraud"
        ))

# 4. Lottery & Prize Scams (Hindi & Hinglish)
for prize in ["10 Lakh", "25 Lakh", "50 Lakh", "7.5 Lakh"]:
    for code in ["KBC88", "WIN99", "LUCKY77", "PM500"]:
        hindi_hinglish_corpus.append((
            f"बधाई हो! आपका मोबाइल नंबर लकी ड्रा में चुना गया है। आप जीते हैं {prize} का नकद इनाम। क्लेम कोड {code}। अभी संपर्क करें: kbc-lottery-claim.net",
            1, "Lottery / Prize Scam"
        ))
        hindi_hinglish_corpus.append((
            f"Badhai ho! Aapka number {prize} prize ke liye select hua hai. Claim code {code}. Turant processing fee jama karke inaam payein: prize-winner-dept.xyz",
            1, "Lottery / Prize Scam"
        ))

# 5. Loan & Financial Pretext Scams (Hindi & Hinglish)
for l_amt in ["50,000", "1,00,000", "2,50,000", "5,00,000"]:
    hindi_hinglish_corpus.append((
        f"खुशखबरी! आपके आधार कार्ड पर ₹{l_amt} का पर्सनल लोन बिना किसी कागजात के स्वीकृत हुआ है। अभी खाते में प्राप्त करें: instant-loan-yojana.xyz",
        1, "Loan Scam"
    ))
    hindi_hinglish_corpus.append((
        f"Alert: Aapke account se Rs. {l_amt} ka loan approve ho chuka hai. Agar aapne apply nahi kiya toh turant cancel karein: loan-cancel-hindi.xyz/refund",
        1, "Loan Scam"
    ))

# 6. Bank Account Freeze / Cyber Crime / Police Impersonation (Hindi & Hinglish)
cyber_samples = [
    ("साइबर क्राइम ब्रांच अलर्ट: आपके नाम से अवैध गतिविधियों में खाते पाए गए हैं। 2 घंटे के भीतर सत्यापन करें अन्यथा कानूनी कार्रवाई होगी: police-cyber-dept.xyz", 1, "Bank Account Freeze Scam"),
    ("Hi Beta, Call me Please. Cyber crime branch s bat kar rha hu, urgent matter hai.", 1, "Bank Account Freeze Scam"),
    ("Aapka bank account freeze kar diya gaya hai. Illegal transactions detect hue hain. CBI clearance ke liye link par click karein: cbi-fraud-clear.xyz", 1, "Bank Account Freeze Scam"),
    ("Important Notice: TRAI ne aapke sabhi SIM cards ko block karne ka aadesh diya hai. Verification ke liye turant call karein: 9876543210", 1, "Bank Account Freeze Scam"),
    ("सावधान: आपके व्हाट्सएप खाते से आपत्तिजनक संदेश भेजे गए हैं। एफआईआर से बचने के लिए तुरंत साइबर सेल से संपर्क करें: 9811223344", 1, "Bank Account Freeze Scam")
]
for s in cyber_samples:
    hindi_hinglish_corpus.append(s)

# 7. Benign Multilingual Everyday Messages (Hindi & Hinglish)
benign_samples = [
    ("नमस्कार, आपका एसबीआई खाता शेष ₹14,250.00 है। अधिक जानकारी के लिए YONO ऐप डाउनलोड करें।", 0, "Legitimate / Benign"),
    ("Aapka OTP for transaction of Rs. 450 at Swiggy is 482910. Valid for 10 mins. Do not share OTP with anyone.", 0, "Legitimate / Benign"),
    ("कल सुबह 10 बजे मीटिंग तय की गई है। कृपया समय पर उपस्थित रहें। धन्यवाद।", 0, "Legitimate / Benign"),
    ("Bhai kal shaam ko milte hain, mera assignment complete ho gaya hai.", 0, "Legitimate / Benign"),
    ("Aapka mobile recharge of Rs. 299 successful raha. Validity: 28 days. Jio ke sath judne ke liye dhanyawad.", 0, "Legitimate / Benign"),
    ("प्रिय उपभोक्ता, आपके घर का बिजली बिल ₹620 जनरेट हो चुका है। अंतिम तिथि 15 तारीख है।", 0, "Legitimate / Benign"),
    ("Maine paise GPay kar diye hain, ek baar check kar lena bhai.", 0, "Legitimate / Benign"),
    ("HDFC Bank: Rs. 1,200 spent on your Debit Card at Amazon India on 28-Aug. Avail balance: Rs. 48,000.", 0, "Legitimate / Benign"),
    ("Papa ghar aa gaye hain, aap kab tak aaoge?", 0, "Legitimate / Benign"),
    ("भारतीय डाक: आपका पार्सल #IN482910 आज दोपहर 2 बजे तक वितरित कर दिया जाएगा।", 0, "Legitimate / Benign"),
    ("Bhai college pahunch gaya kya? Attendance lagwa dena meri.", 0, "Legitimate / Benign"),
    ("Train 15 minute late hai, platform number 4 par aayegi.", 0, "Legitimate / Benign"),
    ("Aapke account mein salary credit ho gayi hai, message check kar lo.", 0, "Legitimate / Benign"),
    ("आज रात का खाना बाहर खाएंगे, सब तैयार रहना।", 0, "Legitimate / Benign"),
    ("Dawai time pe le lena aur rest karna.", 0, "Legitimate / Benign")
]
for s in benign_samples:
    hindi_hinglish_corpus.append(s)

# Benign bank notifications in Hindi & Hinglish
for b in banks:
    for a in ["350", "890", "1,500", "4,200", "12,000"]:
        text_b_hi = f"{b} बैंक: आपके खाते से ₹{a} की राशि का लेनदेन सफल रहा। शेष राशि ₹52,400 है। सुरक्षित लेनदेन हेतु बैंक नियमों का पालन करें।"
        text_b_hing = f"{b} Bank: Rs. {a} debited from A/c XX4829 on POS/E-com. Avail bal: Rs. 41,200. If not done by you, SMS BLOCK to 567676."
        hindi_hinglish_corpus.append((text_b_hi, 0, "Legitimate / Benign"))
        hindi_hinglish_corpus.append((text_b_hing, 0, "Legitimate / Benign"))

# Add all generated multilingual records
for text, is_scam, intent in hindi_hinglish_corpus:
    add_record(text, is_scam, "ScamShield_Curated", intent)

print(f"Total clean unique records after multilingual expansion: {len(records)}")

# Final Multilingual Audit
print("\n" + "="*60)
print("FINAL DATASET MULTILINGUAL AUDIT")
print("="*60)

total_records = len(records)
lang_counts = Counter(r["language"] for r in records)
scam_counts = Counter("Scam" if r["is_scam"] == 1 else "Benign" for r in records)
intent_counts = Counter(r["head2_scam_intent"] for r in records)

print(f"Total Unique Samples: {total_records}")
print("\n--- Language Breakdown ---")
for lang, count in lang_counts.most_common():
    print(f"  - {lang:25s}: {count:6d} ({count/total_records*100:5.2f}%)")

print("\n--- Classification Breakdown ---")
for lbl, count in scam_counts.most_common():
    print(f"  - {lbl:25s}: {count:6d} ({count/total_records*100:5.2f}%)")

print("\n--- Intent Category Breakdown ---")
for intent, count in intent_counts.most_common():
    print(f"  - {intent:30s}: {count:6d} ({count/total_records*100:5.2f}%)")

# Stratified Splitting: 80% Train, 10% Validation, 10% Test
random.shuffle(records)

strata = defaultdict(list)
for r in records:
    strata[(r["language"], r["is_scam"])].append(r)

train_data, val_data, test_data = [], [], []

for key, items in strata.items():
    n = len(items)
    n_train = int(n * 0.80)
    n_val = int(n * 0.10)
    
    train_data.extend(items[:n_train])
    val_data.extend(items[n_train:n_train+n_val])
    test_data.extend(items[n_train+n_val:])

# Save JSON datasets
def save_json(data, filepath):
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"Saved {len(data):6d} records to {filepath.name}")

print("\n" + "="*60)
print("SAVING DATASET SPLITS & LANGUAGE-SPECIFIC TEST SLICES")
print("="*60)
save_json(records, processed_dir / "scamshield_all_unified.json")
save_json(train_data, processed_dir / "train.json")
save_json(val_data, processed_dir / "val.json")
save_json(test_data, processed_dir / "test.json")

# Dedicated Language Test Slices for Granular Multi-language Evaluation
test_english = [r for r in test_data if r["language"] == "English"]
test_hindi = [r for r in test_data if "Hindi" in r["language"]]
test_hinglish = [r for r in test_data if r["language"] == "Hinglish"]

save_json(test_english, processed_dir / "test_english.json")
save_json(test_hindi, processed_dir / "test_hindi.json")
save_json(test_hinglish, processed_dir / "test_hinglish.json")

print("\nLanguage test slices:")
print(f"  - English Test Slice : {len(test_english):4d} samples")
print(f"  - Hindi Test Slice   : {len(test_hindi):4d} samples")
print(f"  - Hinglish Test Slice: {len(test_hinglish):4d} samples")

print("\nMultilingual dataset preparation successfully complete!")
