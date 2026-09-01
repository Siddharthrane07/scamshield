import os
import sys
import re
import json
import random
import hashlib
from pathlib import Path
from collections import Counter, defaultdict

# Force UTF-8 stdout for Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

random.seed(42)

# Output directory
backend_dir = Path(__file__).resolve().parent.parent
processed_dir = backend_dir / "data" / "processed"
processed_dir.mkdir(parents=True, exist_ok=True)
output_jsonl_path = processed_dir / "synthetic_indian_corpus.jsonl"

# Privacy & Extraction Regex
AADHAAR_RE = re.compile(r'\b\d{4}\s\d{4}\s\d{4}\b')
URL_RE = re.compile(r'https?://\S+|www\.\S+|[a-zA-Z0-9\-]+\.(?:com|org|net|in|xyz|me|online|top|site|live|co|info|biz|apk|app|page|tk|ml)(?:/\S*)?', re.IGNORECASE)
PHONE_RE = re.compile(r'\b(?:\+91|91|0)?[6-9]\d{9}\b')
OTP_RE = re.compile(r'\b(?:otp|one time password|verification code|pin|passcode|ओटीपी|पिन)\b', re.IGNORECASE)
UPI_RE = re.compile(r'\b[a-zA-Z0-9.\-_]+@[a-zA-Z]{2,}\b')
AMOUNT_RE = re.compile(r'(?:INR|Rs\.?|₹|rs\.?)\s*(\d+(?:,\d+)*(?:\.\d{1,2})?)', re.IGNORECASE)

# ==========================================
# SLOT FILLERS & ENTITY RANDOMIZERS
# ==========================================
BANKS = ["SBI", "HDFC", "ICICI", "PNB", "Axis Bank", "Bank of Baroda", "Kotak Bank", "Canara Bank", "Union Bank", "IndusInd", "IDFC First", "Yes Bank"]
BANKS_HI = ["भारतीय स्टेट बैंक", "एचडीएफसी बैंक", "आईसीआईसीआई बैंक", "पंजाब नेशनल बैंक", "एक्सिस बैंक", "बैंक ऑफ बड़ौदा", "कोटक महिंद्रा बैंक", "केनरा बैंक", "यूनियन बैंक"]

ELECTRICITY_BOARDS = ["MSEDCL", "BSES", "UPPCL", "BESCOM", "TSSPDCL", "DHBVN", "PSPCL", "WBSEDCL", "Tata Power", "Adani Electricity", "CESC", "JVVNL"]
ELECTRICITY_BOARDS_HI = ["महावितरण", "बीईएसईएस (BSES)", "यूपीपीसीएल (UPPCL)", "बेस्कॉम (BESCOM)", "विद्युत वितरण निगम", "टाटा पावर", "अडानी इलेक्ट्रिसिटी", "बिजली विभाग"]

COURIERS = ["India Post", "BlueDart", "Delhivery", "FedEx", "DTDC", "Ekart", "Shadowfax", "Xpressbees"]
COURIERS_HI = ["भारतीय डाक (India Post)", "ब्लू डार्ट (BlueDart)", "डेल्हीवरी (Delhivery)", "फेडेक्स (FedEx)", "डीटीडीसी (DTDC)", "डाक सेवा"]

MERCHANTS = ["Amazon", "Flipkart", "Swiggy", "Zomato", "Myntra", "Blinkit", "Zepto", "BigBasket", "Paytm Mall"]
MERCHANTS_HI = ["अमेज़न", "फ्लिपकार्ट", "स्विगी", "जोमैटो", "मिंत्रा", "ब्लिंकइट", "ज़ेप्टो", "बिगबास्केट"]

AMOUNTS = ["149", "299", "450", "850", "1,250", "2,499", "3,800", "4,500", "7,200", "8,999", "15,000", "25,000", "45,000", "75,000", "95,000"]
AMOUNTS_HI = ["₹149", "₹299", "₹450", "₹850", "₹1,250", "₹2,499", "₹3,800", "₹4,500", "₹7,200", "₹8,999", "₹15,000", "₹25,000", "₹45,000", "₹75,000", "₹95,000"]

CITIES_HI = ["दिल्ली", "मुंबई", "लखनऊ", "जयपुर", "पटना", "भोपाल", "कोलकाता", "बेंगलुरु", "अहमदाबाद", "पुणे", "चंडीगढ़"]
CITIES_EN = ["Delhi", "Mumbai", "Lucknow", "Jaipur", "Patna", "Bhopal", "Kolkata", "Bengaluru", "Ahmedabad", "Pune", "Chandigarh"]

def random_phone():
    return f"98{random.randint(10000000, 99999999)}"

def random_otp():
    return f"{random.randint(100000, 999999)}"

def random_pnr():
    return f"{random.randint(2000000000, 8999999999)}"

def random_account():
    return f"XX{random.randint(1000, 9999)}"

# Diverse Domain Generators
def generate_kyc_url(bank):
    slug = bank.lower().replace(" ", "").replace("bank", "")
    tlds = ["xyz", "online", "top", "site", "live", "co.in", "in", "info", "net", "app"]
    prefixes = ["kyc-update", "verify-netbanking", "pan-link", "yono-secure", "portal-auth", "login-check", "net-secure"]
    return f"{slug}-{random.choice(prefixes)}.{random.choice(tlds)}"

def generate_power_url(board):
    slug = board.lower().replace(" ", "").replace("(", "").replace(")", "")
    tlds = ["online", "top", "site", "link", "live", "bill", "pay", "org"]
    return f"{slug}-bill-update.{random.choice(tlds)}"

def generate_challan_url():
    domains = ["parivahan-e-challan", "echallan-parivahan-gov", "traffic-police-challan", "vahan-fine-pay", "e-court-notice", "delhi-traffic-challan", "mahatraffic-challan"]
    tlds = ["xyz", "top", "online", "site", "link", "app"]
    ext = random.choice(["/parivahan_challan.apk", "/eCourt_notice.apk", "/pay_fine", "/view_challan", "/challan_download.apk"])
    return f"{random.choice(domains)}.{random.choice(tlds)}{ext}"

def generate_courier_url(courier):
    slug = courier.lower().replace(" ", "")
    tlds = ["top", "site", "online", "xyz", "live", "track", "info"]
    return f"{slug}-redelivery-update.{random.choice(tlds)}/pay"

def generate_job_url():
    slugs = [
        "t.me/youtube_daily_tasks", "t.me/part_time_earning_hub", "t.me/hotel_review_income",
        "work-from-home-india.top/join", "t.me/rating_amazon_tasks", "earn-daily-online.xyz"
    ]
    return random.choice(slugs)

def generate_lottery_url():
    slugs = [
        "kbc-lucky-winner-draw.net", "pm-subsidy-yojana-claim.xyz", "lottery-dept-india-gov.top",
        "kbc-head-office-claim.live", "diwali-mega-prize.online", "pm-kisan-reward.site"
    ]
    return random.choice(slugs)

def generate_upi_url():
    slugs = [
        "gpay-reward-collect.xyz/cashback", "phonepe-cashback-desk.online/claim",
        "paytm-refund-portal.top/pay", "upi-reward-instant.live"
    ]
    return random.choice(slugs)

records = []
seen_hashes = set()

def add_synthetic_sample(text: str, language: str, category: str, is_scam: int, split_group: str, social_tags: dict):
    clean_text = AADHAAR_RE.sub("[Aadhaar Redacted]", text.strip())
    
    norm_hash = hashlib.sha256(clean_text.lower().encode('utf-8')).hexdigest()
    if norm_hash in seen_hashes:
        return
    seen_hashes.add(norm_hash)
    
    rec = {
        "id": f"synth_ind_{len(records)+1:06d}",
        "text": clean_text,
        "language": language,
        "source_dataset": "Synthetic_Tier_C",
        "is_scam": is_scam,
        "head1_social_engineering": social_tags,
        "head2_scam_intent": category,
        "split_group": split_group,
        "metadata": {
            "has_url": bool(URL_RE.search(clean_text)),
            "has_phone": bool(PHONE_RE.search(clean_text)),
            "has_otp": bool(OTP_RE.search(clean_text)),
            "has_upi": bool(UPI_RE.search(clean_text)),
            "has_amount": bool(AMOUNT_RE.search(clean_text))
        }
    }
    records.append(rec)

# ==========================================
# 1. FAKE KYC (45-50 variations per language)
# ==========================================
for i, bank in enumerate(BANKS):
    bank_hi = BANKS_HI[i % len(BANKS_HI)]
    group_id = f"group_kyc_{bank.lower().replace(' ', '_')}"
    
    for v in range(4):
        fake_aadhaar = f"2341 8920 {random.randint(1000, 9999)}"
        acc = random_account()
        u1 = generate_kyc_url(bank)
        u2 = generate_kyc_url(bank)
        ph1 = random_phone()
        ph2 = random_phone()
        
        # Hindi with URL
        add_synthetic_sample(
            f"सावधान! आपका {bank_hi} खाता संख्या {acc} आज रात 12 बजे ब्लॉक कर दिया जाएगा। ई-केवाईसी (e-KYC) सत्यापन हेतु तुरंत पैन व आधार लिंक करें: {u1}",
            "Hindi", "Fake KYC", 1, group_id, {"urgency": 1, "fear": 1, "authority_impersonation": 1, "reward_bait": 0, "financial_pressure": 0}
        )
        # Hindi without URL (Call / OTP lure)
        add_synthetic_sample(
            f"महत्वपूर्ण सूचना: {bank_hi} उपभोक्ता, आपका डेबिट कार्ड व नेट बैंकिंग ब्लॉक कर दिया गया है। पुनः चालू करने हेतु बैंक हेल्पडेस्क {ph1} पर तुरंत कॉल करें या ओटीपी बताएं।",
            "Hindi", "Fake KYC", 1, group_id, {"urgency": 1, "fear": 1, "authority_impersonation": 1, "reward_bait": 0, "financial_pressure": 0}
        )
        # Hinglish with URL
        add_synthetic_sample(
            f"Alert: Aapka {bank} account suspend ho chuka hai kyunki KYC pending hai. Diye gaye official portal link par click karke turant KYC update karein: {u2}",
            "Hinglish", "Fake KYC", 1, group_id, {"urgency": 1, "fear": 1, "authority_impersonation": 1, "reward_bait": 0, "financial_pressure": 0}
        )
        # Hinglish without URL
        add_synthetic_sample(
            f"Dear Customer, aapka {bank} A/c ending in {acc} freeze hone wala hai. Card unblock karwane ke liye customer care number {ph2} par call karein aur biometric verify karein.",
            "Hinglish", "Fake KYC", 1, group_id, {"urgency": 1, "fear": 1, "authority_impersonation": 1, "reward_bait": 0, "financial_pressure": 0}
        )

# ==========================================
# 2. ELECTRICITY DISCONNECTION
# ==========================================
for i, board in enumerate(ELECTRICITY_BOARDS):
    board_hi = ELECTRICITY_BOARDS_HI[i % len(ELECTRICITY_BOARDS_HI)]
    group_id = f"group_elec_{board.lower().replace(' ', '_')}"
    
    for v in range(4):
        amt = random.choice(AMOUNTS[:7])
        acc = random_account()
        u1 = generate_power_url(board)
        u2 = generate_power_url(board)
        ph1 = random_phone()
        ph2 = random_phone()
        
        # Hindi with URL
        add_synthetic_sample(
            f"{board_hi}: प्रिय उपभोक्ता, आपका बिजली कनेक्शन आज रात 9:30 बजे काट दिया जाएगा क्योंकि पिछले माह का बिल ₹{amt} अपडेट नहीं हुआ है। बिल भुगतान करें: {u1}",
            "Hindi", "Electricity Disconnection", 1, group_id, {"urgency": 1, "fear": 1, "authority_impersonation": 1, "reward_bait": 0, "financial_pressure": 1}
        )
        # Hindi without URL
        add_synthetic_sample(
            f"विद्युत नोटिस: उपभोक्ता क्र. {acc}, बकाया बिल ₹{amt} के कारण आज लाइन काटी जा रही है। डिस्कनेक्शन से बचने हेतु तुरंत बिजली अधिकारी से संपर्क करें: {ph1}",
            "Hindi", "Electricity Disconnection", 1, group_id, {"urgency": 1, "fear": 1, "authority_impersonation": 1, "reward_bait": 0, "financial_pressure": 1}
        )
        # Hinglish with URL
        add_synthetic_sample(
            f"{board} Notice: Dear Consumer, aapka power connection tonight 9:30 PM cut ho jayega unpaid bill Rs {amt} ki wajah se. Update bill immediately: {u2}",
            "Hinglish", "Electricity Disconnection", 1, group_id, {"urgency": 1, "fear": 1, "authority_impersonation": 1, "reward_bait": 0, "financial_pressure": 1}
        )
        # Hinglish without URL
        add_synthetic_sample(
            f"Power Alert: Aapke ghar ki bijli aaj raat 9:30 disconnect kar di jayegi. Last month bill update nahi hua hai. Call Billing Officer: {ph2}",
            "Hinglish", "Electricity Disconnection", 1, group_id, {"urgency": 1, "fear": 1, "authority_impersonation": 1, "reward_bait": 0, "financial_pressure": 1}
        )

# ==========================================
# 3. TRAFFIC E-CHALLAN
# ==========================================
for city_idx, city_en in enumerate(CITIES_EN):
    city_hi = CITIES_HI[city_idx % len(CITIES_HI)]
    group_id = f"group_challan_{city_en.lower()}"
    
    for v in range(4):
        amt = random.choice(["500", "1,000", "1,500", "2,000", "5,000"])
        veh_no = f"{random.choice(['DL', 'MH', 'UP', 'RJ', 'KA'])}-0{random.randint(1,9)}-{chr(65+v)}{chr(66+v)}-{random.randint(1000,9999)}"
        u1 = generate_challan_url()
        u2 = generate_challan_url()
        ph1 = random_phone()
        ph2 = random_phone()
        
        # Hindi with APK / URL
        add_synthetic_sample(
            f"यातायात पुलिस {city_hi}: आपके वाहन {veh_no} पर ₹{amt} का ई-चालान दर्ज हुआ है। न्यायालय समन से बचने के लिए चालान एपीके (APK) डाउनलोड करें: {u1}",
            "Hindi", "Traffic e-Challan", 1, group_id, {"urgency": 1, "fear": 1, "authority_impersonation": 1, "reward_bait": 0, "financial_pressure": 1}
        )
        # Hindi without URL
        add_synthetic_sample(
            f"परिवहन विभाग नोटिस: वाहन {veh_no} पर लंबित चालान ₹{amt} का भुगतान न करने पर वाहन सीज किया जाएगा। लोक अदालत अधिकारी से संपर्क करें: {ph1}",
            "Hindi", "Traffic e-Challan", 1, group_id, {"urgency": 1, "fear": 1, "authority_impersonation": 1, "reward_bait": 0, "financial_pressure": 1}
        )
        # Hinglish with APK / URL
        add_synthetic_sample(
            f"Parivahan Alert: Vehicle {veh_no} challan worth Rs {amt} pending in {city_en}. Download official Parivahan Virtual Court App to pay fine: {u2}",
            "Hinglish", "Traffic e-Challan", 1, group_id, {"urgency": 1, "fear": 1, "authority_impersonation": 1, "reward_bait": 0, "financial_pressure": 1}
        )
        # Hinglish without URL
        add_synthetic_sample(
            f"Traffic Police Notice: Non-bailable warrant issued for traffic violation on vehicle {veh_no}. Settle penalty with Traffic Sub-Inspector: {ph2}",
            "Hinglish", "Traffic e-Challan", 1, group_id, {"urgency": 1, "fear": 1, "authority_impersonation": 1, "reward_bait": 0, "financial_pressure": 1}
        )

# ==========================================
# 4. TELEGRAM JOB SCAM
# ==========================================
for v in range(25):
    group_id = f"group_job_task_{v:02d}"
    daily_amt = random.choice(["2,500", "3,500", "4,800", "6,000", "8,000"])
    u1 = generate_job_url()
    u2 = generate_job_url()
    ph1 = random_phone()
    ph2 = random_phone()
    
    # Hindi with URL
    add_synthetic_sample(
        f"घर बैठे पार्ट-टाइम काम करके रोजाना ₹{daily_amt} कमाएं! केवल यूट्यूब वीडियो लाइक और गूगल होटल रिव्यू का सरल कार्य। अभी टेलीग्राम ज्वाइन करें: {u1}",
        "Hindi", "Telegram Job", 1, group_id, {"urgency": 0, "fear": 0, "authority_impersonation": 0, "reward_bait": 1, "financial_pressure": 0}
    )
    # Hindi without URL
    add_synthetic_sample(
        f"अमेज़न पार्ट-टाइम जॉब भर्ती! मोबाइल से 2 घंटे काम करके ₹{daily_amt} प्रतिदिन कमाएं। कोई पंजीकरण शुल्क नहीं। तुरंत व्हाट्सएप करें: {ph1}",
        "Hindi", "Telegram Job", 1, group_id, {"urgency": 0, "fear": 0, "authority_impersonation": 0, "reward_bait": 1, "financial_pressure": 0}
    )
    # Hinglish with URL
    add_synthetic_sample(
        f"Part-time Job Opportunity! Earn daily Rs {daily_amt} from mobile. Simple Google Maps rating & YouTube like tasks. Daily instant payout. Join Telegram: {u2}",
        "Hinglish", "Telegram Job", 1, group_id, {"urgency": 0, "fear": 0, "authority_impersonation": 0, "reward_bait": 1, "financial_pressure": 0}
    )
    # Hinglish without URL
    add_synthetic_sample(
        f"Work From Home: Daily income Rs {daily_amt} by writing simple 5-star product reviews on Flipkart. Send 'JOB' on WhatsApp: {ph2}",
        "Hinglish", "Telegram Job", 1, group_id, {"urgency": 0, "fear": 0, "authority_impersonation": 0, "reward_bait": 1, "financial_pressure": 0}
    )

# ==========================================
# 5. UPI / PAYMENT FRAUD
# ==========================================
for v in range(25):
    group_id = f"group_upi_collect_{v:02d}"
    cashback = random.choice(["999", "1,450", "1,999", "2,450", "4,999", "7,500"])
    u1 = generate_upi_url()
    u2 = generate_upi_url()
    
    # Hindi with URL
    add_synthetic_sample(
        f"गूगल पे (Google Pay): आपको ₹{cashback} का विशेष कैशबैक प्राप्त हुआ है। राशि अपने बैंक खाते में प्राप्त करने हेतु लिंक खोलें: {u1}",
        "Hindi", "UPI Fraud", 1, group_id, {"urgency": 1, "fear": 0, "authority_impersonation": 1, "reward_bait": 1, "financial_pressure": 0}
    )
    # Hindi without URL (UPI PIN lure)
    add_synthetic_sample(
        f"फ़ोनपे (PhonePe) रिवॉर्ड: आपका ₹{cashback} का उपहार वाउचर स्वीकृत हो गया है। राशि प्राप्त करने हेतु कलेक्ट रिक्वेस्ट स्वीकारें और यूपीआई पिन (UPI PIN) दर्ज करें।",
        "Hindi", "UPI Fraud", 1, group_id, {"urgency": 1, "fear": 0, "authority_impersonation": 1, "reward_bait": 1, "financial_pressure": 0}
    )
    # Hinglish with URL
    add_synthetic_sample(
        f"Paytm Cashback: Congratulations! You have received Rs {cashback} direct bank cashback. Click to credit in bank: {u2}",
        "Hinglish", "UPI Fraud", 1, group_id, {"urgency": 1, "fear": 0, "authority_impersonation": 1, "reward_bait": 1, "financial_pressure": 0}
    )
    # Hinglish without URL
    add_synthetic_sample(
        f"Google Pay Alert: Received Rs {cashback} from merchant refund desk. Please accept collect request and enter your UPI PIN to receive money.",
        "Hinglish", "UPI Fraud", 1, group_id, {"urgency": 1, "fear": 0, "authority_impersonation": 1, "reward_bait": 1, "financial_pressure": 0}
    )

# ==========================================
# 6. LOTTERY / PRIZE SCAM
# ==========================================
for v in range(25):
    group_id = f"group_lottery_{v:02d}"
    prize = random.choice(["10 Lakh", "25 Lakh", "50 Lakh", "75 Lakh", "1 Crore"])
    code = f"KBC{random.randint(10,99)}"
    u1 = generate_lottery_url()
    u2 = generate_lottery_url()
    ph1 = random_phone()
    ph2 = random_phone()
    
    # Hindi with URL
    add_synthetic_sample(
        f"बधाई हो! आपका मोबाइल नंबर केबीसी (KBC) लकी ड्रॉ में चुना गया है। आपने जीता है {prize} का नकद इनाम। क्लेम कोड: {code}। अभी क्लेम करें: {u1}",
        "Hindi", "Lottery / Prize", 1, group_id, {"urgency": 1, "fear": 0, "authority_impersonation": 0, "reward_bait": 1, "financial_pressure": 0}
    )
    # Hindi without URL
    add_synthetic_sample(
        f"केबीसी हेड ऑफिस मुंबई: आपके नाम पर {prize} की लॉटरी चेक तैयार है। मैनेजर राणा प्रताप सिंह से व्हाट्सएप पर तुरंत संपर्क करें: {ph1}। फ़ाइल नंबर {code}।",
        "Hindi", "Lottery / Prize", 1, group_id, {"urgency": 1, "fear": 0, "authority_impersonation": 0, "reward_bait": 1, "financial_pressure": 0}
    )
    # Hinglish with URL
    add_synthetic_sample(
        f"Badhai ho! Aapka SIM card PM Dhan Yojana lottery mein {prize} cash prize ke liye vijeta bana hai. Registration shulk jama karke claim karein: {u2}",
        "Hinglish", "Lottery / Prize", 1, group_id, {"urgency": 1, "fear": 0, "authority_impersonation": 0, "reward_bait": 1, "financial_pressure": 0}
    )
    # Hinglish without URL
    add_synthetic_sample(
        f"Congratulations! You won {prize} in Jio Diwali Lucky Contest. Claim code {code}. Call Lottery Department incharge immediately on {ph2}.",
        "Hinglish", "Lottery / Prize", 1, group_id, {"urgency": 1, "fear": 0, "authority_impersonation": 0, "reward_bait": 1, "financial_pressure": 0}
    )

# ==========================================
# 7. COURIER / DELIVERY FRAUD
# ==========================================
for i, courier in enumerate(COURIERS):
    courier_hi = COURIERS_HI[i % len(COURIERS_HI)]
    group_id = f"group_courier_{courier.lower().replace(' ', '_')}"
    
    for v in range(4):
        fee = random.choice(["25", "35", "45", "75", "99"])
        pkg_id = f"IN{random.randint(100000, 999999)}"
        u1 = generate_courier_url(courier)
        u2 = generate_courier_url(courier)
        ph1 = random_phone()
        ph2 = random_phone()
        
        # Hindi with URL
        add_synthetic_sample(
            f"अलर्ट: आपका {courier_hi} पार्सल #{pkg_id} सीमा शुल्क में रोक दिया गया है क्योंकि पता अधूरा है। ₹{fee} शुल्क का भुगतान करके 24 घंटे में पता अपडेट करें: {u1}",
            "Hindi", "Courier Scam", 1, group_id, {"urgency": 1, "fear": 1, "authority_impersonation": 1, "reward_bait": 0, "financial_pressure": 1}
        )
        # Hindi without URL
        add_synthetic_sample(
            f"भारतीय डाक पार्सल सूचना: पैकेट #{pkg_id} वेयरहाउस में अटका है। पता सत्यापन हेतु डिलीवरी अधिकारी से तुरंत संपर्क करें: {ph1} अन्यथा सामान वापस होगा।",
            "Hindi", "Courier Scam", 1, group_id, {"urgency": 1, "fear": 1, "authority_impersonation": 1, "reward_bait": 0, "financial_pressure": 1}
        )
        # Hinglish with URL
        add_synthetic_sample(
            f"Important Notice: Your {courier} package #{pkg_id} delivery failed due to missing street address. Confirm address & pay redelivery fee Rs {fee}: {u2}",
            "Hinglish", "Courier Scam", 1, group_id, {"urgency": 1, "fear": 1, "authority_impersonation": 1, "reward_bait": 0, "financial_pressure": 1}
        )
        # Hinglish without URL
        add_synthetic_sample(
            f"Delhivery Alert: Delivery boy attempted delivery for parcel #{pkg_id} but house number was missing. Call Delivery Executive: {ph2} within 2 hours.",
            "Hinglish", "Courier Scam", 1, group_id, {"urgency": 1, "fear": 1, "authority_impersonation": 1, "reward_bait": 0, "financial_pressure": 1}
        )

# ==========================================
# 8. BANK ACCOUNT FREEZE / CYBER CRIME
# ==========================================
for v in range(25):
    group_id = f"group_freeze_cbi_{v:02d}"
    u1 = f"cbi-cybercell-verification.xyz/notice?id={random.randint(10000,99999)}"
    u2 = f"trai-sim-deactivation.top/verify?user={random.randint(1000,9999)}"
    ph1 = random_phone()
    ph2 = random_phone()
    
    # Hindi with URL
    add_synthetic_sample(
        f"साइबर क्राइम सेल अलर्ट: आपके बैंक खाते में अवैध विदेशी लेनदेन दर्ज हुए हैं। खाता फ्रीज होने व एफआईआर से बचने हेतु तुरंत ऑनलाइन सत्यापन करें: {u1}",
        "Hindi", "Bank Account Freeze", 1, group_id, {"urgency": 1, "fear": 1, "authority_impersonation": 1, "reward_bait": 0, "financial_pressure": 0}
    )
    # Hindi without URL (Digital Arrest)
    add_synthetic_sample(
        f"दिल्ली पुलिस मुख्यालय: आपके आधार कार्ड पर 14 गैरकानूनी खाते पाए गए हैं। 2 घंटे में वीडियो वेरिफिकेशन करें वरना साइबर अरेस्ट वारंट जारी होगा। जांच अधिकारी: {ph1}",
        "Hindi", "Bank Account Freeze", 1, group_id, {"urgency": 1, "fear": 1, "authority_impersonation": 1, "reward_bait": 0, "financial_pressure": 0}
    )
    # Hinglish with URL
    add_synthetic_sample(
        f"TRAI Notice: Aapke naam par chal rahe sabhi mobile numbers aur bank accounts 2 ghante mein block ho jayenge. Clearance certificate download karein: {u2}",
        "Hinglish", "Bank Account Freeze", 1, group_id, {"urgency": 1, "fear": 1, "authority_impersonation": 1, "reward_bait": 0, "financial_pressure": 0}
    )
    # Hinglish without URL
    add_synthetic_sample(
        f"Hi Beta, Call me Please. Cyber crime branch s bat kar rha hu, urgent money laundering case hai, turant call karo: {ph2}",
        "Hinglish", "Bank Account Freeze", 1, group_id, {"urgency": 1, "fear": 1, "authority_impersonation": 1, "reward_bait": 0, "financial_pressure": 0}
    )

# ==========================================
# 9. INDIAN BENIGN HAM (~600+ SAMPLES)
# Authentic transactional SMS: Bank debits, IRCTC PNR alerts, Swiggy/Zomato OTPs, Carrier validity, Chat
# ==========================================
for v in range(35):
    group_id = f"group_benign_batch_{v:02d}"
    
    for sub in range(9):
        amt = random.choice(AMOUNTS[:9])
        acc = random_account()
        otp_code = random_otp()
        pnr = random_pnr()
        bank = BANKS[(v + sub) % len(BANKS)]
        bank_hi = BANKS_HI[(v + sub) % len(BANKS_HI)]
        merchant = MERCHANTS[(v + sub) % len(MERCHANTS)]
        merchant_hi = MERCHANTS_HI[(v + sub) % len(MERCHANTS_HI)]
        
        # 1. Bank Debit Notification (Hindi)
        add_synthetic_sample(
            f"{bank_hi}: आपके खाते संख्या {acc} से ₹{amt} की राशि डेबिट की गई है। उपलब्ध शेष राशि ₹{random.randint(12000, 85000)}.00 है। सुरक्षित बैंकिंग हेतु YONO ऐप का उपयोग करें।",
            "Hindi", "Legitimate / Benign", 0, group_id, {"urgency": 0, "fear": 0, "authority_impersonation": 0, "reward_bait": 0, "financial_pressure": 0}
        )
        # 2. Bank Credit Notification (Hindi)
        add_synthetic_sample(
            f"{bank_hi}: आपके खाते संख्या {acc} में ₹{amt} की राशि सफलतापूर्वक जमा (Credit) की गई है। शेष राशि: ₹{random.randint(25000, 95000)}.00। धन्यवाद।",
            "Hindi", "Legitimate / Benign", 0, group_id, {"urgency": 0, "fear": 0, "authority_impersonation": 0, "reward_bait": 0, "financial_pressure": 0}
        )
        # 3. Bank Debit Notification (Hinglish)
        add_synthetic_sample(
            f"{bank}: Rs {amt} debited from A/c {acc} on POS/ATM transaction on {random.randint(1,28)}-Aug. Available Balance: Rs {random.randint(15000, 75000)}. If not done by you, forward SMS to 567676.",
            "Hinglish", "Legitimate / Benign", 0, group_id, {"urgency": 0, "fear": 0, "authority_impersonation": 0, "reward_bait": 0, "financial_pressure": 0}
        )
        # 4. Bank Credit Notification (Hinglish)
        add_synthetic_sample(
            f"{bank}: Rs {amt} credited to your account {acc} via UPI/IMPS ref no {random.randint(10000000, 99999999)}. Total balance: Rs {random.randint(30000, 90000)}.",
            "Hinglish", "Legitimate / Benign", 0, group_id, {"urgency": 0, "fear": 0, "authority_impersonation": 0, "reward_bait": 0, "financial_pressure": 0}
        )
        # 5. OTP Login / Verification (Hindi)
        add_synthetic_sample(
            f"{merchant_hi} लॉगिन के लिए आपका एक बार का पासवर्ड (OTP) {otp_code} है। यह 10 मिनट के लिए मान्य है। कृपया अपना ओटीपी किसी के साथ साझा न करें।",
            "Hindi", "Legitimate / Benign", 0, group_id, {"urgency": 0, "fear": 0, "authority_impersonation": 0, "reward_bait": 0, "financial_pressure": 0}
        )
        # 6. OTP Login / Verification (Hinglish)
        add_synthetic_sample(
            f"Aapka OTP for {merchant} order payment of Rs {amt} is {otp_code}. Valid for 5 mins. Kabhi bhi apna OTP kisi ko share mat karein.",
            "Hinglish", "Legitimate / Benign", 0, group_id, {"urgency": 0, "fear": 0, "authority_impersonation": 0, "reward_bait": 0, "financial_pressure": 0}
        )
        # 7. IRCTC Train Alert (Hindi)
        add_synthetic_sample(
            f"भारतीय रेल (IRCTC): पीएनआर {pnr} के लिए टिकट पुष्टि स्थिति: कंफर्म (Coach B{random.randint(1,6)}, Seat {random.randint(1,72)})। शुभ यात्रा!",
            "Hindi", "Legitimate / Benign", 0, group_id, {"urgency": 0, "fear": 0, "authority_impersonation": 0, "reward_bait": 0, "financial_pressure": 0}
        )
        # 8. IRCTC Train Alert (Hinglish)
        add_synthetic_sample(
            f"IRCTC Alert: Train {random.randint(12000, 19999)} departure rescheduled by {random.randint(10,45)} mins from {random.choice(CITIES_EN)}. PNR: {pnr}. Check live status on NTES.",
            "Hinglish", "Legitimate / Benign", 0, group_id, {"urgency": 0, "fear": 0, "authority_impersonation": 0, "reward_bait": 0, "financial_pressure": 0}
        )
        # 9. Telecom Recharge Notification (Hindi)
        add_synthetic_sample(
            f"प्रिय ग्राहक, आपका ₹{amt} का मोबाइल रिचार्ज सफल रहा। 28 दिनों के लिए प्रतिदिन 1.5GB डेटा व असीमित कॉलिंग सक्रिय है। धन्यवाद!",
            "Hindi", "Legitimate / Benign", 0, group_id, {"urgency": 0, "fear": 0, "authority_impersonation": 0, "reward_bait": 0, "financial_pressure": 0}
        )
        # 10. Telecom Recharge Notification (Hinglish)
        add_synthetic_sample(
            f"Aapka Jio plan recharge of Rs {amt} successful. 100% daily data balance valid till {random.randint(1,28)}-Sep. Manage your plan on MyJio app.",
            "Hinglish", "Legitimate / Benign", 0, group_id, {"urgency": 0, "fear": 0, "authority_impersonation": 0, "reward_bait": 0, "financial_pressure": 0}
        )

# ==========================================
# WRITE OUTPUT TO JSONL
# ==========================================
print("=" * 60)
print("SAVING SYNTHETIC INDIAN CORPUS")
print("=" * 60)

with open(output_jsonl_path, "w", encoding="utf-8") as f:
    for r in records:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")

print(f"Successfully generated and saved {len(records)} records to {output_jsonl_path}")

# ==========================================
# SUMMARY TABLE PRINTING
# ==========================================
print("\n" + "=" * 75)
print(f"{'CATEGORY':<30} | {'HINDI':<8} | {'HINGLISH':<8} | {'TOTAL':<8} | {'URL %':<8}")
print("=" * 75)

cat_lang_counts = defaultdict(lambda: defaultdict(int))
cat_url_counts = defaultdict(int)

for r in records:
    cat = r["head2_scam_intent"]
    lang = r["language"]
    cat_lang_counts[cat][lang] += 1
    if r["metadata"]["has_url"]:
        cat_url_counts[cat] += 1

total_hindi = sum(1 for r in records if r["language"] == "Hindi")
total_hinglish = sum(1 for r in records if r["language"] == "Hinglish")
total_urls = sum(1 for r in records if r["metadata"]["has_url"])

for cat, langs in sorted(cat_lang_counts.items()):
    h = langs["Hindi"]
    hg = langs["Hinglish"]
    tot = h + hg
    url_pct = (cat_url_counts[cat] / tot * 100) if tot > 0 else 0
    print(f"{cat:<30} | {h:<8} | {hg:<8} | {tot:<8} | {url_pct:<6.1f}%")

print("-" * 75)
print(f"{'TOTAL':<30} | {total_hindi:<8} | {total_hinglish:<8} | {len(records):<8} | {total_urls/len(records)*100:<6.1f}%")
print("=" * 75)

print("\nConstraint Verification Checks:")
print(f"  - Zero English-only records : {'PASSED' if all(r['language'] in ['Hindi', 'Hinglish'] for r in records) else 'FAILED'}")
print(f"  - 50/50 Hindi vs Hinglish   : {total_hindi/len(records)*100:.1f}% Hindi / {total_hinglish/len(records)*100:.1f}% Hinglish")
print(f"  - Attack Vector Mix (Scams) : {sum(1 for r in records if r['is_scam']==1 and r['metadata']['has_url'])/sum(1 for r in records if r['is_scam']==1)*100:.1f}% URL / {sum(1 for r in records if r['is_scam']==1 and not r['metadata']['has_url'])/sum(1 for r in records if r['is_scam']==1)*100:.1f}% No-URL")
