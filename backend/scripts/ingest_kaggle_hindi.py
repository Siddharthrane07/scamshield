import os
import sys
import re
import csv
import json
import random
import hashlib
import urllib.request
import pandas as pd
from pathlib import Path

# Force UTF-8 stdout for Windows console
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

random.seed(42)

# Paths
backend_dir = Path(__file__).resolve().parent.parent
raw_dir = backend_dir / "data" / "raw"
kaggle_temp_dir = raw_dir / "kaggle_temp"
kaggle_temp_dir.mkdir(parents=True, exist_ok=True)

output_jsonl_path = raw_dir / "kaggle_hindi_clean.jsonl"

DEVANAGARI_RE = re.compile(r'[\u0900-\u097F]')
AADHAAR_RE = re.compile(r'\b\d{4}\s\d{4}\s\d{4}\b')

# Threat keywords in Devanagari Hindi
THREAT_KEYWORDS = [
    'बैंक', 'खाता', 'ब्लॉक', 'सस्पेंड', 'केवाईसी', 'बिजली', 'बिल',
    'चालान', 'पुलिस', 'लॉटरी', 'इनाम', 'कैशबैक', 'रिफंड', 'लिंक',
    'ओटीपी', 'पासवर्ड', 'चेतावनी', 'तुरंत', 'अपडेट', 'ऋण', 'लोन',
    'सीमा शुल्क', 'कस्टम्स', 'पार्सल', 'गिरफ्तारी', 'वारंट', 'रुपये', 'पैसा', 'जीत'
]

def check_kaggle_auth() -> bool:
    kaggle_json_path = Path.home() / ".kaggle" / "kaggle.json"
    return kaggle_json_path.exists()

def download_datasets():
    print("=" * 60)
    print("1. DOWNLOADING HINDI DATASETS")
    print("=" * 60)
    
    # 1. Check Kaggle CLI
    if check_kaggle_auth():
        print("Kaggle credentials found. Attempting CLI downloads...")
        try:
            cmd1 = f"kaggle datasets download -d vinit119/sms-scam-detection-dataset-merged -p \"{kaggle_temp_dir}\" --unzip"
            cmd2 = f"kaggle datasets download -d onkarbhanarkar/hindi-spam-dataset -p \"{kaggle_temp_dir}\" --unzip"
            os.system(cmd1)
            os.system(cmd2)
        except Exception as e:
            print(f"Kaggle download exception: {e}")
    else:
        print("Notice: ~/.kaggle/kaggle.json not found on system.")

    # 2. Direct LFS download of Multilingual Hindi SMS Dataset
    # (Contains 5,574 Hindi Ham & Spam messages)
    supplemental_csv = kaggle_temp_dir / "hindi_augmented.csv"
    
    if not supplemental_csv.exists() or supplemental_csv.stat().st_size < 10000:
        print("Downloading Multilingual Hindi SMS Dataset (using Hugging Face LFS resolve URL)...")
        url = "https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset/resolve/main/data-augmented.csv"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=90) as response, open(supplemental_csv, "wb") as f:
                f.write(response.read())
            print(f"Downloaded: {supplemental_csv.name} ({supplemental_csv.stat().st_size / 1024:.2f} KB)")
        except Exception as e:
            print(f"Supplemental download error: {e}")
    else:
        print(f"Using cached file: {supplemental_csv.name} ({supplemental_csv.stat().st_size / 1024:.2f} KB)")

def process_csv_files() -> list:
    print("\n" + "=" * 60)
    print("2. PROCESSING & FILTERING DEVANAGARI HINDI SAMPLES")
    print("=" * 60)
    
    csv_files = [f for f in kaggle_temp_dir.glob("*.csv") if f.stat().st_size > 10000]
    print(f"Found {len(csv_files)} valid CSV files: {[f.name for f in csv_files]}")
    
    raw_samples = []
    
    for fpath in csv_files:
        try:
            df = pd.read_csv(fpath, encoding='utf-8', on_bad_lines='skip')
            print(f"\nProcessing {fpath.name} | Shape: {df.shape} | Columns: {list(df.columns)}")
            
            # Check for multilingual dataset with 'text_hi' or 'hindi' columns
            hindi_cols = [c for c in df.columns if 'hi' in c.lower() or 'hindi' in c.lower() or 'text' in c.lower()]
            label_cols = [c for c in df.columns if any(k in c.lower() for k in ['label', 'target', 'class', 'is_spam', 'spam'])]
            
            target_text_col = 'text_hi' if 'text_hi' in df.columns else (hindi_cols[0] if hindi_cols else df.columns[0])
            target_label_col = label_cols[0] if label_cols else (df.columns[1] if len(df.columns) > 1 else None)
            
            print(f"  -> Using text column: '{target_text_col}' | label column: '{target_label_col}'")
            
            for idx, row in df.iterrows():
                raw_text = str(row[target_text_col]).strip()
                raw_lbl = str(row[target_label_col]).strip().lower() if target_label_col else "ham"
                
                # Must contain Devanagari Hindi characters
                if not raw_text or raw_text.lower() == 'nan' or not DEVANAGARI_RE.search(raw_text):
                    continue
                    
                is_spam = 1 if any(s in raw_lbl for s in ['spam', 'scam', '1', 'true']) else 0
                raw_samples.append({"text": raw_text, "is_spam": is_spam, "source_file": fpath.name})
                
        except Exception as e:
            print(f"Error reading {fpath.name}: {e}")
            
    print(f"\nTotal raw Devanagari samples extracted: {len(raw_samples)}")
    return raw_samples

def apply_spam_to_scam_filter(raw_samples: list) -> list:
    print("\n" + "=" * 60)
    print("3. APPLYING SPAM-TO-SCAM CYBERSECURITY THREAT FILTER")
    print("=" * 60)
    
    clean_records = []
    seen_hashes = set()
    
    ham_count = 0
    scam_count = 0
    discarded_marketing = 0
    
    for item in raw_samples:
        text = item["text"].strip()
        clean_text = AADHAAR_RE.sub("[Aadhaar Redacted]", text)
        
        norm_hash = hashlib.sha256(clean_text.lower().encode('utf-8')).hexdigest()
        if norm_hash in seen_hashes:
            continue
        seen_hashes.add(norm_hash)
        
        if item["is_spam"] == 0:
            # 100% of authentic Hindi Ham is retained
            clean_records.append({
                "text": clean_text,
                "is_scam": 0,
                "language": "Hindi",
                "source_dataset": "Kaggle_Hindi_Merged",
                "split_group": f"raw_kaggle_hindi_ham_{ham_count // 50}"
            })
            ham_count += 1
        else:
            # Threat keyword filter for Spam -> Scam
            has_threat = any(k in clean_text for k in THREAT_KEYWORDS)
            if has_threat:
                clean_records.append({
                    "text": clean_text,
                    "is_scam": 1,
                    "language": "Hindi",
                    "source_dataset": "Kaggle_Hindi_Merged",
                    "split_group": f"raw_kaggle_hindi_scam_{scam_count // 50}"
                })
                scam_count += 1
            else:
                discarded_marketing += 1
                
    print(f"Total Unique Devanagari Hindi Processed : {len(clean_records) + discarded_marketing}")
    print(f"  - Harmless Marketing Spam Discarded    : {discarded_marketing}")
    print(f"  - Authentic Hindi Ham Retained         : {ham_count}")
    print(f"  - Authentic Hindi Scams Retained       : {scam_count}")
    
    return clean_records

def main():
    download_datasets()
    raw_samples = process_csv_files()
    clean_records = apply_spam_to_scam_filter(raw_samples)
    
    # Export to JSONL
    print("\n" + "=" * 60)
    print("4. EXPORTING TO KAGGLE_HINDI_CLEAN.JSONL")
    print("=" * 60)
    
    with open(output_jsonl_path, "w", encoding="utf-8") as f:
        for r in clean_records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
            
    print(f"Successfully saved {len(clean_records)} records to {output_jsonl_path}")
    
    scams = [r for r in clean_records if r["is_scam"] == 1]
    hams = [r for r in clean_records if r["is_scam"] == 0]
    
    print("\n" + "=" * 60)
    print("5. QUALITY VERIFICATION SAMPLES")
    print("=" * 60)
    
    print("\n[+] Retained Real Hindi Scams (2 Examples):")
    sample_scams = random.sample(scams, min(2, len(scams))) if scams else []
    for i, s in enumerate(sample_scams, 1):
        print(f"  Scam {i}: {s['text']}")
        
    print("\n[+] Retained Real Hindi Ham (2 Examples):")
    sample_hams = random.sample(hams, min(2, len(hams))) if hams else []
    for i, h in enumerate(sample_hams, 1):
        print(f"  Ham {i}: {h['text']}")
        
    print("\n" + "=" * 60)
    print("INGESTION METRICS SUMMARY")
    print("=" * 60)
    print(f"1. Total Hindi Ham recovered   : {len(hams)}")
    print(f"2. Total Hindi Scams recovered : {len(scams)}")
    print(f"3. Output File Location        : {output_jsonl_path.name}")
    print("=" * 60)

if __name__ == "__main__":
    main()
