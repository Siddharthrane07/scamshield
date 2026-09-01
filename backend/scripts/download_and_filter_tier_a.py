import os
import sys
import re
import csv
import json
import urllib.request
import pandas as pd
from pathlib import Path

# Force UTF-8 for Windows console
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# Directory Paths
backend_dir = Path(__file__).resolve().parent.parent
raw_dir = backend_dir / "data" / "raw"
processed_dir = backend_dir / "data" / "processed"

raw_tier_a_dir = raw_dir / "tier_a_scam"
raw_clove_dir = raw_dir / "clove_india_sms"

raw_tier_a_dir.mkdir(parents=True, exist_ok=True)
raw_clove_dir.mkdir(parents=True, exist_ok=True)
processed_dir.mkdir(parents=True, exist_ok=True)

tier_a_csv_path = raw_tier_a_dir / "India_Cyber_Scam_Hinglish_Dataset.csv"
clove_parquet_path = raw_clove_dir / "train-00000-of-00001.parquet"
output_jsonl_path = processed_dir / "tier_a_indian_filtered.jsonl"

TIER_A_URL = "https://huggingface.co/datasets/ysangam/Indian_Cyber_Scam_PhoneCall_Hinglish_Dataset/raw/main/India_Cyber_Scam_Hinglish_Dataset.csv"
CLOVE_URL = "https://huggingface.co/datasets/CloveAI/india-spam-sms/resolve/main/data/train-00000-of-00001.parquet"

# Regex Patterns
DEVANAGARI_RE = re.compile(r'[\u0900-\u097F]')
AADHAAR_RE = re.compile(r'\b\d{4}\s\d{4}\s\d{4}\b')

# Hinglish linguistic markers
HINGLISH_KEYWORDS = [
    'aapka', 'aapke', 'aapko', 'apna', 'apne', 'apni',
    'karein', 'kare', 'karo', 'karna', 'kijiye', 'kro', 'krwalo', 'kardo',
    'hoga', 'hogi', 'hoge', 'hua', 'hui', 'hue',
    'turant', 'jaldi', 'shighra',
    'khata', 'khate', 'paisa', 'paise', 'rupaye', 'rupay',
    'bhejo', 'bheja', 'bheje', 'diya', 'liye',
    'aaj', 'raat', 'kal', 'shaam',
    'sampark', 'band', 'dhokhadhadi', 'hai', 'hain', 'ho',
    'nahi', 'nahin', 'mat', 'varna', 'warna',
    'yojana', 'inaam', 'mubarak', 'badhai', 'bijli', 'sarkari',
    'police', 'challan', 'shulk', 'jama', 'bhugtan',
    'kripya', 'dhanyawad', 'chahiye',
    'raha', 'rahe', 'rahi', 'rha', 'rhi',
    'mujhe', 'mera', 'meri', 'mere', 'tera', 'teri', 'tere', 'humare', 'humara',
    'bhai', 'beta', 'papa', 'sahab', 'suchna', 'adhikari'
]

HINGLISH_TOKEN_SET = set(k.lower() for k in HINGLISH_KEYWORDS)

def download_file(url: str, dest_path: Path):
    if not dest_path.exists():
        print(f"Downloading from {url}...")
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=45) as response, open(dest_path, "wb") as f:
            f.write(response.read())
        print(f"Downloaded: {dest_path.name} ({dest_path.stat().st_size / 1024:.2f} KB)")
    else:
        print(f"Using cached file: {dest_path.name} ({dest_path.stat().st_size / 1024:.2f} KB)")

def is_hindi_or_hinglish(text: str) -> tuple[bool, str]:
    """
    Returns (True, 'Hindi') if Devanagari is present.
    Returns (True, 'Hinglish') if text contains Hinglish linguistic markers.
    Returns (False, 'English') otherwise.
    """
    if bool(DEVANAGARI_RE.search(text)):
        return True, "Hindi"
    
    # Tokenize words for Hinglish detection
    tokens = [w.lower().strip(".,!?:;\"'()[]{}<>-/\\#@$%^&*~`") for w in text.split()]
    if not tokens:
        return False, "English"
    
    # Check keyword matches
    matches = sum(1 for t in tokens if t in HINGLISH_TOKEN_SET)
    ratio = matches / len(tokens)
    
    # Strict filter: At least 1 specific marker or >= 5% match ratio
    if matches >= 1 and (matches >= 2 or ratio >= 0.05 or any(k in tokens for k in ['aapka', 'karein', 'turant', 'khata', 'dhokhadhadi', 'yojana', 'inaam', 'badhai', 'bijli', 'sarkari', 'challan', 'bhugtan'])):
        return True, "Hinglish"
    
    return False, "English"

def redact_aadhaar(text: str) -> str:
    return AADHAAR_RE.sub("[Aadhaar Redacted]", text)

def main():
    print("=" * 60)
    print("TIER A DATASET DOWNLOAD & HINDI/HINGLISH FILTERING")
    print("=" * 60)
    
    # 1. Download datasets
    download_file(TIER_A_URL, tier_a_csv_path)
    download_file(CLOVE_URL, clove_parquet_path)
    
    total_inspected = 0
    total_discarded = 0
    total_retained = 0
    retained_records = []
    
    # 2. Process Tier A CSV Dataset
    print("\n--- Processing ysangam Indian Cyber Scam Hinglish Dataset ---")
    if tier_a_csv_path.exists():
        try:
            df_tier_a = pd.read_csv(tier_a_csv_path, encoding='utf-8', on_bad_lines='skip')
            # Identify text column
            text_col = None
            for col in ['text', 'message', 'Text', 'Message', 'content', 'Content']:
                if col in df_tier_a.columns:
                    text_col = col
                    break
            if text_col is None and len(df_tier_a.columns) > 0:
                text_col = df_tier_a.columns[0]
                
            print(f"Columns: {list(df_tier_a.columns)} | Using text column: '{text_col}'")
            
            for idx, row in df_tier_a.iterrows():
                total_inspected += 1
                raw_text = str(row[text_col]).strip()
                if not raw_text or raw_text.lower() == 'nan' or len(raw_text) < 4:
                    total_discarded += 1
                    continue
                
                is_target, lang = is_hindi_or_hinglish(raw_text)
                if is_target:
                    clean_text = redact_aadhaar(raw_text)
                    retained_records.append({
                        "id": f"tier_a_scam_{len(retained_records)+1:06d}",
                        "text": clean_text,
                        "language": lang,
                        "source_dataset": "ysangam/Indian_Cyber_Scam_Hinglish",
                        "raw_label": str(row.get('label', row.get('Label', 'scam')))
                    })
                    total_retained += 1
                else:
                    total_discarded += 1
        except Exception as e:
            print(f"Error processing Tier A CSV: {e}")
            
    # 3. Process CloveAI India Spam SMS Parquet Dataset
    print("\n--- Processing CloveAI India Spam SMS Parquet Dataset ---")
    if clove_parquet_path.exists():
        try:
            df_clove = pd.read_parquet(clove_parquet_path)
            print(f"Columns: {list(df_clove.columns)} | Total Rows: {len(df_clove)}")
            
            text_col = 'text' if 'text' in df_clove.columns else df_clove.columns[0]
            label_col = 'label' if 'label' in df_clove.columns else (df_clove.columns[1] if len(df_clove.columns) > 1 else None)
            
            for idx, row in df_clove.iterrows():
                total_inspected += 1
                raw_text = str(row[text_col]).strip()
                if not raw_text or raw_text.lower() == 'nan' or len(raw_text) < 4:
                    total_discarded += 1
                    continue
                
                is_target, lang = is_hindi_or_hinglish(raw_text)
                if is_target:
                    clean_text = redact_aadhaar(raw_text)
                    raw_lbl = str(row[label_col]) if label_col else "unknown"
                    retained_records.append({
                        "id": f"clove_ind_{len(retained_records)+1:06d}",
                        "text": clean_text,
                        "language": lang,
                        "source_dataset": "CloveAI/india-spam-sms",
                        "raw_label": raw_lbl
                    })
                    total_retained += 1
                else:
                    total_discarded += 1
        except Exception as e:
            print(f"Error processing CloveAI Parquet: {e}")
            
    # 4. Save to JSONL
    print("\n" + "=" * 60)
    print("SAVING FILTERED HINDI & HINGLISH SAMPLES")
    print("=" * 60)
    
    with open(output_jsonl_path, "w", encoding="utf-8") as f:
        for r in retained_records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
            
    print(f"Successfully saved {len(retained_records)} rows to {output_jsonl_path}")
    
    # 5. Print Final Summary Metrics
    print("\n" + "=" * 60)
    print("TIER A FILTERING METRICS SUMMARY")
    print("=" * 60)
    print(f"Total raw rows inspected        : {total_inspected}")
    print(f"Total English rows discarded    : {total_discarded}")
    print(f"Total Hindi / Hinglish retained : {total_retained}")
    if total_retained > 0:
        hindi_count = sum(1 for r in retained_records if r["language"] == "Hindi")
        hinglish_count = sum(1 for r in retained_records if r["language"] == "Hinglish")
        print(f"  -> Pure Hindi (Devanagari)    : {hindi_count} ({hindi_count/total_retained*100:.2f}%)")
        print(f"  -> Hinglish (Romanized Hindi) : {hinglish_count} ({hinglish_count/total_retained*100:.2f}%)")
        
        print("\nSample Retained Records:")
        for i, r in enumerate(retained_records[:3], 1):
            print(f"  [{i}] [{r['language']}] {r['text'][:120]}...")

if __name__ == "__main__":
    main()
