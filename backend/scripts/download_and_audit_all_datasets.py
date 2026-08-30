import os
import sys
import urllib.request
import csv
import json
from pathlib import Path
from collections import Counter

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

raw_dir = Path(__file__).resolve().parent.parent / "data" / "raw"
raw_dir.mkdir(parents=True, exist_ok=True)

datasets = {
    "indian_sms": {
        "url": "https://raw.githubusercontent.com/junioralive/india-spam-sms-classification/main/dataset/spam_ham_india.csv",
        "filename": raw_dir / "indian_sms" / "spam_ham_india.csv",
        "description": "Indian Telecom SMS Spam/Ham Dataset"
    },
    "smishing_dataset": {
        "url": "https://raw.githubusercontent.com/shaghayegh-hp/Smishing_Dataset/main/Combined-Labeled-Dataset.csv",
        "filename": raw_dir / "smishing_dataset" / "Combined-Labeled-Dataset.csv",
        "description": "Smishing (SMS Phishing with URLs) Dataset"
    }
}

def download_file(url, dest_path):
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    if not dest_path.exists():
        print(f"Downloading {url} to {dest_path}...")
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as response, open(dest_path, "wb") as f:
            f.write(response.read())
        print(f"Downloaded successfully: {dest_path.stat().st_size / 1024:.2f} KB")
    else:
        print(f"File already exists: {dest_path} ({dest_path.stat().st_size / 1024:.2f} KB)")

print("="*60)
print("DOWNLOADING & AUDITING MULTILINGUAL SCAM DATASETS")
print("="*60)

for key, info in datasets.items():
    try:
        download_file(info["url"], info["filename"])
    except Exception as e:
        print(f"Failed to download {key}: {e}")

# Audit 1: Indian SMS Dataset
print("\n" + "="*50)
print("AUDIT 1: INDIAN TELECOM SMS DATASET")
print("="*50)
ind_path = datasets["indian_sms"]["filename"]
if ind_path.exists():
    rows = []
    with open(ind_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        for row in reader:
            if len(row) >= 2:
                text = row[0].strip()
                label = row[1].strip()
                if text and label:
                    rows.append({"label": label, "text": text})
                
    total = len(rows)
    label_counts = Counter(r["label"].lower() for r in rows)
    char_lens = [len(r["text"]) for r in rows]
    print(f"Header: {header}")
    print(f"Total Valid Samples: {total}")
    for label, count in label_counts.items():
        print(f"  - {label.upper():10s}: {count} ({count/total*100:.2f}%)")
    print(f"Avg Length (chars): {sum(char_lens)/len(char_lens):.1f}")
    print(f"Max Length (chars): {max(char_lens)}")
    
    print("\nSample Indian Spam/Scam Messages:")
    spams = [r["text"] for r in rows if "spam" in r["label"].lower()][:3]
    for i, s in enumerate(spams, 1):
        print(f"  [{i}] {s}")

# Audit 2: Smishing Dataset (Phishing with URLs)
print("\n" + "="*50)
print("AUDIT 2: SMISHING (PHISHING WITH URLS) DATASET")
print("="*50)
smish_path = datasets["smishing_dataset"]["filename"]
if smish_path.exists():
    rows = []
    with open(smish_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        for row in reader:
            if len(row) >= 2:
                # Column 0: text, Column 1: label or vice versa
                rows.append({"col0": row[0].strip(), "col1": row[1].strip() if len(row) > 1 else ""})
                
    total = len(rows)
    print(f"Header: {header}")
    print(f"Total Rows: {total}")
    
    # Inspect labels
    col1_counts = Counter(r["col1"].lower() for r in rows)
    col0_counts = Counter(r["col0"].lower() for r in rows)
    print(f"Column 1 values: {col1_counts.most_common(5)}")
    print(f"Column 0 values: {col0_counts.most_common(5)}")
    
    # Inspect sample rows
    print("\nSample Rows:")
    for i, r in enumerate(rows[:4], 1):
        print(f"  [{i}] {r}")
