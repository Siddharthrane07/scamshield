import os
import urllib.request
import zipfile
import pandas as pd
from pathlib import Path

# Target directories
raw_data_dir = Path(__file__).resolve().parent.parent / "data" / "raw" / "uci_sms_spam"
raw_data_dir.mkdir(parents=True, exist_ok=True)

zip_path = raw_data_dir / "sms_spam_collection.zip"
data_file_path = raw_data_dir / "SMSSpamCollection"

UCI_URL = "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"

print(f"1. Downloading UCI SMS Spam Collection dataset from {UCI_URL}...")
try:
    req = urllib.request.Request(
        UCI_URL,
        headers={"User-Agent": "Mozilla/5.0"}
    )
    with urllib.request.urlopen(req, timeout=30) as response, open(zip_path, "wb") as out_file:
        out_file.write(response.read())
    print(f"Downloaded successfully: {zip_path.stat().st_size / 1024:.2f} KB")

    print("2. Extracting zip archive...")
    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        zip_ref.extractall(raw_data_dir)
    print("Extraction complete.")

except Exception as e:
    print(f"Direct download failed ({e}). Trying fallback URL...")
    FALLBACK_URL = "https://raw.githubusercontent.com/justmarkham/pycon-2016-tutorial/master/data/sms.tsv"
    req = urllib.request.Request(FALLBACK_URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as response, open(data_file_path, "wb") as out_file:
        out_file.write(response.read())
    print("Downloaded fallback TSV successfully.")

# Audit Dataset
print("\n" + "="*50)
print("UCI SMS SPAM COLLECTION AUDIT")
print("="*50)

if data_file_path.exists():
    # Read tab-separated file
    rows = []
    with open(data_file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parts = line.strip().split("\t", 1)
            if len(parts) == 2:
                rows.append({"label": parts[0].strip(), "text": parts[1].strip()})
    
    total = len(rows)
    spam_count = sum(1 for r in rows if r["label"].lower() == "spam")
    ham_count = sum(1 for r in rows if r["label"].lower() == "ham")
    
    char_lens = [len(r["text"]) for r in rows]
    word_lens = [len(r["text"].split()) for r in rows]
    
    print(f"Total Samples: {total}")
    print(f"  - Ham (Benign)  : {ham_count} ({ham_count/total*100:.2f}%)")
    print(f"  - Spam (Malicious): {spam_count} ({spam_count/total*100:.2f}%)")
    print(f"\nText Statistics:")
    print(f"  - Avg Length (chars): {sum(char_lens)/len(char_lens):.1f}")
    print(f"  - Max Length (chars): {max(char_lens)}")
    print(f"  - Min Length (chars): {min(char_lens)}")
    print(f"  - Avg Length (words): {sum(word_lens)/len(word_lens):.1f}")
    print(f"  - Max Length (words): {max(word_lens)}")
    
    print("\nSample Spam Messages:")
    spam_samples = [r["text"] for r in rows if r["label"].lower() == "spam"][:3]
    for i, s in enumerate(spam_samples, 1):
        print(f"  [{i}] {s}")
        
    print("\nSample Ham Messages:")
    ham_samples = [r["text"] for r in rows if r["label"].lower() == "ham"][:3]
    for i, s in enumerate(ham_samples, 1):
        print(f"  [{i}] {s}")
else:
    print(f"Error: Data file not found at {data_file_path}")
