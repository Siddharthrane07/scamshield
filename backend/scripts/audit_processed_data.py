import os
import sys
import re
import json
from pathlib import Path
from collections import Counter, defaultdict

# Force UTF-8 stdout for Windows console
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

backend_dir = Path(__file__).resolve().parent.parent
processed_dir = backend_dir / "data" / "processed"

files_to_check = {
    "train": processed_dir / "train.jsonl",
    "val": processed_dir / "val.jsonl",
    "test": processed_dir / "test.jsonl",
    "test_english": processed_dir / "test_english.jsonl",
    "test_hinglish": processed_dir / "test_hinglish.jsonl",
    "test_hindi": processed_dir / "test_hindi.jsonl"
}

AADHAAR_RAW_RE = re.compile(r'\b\d{4}\s\d{4}\s\d{4}\b')

def load_jsonl(path: Path) -> list:
    if not path.exists():
        return []
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line_str = line.strip()
            if line_str:
                records.append(json.loads(line_str))
    return records

def main():
    print("=" * 75)
    print("PROCESSED DATASET QUALITY & INTEGRITY AUDIT")
    print("=" * 75)
    
    datasets = {}
    for name, path in files_to_check.items():
        datasets[name] = load_jsonl(path)
        print(f"Loaded {name:<15}: {len(datasets[name]):6d} rows from {path.name}")
        
    train_data = datasets["train"]
    val_data = datasets["val"]
    test_data = datasets["test"]
    
    # ---------------------------------------------------------
    # 1. ASSERTION CHECKS
    # ---------------------------------------------------------
    print("\n" + "=" * 75)
    print("1. INTEGRITY & LEAKAGE ASSERTIONS")
    print("=" * 75)
    
    synth_in_val = sum(1 for r in val_data if r.get("source_dataset") == "Synthetic_Tier_C")
    synth_in_test = sum(1 for r in test_data if r.get("source_dataset") == "Synthetic_Tier_C")
    
    print(f"[*] Synthetic records in val.jsonl  : {synth_in_val} (Expected: 0)")
    print(f"[*] Synthetic records in test.jsonl : {synth_in_test} (Expected: 0)")
    
    assert synth_in_val == 0, f"ASSERTION FAILED: Found {synth_in_val} synthetic records in val.jsonl!"
    assert synth_in_test == 0, f"ASSERTION FAILED: Found {synth_in_test} synthetic records in test.jsonl!"
    print("  -> Zero Synthetic Contamination Check: PASSED (100% Real-world Validation & Test)")

    # Aadhaar / 12-digit ID privacy leak scan
    total_unmasked_aadhaar = 0
    for name, recs in datasets.items():
        unmasked = 0
        for r in recs:
            matches = AADHAAR_RAW_RE.findall(r.get("text", ""))
            if matches:
                unmasked += len(matches)
        if unmasked > 0:
            print(f"  -> WARNING: {name} contains {unmasked} unmasked 12-digit IDs!")
        total_unmasked_aadhaar += unmasked
        
    print(f"[*] Total unmasked 12-digit Indian IDs across all splits: {total_unmasked_aadhaar} (Expected: 0)")
    assert total_unmasked_aadhaar == 0, f"PRIVACY ASSERTION FAILED: {total_unmasked_aadhaar} unmasked IDs found!"
    print("  -> Privacy Redaction Check: PASSED ([Aadhaar Redacted] mask applied)")

    # ---------------------------------------------------------
    # 2. SPLIT & LANGUAGE DISTRIBUTION
    # ---------------------------------------------------------
    print("\n" + "=" * 75)
    print("2. SPLIT & LANGUAGE DISTRIBUTION SUMMARY")
    print("=" * 75)
    print(f"{'SPLIT':<12} | {'TOTAL':<8} | {'BENIGN':<8} | {'SCAM':<8} | {'ENGLISH':<8} | {'HINDI':<8} | {'HINGLISH':<8}")
    print("-" * 75)
    
    for name in ["train", "val", "test"]:
        recs = datasets[name]
        tot = len(recs)
        benign = sum(1 for r in recs if r["is_scam"] == 0)
        scam = sum(1 for r in recs if r["is_scam"] == 1)
        eng = sum(1 for r in recs if r["language"] == "English")
        hi = sum(1 for r in recs if r["language"] == "Hindi")
        hg = sum(1 for r in recs if r["language"] == "Hinglish")
        print(f"{name:<12} | {tot:<8} | {benign:<8} | {scam:<8} | {eng:<8} | {hi:<8} | {hg:<8}")

    print("-" * 75)
    
    # Check false-positive defense (Benign ham in Hindi and Hinglish in train.jsonl)
    benign_hi_train = sum(1 for r in train_data if r["is_scam"] == 0 and r["language"] == "Hindi")
    benign_hg_train = sum(1 for r in train_data if r["is_scam"] == 0 and r["language"] == "Hinglish")
    print(f"\n[*] False-Positive Defense Samples in train.jsonl:")
    print(f"  - Hindi Benign Ham (IRCTC, Bank Debits, OTPs)    : {benign_hi_train:5d} samples")
    print(f"  - Hinglish Benign Ham (IRCTC, Debits, Swiggy/Jio): {benign_hg_train:5d} samples")
    print(f"  - Total Non-English Benign Defense Samples       : {benign_hi_train + benign_hg_train:5d} samples")

    # ---------------------------------------------------------
    # 3. MULTI-TASK HEAD DISTRIBUTIONS IN TRAIN.JSONL
    # ---------------------------------------------------------
    print("\n" + "=" * 75)
    print("3. MULTI-TASK HEAD DISTRIBUTIONS (train.jsonl)")
    print("=" * 75)
    
    # Head 1: Social Engineering
    print("\n--- Head 1: Social Engineering Psychological Triggers (Scam subset) ---")
    scam_train = [r for r in train_data if r["is_scam"] == 1]
    tags = ["urgency", "fear", "authority_impersonation", "reward_bait", "financial_pressure"]
    
    for tag in tags:
        pos_count = sum(r["head1_social_engineering"].get(tag, 0) for r in scam_train)
        pct = (pos_count / len(scam_train) * 100) if len(scam_train) > 0 else 0
        print(f"  - {tag:<28}: {pos_count:6d} / {len(scam_train):6d} ({pct:5.2f}%)")

    # Head 2: Scam Intent Taxonomy
    print("\n--- Head 2: Scam Intent Class Distribution (All train.jsonl) ---")
    intent_counts = Counter(r["head2_scam_intent"] for r in train_data)
    print(f"{'INTENT CATEGORY':<35} | {'COUNT':<8} | {'PERCENTAGE':<10}")
    print("-" * 60)
    for intent, count in intent_counts.most_common():
        pct = count / len(train_data) * 100
        print(f"{intent:<35} | {count:<8} | {pct:5.2f}%")

    print("\n" + "=" * 75)
    print("AUDIT STATUS: ALL INTEGRITY, PRIVACY & DISTRIBUTION CHECKS PASSED ✅")
    print("=" * 75)

if __name__ == "__main__":
    main()
