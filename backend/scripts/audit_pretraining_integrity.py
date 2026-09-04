import os
import sys
import re
import json
import random
from pathlib import Path
from collections import Counter, defaultdict

# Force UTF-8 stdout for Windows console
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

random.seed(42)

# Paths
backend_dir = Path(__file__).resolve().parent.parent
processed_dir = backend_dir / "data" / "processed"
raw_dir = backend_dir / "data" / "raw"

report_json_path = processed_dir / "audit_pretraining_integrity_report_v3.json"

train_path = processed_dir / "train.jsonl"
val_path = processed_dir / "val.jsonl"
test_path = processed_dir / "test.jsonl"
kaggle_hindi_path = raw_dir / "kaggle_hindi_clean.jsonl"

AADHAAR_RAW_RE = re.compile(r'\b\d{4}\s\d{4}\s\d{4}\b')

# True Indic grammatical particles & core vocabulary
TRUE_INDIC_CORE_WORDS = {
    'hai', 'hain', 'ho', 'karein', 'kare', 'karo', 'karna', 'kijiye', 'kro',
    'hoga', 'hogi', 'hoge', 'hua', 'hui', 'hue', 'aapka', 'aapke', 'aapko',
    'apna', 'apne', 'apni', 'nahi', 'nahin', 'mat', 'bhejo', 'bheja', 'bheje',
    'khata', 'khate', 'raat', 'aaj', 'kal', 'turant', 'jaldi', 'paayein',
    'sampark', 'yojana', 'inaam', 'badhai', 'bijli', 'sarkari', 'police',
    'challan', 'paisa', 'paise', 'rupaye', 'rupay', 'shulk', 'jama', 'bhugtan',
    'dhokhadhadi', 'varna', 'warna', 'band', 'kripya', 'dhanyawad', 'chahiye',
    'raha', 'rahe', 'rahi', 'rha', 'rhi', 'mujhe', 'mera', 'meri', 'mere',
    'tera', 'teri', 'tere', 'humare', 'humara', 'bhai', 'beta', 'papa'
}

# Ambiguous short words that could cause English false positive collisions
AMBIGUOUS_SHORT_WORDS = {'me', 'to', 'in', 'on', 'at', 'lo', 'le', 'leh', 'se', 'pe', 'ko', 'ka', 'ki', 'ke', 'par', 'do'}

def load_jsonl(path: Path) -> list:
    if not path.exists():
        return []
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line_str = line.strip()
            if line_str:
                try:
                    records.append(json.loads(line_str))
                except Exception as e:
                    print(f"Error parsing line {line_num} in {path.name}: {e}")
    return records

def normalize_text_for_dedup(text: str) -> str:
    t = text.lower().strip()
    t = re.sub(r'https?://\S+|www\.\S+|\S+\.(?:com|org|net|in|xyz|top|online|site)\S*', '<URL>', t)
    t = re.sub(r'\b(?:\+91|91|0)?[6-9]\d{9}\b|\b\d{5}[-\s]?\d{5}\b', '<PHONE>', t)
    t = re.sub(r'(?:inr|rs\.?|₹)\s*\d+(?:,\d+)*(?:\.\d+)?', '<AMOUNT>', t)
    t = re.sub(r'\b\d+\b', '<NUM>', t)
    t = re.sub(r'[^\w\s\u0900-\u097F]', ' ', t)
    t = re.sub(r'\s+', ' ', t).strip()
    return t

def main():
    print("=" * 80)
    print("SCAMSHIELD ML DATA QUALITY & PRE-TRAINING INTEGRITY AUDIT")
    print("=" * 80)

    train_records = load_jsonl(train_path)
    val_records = load_jsonl(val_path)
    test_records = load_jsonl(test_path)
    kaggle_hindi_records = load_jsonl(kaggle_hindi_path)

    all_splits = {
        "Train": train_records,
        "Val": val_records,
        "Test": test_records
    }

    report = {
        "timestamp": "2026-09-03",
        "module1_split_matrix": {},
        "module2_hinglish_purity": {},
        "module3_hindi_diversity": {},
        "module4_cross_split_leakage": {},
        "module5_privacy_aadhaar": {}
    }

    # ---------------------------------------------------------
    # MODULE 1: Split × Language × Label Matrix
    # ---------------------------------------------------------
    print("\n" + "=" * 80)
    print("MODULE 1: COMPREHENSIVE SPLIT × LANGUAGE × LABEL MATRIX")
    print("=" * 80)

    print(f"| {'Split':<6} | {'Eng Ham':<8} | {'Eng Scam':<8} | {'Hi Ham':<8} | {'Hi Scam':<8} | {'Hing Ham':<8} | {'Hing Scam':<9} | {'Synthetic':<9} | {'Real':<8} | {'Total':<8} |")
    print(f"|{'-'*8}|{'-'*10}|{'-'*10}|{'-'*9}|{'-'*9}|{'-'*10}|{'-'*11}|{'-'*11}|{'-'*10}|{'-'*10}|")

    for name, recs in all_splits.items():
        eng_ham = sum(1 for r in recs if r.get("language") == "English" and r.get("is_scam") == 0)
        eng_scam = sum(1 for r in recs if r.get("language") == "English" and r.get("is_scam") == 1)
        hi_ham = sum(1 for r in recs if r.get("language") == "Hindi" and r.get("is_scam") == 0)
        hi_scam = sum(1 for r in recs if r.get("language") == "Hindi" and r.get("is_scam") == 1)
        hg_ham = sum(1 for r in recs if r.get("language") == "Hinglish" and r.get("is_scam") == 0)
        hg_scam = sum(1 for r in recs if r.get("language") == "Hinglish" and r.get("is_scam") == 1)
        synth_cnt = sum(1 for r in recs if r.get("source_dataset") == "Synthetic_Tier_C")
        real_cnt = len(recs) - synth_cnt
        total = len(recs)

        report["module1_split_matrix"][name] = {
            "english_ham": eng_ham, "english_scam": eng_scam,
            "hindi_ham": hi_ham, "hindi_scam": hi_scam,
            "hinglish_ham": hg_ham, "hinglish_scam": hg_scam,
            "synthetic": synth_cnt, "real": real_cnt, "total": total
        }

        print(f"| {name:<6} | {eng_ham:<8d} | {eng_scam:<8d} | {hi_ham:<8d} | {hi_scam:<8d} | {hg_ham:<8d} | {hg_scam:<9d} | {synth_cnt:<9d} | {real_cnt:<8d} | {total:<8d} |")

    # ---------------------------------------------------------
    # MODULE 2: Hinglish Linguistic Purity & False-Positive Audit
    # ---------------------------------------------------------
    print("\n" + "=" * 80)
    print("MODULE 2: HINGLISH LINGUISTIC PURITY & FALSE-POSITIVE AUDIT")
    print("=" * 80)

    all_hinglish = [r for recs in all_splits.values() for r in recs if r.get("language") == "Hinglish"]
    total_hinglish = len(all_hinglish)

    true_indic_count = 0
    purely_ambiguous_short_count = 0
    zero_keyword_count = 0

    for r in all_hinglish:
        tokens = set(w.lower().strip(".,!?:;\"'()[]{}<>-/\\#@$%^&*~`") for w in r.get("text", "").split())
        indic_matches = tokens & TRUE_INDIC_CORE_WORDS
        ambig_matches = tokens & AMBIGUOUS_SHORT_WORDS
        
        if len(indic_matches) >= 1:
            true_indic_count += 1
        elif len(ambig_matches) > 0 and len(indic_matches) == 0:
            purely_ambiguous_short_count += 1
        else:
            zero_keyword_count += 1

    purity_pct = (true_indic_count / total_hinglish * 100) if total_hinglish > 0 else 0
    ambig_pct = (purely_ambiguous_short_count / total_hinglish * 100) if total_hinglish > 0 else 0

    report["module2_hinglish_purity"] = {
        "total_hinglish_inspected": total_hinglish,
        "true_indic_vocabulary_count": true_indic_count,
        "true_indic_purity_percentage": round(purity_pct, 2),
        "purely_ambiguous_substring_count": purely_ambiguous_short_count,
        "purely_ambiguous_percentage": round(ambig_pct, 2),
        "zero_keyword_count": zero_keyword_count
    }

    print(f"[*] Total Hinglish records inspected            : {total_hinglish}")
    print(f"[*] Records with True Indic core vocabulary     : {true_indic_count} ({purity_pct:.2f}%)")
    print(f"[*] Records classified via ambiguous collisions : {purely_ambiguous_short_count} ({ambig_pct:.2f}%)")
    print(f"[*] Records with zero matched keywords          : {zero_keyword_count}")

    # Random Samples for Visual Verification
    hinglish_ham = [r for r in all_hinglish if r.get("is_scam") == 0]
    hinglish_scam = [r for r in all_hinglish if r.get("is_scam") == 1]

    print("\n--- Visual Verification: 5 Random Hinglish Ham Samples ---")
    sample_h_ham = random.sample(hinglish_ham, min(5, len(hinglish_ham))) if hinglish_ham else []
    for i, s in enumerate(sample_h_ham, 1):
        print(f"  [{i}] {s.get('text')}")

    print("\n--- Visual Verification: 5 Random Hinglish Scam Samples ---")
    sample_h_scam = random.sample(hinglish_scam, min(5, len(hinglish_scam))) if hinglish_scam else []
    for i, s in enumerate(sample_h_scam, 1):
        print(f"  [{i}] {s.get('text')}")

    # ---------------------------------------------------------
    # MODULE 3: Hindi Scam Intent & Taxonomy Diversity Audit
    # ---------------------------------------------------------
    print("\n" + "=" * 80)
    print("MODULE 3: HINDI SCAM INTENT & TAXONOMY DIVERSITY AUDIT")
    print("=" * 80)

    all_hindi_scams = [r for recs in all_splits.values() for r in recs if r.get("language") == "Hindi" and r.get("is_scam") == 1]
    hindi_scam_intents = Counter(r.get("head2_scam_intent", "Unknown") for r in all_hindi_scams)

    print(f"Total Hindi Scam Samples in Active Splits: {len(all_hindi_scams)}")
    print(f"\n| {'Hindi Scam Intent Category':<32} | {'Count':<8} | {'Percentage':<10} |")
    print(f"|{'-'*34}|{'-'*10}|{'-'*12}|")
    for intent, count in hindi_scam_intents.most_common():
        pct = count / len(all_hindi_scams) * 100 if all_hindi_scams else 0
        print(f"| {intent:<32} | {count:<8d} | {pct:6.2f}%    |")

    # Ingested Kaggle Hindi Real Scams breakdown
    print("\n--- Ingested Real Hindi Scams in kaggle_hindi_clean.jsonl ---")
    kaggle_scams = [r for r in kaggle_hindi_records if r.get("is_scam") == 1]
    print(f"Total Real Hindi Scams in kaggle_hindi_clean.jsonl: {len(kaggle_scams)}")
    
    report["module3_hindi_diversity"] = {
        "total_hindi_scams_active": len(all_hindi_scams),
        "intent_distribution": dict(hindi_scam_intents),
        "kaggle_hindi_real_scams_count": len(kaggle_scams)
    }

    # ---------------------------------------------------------
    # MODULE 4: Cross-Split Duplicate & Leakage Detection
    # ---------------------------------------------------------
    print("\n" + "=" * 80)
    print("MODULE 4: CROSS-SPLIT DUPLICATE & LEAKAGE DETECTION")
    print("=" * 80)

    train_raw_texts = set(r.get("text", "").strip() for r in train_records)
    val_raw_texts = set(r.get("text", "").strip() for r in val_records)
    test_raw_texts = set(r.get("text", "").strip() for r in test_records)

    exact_train_test = train_raw_texts & test_raw_texts
    exact_val_test = val_raw_texts & test_raw_texts
    exact_train_val = train_raw_texts & val_raw_texts

    print(f"[*] Exact Duplicate Matches:")
    print(f"  - Train vs. Test exact duplicates : {len(exact_train_test)}")
    print(f"  - Val vs. Test exact duplicates   : {len(exact_val_test)}")
    print(f"  - Train vs. Val exact duplicates  : {len(exact_train_val)}")

    # Normalized Template Overlap (Indian Languages: Hindi & Hinglish)
    train_templates_ind = set(
        normalize_text_for_dedup(r.get("text", "")) for r in train_records if r.get("language") in ["Hindi", "Hinglish"]
    )
    test_templates_ind = [
        normalize_text_for_dedup(r.get("text", "")) for r in test_records if r.get("language") in ["Hindi", "Hinglish"]
    ]
    
    template_matches = sum(1 for t in test_templates_ind if t in train_templates_ind)
    template_overlap_pct = (template_matches / len(test_templates_ind) * 100) if test_templates_ind else 0

    print(f"\n[*] Normalized Template Overlap in Test (Hindi + Hinglish):")
    print(f"  - Total Indic Test Samples        : {len(test_templates_ind)}")
    print(f"  - Overlapping Templates in Train   : {template_matches} ({template_overlap_pct:.2f}%)")

    # Synthetic Leakage Verification
    synth_in_val = sum(1 for r in val_records if r.get("source_dataset") == "Synthetic_Tier_C")
    synth_in_test = sum(1 for r in test_records if r.get("source_dataset") == "Synthetic_Tier_C")

    print(f"\n[*] Synthetic Row Leakage Check:")
    print(f"  - Synthetic rows in val.jsonl      : {synth_in_val} (Target: 0)")
    print(f"  - Synthetic rows in test.jsonl     : {synth_in_test} (Target: 0)")
    assert synth_in_val == 0, f"ASSERTION FAILED: {synth_in_val} synthetic rows in val.jsonl"
    assert synth_in_test == 0, f"ASSERTION FAILED: {synth_in_test} synthetic rows in test.jsonl"
    print("  -> Synthetic Leakage Assertion    : PASSED ✅")

    report["module4_cross_split_leakage"] = {
        "exact_duplicates_train_test": len(exact_train_test),
        "exact_duplicates_val_test": len(exact_val_test),
        "exact_duplicates_train_val": len(exact_train_val),
        "indic_test_templates_count": len(test_templates_ind),
        "indic_test_template_overlap_count": template_matches,
        "indic_test_template_overlap_percentage": round(template_overlap_pct, 2),
        "synthetic_in_val": synth_in_val,
        "synthetic_in_test": synth_in_test
    }

    # ---------------------------------------------------------
    # MODULE 5: Privacy & Aadhaar Redaction Check
    # ---------------------------------------------------------
    print("\n" + "=" * 80)
    print("MODULE 5: PRIVACY & AADHAAR REDACTION CHECK")
    print("=" * 80)

    total_unmasked_aadhaar = 0
    total_redacted_tokens = 0

    for name, recs in all_splits.items():
        unmasked = 0
        redacted = 0
        for r in recs:
            txt = r.get("text", "")
            raw_matches = AADHAAR_RAW_RE.findall(txt)
            if raw_matches:
                unmasked += len(raw_matches)
            if "[Aadhaar Redacted]" in txt:
                redacted += txt.count("[Aadhaar Redacted]")
                
        total_unmasked_aadhaar += unmasked
        total_redacted_tokens += redacted
        print(f"[*] {name:<6} -> Unmasked 12-digit IDs: {unmasked:4d} | Redacted Tokens: {redacted:4d}")

    print(f"\n[*] Cumulative Unmasked 12-digit Indian IDs : {total_unmasked_aadhaar} (Target: 0)")
    print(f"[*] Cumulative [Aadhaar Redacted] Tags        : {total_redacted_tokens}")

    assert total_unmasked_aadhaar == 0, f"PRIVACY ASSERTION FAILED: {total_unmasked_aadhaar} unmasked IDs found!"
    print("  -> Privacy & Redaction Assertion           : PASSED ✅")

    report["module5_privacy_aadhaar"] = {
        "total_unmasked_aadhaar": total_unmasked_aadhaar,
        "total_redacted_tokens": total_redacted_tokens,
        "status": "PASSED"
    }

    # ---------------------------------------------------------
    # SAVE AUDIT REPORT JSON
    # ---------------------------------------------------------
    with open(report_json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print("\n" + "=" * 80)
    print(f"AUDIT COMPLETE — Diagnostic report saved to: {report_json_path.name}")
    print("=" * 80)

if __name__ == "__main__":
    main()
