import json
import os
from pathlib import Path
import sys

def levenshtein_distance(s1, s2):
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def main():
    base_dir = Path(__file__).resolve().parent
    
    with open(base_dir / "hindi_copilot.json", "r", encoding="utf-8") as f:
        hindi_gt = json.load(f)
        
    with open(base_dir / "english_copilot.json", "r", encoding="utf-8") as f:
        english_gt = json.load(f)
        
    with open(base_dir.parent / "benchmark_results.json", "r", encoding="utf-8") as f:
        bench_res = json.load(f)
        
    all_copilot = list(hindi_gt.values()) + list(english_gt.values())
    mapped_gt = {}
    
    for r in bench_res["results"]:
        filename = r["filename"]
        ocr_text = r.get("clean_text", "")
        
        if not ocr_text:
            continue
        # Find best match in copilot strings
        best_match = None
        best_dist = float('inf')
        
        for c_text in all_copilot:
            dist = levenshtein_distance(ocr_text, c_text)
            if dist < best_dist:
                best_dist = dist
                best_match = c_text
                
        mapped_gt[filename] = best_match
        print(f"Mapped {filename} (Dist: {best_dist})")
        
    with open(base_dir / "ground_truth.json", "w", encoding="utf-8") as f:
        json.dump(mapped_gt, f, indent=4, ensure_ascii=False)
        
    print(f"Successfully mapped {len(mapped_gt)} ground truth entries.")

if __name__ == "__main__":
    main()
