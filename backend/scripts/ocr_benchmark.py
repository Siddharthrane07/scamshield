import os
import sys
import json
import time
import argparse
import numpy as np
from pathlib import Path
from collections import defaultdict
from urllib.parse import urlparse

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# Add backend directory to sys.path to allow imports
backend_dir = Path(__file__).resolve().parent.parent
sys.path.append(str(backend_dir))

from app.services.ocr.ocr_engine import OCRPipeline
from app.services.ocr.ocr_postprocess import extract_entities

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

def compute_cer(reference, hypothesis):
    ref_len = len(reference)
    if ref_len == 0:
        return 0.0 if len(hypothesis) == 0 else 1.0
    dist = levenshtein_distance(reference, hypothesis)
    return dist / ref_len

def compute_wer(reference, hypothesis):
    ref_words = reference.split()
    hyp_words = hypothesis.split()
    ref_len = len(ref_words)
    if ref_len == 0:
        return 0.0 if len(hyp_words) == 0 else 1.0
    dist = levenshtein_distance(ref_words, hyp_words)
    return dist / ref_len

def log_url_failures(image_name, ground_truth_urls, extracted_urls, ocr_clean_text):
    for gt_url in ground_truth_urls:
        if gt_url not in extracted_urls:
            # Extract domain
            domain = ""
            try:
                parse_url = gt_url if "://" in gt_url else "http://" + gt_url
                parsed = urlparse(parse_url)
                domain = parsed.netloc
            except:
                domain = gt_url
                
            domain_fragment = domain[:8]
            is_present = domain_fragment.lower() in ocr_clean_text.lower()
            
            snippet = ocr_clean_text[:250].replace('\n', ' ')
            print(f"[URL FAIL] {image_name}")
            print(f"  Expected  : {gt_url}")
            print(f"  Extracted : {extracted_urls}")
            print(f"  Domain fragment present: {is_present}")
            print(f"  Relevant OCR snippet   : {snippet}")


def evaluate_entity_preservation(extracted_entities, expected_entities):
    """
    Evaluate how many expected security-critical entities survived OCR exactly.
    """
    stats = {}
    
    for key in ["urls", "phone_numbers", "upi_ids", "amounts"]:
        expected_list = expected_entities.get(key, [])
        extracted_list = extracted_entities.get(key, [])
        
        expected_count = len(expected_list)
        if expected_count == 0:
            stats[key] = {"expected": 0, "matched": 0}
            continue
            
        matched = 0
        for e in expected_list:
            if e in extracted_list:
                matched += 1
                
        stats[key] = {"expected": expected_count, "matched": matched}
        
    return stats

def process_directory(image_dir, ground_truth, pipeline):
    image_dir = Path(image_dir)
    results = []
    
    for ext in ["*.png", "*.jpg", "*.jpeg", "*.webp"]:
        for image_path in image_dir.rglob(ext):
            try:
                with open(image_path, "rb") as f:
                    image_bytes = f.read()
                
                print(f"Processing {image_path.name}...")
                
                # Execute pipeline and measure pure inference
                start_inf = time.perf_counter()
                res = pipeline.process_image(image_bytes)
                inf_time_ms = (time.perf_counter() - start_inf) * 1000.0

                
                record = {
                    "filename": image_path.name,
                    "filepath": str(image_path),
                    "folder": image_path.parent.name,
                    "folder": image_path.parent.name,
                    "clean_text": res.get("clean_text", ""),
                    "ocr_quality_score": res.get("ocr_quality_score", 0.0),
                    "execution_time_ms": inf_time_ms,
                    "fallback_used": res.get("fallback_used", False),
                    "ocr_path": "Tesseract Fallback" if res.get("fallback_used") else "Paddle Only",
                    "detected_urls": res.get("entities", {}).get("urls", []),
                    "detected_phones": res.get("entities", {}).get("phone_numbers", []),
                    "detected_upis": res.get("entities", {}).get("upi_ids", []),
                    "error": None
                }
                
                if ground_truth and image_path.name in ground_truth:
                    gt_text = ground_truth[image_path.name]
                    record["ground_truth"] = gt_text
                    record["cer"] = compute_cer(gt_text, record["clean_text"])
                    record["wer"] = compute_wer(gt_text, record["clean_text"])
                    
                    # Task 2.2: Entity Preservation
                    expected_entities = extract_entities(gt_text)
                    extracted_entities = extract_entities(record["clean_text"])
                    record["expected_entities"] = expected_entities
                    record["extracted_entities"] = extracted_entities
                    record["entity_stats"] = evaluate_entity_preservation(extracted_entities, expected_entities)

                    log_url_failures(
                        image_path.name,
                        expected_entities.get("urls", []),
                        extracted_entities.get("urls", []),
                        record["clean_text"]
                    )

                
                results.append(record)
                
            except Exception as e:
                print(f"Failed to process {image_path.name}: {e}")
                results.append({
                    "filename": image_path.name,
                    "filepath": str(image_path),
                    "folder": image_path.parent.name,
                    "error": str(e)
                })
    return results

def calculate_metrics(results):
    successful = [r for r in results if r.get("error") is None]
    failed = [r for r in results if r.get("error") is not None]
    
    metrics = {
        "total_images": len(results),
        "successful_images": len(successful),
        "failed_images": len(failed),
    }
    
    if successful:
        latencies = [r["execution_time_ms"] for r in successful]
        metrics["avg_latency_ms"] = float(np.mean(latencies))
        metrics["median_latency_ms"] = float(np.median(latencies))
        metrics["p95_latency_ms"] = float(np.percentile(latencies, 95))
        
        metrics["tesseract_fallbacks"] = sum(1 for r in successful if r["fallback_used"])
        
        with_gt = [r for r in successful if "cer" in r]
        if with_gt:
            metrics["avg_cer"] = float(np.mean([r["cer"] for r in with_gt]))
            metrics["avg_wer"] = float(np.mean([r["wer"] for r in with_gt]))
            
            # Aggregate entity stats
            total_expected = {"urls": 0, "phone_numbers": 0, "upi_ids": 0, "amounts": 0}
            total_matched = {"urls": 0, "phone_numbers": 0, "upi_ids": 0, "amounts": 0}
            for r in with_gt:
                if "entity_stats" in r:
                    for key in total_expected:
                        total_expected[key] += r["entity_stats"][key]["expected"]
                        total_matched[key] += r["entity_stats"][key]["matched"]
                        
            metrics["entity_preservation"] = {
                "urls_pct": (total_matched["urls"] / total_expected["urls"] * 100) if total_expected["urls"] > 0 else 0.0,
                "phone_numbers_pct": (total_matched["phone_numbers"] / total_expected["phone_numbers"] * 100) if total_expected["phone_numbers"] > 0 else 0.0,
                "upi_ids_pct": (total_matched["upi_ids"] / total_expected["upi_ids"] * 100) if total_expected["upi_ids"] > 0 else 0.0,
                "amounts_pct": (total_matched["amounts"] / total_expected["amounts"] * 100) if total_expected["amounts"] > 0 else 0.0,
            }
            
    return metrics

def main():
    parser = argparse.ArgumentParser(description="OCR Benchmark Harness")
    parser.add_argument("--image-dir", type=str, default=str(Path(__file__).parent / "test_images"), help="Directory containing test images")
    parser.add_argument("--ground-truth", type=str, default=None, help="Path to ground truth JSON file")
    parser.add_argument("--output", type=str, default="benchmark_results.json", help="Path to output JSON file")
    args = parser.parse_args()
    
    ground_truth = {}
    if args.ground_truth and os.path.exists(args.ground_truth):
        with open(args.ground_truth, "r", encoding="utf-8") as f:
            ground_truth = json.load(f)
            
    print(f"Starting OCR benchmark on {args.image_dir}...")
    
    # Task 2.1: Instantiate OCRPipeline ONCE outside the dataset iteration loop
    print("Initializing OCR Pipeline (Cold-Start)...")
    start_init = time.perf_counter()
    pipeline = OCRPipeline()
    init_time_ms = (time.perf_counter() - start_init) * 1000.0
    print(f"Cold-Start Init Time: {init_time_ms:.2f} ms")
    
    results = process_directory(args.image_dir, ground_truth, pipeline)
    
    if not results:
        print("No images found to process.")
        return
        
    # Calculate global metrics
    global_metrics = calculate_metrics(results)
    
    # Calculate folder-level metrics
    folder_metrics = {}
    by_folder = defaultdict(list)
    for r in results:
        by_folder[r["folder"]].append(r)
        
    for folder, folder_results in by_folder.items():
        folder_metrics[folder] = calculate_metrics(folder_results)
    
    output_data = {
        "cold_start_init_ms": init_time_ms,
        "global_metrics": global_metrics,
        "folder_metrics": folder_metrics,
        "results": results
    }
    
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=4, ensure_ascii=False)
        
    print("\n" + "="*50)
    print("OCR BENCHMARK SUMMARY")
    print("="*50)
    print(f"Total Images: {global_metrics['total_images']}")
    print(f"Successful: {global_metrics['successful_images']} | Failed: {global_metrics['failed_images']}")
    
    if global_metrics['successful_images'] > 0:
        print(f"\nGlobal Latency:")
        print(f"  Average: {global_metrics['avg_latency_ms']:.2f} ms")
        print(f"  Median:  {global_metrics['median_latency_ms']:.2f} ms")
        print(f"  P95:     {global_metrics['p95_latency_ms']:.2f} ms")
        print(f"\nTesseract Fallbacks: {global_metrics['tesseract_fallbacks']}")
        
        if "avg_cer" in global_metrics:
            print(f"\nAccuracy (Overall):")
            print(f"  Avg CER: {global_metrics['avg_cer']:.4f}")
            print(f"  Avg WER: {global_metrics['avg_wer']:.4f}")
            
            ent = global_metrics.get("entity_preservation", {})
            print(f"\nEntity Preservation Rates:")
            print(f"  URLs:   {ent.get('urls_pct', 0.0):.2f}%")
            print(f"  Phones: {ent.get('phone_numbers_pct', 0.0):.2f}%")
            print(f"  UPIs:   {ent.get('upi_ids_pct', 0.0):.2f}%")
            print(f"  Amounts:{ent.get('amounts_pct', 0.0):.2f}%")
            
    print("\n--- Folder Breakdown ---")
    for folder, m in folder_metrics.items():
        print(f"\nFolder: {folder} ({m['total_images']} images)")
        if m['successful_images'] > 0:
            print(f"  Avg Latency: {m['avg_latency_ms']:.2f} ms")
            print(f"  Fallbacks:   {m['tesseract_fallbacks']}")
            if "avg_cer" in m:
                print(f"  Avg CER:     {m['avg_cer']:.4f} | Avg WER: {m['avg_wer']:.4f}")
                
    print(f"\nResults saved to {args.output}")

if __name__ == "__main__":
    main()
