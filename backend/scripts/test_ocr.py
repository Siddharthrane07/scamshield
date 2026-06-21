import sys
import os
import argparse
import time
import json

# Add backend to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.services.ocr.ocr_engine import OCRPipeline

def main():
    parser = argparse.ArgumentParser(description="Test OCR Pipeline")
    parser.add_argument("image_path", type=str, help="Path to the test image")
    args = parser.parse_args()

    if not os.path.exists(args.image_path):
        print(f"Error: File not found at {args.image_path}")
        sys.exit(1)

    print(f"Loading image from {args.image_path}...")
    with open(args.image_path, "rb") as f:
        image_bytes = f.read()

    print("Running OCR Pipeline...")
    
    # Run once to warm up paddle models
    print("Warming up models...")
    _ = OCRPipeline.process_image(image_bytes)
    
    # Real test
    start_time = time.perf_counter()
    result = OCRPipeline.process_image(image_bytes)
    total_time_ms = (time.perf_counter() - start_time) * 1000

    print("\n--- TEST RESULTS ---")
    print(f"Raw Text:\n{result['raw_text']}\n")
    print(f"Clean Text:\n{result['clean_text']}\n")
    print(f"Entities:\n{json.dumps(result['entities'], indent=2)}\n")
    
    print(f"Dark Mode Detected: {result['dark_mode_detected']}")
    print(f"Devanagari Detected: {result['devanagari_detected']}")
    print(f"Fallback Used: {result['fallback_used']}")
    print(f"OCR Quality Score: {result['ocr_quality_score']:.2f}")
    
    print(f"\nExecution Time (Reported): {result['execution_time_ms']:.2f} ms")
    print(f"Execution Time (Actual): {total_time_ms:.2f} ms")
    
    if result['execution_time_ms'] < 800:
        print("✅ SLA MET: Total execution under 800ms")
    else:
        print("❌ SLA FAILED: Total execution over 800ms")

if __name__ == "__main__":
    main()
