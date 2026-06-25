"""
Diagnostic: Test PaddleOCR English vs Hindi (Devanagari) on the actual screenshot.
Prints raw results from both engines so we can see exactly what each produces.
"""
import sys, os, cv2, numpy as np

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from paddleocr import PaddleOCR
import re

def main():
    img_path = sys.argv[1] if len(sys.argv) > 1 else "test_scam_img.png"
    
    # Load image
    img = cv2.imread(img_path)
    if img is None:
        print(f"ERROR: Cannot load {img_path}")
        return
    img_rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
    print(f"Image loaded: {img_rgb.shape}")
    
    # Dark mode inversion
    gray = cv2.cvtColor(img_rgb, cv2.COLOR_RGB2GRAY)
    if np.mean(gray) < 110:
        print("Dark mode detected - inverting")
        img_rgb = cv2.bitwise_not(img_rgb)
    
    # ===== TEST 1: English OCR =====
    print("\n" + "="*60)
    print("TEST 1: PaddleOCR lang='en'")
    print("="*60)
    paddle_en = PaddleOCR(lang='en', use_mkldnn=True, show_log=False)
    result_en = paddle_en.ocr(img_rgb)
    
    devnagari_re = re.compile(r'[\u0900-\u097F]')
    
    if result_en and result_en[0]:
        for i, line in enumerate(result_en[0]):
            bbox, (text, conf) = line
            has_dev = "DEVANAGARI" if devnagari_re.search(text) else ""
            print(f"  [{i:2d}] conf={conf:.3f} {has_dev:12s} | {text}")
    else:
        print("  No results")
    
    # ===== TEST 2: Hindi (Devanagari) OCR - FULL IMAGE =====
    print("\n" + "="*60)
    print("TEST 2: PaddleOCR lang='hi' (FULL IMAGE)")
    print("="*60)
    paddle_hi = PaddleOCR(lang='hi', use_mkldnn=True, show_log=False)
    result_hi = paddle_hi.ocr(img_rgb)
    
    if result_hi and result_hi[0]:
        for i, line in enumerate(result_hi[0]):
            bbox, (text, conf) = line
            has_dev = "DEVANAGARI" if devnagari_re.search(text) else ""
            print(f"  [{i:2d}] conf={conf:.3f} {has_dev:12s} | {text}")
    else:
        print("  No results")
    
    # ===== TEST 3: Compare approach - only crop+run Hindi where English detected Devanagari =====
    print("\n" + "="*60)
    print("TEST 3: Crop+Hindi on regions where English found Devanagari")
    print("="*60)
    if result_en and result_en[0]:
        for i, line in enumerate(result_en[0]):
            bbox, (text, conf) = line
            if devnagari_re.search(text):
                tl_x = max(0, int(bbox[0][0]) - 10)
                tl_y = max(0, int(bbox[0][1]) - 10)
                br_x = min(img_rgb.shape[1], int(bbox[2][0]) + 10)
                br_y = min(img_rgb.shape[0], int(bbox[2][1]) + 10)
                crop = img_rgb[tl_y:br_y, tl_x:br_x]
                if crop.size == 0:
                    continue
                result_crop = paddle_hi.ocr(crop)
                if result_crop and result_crop[0]:
                    for j, cline in enumerate(result_crop[0]):
                        _, (ctext, cconf) = cline
                        print(f"  EN[{i:2d}] '{text[:30]}...' -> HI crop: conf={cconf:.3f} | {ctext}")
                else:
                    print(f"  EN[{i:2d}] '{text[:30]}...' -> HI crop: No results")

if __name__ == "__main__":
    main()
