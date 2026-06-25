import cv2
import numpy as np
from typing import Dict, Any


def preprocess_image(image_bytes: bytes) -> Dict[str, Any]:
    """
    Stage 1: Image preprocessing pipeline.
    
    Steps:
    1. Decode image bytes to RGB
    2. Detect dark mode and invert if needed
    3. Resize to standard dimensions (longest side = 1400px)
    4. Apply CLAHE for contrast enhancement (gentle for Devanagari)
    5. Apply bilateral filter for noise reduction
    6. Apply mild sharpening (safe for Devanagari ligatures)
    """
    nparr = np.frombuffer(image_bytes, np.uint8)
    img_bgr = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

    if img_bgr is None:
        raise ValueError("Failed to decode image")

    img_rgb = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2RGB)

    # 2. Dark Mode Detection
    gray = cv2.cvtColor(img_rgb, cv2.COLOR_RGB2GRAY)
    mean_val = np.mean(gray)
    dark_mode_detected = bool(mean_val < 110)

    if dark_mode_detected:
        img_rgb = cv2.bitwise_not(img_rgb)

    # 3. Resize maintaining aspect ratio so longest side = 1400px
    h, w = img_rgb.shape[:2]
    longest_side = max(h, w)
    if longest_side > 1400:
        scale = 1400.0 / longest_side
        new_w = int(w * scale)
        new_h = int(h * scale)
        img_rgb = cv2.resize(img_rgb, (new_w, new_h), interpolation=cv2.INTER_AREA)
    elif longest_side < 800:
        # Upscale small images for better OCR
        scale = 1200.0 / longest_side
        new_w = int(w * scale)
        new_h = int(h * scale)
        img_rgb = cv2.resize(img_rgb, (new_w, new_h), interpolation=cv2.INTER_CUBIC)

    # 4. CLAHE on L-channel (gentle clipLimit for Devanagari)
    lab = cv2.cvtColor(img_rgb, cv2.COLOR_RGB2LAB)
    l, a, b = cv2.split(lab)
    clahe = cv2.createCLAHE(clipLimit=1.5, tileGridSize=(8, 8))
    l_clahe = clahe.apply(l)
    lab_clahe = cv2.merge((l_clahe, a, b))
    img_rgb = cv2.cvtColor(lab_clahe, cv2.COLOR_LAB2RGB)

    # 5. Bilateral Filter (preserves edges while smoothing)
    img_rgb = cv2.bilateralFilter(img_rgb, d=5, sigmaColor=50, sigmaSpace=50)

    # 6. Mild Sharpen (reduced from [-1,5,-1] to [-0.5,3,-0.5])
    # Aggressive sharpening creates edge artifacts on Devanagari matras/ligatures
    kernel = np.array([[0, -0.5, 0],
                       [-0.5, 3, -0.5],
                       [0, -0.5, 0]], dtype=np.float32)
    img_rgb = cv2.filter2D(img_rgb, -1, kernel)

    return {
        "image": img_rgb,
        "dark_mode_detected": dark_mode_detected,
    }
