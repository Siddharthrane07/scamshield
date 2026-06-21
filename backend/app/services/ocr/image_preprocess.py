import cv2
import numpy as np
from typing import Dict, Any

def preprocess_image(image_bytes: bytes) -> Dict[str, Any]:
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
    scale = 1400.0 / longest_side
    if scale != 1.0:
        new_w = int(w * scale)
        new_h = int(h * scale)
        img_rgb = cv2.resize(img_rgb, (new_w, new_h), interpolation=cv2.INTER_AREA if scale < 1.0 else cv2.INTER_CUBIC)
        
    # 4. Convert RGB->LAB, apply CLAHE to L-channel, LAB->RGB
    lab = cv2.cvtColor(img_rgb, cv2.COLOR_RGB2LAB)
    l, a, b = cv2.split(lab)
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    l_clahe = clahe.apply(l)
    lab_clahe = cv2.merge((l_clahe, a, b))
    img_rgb = cv2.cvtColor(lab_clahe, cv2.COLOR_LAB2RGB)
    
    # 5. Bilateral Filter
    img_rgb = cv2.bilateralFilter(img_rgb, d=5, sigmaColor=75, sigmaSpace=75)
    
    # 6. Sharpen
    kernel = np.array([[0, -1, 0],
                       [-1, 5, -1],
                       [0, -1, 0]], dtype=np.float32)
    img_rgb = cv2.filter2D(img_rgb, -1, kernel)
    
    return {
        "image": img_rgb,
        "dark_mode_detected": dark_mode_detected
    }
