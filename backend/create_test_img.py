import cv2
import numpy as np

img = np.zeros((400, 800, 3), dtype=np.uint8)
img.fill(255)
cv2.putText(img, "Please pay Rs 5000 urgently.", (50, 100), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 0), 2)
cv2.putText(img, "UPI: scammer@hdfc", (50, 150), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 0), 2)
cv2.putText(img, "Call 9876543210 immediately!", (50, 200), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 0), 2)
cv2.putText(img, "Visit http://fake-electricity-bill.in", (50, 250), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 0), 2)
cv2.putText(img, "12:45 PM", (50, 350), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (100, 100, 100), 1)

cv2.imwrite("test_scam_img.png", img)
print("Created test_scam_img.png")
