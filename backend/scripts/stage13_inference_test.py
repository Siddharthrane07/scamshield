import os
import sys
import json
import time

# Ensure backend directory is on sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app.services.ml_engine import ScamShieldPredictor

def run_stage13_smoke_test():
    print("=" * 80)
    print("SCAMSHIELD AI: STAGE 13 — LOCAL INFERENCE & FASTAPI SMOKE TEST")
    print("=" * 80)
    
    print("\n[Step 1] Instantiating ScamShieldPredictor from local package...")
    t0 = time.time()
    predictor = ScamShieldPredictor()
    load_time = time.time() - t0
    print(f"  [OK] Predictor loaded on {predictor.device} in {load_time:.2f}s.\n")

    # Test Case 1: High-Urgency KYC Phishing Attack
    test_1_text = (
        "URGENT: Your SBI bank account KYC is suspended. "
        "Click http://sbi-kyc-update.xyz immediately to verify your PAN or your account will be frozen today."
    )

    # Test Case 2: Clean Benign Social Message
    test_2_text = (
        "Hey man, are we still on for dinner at 8pm tonight? Let me know."
    )

    print("=" * 80)
    print("RUNNING TEST CASE 1: High-Urgency KYC Scam")
    print("=" * 80)
    print(f"Input Text: \"{test_1_text}\"\n")
    
    t0 = time.time()
    res1 = predictor.predict(test_1_text)
    lat1 = (time.time() - t0) * 1000

    print(json.dumps(res1, indent=2))
    print(f"\nLatency: {lat1:.2f} ms")

    # Assertions for Case 1
    assert res1["is_scam"] is True, f"Expected is_scam=True, got {res1['is_scam']}"
    assert res1["risk_score"] >= 80, f"Expected risk_score >= 80, got {res1['risk_score']}"
    assert res1["predicted_intent"] != "Legitimate / Benign", f"Expected malicious scenario, got {res1['predicted_intent']}"
    assert len(res1["social_engineering_triggers"]) > 0, "Expected at least one active trigger"
    print("  [OK] Test Case 1 PASS: Correctly identified as malicious scam attack.")

    print("\n" + "=" * 80)
    print("RUNNING TEST CASE 2: Legitimate Benign Message")
    print("=" * 80)
    print(f"Input Text: \"{test_2_text}\"\n")
    
    t0 = time.time()
    res2 = predictor.predict(test_2_text)
    lat2 = (time.time() - t0) * 1000

    print(json.dumps(res2, indent=2))
    print(f"\nLatency: {lat2:.2f} ms")

    # Assertions for Case 2
    assert res2["is_scam"] is False, f"Expected is_scam=False, got {res2['is_scam']}"
    assert res2["risk_score"] < 25, f"Expected risk_score < 25, got {res2['risk_score']}"
    assert res2["predicted_intent"] == "Legitimate / Benign", f"Expected 'Legitimate / Benign', got {res2['predicted_intent']}"
    assert len(res2["social_engineering_triggers"]) == 0, f"Expected 0 triggers, got {res2['social_engineering_triggers']}"
    print("  [OK] Test Case 2 PASS: Correctly identified as safe legitimate communication.")

    print("\n" + "=" * 80)
    print("STAGE 13 SMOKE TEST COMPLETE: LOCAL FASTAPI INTEGRATION VERIFIED!")
    print("=" * 80)

if __name__ == "__main__":
    run_stage13_smoke_test()
