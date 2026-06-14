import logging
from typing import Dict, Any, List

logger = logging.getLogger("scamshield.explanation")

# Dictionary containing English safety narrative templates
TEMPLATES_EN = {
    "intro": "This communication has been analyzed and classified as {category} (Risk Score: {score}/100).",
    
    # Social engineering signals
    "social_urgency": "• It contains high-urgency language demanding immediate action to avoid consequences.",
    "social_fear": "• It attempts to induce fear, threatening legal action, police involvement, or account suspension.",
    "social_authority_impersonation": "• It impersonates an authority figure, government department, utility board, or bank support desk.",
    "social_reward_bait": "• It uses bait tactics, offering lottery winnings, gifts, rewards, or free cashbacks.",
    "social_financial_pressure": "• It references unpaid bills, pending charges, or fines to pressure you into paying.",
    
    # Intent signals
    "fake_kyc": "• The message intent is highly indicative of a Fake KYC verification scam designed to steal identity details.",
    "otp_theft": "• The message is structured to solicit an OTP (One-Time Password) or security PIN.",
    "upi_fraud": "• It requests or links to suspicious UPI payments or cash-request transfers.",
    "job_scams": "• It offers suspicious work-from-home or high-paying job opportunities with minimal requirements.",
    "delivery_scams": "• It mimics package tracking or delivery failure alerts to request payment or details.",
    
    # Link intelligence signals
    "typosquatting": "• The link mimics the trusted brand '{brand}' but uses typosquatting (altered spelling) to deceive you.",
    "virustotal": "• The link was flagged as malicious or suspicious by multiple security engines on VirusTotal.",
    "recent_domain": "• The destination website domain is extremely new (registered less than 30 days ago).",
    "ssl_free": "• The website uses a free/anonymous SSL certificate, a setup frequently chosen for short-lived scam sites.",
    "ssl_invalid": "• The destination website has an invalid or expired SSL certificate, exposing you to connection tampering.",
    
    # Sandbox signals
    "sandbox_dom": "• Automated sandbox analysis detected input fields requesting passwords or payment details on the landing page.",
    "sandbox_timeout": "• The destination website failed to load or attempted to block automated inspection (hostile timeout penalty applied).",

    # Outro
    "recommendation_Safe": "ScamShield Recommendation: The message appears safe, but always verify details before acting on unscheduled alerts.",
    "recommendation_Suspicious": "ScamShield Recommendation: Exercise caution. Do not click links or share details. Verify the sender through official contact channels.",
    "recommendation_High Risk": "ScamShield Recommendation: DO NOT click any links, do not share OTPs, and block the sender immediately. This is a confirmed threat."
}

# Dictionary containing Hindi safety narrative templates
TEMPLATES_HI = {
    "intro": "इस संदेश का विश्लेषण किया गया है और इसे {category} (जोखिम स्कोर: {score}/100) के रूप में वर्गीकृत किया गया है।",
    
    # Social engineering signals
    "social_urgency": "• इसमें परिणामों से बचने के लिए तत्काल कार्रवाई की मांग करने वाले शब्द शामिल हैं।",
    "social_fear": "• यह कानूनी कार्रवाई, पुलिस भागीदारी, या खाता निलंबन की धमकी देकर डर पैदा करने का प्रयास करता है।",
    "social_authority_impersonation": "• यह किसी सरकारी विभाग, बिजली विभाग, बैंक अधिकारी या सहायता कर्मचारी का रूप धारण करता है।",
    "social_reward_bait": "• यह लॉटरी, उपहार, कैशबैक, या पुरस्कार का लालच देने वाले हथकंडों का उपयोग करता है।",
    "social_financial_pressure": "• भुगतान के लिए दबाव बनाने के लिए यह बकाया बिलों या शुल्कों का संदर्भ देता है।",
    
    # Intent signals
    "fake_kyc": "• इसका इरादा नकली केवाईसी (KYC) सत्यापन घोटाला लगता है जो क्रेडेंशियल्स चुराने के लिए बनाया गया है।",
    "otp_theft": "• यह संदेश संभवतः ओटीपी (OTP) या सुरक्षा पिन चुराने के लिए बनाया गया है।",
    "upi_fraud": "• यह संदिग्ध यूपीआई (UPI) लेनदेन का अनुरोध या संचालन करता है।",
    "job_scams": "• यह संदिग्ध वर्क-फ्रॉम-होम या उच्च-कमाई वाले नकली नौकरी के अवसरों की पेशकश करता है।",
    "delivery_scams": "• यह व्यक्तिगत जानकारी प्राप्त करने के लिए कूरियर/पैकेज डिलीवरी समस्याओं की नकल करता है।",
    
    # Link intelligence signals
    "typosquatting": "• यह लिंक एक विश्वसनीय ब्रांड '{brand}' की नकल करता है लेकिन आपको धोखा देने के लिए बदली हुई स्पेलिंग का उपयोग करता है।",
    "virustotal": "• यूआरएल को एंटीवायरस इंजन द्वारा दुर्भावनापूर्ण या संदिग्ध के रूप में चिह्नित किया गया था।",
    "recent_domain": "• यह लिंक एक बहुत ही हाल ही में पंजीकृत डोमेन (30 दिनों से कम समय पहले बनाया गया) की ओर इशारा करता है।",
    "ssl_free": "• वेबसाइट एक मुफ्त/अनाम एसएसएल प्रमाणपत्र का उपयोग करती है जो आमतौर पर अस्थायी धोखाधड़ी साइटों द्वारा उपयोग किया जाता है।",
    "ssl_invalid": "• वेबसाइट का एसएसएल सर्टिफिकेट अमान्य या समाप्त हो चुका है, जो आपके कनेक्शन को जोखिम में डालता है।",
    
    # Sandbox signals
    "sandbox_dom": "• सैंडबॉक्स स्कैन ने लैंडिंग पृष्ठ पर पासवर्ड या भुगतान इनपुट का पता लगाया है।",
    "sandbox_timeout": "• लैंडिंग पृष्ठ लोड होने में विफल रहा या स्वचालित निरीक्षण को अवरुद्ध करने का प्रयास किया (समय सीमा जुर्माना लागू)।",

    # Outro
    "recommendation_Safe": "स्कैमशील्ड की सिफारिश: संदेश सुरक्षित प्रतीत होता है, लेकिन किसी भी संदिग्ध चेतावनी पर कार्रवाई करने से पहले हमेशा विवरणों को सत्यापित करें।",
    "recommendation_Suspicious": "स्कैमशील्ड की सिफारिश: सावधानी बरतें। लिंक पर क्लिक न करें या विवरण साझा न करें। आधिकारिक चैनलों के माध्यम से प्रेषक की पहचान सत्यापित करें।",
    "recommendation_High Risk": "स्कैमशील्ड की सिफारिश: किसी भी लिंक पर क्लिक न करें, ओटीपी (OTP) साझा न करें और प्रेषक को तुरंत ब्लॉक करें। यह एक पुष्टि खतरा है।"
}

class ExplanationEngine:
    @classmethod
    def generate_narrative(cls, pipeline_result: Dict[str, Any]) -> Dict[str, str]:
        """
        Layer 7 Explanation Engine.
        Maps pipeline indicators mathematically to localized templates.
        """
        score = pipeline_result.get("risk_score", 0)
        category = pipeline_result.get("risk_category", "Safe")
        
        tracks = pipeline_result.get("tracks", {})
        track_a = tracks.get("track_a_url_intel", {})
        track_b = tracks.get("track_b_domain_intel", {})
        track_c = tracks.get("track_c_sandbox", {})
        track_d = tracks.get("track_d_ml_engine", {})
        
        # Lists to store active bullet points
        bullets_en = []
        bullets_hi = []
        
        # 1. Social Engineering Indicators (ML Head 1)
        social_eng = track_d.get("social_engineering", {})
        for facet, prob in social_eng.items():
            if prob >= 0.5:
                if facet in TEMPLATES_EN:
                    bullets_en.append(TEMPLATES_EN[facet])
                    bullets_hi.append(TEMPLATES_HI[facet])
                    
        # 2. Scam Intent Indicators (ML Head 2)
        intent_data = track_d.get("scam_intent", {})
        detected_intent = intent_data.get("detected_intent", "legitimate")
        if detected_intent != "legitimate":
            if detected_intent in TEMPLATES_EN:
                bullets_en.append(TEMPLATES_EN[detected_intent])
                bullets_hi.append(TEMPLATES_HI[detected_intent])
                
        # 3. URL/Typosquatting Indicators (Track A)
        urls_analyzed = track_a.get("urls_analyzed", [])
        typosquatted_brand = None
        for url_item in urls_analyzed:
            typo_info = url_item.get("typosquatting", {})
            if typo_info.get("is_typosquatted"):
                typosquatted_brand = typo_info.get("target_brand", "trusted brand")
                break
                
        if typosquatted_brand:
            bullets_en.append(TEMPLATES_EN["typosquatting"].format(brand=typosquatted_brand.upper()))
            bullets_hi.append(TEMPLATES_HI["typosquatting"].format(brand=typosquatted_brand.upper()))
            
        # VirusTotal indicator
        vt_flagged = any(u.get("virustotal", {}).get("verdict") == "malicious" for u in urls_analyzed)
        if vt_flagged:
            bullets_en.append(TEMPLATES_EN["virustotal"])
            bullets_hi.append(TEMPLATES_HI["virustotal"])
            
        # 4. Domain & SSL Indicators (Track B)
        domains_analyzed = track_b.get("domains_analyzed", [])
        recent_domain_detected = any(d.get("whois", {}).get("is_recent_domain") for d in domains_analyzed)
        free_ssl_detected = any(d.get("ssl", {}).get("is_free_ssl") for d in domains_analyzed)
        invalid_ssl_detected = any(not d.get("ssl", {}).get("ssl_valid") for d in domains_analyzed)
        
        if recent_domain_detected:
            bullets_en.append(TEMPLATES_EN["recent_domain"])
            bullets_hi.append(TEMPLATES_HI["recent_domain"])
        if free_ssl_detected:
            bullets_en.append(TEMPLATES_EN["ssl_free"])
            bullets_hi.append(TEMPLATES_HI["ssl_free"])
        if invalid_ssl_detected:
            bullets_en.append(TEMPLATES_EN["ssl_invalid"])
            bullets_hi.append(TEMPLATES_HI["ssl_invalid"])
            
        # 5. Sandbox Indicators (Track C)
        sandbox_status = track_c.get("sandbox_status", "skipped")
        if sandbox_status == "hostile_timeout":
            bullets_en.append(TEMPLATES_EN["sandbox_timeout"])
            bullets_hi.append(TEMPLATES_HI["sandbox_timeout"])
        elif sandbox_status == "completed":
            dom_signals = track_c.get("dom_signals", {})
            if dom_signals.get("has_auth_inputs") or dom_signals.get("has_payment_forms"):
                bullets_en.append(TEMPLATES_EN["sandbox_dom"])
                bullets_hi.append(TEMPLATES_HI["sandbox_dom"])

        # Translate Category names for intro
        cat_map_hi = {
            "Safe": "सुरक्षित (Safe)",
            "Suspicious": "संदिग्ध (Suspicious)",
            "High Risk": "अत्यंत जोखिम (High Risk)"
        }
        category_hi = cat_map_hi.get(category, category)

        # Stitch together the final narrative
        intro_en = TEMPLATES_EN["intro"].format(category=category, score=score)
        intro_hi = TEMPLATES_HI["intro"].format(category=category_hi, score=score)
        
        outro_en = TEMPLATES_EN[f"recommendation_{category}"]
        outro_hi = TEMPLATES_HI[f"recommendation_{category}"]
        
        # Combine bullets
        body_en = "\n".join(bullets_en) if bullets_en else "• No active scam indicators or social engineering cues detected."
        body_hi = "\n".join(bullets_hi) if bullets_hi else "• कोई सक्रिय घोटाला संकेतक या सोशल इंजीनियरिंग संकेत नहीं मिले।"
        
        narrative_en = f"{intro_en}\n\nAnalysis Findings:\n{body_en}\n\n{outro_en}"
        narrative_hi = f"{intro_hi}\n\nविश्लेषण के निष्कर्ष:\n{body_hi}\n\n{outro_hi}"
        
        return {
            "en": narrative_en,
            "hi": narrative_hi
        }
