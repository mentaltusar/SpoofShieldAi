import os
import re
import email
import mailbox
import idna
import tldextract
import pandas as pd
from email.utils import parseaddr
import joblib
from Levenshtein import ratio as levenshtein_ratio
import pytesseract
from PIL import Image
import io
import cv2


pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"


# =======================================
# Load Trained Body Spam Model (AI #1)
# =======================================
MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")
VECTORIZER_PATH = os.path.join(MODELS_DIR, "vectorizer.pkl")
BODY_MODEL_PATH = os.path.join(MODELS_DIR, "body_spam_model.pkl")

vectorizer, body_model = None, None
if os.path.exists(VECTORIZER_PATH) and os.path.exists(BODY_MODEL_PATH):
    vectorizer = joblib.load(VECTORIZER_PATH)
    body_model = joblib.load(BODY_MODEL_PATH)
    print("[+] Body spam model loaded successfully.")
else:
    print("[!] body_spam_model.pkl or vectorizer.pkl not found. Run train_body_model.py first.")


# =======================================
# Utility Functions
# =======================================
def decode_idn(domain):
    try:
        return idna.decode(domain)
    except Exception:
        return domain

def punycode_used(domain):
    return "Yes" if str(domain).startswith("xn--") else "No"

def extract_domain(addr):
    try:
        email_addr = parseaddr(addr)[1]
        return email_addr.split("@")[-1].lower() if "@" in email_addr else "null"
    except Exception:
        return "null"

def extract_registered(domain):
    try:
        ext = tldextract.extract(domain)
        return ext.top_domain_under_public_suffix

    except Exception:
        return "null"

def extract_spf_dkim_dmarc(headers):
    spf, dkim, dmarc = "none", "none", "none"
    for h, v in headers.items():
        hv = str(v).lower()
        if "spf" in h.lower():
            if "pass" in hv: spf = "pass"
            elif "fail" in hv: spf = "fail"
        if "dkim" in h.lower():
            if "pass" in hv: dkim = "pass"
            elif "fail" in hv: dkim = "fail"
        if "dmarc" in h.lower():
            if "pass" in hv: dmarc = "pass"
            elif "fail" in hv: dmarc = "fail"
    return spf, dkim, dmarc

# =======================================
# Domain Similarity Detector
# =======================================
KNOWN_BRANDS = [
    "paypal.com", "google.com", "apple.com", "microsoft.com",
    "amazon.com", "facebook.com", "netflix.com", "gov.in", "icici.com",
    "sbi.co.in", "hdfcbank.com", "flipkart.com"
]

def domain_similarity(domain):
    """Return similarity score and the closest known brand domain."""
    domain = str(domain).lower()
    if not domain or domain == "null":
        return 0.0, "none"

    best_score = 0.0
    closest_brand = "none"

    for brand in KNOWN_BRANDS:
        score = levenshtein_ratio(domain, brand)
        if score > best_score:
            best_score = score
            closest_brand = brand

    return round(best_score * 100, 2), closest_brand

# =======================================
# OCR Logo Text Detection
# =======================================
def detect_logo_text(msg):
    """Extract text from inline images or attachments and infer logo brand similarity."""
    extracted_texts = []
    detected_brands = []
    suspicious_keywords = ["paypal", "google", "amazon", "microsoft", "apple", "gov", "bank", "login"]

    for part in msg.walk():
        ctype = part.get_content_type()
        if "image" in ctype:
            try:
                img_data = part.get_payload(decode=True)
                img = Image.open(io.BytesIO(img_data)).convert("RGB")
                text = pytesseract.image_to_string(img)
                clean_text = re.sub(r"[^A-Za-z0-9]+", " ", text).lower()
                extracted_texts.append(clean_text)

                for brand in suspicious_keywords:
                    if brand in clean_text:
                        detected_brands.append(brand)
            except Exception as e:
                continue

    if not extracted_texts:
        return "No image text found", 0.0, "none"

    # Combine OCR text from all images
    combined_text = " ".join(extracted_texts).strip()
    if not combined_text:
        return "No text detected", 0.0, "none"

    # Calculate similarity if any known brand appears
    best_score, best_brand = 0.0, "none"
    for brand in suspicious_keywords:
        if brand in combined_text:
            score = levenshtein_ratio(combined_text, brand) * 100
            if score > best_score:
                best_score, best_brand = score, brand

    return combined_text, round(best_score, 2), best_brand

# =======================================
# Body Analysis using ML Model
# =======================================
def analyze_body_ml(text):
    """Predict spam probability using the trained body model."""
    if not body_model or not vectorizer:
        return 0.0, "Body model unavailable"

    clean_text = re.sub(r'\s+', ' ', str(text).lower().strip())
    if not clean_text:
        return 0.0, "Empty body text"

    try:
        X = vectorizer.transform([clean_text])
        prob = body_model.predict_proba(X)[0][1] * 100
    except Exception as e:
        print(f"[!] Body model prediction error: {e}")
        return 0.0, "Prediction error"

    if prob >= 80:
        reason = "Highly suspicious or phishing tone"
    elif prob >= 50:
        reason = "Moderately spammy"
    elif prob >= 20:
        reason = "Mild spam indicators"
    else:
        reason = "Clean message"

    return round(prob, 2), reason


# =======================================
# Feature Extraction Core
# =======================================
def extract_features(msg):
    headers = dict(msg.items())

    sender_raw = extract_domain(headers.get("From", ""))
    return_raw = extract_domain(headers.get("Return-Path", ""))
    mid_raw = extract_domain(headers.get("Message-ID", ""))

    sender_decoded = decode_idn(sender_raw)
    return_decoded = decode_idn(return_raw)
    mid_decoded = decode_idn(mid_raw)

    sender_registered = extract_registered(sender_raw)
    return_registered = extract_registered(return_raw)
    mid_registered = extract_registered(mid_raw)
    similarity_score, closest_brand = domain_similarity(sender_registered)
    ocr_text, logo_match_score, logo_brand = detect_logo_text(msg)

    spf, dkim, dmarc = extract_spf_dkim_dmarc(headers)

    domains_match = "Yes" if sender_registered == return_registered else "No"
    mismatch = "Yes" if sender_registered != return_registered else "No"

    received_count = len([h for h in headers.keys() if h.lower() == "received"])

    # ---------- Extract Body ----------
    body_text = ""
    body_length, upper_words, exclamations, suspicious_keywords = 0, 0, 0, 0
    total_links, idn_links, emd_embed = 0, 0, 0
    suspicious_kw_list = ["verify", "update", "password", "bank", "account", "urgent"]

    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype in ["text/plain", "text/html"]:
            try:
                text = part.get_payload(decode=True).decode(errors="ignore")
            except Exception:
                text = str(part.get_payload())

            body_text += " " + text
            body_length += len(text)
            upper_words += sum(1 for w in text.split() if w.isupper())
            exclamations += text.count("!")
            suspicious_keywords += sum(text.lower().count(kw) for kw in suspicious_kw_list)

            urls = re.findall(r"https?://[^\s]+", text)
            total_links += len(urls)
            for url in urls:
                domain = tldextract.extract(url).top_domain_under_public_suffix

                if punycode_used(domain) == "Yes":
                    idn_links += 1

            if "emd:embed" in text.lower():
                emd_embed = 1

    # ---------- Attachments ----------
    attachments, suspicious_attachments = 0, 0
    bad_ext = [".exe", ".scr", ".js", ".bat", ".vbs"]
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            attachments += 1
            if any(filename.lower().endswith(ext) for ext in bad_ext):
                suspicious_attachments += 1

    # ---------- Images ----------
    total_images, suspicious_images, base64_images = 0, 0, 0
    suspicious_logo_keywords = ["paypal", "amazon", "bank", "login", "microsoft", "gov", "apple", "google"]
    for part in msg.walk():
        ctype = part.get_content_type()
        if "image" in ctype:
            total_images += 1
            filename = part.get_filename() or ""
            if any(kw in filename.lower() for kw in suspicious_logo_keywords):
                suspicious_images += 1
            if "base64" in str(part.get("Content-Transfer-Encoding", "")).lower():
                base64_images += 1

    # ---------- ML Spam Analysis ----------
    ml_body_prob_pct, ml_body_reason = analyze_body_ml(body_text)

    return {
        "sender_raw_domain": sender_raw,
        "sender_decoded": sender_decoded,
        "return_raw_domain": return_raw,
        "return_decoded": return_decoded,
        "message_id_raw": mid_raw,
        "message_id_decoded": mid_decoded,
        "sender_registered": sender_registered,
        "return_registered": return_registered,
        "mid_registered": mid_registered,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "idn_used": punycode_used(sender_raw),
        "domains_match": domains_match,
        "mismatch": mismatch,
        "domain_similarity_score": similarity_score,
        "closest_brand_match": closest_brand,
        "logo_text_extracted": ocr_text,
        "logo_match_score": logo_match_score,
        "logo_brand_detected": logo_brand,
        "received_count": received_count,
        "body_length": body_length,
        "upper_words": upper_words,
        "exclamations": exclamations,
        "suspicious_keywords": suspicious_keywords,
        "total_links": total_links,
        "idn_links": idn_links,
        "emd_embed": emd_embed,
        "attachments": attachments,
        "suspicious_attachments": suspicious_attachments,
        "total_images": total_images,
        "suspicious_images": suspicious_images,
        "base64_images": base64_images,
        "ml_body_prob_pct": ml_body_prob_pct,
        "ml_body_reason": ml_body_reason
    }


# =======================================
# Process .eml, .mbox or directory
# =======================================
def process_eml_or_mbox(input_path="emails", output_csv="dataset.csv"):
    data = []

    def handle_msg(msg):
        try:
            feats = extract_features(msg)
            if feats:
                data.append(feats)
        except Exception as e:
            print(f"[!] Error processing message: {e}")

    if os.path.isdir(input_path):
        for root, _, files in os.walk(input_path):
            for f in files:
                full = os.path.join(root, f)
                if f.endswith(".eml"):
                    with open(full, "rb") as eml:
                        msg = email.message_from_binary_file(eml)
                        handle_msg(msg)
                elif f.endswith(".mbox"):
                    mbox = mailbox.mbox(full)
                    for msg in mbox:
                        handle_msg(msg)
    elif input_path.endswith(".eml"):
        with open(input_path, "rb") as eml:
            msg = email.message_from_binary_file(eml)
            handle_msg(msg)
    elif input_path.endswith(".mbox"):
        mbox = mailbox.mbox(input_path)
        for msg in mbox:
            handle_msg(msg)
    else:
        print("[!] Unsupported input type. Provide a directory, .eml or .mbox file.")
        return

    if not data:
        print("[!] No valid emails processed.")
        return

    df = pd.DataFrame(data)
    df.to_csv(output_csv, index=False, encoding="utf-8")
    print(f"[+] Extraction complete! {len(df)} emails analyzed → {output_csv}")
    return df


# =======================================
# Auto-run when executed directly
# =======================================
if __name__ == "__main__":
    process_eml_or_mbox(input_path="../emails", output_csv="dataset.csv")
