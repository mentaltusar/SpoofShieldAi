import os
import re
import email
import mailbox
import idna
import tldextract
import pandas as pd
from email.utils import parseaddr

# ---------------- Utility Functions ----------------
def decode_idn(domain):
    try:
        return idna.decode(domain)
    except:
        return domain

def punycode_used(domain):
    return "Yes" if str(domain).startswith("xn--") else "No"

def extract_domain(addr):
    try:
        email_addr = parseaddr(addr)[1]
        return email_addr.split("@")[-1].lower() if "@" in email_addr else "null"
    except:
        return "null"

def extract_registered(domain):
    try:
        ext = tldextract.extract(domain)
        return ext.registered_domain
    except:
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

# ---------------- Feature Extractor ----------------
def extract_features(msg):
    headers = dict(msg.items())

    sender_raw = extract_domain(headers.get("From",""))
    return_raw = extract_domain(headers.get("Return-Path",""))
    mid_raw = extract_domain(headers.get("Message-ID",""))

    sender_decoded = decode_idn(sender_raw)
    return_decoded = decode_idn(return_raw)
    mid_decoded = decode_idn(mid_raw)

    sender_registered = extract_registered(sender_raw)
    return_registered = extract_registered(return_raw)
    mid_registered = extract_registered(mid_raw)

    spf, dkim, dmarc = extract_spf_dkim_dmarc(headers)

    # mismatch
    domains_match = "Yes" if sender_registered == return_registered else "No"
    mismatch = "Yes" if sender_registered != return_registered else "No"

    # received headers
    received_count = len([h for h in headers.keys() if h.lower()=="received"])

    # body analysis
    body_length, upper_words, exclamations, suspicious_keywords = 0,0,0,0
    total_links, idn_links, emd_embed = 0,0,0
    suspicious_kw_list = ["verify","update","password","bank","account","urgent"]

    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype in ["text/plain","text/html"]:
            try:
                text = part.get_payload(decode=True).decode(errors="ignore")
            except:
                text = str(part.get_payload())

            body_length += len(text)
            upper_words += sum(1 for w in text.split() if w.isupper())
            exclamations += text.count("!")
            suspicious_keywords += sum(text.lower().count(kw) for kw in suspicious_kw_list)

            # links
            urls = re.findall(r"https?://[^\s]+", text)
            total_links += len(urls)
            for url in urls:
                domain = tldextract.extract(url).registered_domain
                if punycode_used(domain)=="Yes":
                    idn_links += 1

            if "emd:embed" in text.lower():
                emd_embed = 1

    # attachments
    attachments, suspicious_attachments = 0,0
    bad_ext = [".exe",".scr",".js",".bat",".vbs"]
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            attachments += 1
            if any(filename.lower().endswith(ext) for ext in bad_ext):
                suspicious_attachments += 1

    # images
    total_images, suspicious_images, base64_images = 0,0,0
    suspicious_logo_keywords = ["paypal","amazon","bank","login","microsoft","gov","apple","google"]

    for part in msg.walk():
        ctype = part.get_content_type()
        if "image" in ctype:
            total_images += 1
            filename = part.get_filename() or ""
            if any(kw in filename.lower() for kw in suspicious_logo_keywords):
                suspicious_images += 1
            if "base64" in str(part.get("Content-Transfer-Encoding","")).lower():
                base64_images += 1

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
        "base64_images": base64_images
    }

def process_eml_or_mbox(path):
    data = []
    try:
        if path.endswith(".eml"):
            with open(path,"rb") as f:
                msg = email.message_from_binary_file(f)
                data.append(extract_features(msg))
        elif path.endswith(".mbox"):
            mbox = mailbox.mbox(path)
            for msg in mbox:
                data.append(extract_features(msg))
    except Exception as e:
        print(f"Error processing {path}: {e}")
    return pd.DataFrame(data)
