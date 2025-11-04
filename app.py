# SpoofShield AI - Flask Web App
import os
import re
from dotenv import load_dotenv
load_dotenv()
from joblib import load
import lightgbm as lgb
import pandas as pd
import email
import mailbox
import traceback
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
from extractor_features import extract_features
import warnings
from oauth_setup import google_bp, github_bp
warnings.filterwarnings("ignore", category=UserWarning)


app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "supersecretkey_dev")

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "models")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Store your keys as environment variables, NOT hardcoded in the file
app.config["GOOGLE_OAUTH_CLIENT_ID"] = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")
app.config["GITHUB_OAUTH_CLIENT_ID"] = os.environ.get("GITHUB_OAUTH_CLIENT_ID")
app.config["GITHUB_OAUTH_CLIENT_SECRET"] = os.environ.get("GITHUB_OAUTH_CLIENT_SECRET")

# Create OAuth blueprints
app.register_blueprint(google_bp, url_prefix="/login")
app.register_blueprint(github_bp, url_prefix="/login")

# Register blueprints with your main app

# ---------- Load Models ----------
model = None
vectorizer = None

try:
    body_model_path = os.path.join(MODEL_DIR, "body_spam_model.pkl")
    main_model_path = os.path.join(MODEL_DIR, "random_forest_model.pkl")
    vectorizer_path = os.path.join(MODEL_DIR, "tfidf_vectorizer.pkl")

    if os.path.exists(main_model_path):
        model = load(main_model_path)
        print("[+] SpoofShield AI model loaded successfully!")
    else:
        print("[!] SpoofShield AI model not found:", main_model_path)

    # Load the vectorizer
    if os.path.exists(vectorizer_path):
        vectorizer = load(vectorizer_path)
        print("[+] TF-IDF vectorizer loaded successfully!")
    else:
        print("[!] TF-IDF vectorizer not found:", vectorizer_path)

except Exception as e:
    print("[ERROR] Could not load model/vectorizer:", e)


ALLOWED_EXTENSIONS = {"eml", "mbox"}

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# ---------- Helper Functions ----------
def safe_extract_features_from_path(filepath):
    try:
        out = extract_features(filepath)
        if isinstance(out, dict):
            return out
    except Exception:
        pass

    try:
        with open(filepath, "rb") as f:
            msg = email.message_from_binary_file(f)
        out = extract_features(msg)
        if isinstance(out, dict):
            return out
    except Exception:
        pass

    try:
        mbox = mailbox.mbox(filepath)
        for m in mbox:
            try:
                out = extract_features(m)
                if isinstance(out, dict):
                    return out
            except Exception:
                continue
    except Exception:
        pass

    return {}

def extract_domain_from_addr(s):
    if not s:
        return ""
    m = re.search(r"@([A-Za-z0-9\.\-\u00A0-\uFFFF]+)", str(s))
    if m:
        return m.group(1)
    parts = re.split(r"[<>\s/]", str(s))
    for p in reversed(parts):
        if "." in p:
            return p.strip()
    return str(s)

def find_spammy_words_from_body(body_text):
    kw = ["urgent", "password", "verify", "account", "bank", "pay", "payment", "loan", "credit", "confirm", "click", "update"]
    found = []
    if not body_text:
        return []
    txt = str(body_text).lower()
    for k in kw:
        if k in txt:
            found.append(k)
    return list(dict.fromkeys(found))[:8]
@app.context_processor
def inject_user_data():
    user_name = None
    try:
        if google_bp.authorized:
            # Use google_bp.session (from oauth_setup.py)
            resp = google_bp.session.get("/oauth2/v2/userinfo")
            if resp.ok:
                user_name = resp.json().get("name", "User")
        elif github_bp.authorized:
            # Use github_bp.session (from oauth_setup.py)
            resp = github_bp.session.get("/user")
            if resp.ok:
                user_name = resp.json().get("login", "User")
    except Exception as e:
        print(f"Error fetching user data: {e}")
        pass
    return dict(user_name=user_name)
# ---------- Routes ----------

@app.route('/')
def home():
    user_name = None
    # Check authorization using the imported blueprints
    if google_bp.authorized:  # Use google_bp.authorized
        try:
            resp = google_bp.session.get("/oauth2/v2/userinfo")  # Use google_bp.session
            if resp.ok:
                user_name = resp.json().get("name", "User")
        except Exception:
            user_name = "Google User"

    if github_bp.authorized:  # Use github_bp.authorized
        try:
            resp = github_bp.session.get("/user")  # Use github_bp.session
            if resp.ok:
                user_name = resp.json().get("login", "User")
        except Exception:
            user_name = "GitHub User"# Fallback

    news = [
        {"title": "New BEC campaign uses IDN homograph domains", "time": "2 hours"},
        {"title": "Logo spoofing rises in recent phishing waves", "time": "1 day"},
        {"title": "Users tricked by reply-to mismatches — tips to spot them", "time": "3 days"}
    ]
    # Pass the user_name to the template
    return render_template("home.html", news=news, user_name=user_name)
@app.route('/login')
def login():
    return render_template("login.html")

@app.route('/register')
def register():
    return render_template("register.html")

@app.route('/contact')
def contact():
    return render_template("contact.html")

@app.route("/analyze", methods=["GET", "POST"])
def analyze():
    try:
        if request.method == "GET":
            return render_template("analyze.html")

        # ✅ Match the input name in HTML exactly
        if "eml_file" not in request.files:
            flash("No file part found. Please upload an .eml file.")
            return render_template("analyze.html", error="No file found!")

        file = request.files["eml_file"]

        # ✅ Check for filename
        if file.filename == "":
            flash("No file selected.")
            return render_template("analyze.html", error="No file selected!")

        # ✅ Allow only .eml and .mbox
        if not file.filename.lower().endswith((".eml", ".mbox")):
            flash("Unsupported file type. Please upload an .eml or .mbox file.")
            return render_template("analyze.html", error="Unsupported file type!")

        # ✅ Save uploaded file
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)

        # ------------------ EMAIL FEATURE EXTRACTION ------------------
        import email, tldextract, idna
        from email.utils import parseaddr

        def decode_idn(domain):
            try:
                return idna.decode(domain)
            except Exception:
                return domain

        def punycode_used(domain):
            return "Yes" if "xn--" in str(domain) else "No"

        def extract_domain(addr):
            try:
                email_addr = parseaddr(addr)[1]
                return email_addr.split("@")[-1].lower() if "@" in email_addr else "null"
            except Exception:
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
                if "spf" in h.lower() or "spf" in hv:
                    spf = "pass" if "pass" in hv else "fail" if "fail" in hv else spf
                if "dkim" in h.lower() or "dkim" in hv:
                    dkim = "pass" if "pass" in hv else "fail" if "fail" in hv else dkim
                if "dmarc" in h.lower() or "dmarc" in hv:
                    dmarc = "pass" if "pass" in hv else "fail" if "fail" in hv else dmarc
            return spf, dkim, dmarc

        def count_suspicious_keywords(msg):
            keywords = ["verify", "update", "password", "bank", "account", "urgent", "click", "confirm", "security"]
            total = 0
            for part in msg.walk():
                if part.get_content_type() in ["text/plain", "text/html"]:
                    try:
                        payload = part.get_payload(decode=True) or b""
                        text = payload.decode(errors="ignore").lower()
                        total += sum(text.count(k) for k in keywords)
                    except Exception:
                        continue
            return total

        def extract_text(msg):
            text = ""
            for part in msg.walk():
                if part.get_content_type() in ["text/plain", "text/html"]:
                    try:
                        payload = part.get_payload(decode=True) or b""
                        text += payload.decode(errors="ignore")
                    except Exception:
                        continue
            return text

        # --------------- PARSE EMAIL ---------------
        with open(filepath, "rb") as f:
            msg = email.message_from_binary_file(f)
        headers = dict(msg.items())

        sender_raw = extract_domain(headers.get("From", ""))
        message_id_raw = extract_domain(headers.get("Message-ID", ""))
        return_raw = extract_domain(headers.get("Return-Path", ""))
        sender_registered = extract_registered(sender_raw)
        return_registered = extract_registered(return_raw)
        decoded_domain = decode_idn(sender_raw)
        idn_flag = punycode_used(sender_raw)
        spf, dkim, dmarc = extract_spf_dkim_dmarc(headers)
        suspicious_count = count_suspicious_keywords(msg)
        body_text = extract_text(msg)

        # --------------- ML Prediction ---------------
        text_features = sender_raw + " " + message_id_raw
        vectorized = vectorizer.transform([text_features])
        pred = model.predict(vectorized)[0]

        if pred == 1:
            result_label = "Phishing Detected!"
        else:
            result_label = "Appears Legitimate"

        # --------------- RULES & REASONS ---------------
        causes = []
        if sender_registered != return_registered and sender_registered != "null":
            causes.append("Domain mismatch between 'From' and 'Return-Path'.")
        if idn_flag == "Yes":
            causes.append("Punycode/IDN detected — possible homograph attack.")
        if any(x == "fail" for x in [spf, dkim, dmarc]):
            causes.append("Authentication failure (SPF, DKIM, or DMARC).")
        if suspicious_count > 0:
            causes.append(f"Suspicious keywords found ({suspicious_count}).")
        if not causes:
            causes.append("No strong phishing indicators found.")

        analysis = {
            "result": result_label,
            "sender_raw": sender_raw,
            "decoded_domain": decoded_domain,
            "return_raw": return_raw,
            "idn_used": idn_flag,
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
            "suspicious_count": suspicious_count,
            "body_excerpt": body_text[:400] + ("..." if len(body_text) > 400 else ""),
            "causes": causes
        }

        print("\n[DEBUG] Analysis:", analysis, "\n")

        return render_template("result.html", result=analysis)

    except Exception as e:
        import traceback
        traceback.print_exc()
        flash(f"Error analyzing email: {str(e)}")
        return render_template("analyze.html", error=str(e))




# ---------- Run ----------
if __name__ == "__main__":
    app.run(debug=True)
