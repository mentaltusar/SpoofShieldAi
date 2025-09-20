import os
import re
import email
import mailbox
import idna
import tldextract
import pandas as pd
from email.utils import parseaddr
import tkinter as tk
from tkinter import filedialog, ttk
import pickle
import joblib
import warnings

# Suppress joblib warnings which can be noisy
warnings.filterwarnings("ignore", category=UserWarning, module='joblib')


# ---------------- Utility Functions (from original script, slightly modified) ----------------
def decode_idn(domain):
    """Decodes Punycode domain names."""
    try:
        return idna.decode(domain)
    except (idna.IDNAError, UnicodeError):
        return domain


def punycode_used(domain):
    """Checks if a domain uses Punycode."""
    return "Yes" if str(domain).startswith("xn--") else "No"


def extract_domain(addr):
    """Extracts the domain from an email address string."""
    try:
        email_addr = parseaddr(addr)[1]
        return email_addr.split("@")[-1].lower() if "@" in email_addr else "null"
    except Exception:
        return "null"


def extract_registered(domain):
    """Extracts the registered domain using tldextract."""
    try:
        ext = tldextract.extract(domain)
        return ext.registered_domain
    except:
        return "null"


def extract_spf_dkim_dmarc(headers):
    """Extracts SPF, DKIM, and DMARC status from email headers."""
    spf, dkim, dmarc = "none", "none", "none"
    for h, v in headers.items():
        hv = str(v).lower()
        if "spf" in h.lower():
            if "pass" in hv:
                spf = "pass"
            elif "fail" in hv:
                spf = "fail"
        if "dkim" in h.lower():
            if "pass" in hv:
                dkim = "pass"
            elif "fail" in hv:
                dkim = "fail"
        if "dmarc" in h.lower():
            if "pass" in hv:
                dmarc = "pass"
            elif "fail" in hv:
                dmarc = "fail"
    return spf, dkim, dmarc


# ---------------- Feature Extractor (adapted for single email) ----------------
def extract_features_from_msg(msg, vectorizer):
    """
    Extracts features from a single email message and returns a DataFrame
    ready for prediction.
    """
    headers = dict(msg.items())

    # The training notebook used a combined text feature of sender_raw_domain
    # and message_id_raw. We need to replicate this exactly.
    sender_raw = extract_domain(headers.get("From", ""))
    mid_raw = extract_domain(headers.get("Message-ID", ""))

    # Handle NaN values explicitly, as done in the notebook's preprocessing step.
    if pd.isna(sender_raw):
        sender_raw = ''
    if pd.isna(mid_raw):
        mid_raw = ''

    text_features = sender_raw + ' ' + mid_raw

    # Transform the new text using the fitted TF-IDF vectorizer
    new_text_features_tfidf = vectorizer.transform([text_features])

    # Convert the sparse matrix to a DataFrame for compatibility with subsequent steps
    vectorized_df = pd.DataFrame(new_text_features_tfidf.toarray(), columns=vectorizer.get_feature_names_out())

    return vectorized_df


# ---------------- GUI Application Class ----------------
class EmailAnalyzerApp(tk.Tk):
    def __init__(self, model, vectorizer):
        super().__init__()
        self.title("Email Phishing Analyzer")
        self.geometry("800x600")
        self.model = model
        self.vectorizer = vectorizer
        self.style = ttk.Style(self)
        self.style.theme_use('clam')
        self.create_widgets()

    def create_widgets(self):
        # Header
        header_frame = ttk.Frame(self, padding="20")
        header_frame.pack(fill="x")
        ttk.Label(header_frame, text="Email Phishing Analyzer", font=("Helvetica", 24, "bold")).pack(pady=5)
        ttk.Label(header_frame, text="Select an .eml file to analyze for phishing indicators.").pack()

        # File selection
        file_frame = ttk.Frame(self, padding="20")
        file_frame.pack(fill="x")
        self.file_path_label = ttk.Label(file_frame, text="No file selected", font=("Helvetica", 10))
        self.file_path_label.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.select_button = ttk.Button(file_frame, text="Select .eml File", command=self.select_file)
        self.select_button.pack(side="right")

        # Loading indicator
        self.loading_label = ttk.Label(self, text="", font=("Helvetica", 12, "italic"))
        self.loading_label.pack(pady=10)

        # Result display
        self.result_frame = ttk.Frame(self, padding="20", relief="solid", borderwidth=1)
        self.result_frame.pack(fill="both", expand=True, padx=20, pady=10)

        self.status_label = ttk.Label(self.result_frame, text="Status: Awaiting file...",
                                      font=("Helvetica", 18, "bold"))
        self.status_label.pack(pady=10)

        self.sender_label = ttk.Label(self.result_frame, text="Sender Domain: ", font=("Helvetica", 12))
        self.sender_label.pack(anchor="w")

        self.message_id_label = ttk.Label(self.result_frame, text="Message-ID: ", font=("Helvetica", 12))
        self.message_id_label.pack(anchor="w")

        self.summary_label = ttk.Label(self.result_frame, text="Analysis Summary:", font=("Helvetica", 14, "bold"))
        self.summary_label.pack(anchor="w", pady=(20, 5))

        self.summary_text = tk.Text(self.result_frame, wrap="word", height=10, font=("Helvetica", 10))
        self.summary_text.pack(fill="both", expand=True)

    def select_file(self):
        file_path = filedialog.askopenfilename(
            title="Select an .eml file",
            filetypes=[("Email files", "*.eml")]
        )
        if file_path:
            self.file_path_label.config(text=os.path.basename(file_path))
            self.analyze_file(file_path)

    def analyze_file(self, file_path):
        self.loading_label.config(text="Analyzing file...")
        self.select_button.config(state="disabled")
        self.update_idletasks()

        try:
            with open(file_path, "rb") as f:
                msg = email.message_from_binary_file(f)

            # Extract features correctly according to the training data.
            features_df = extract_features_from_msg(msg, self.vectorizer)

            # Predict using the loaded model
            prediction = self.model.predict(features_df)

            # Assuming label '1' is phishing, as per typical binary classification.
            is_phishing = prediction[0] == 1

            # Extract the raw headers again for display, as the features_df is now just vectorized data.
            headers = dict(msg.items())
            sender_raw = extract_domain(headers.get("From", ""))
            mid_raw = extract_domain(headers.get("Message-ID", ""))

            # The model prediction is not explainable, so we'll use rule-based checks
            # for the summary, just like in the previous version.
            non_vectorized_features = {
                "sender_raw_domain": sender_raw,
                "return_raw_domain": extract_domain(headers.get("Return-Path", "")),
                "sender_registered": extract_registered(sender_raw),
                "return_registered": extract_registered(extract_domain(headers.get("Return-Path", ""))),
                "idn_used": punycode_used(sender_raw),
                "suspicious_keywords": sum(
                    1 for part in msg.walk() if part.get_content_type() in ["text/plain", "text/html"] for kw in
                    ["verify", "update", "password", "bank", "account", "urgent"] if
                    str(part.get_payload(decode=True)).lower().count(kw) > 0),
                "spf": extract_spf_dkim_dmarc(headers)[0],
                "dkim": extract_spf_dkim_dmarc(headers)[1],
                "dmarc": extract_spf_dkim_dmarc(headers)[2]
            }

            self.update_ui(sender_raw, mid_raw, is_phishing, non_vectorized_features)

        except Exception as e:
            self.show_error(f"Error analyzing file: {e}")

        finally:
            self.loading_label.config(text="")
            self.select_button.config(state="normal")

    def update_ui(self, sender_raw, mid_raw, is_phishing, non_vectorized_features):
        self.summary_text.delete("1.0", "end")

        # Display headers
        self.sender_label.config(text=f"Sender Domain: {sender_raw}")
        self.message_id_label.config(text=f"Message-ID: {mid_raw}")

        if is_phishing:
            self.status_label.config(text="Status: Phishing Detected!", foreground="red")
            self.summary_label.config(text="Causes & Warnings:")
            self.summary_text.insert("1.0",
                                     "WARNING: This email has been flagged as a potential phishing attempt based on the following indicators:\n\n")

            causes = self.get_rule_based_causes(non_vectorized_features)
            for cause in causes:
                self.summary_text.insert("end", f"- {cause}\n")

            self.summary_text.insert("end", "\n---\n\n")
            self.summary_text.insert("end",
                                     "Precautions:\n- Do not click on any links.\n- Do not download or open any attachments.\n- Do not reply to the sender.\n- Delete this email and block the sender's address.\n- Manually navigate to the official website of any service mentioned.\n")
        else:
            self.status_label.config(text="Status: Appears Legitimate", foreground="green")
            self.summary_label.config(text="Analysis Summary:")
            self.summary_text.insert("1.0",
                                     "The analysis did not find any major indicators of a phishing attempt. Always be cautious with unsolicited emails, but this one seems to be legitimate based on the headers and body content.")

    def get_rule_based_causes(self, features):
        causes = []
        if features['sender_registered'] != features['return_registered']:
            causes.append(
                "Domain Mismatch: The 'From' domain does not match the 'Return-Path' domain. This is a very strong phishing indicator.")
        if features['idn_used'] == "Yes":
            causes.append(
                "Punycode Found: The sender's domain uses international characters (IDN) which is a common obfuscation technique.")
        if features['spf'] == 'fail' or features['dkim'] == 'fail' or features['dmarc'] == 'fail':
            causes.append(
                "Email Authentication Failure: SPF, DKIM, or DMARC checks failed, suggesting a spoofed email.")
        if features['suspicious_keywords'] > 0:
            causes.append(
                f"Suspicious Keywords: The email body contains {features['suspicious_keywords']} keywords common in phishing scams.")

        if not causes:
            causes.append("No obvious rule-based indicators of phishing found.")

        return causes

    def show_error(self, message):
        self.status_label.config(text="Error", foreground="red")
        self.summary_text.delete("1.0", "end")
        self.summary_text.insert("1.0", message)


if __name__ == "__main__":
    try:
        # Load the trained model and vectorizer
        model = joblib.load('random_forest_model.pkl')
        vectorizer = joblib.load('tfidf_vectorizer.pkl')

        # Instantiate and run the GUI app
        app = EmailAnalyzerApp(model, vectorizer)
        app.mainloop()
    except FileNotFoundError as e:
        print(
            f"Error: Required file not found. Make sure 'random_forest_model.pkl' and 'tfidf_vectorizer.pkl' are in the same directory.")
        print(e)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
