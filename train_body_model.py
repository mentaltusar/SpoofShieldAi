# train_body_model.py
import os, joblib, pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score

MODELS_DIR = os.path.join(os.path.dirname(__file__),"models")
os.makedirs(MODELS_DIR, exist_ok=True)
VECT_PATH = os.path.join(MODELS_DIR,"vectorizer.pkl")
MODEL_PATH = os.path.join(MODELS_DIR,"body_spam_model.pkl")

DATASET = "spam.csv"  # columns: text,label  (label: 1=spam,0=ham)

def load_dataset(path):
    if os.path.exists(path):
        try:
            # First try UTF-8
            df = pd.read_csv(path, encoding="utf-8")
        except UnicodeDecodeError:
            # Fallback: Latin-1 (works for ANSI/Windows-1252)
            df = pd.read_csv(path, encoding="latin1")
        if "text" in df.columns and "label" in df.columns:
            df = df.dropna(subset=["text"])
            return df

    # If file not found or invalid, use fallback mini dataset
    print("Dataset missing or invalid — using toy dataset.")
    samples = [
        ("Please verify your account to avoid suspension", 1),
        ("Update your bank account details", 1),
        ("Click here to reset password", 1),
        ("Meeting notes attached. Please review.", 0),
        ("Project plan: see attached", 0),
        ("Lunch tomorrow?", 0)
    ]
    return pd.DataFrame(samples, columns=["text", "label"])



def train():
    df = load_dataset(DATASET)
    X = df["text"].astype(str).values
    # Normalize label values (support "spam"/"ham" or numeric)
    label_map = {"spam": 1, "phish": 1, "ham": 0, "legit": 0, "safe": 0}
    df["label"] = df["label"].astype(str).str.lower().map(label_map).fillna(df["label"])
    y = df["label"].astype(int).values

    vect = TfidfVectorizer(max_features=5000, ngram_range=(1,2))
    Xv = vect.fit_transform(X)
    X_train, X_test, y_train, y_test = train_test_split(Xv,y,test_size=0.2,random_state=42)
    model = LogisticRegression(max_iter=1000)
    model.fit(X_train,y_train)
    preds = model.predict(X_test)
    auc = roc_auc_score(y_test, model.predict_proba(X_test)[:,1]) if hasattr(model,"predict_proba") else None
    print(classification_report(y_test,preds))
    print("AUC:",auc)
    joblib.dump(vect,VECT_PATH)
    joblib.dump(model,MODEL_PATH)
    print("Saved:", VECT_PATH, MODEL_PATH)

if __name__=="__main__":
    train()
