import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, classification_report
import joblib
import requests
import io
import os

# Configuration
DATASET_URL = "https://raw.githubusercontent.com/GregaVrbancic/Phishing-Dataset/master/dataset_small.csv" # Example URL
# Alternative robust dataset: https://raw.githubusercontent.com/subadhrak/Phishing-Email-Detection/master/phishing_email.csv 
# However, for stability, we will try to use a known stable CSV or fallback to synthetic data.

MODEL_PATH = 'phishing_model.pkl'
VECTORIZER_PATH = 'tfidf_vectorizer.pkl'

def get_data():
    print("Downloading dataset...")
    # Using a specific known dataset (Phishing Email Dataset)
    # This URL is a placeholder for a common dataset structure. 
    # If this fails, we create a small synthetic dataset for demonstration purposes.
    
    try:
        # Trying a reliable source (CodeForPhishing) or similar. 
        # Since I cannot browse to find a guaranteed live raw link without risk of 404,
        # I will use a local fallback strategy if download fails.
        
        # Let's try downloading a known dataset
        url = "https://raw.githubusercontent.com/subadhrak/Phishing-Email-Detection/master/phishing_email.csv"
        response = requests.get(url)
        if response.status_code == 200:
            df = pd.read_csv(io.StringIO(response.text))
            print("Dataset downloaded successfully.")
            # Expected columns: text, label (or similar)
            # Adjust column names based on common datasets
            if 'text_combined' in df.columns: # Adjust based on dataset
                df = df.rename(columns={'text_combined': 'text', 'label': 'label'})
            return df
    except Exception as e:
        print(f"Download failed: {e}")

    print("Using synthesized fallback dataset for training (Demo Mode)...")
    # Synthetic data to ensure model works even without internet/dataset
    data = {
        'text': [
            "Urgent: Your account is locked. Click here to verify.", 
            "Win a free iPhone! Claim now.",
            "Please review the attached invoice.",
            "Meeting at 3 PM tomorrow.",
            "Security Alert: Suspicious login detected.",
            "Happy Birthday! Hope you have a great day.",
            "Verify your bank account details immediately.",
            "Project update: We are on track for the deadline.",
            "PayPal: You received $500. Log in to claim.",
            "Can we reschedule our call?"
        ] * 50, # Duplicate to simulate volume
        'label': [1, 1, 0, 0, 1, 0, 1, 0, 1, 0] * 50 # 1=Phishing, 0=Safe
    }
    return pd.DataFrame(data)

def train():
    df = get_data()
    
    # Preprocessing (Basic)
    # Check for likely column names
    text_col = 'text'
    label_col = 'label'
    
    # Normalize varied dataset column names
    for col in df.columns:
        if 'text' in col.lower() or 'body' in col.lower() or 'content' in col.lower():
            text_col = col
        if 'label' in col.lower() or 'type' in col.lower():
            label_col = col
            
    print(f"Training on columns: {text_col} (Features) -> {label_col} (Target)")
    
    df[text_col] = df[text_col].astype(str).fillna('')
    X = df[text_col]
    y = df[label_col]

    # Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Pipeline: TF-IDF -> Random Forest
    print("Vectorizing and Training Random Forest...")
    
    # Tfidf: 
    # - max_features=5000: Limit vocab size for speed/size
    # - ngram_range=(1,2): Capture "urgent action" phrases
    vectorizer = TfidfVectorizer(max_features=5000, stop_words='english', ngram_range=(1,2))
    
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    # Random Forest
    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X_train_vec, y_train)

    # Evaluate
    preds = rf.predict(X_test_vec)
    acc = accuracy_score(y_test, preds)
    print(f"Model Accuracy: {acc * 100:.2f}%")
    print(classification_report(y_test, preds))

    # Save
    joblib.dump(rf, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    print(f"Model saved to {MODEL_PATH}")

if __name__ == "__main__":
    train()
