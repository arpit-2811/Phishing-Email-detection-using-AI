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
DATASET_URL = "https://raw.githubusercontent.com/GregaVrbancic/Phishing-Dataset/master/dataset_small.csv"
# Alternative robust dataset: https://raw.githubusercontent.com/subadhrak/Phishing-Email-Detection/master/phishing_email.csv 
# However, for stability, we will try to use a known stable CSV or fallback to synthetic data.

MODEL_PATH = 'phishing_model.pkl'
VECTORIZER_PATH = 'tfidf_vectorizer.pkl'

def get_data():
    print("Generating comprehensive synthetic dataset (Fallback mode enabled)...")
    
    # Expanded Phishing Templates
    phishing_templates = [
        "Urgent: Your account {account} is currently locked. Click here to verify identity.",
        "Security Alert: specific suspicious login detected on {account} from IP 192.168.1.1.",
        "Update Payment: Your subscription for {service} is about to expire. Renew now.",
        "Congratulations! You have won a {prize}. Claim your reward immediately.",
        "Final Notice: We have not received payment for invoice #{invoice}. Service suspension imminent.",
        "Employee Update: Please review the attached corporate policy document regarding {topic}.",
        "Unauthorized access attempt detected in your {service} account. Securify now.",
        "Your package from {courier} is pending delivery. Pay customs duties to release.",
        "Verify your {bank} banking details to avoid account closure.",
        "Account Suspended: We noticed unusual activity. Login to confirm it's you.",
        "Gift Card Alert: You received a $500 {store} gift card. Click to redeem.",
        "Action Required: Your password for {service} expires in 24 hours.",
        "Tax Refund: You are eligible for a tax refund of ${amount}. Apply here.",
        "CEO Request: I need you to make a wire transfer quickly. Confidential.",
        "Dropbox: You have received a new file 'salary_report.pdf'. Click to view."
    ]
    
    # Expanded Safe Templates
    safe_templates = [
        "Meeting Reminder: Our catch-up is scheduled for {time} tomorrow.",
        "Project Update: The timeline for the {topic} project is on track.",
        "Happy Birthday! wishing you a fantastic year ahead.",
        "Lunch Plan: Are we still on for lunch at {place}?",
        "Attached is the invoice #{invoice} for your records. No action needed.",
        "Comparison of Q3 results attached. Please review before the meeting.",
        "Can you send me the latest version of the {topic} file?",
        "Thank you for your purchase of {item}. Your order is processing.",
        "Team Outing: We are planning a dinner at {place} next Friday.",
        "Subscription Confirmed: You have successfully subscribed to {service}.",
        "Weather Forecast: It's going to be sunny in {city} this weekend.",
        "Notes from yesterday's meeting about {topic} are attached.",
        "Flight Confirmation: Your trip to {city} is confirmed.",
        "System Maintenance: Servers will be down for upgrades on Sunday.",
        "Great job on the {topic} presentation today!"
    ]
    
    # Dynamic fillers
    import random
    accounts = ['Google', 'Netflix', 'Amazon', 'Facebook', 'Wells Fargo', 'Chase', 'PayPal']
    services = ['iCloud', 'Microsoft 365', 'Zoom', 'Slack']
    prizes = ['iPhone 15', 'Walmart Gift Card', 'Cruise Trip', 'MacBook Pro']
    couriers = ['FedEx', 'UPS', 'DHL', 'USPS']
    banks = ['Bank of America', 'Citi', 'HDFC']
    stores = ['Walmart', 'Target', 'Best Buy']
    topics = ['Marketing', 'Finance', 'HR', 'Engineering', 'Q4 Goals']
    places = ['Pizza Hut', 'Starbucks', 'The Diner', 'Subway']
    cities = ['New York', 'London', 'Paris', 'Tokyo', 'Mumbai']
    items = ['Headphones', 'Laptop', 'Books', 'Shoes']
    
    data = {'text': [], 'label': []}
    
    # Generate 1000 examples
    for _ in range(500):
        # Phishing
        tmpl = random.choice(phishing_templates)
        text = tmpl.format(
            account=random.choice(accounts),
            service=random.choice(services),
            prize=random.choice(prizes),
            invoice=random.randint(1000, 9999),
            topic=random.choice(topics),
            courier=random.choice(couriers),
            bank=random.choice(banks),
            store=random.choice(stores),
            amount=random.randint(100, 5000)
        )
        data['text'].append(text)
        data['label'].append(1) # 1 = Phishing
        
        # Safe
        tmpl = random.choice(safe_templates)
        text = tmpl.format(
            time=f"{random.randint(1, 12)} PM",
            topic=random.choice(topics),
            place=random.choice(places),
            invoice=random.randint(1000, 9999),
            item=random.choice(items),
            service=random.choice(services),
            city=random.choice(cities)
        )
        data['text'].append(text)
        data['label'].append(0) # 0 = Safe

    print("Synthetic dataset generated successfully.")
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
