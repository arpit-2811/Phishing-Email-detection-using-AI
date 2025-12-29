import requests
import base64
from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import os
import re



VT_API_KEY = "fde78d879aa23386e74881baad6ed50ba086b3081e2064cb1350b178d607a67d"

app = Flask(__name__)
CORS(app)

# Load Model if exists
MODEL_PATH = 'phishing_model.pkl'
VECTORIZER_PATH = 'tfidf_vectorizer.pkl'

model = None
vectorizer = None

def load_model():
    global model, vectorizer
    try:
        if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
            model = joblib.load(MODEL_PATH)
            vectorizer = joblib.load(VECTORIZER_PATH)
            print("Model loaded successfully.")
        else:
            print("Model not found. Please run train_model.py first.")
    except Exception as e:
        print(f"Error loading model: {e}")

load_model()

@app.route('/api/status', methods=['GET'])
def status():
    return jsonify({
        "status": "online",
        "model_loaded": model is not None
    })

@app.route('/api/analyze', methods=['POST'])
def analyze():
    data = request.json
    text = data.get('text', '')
    scan_type = data.get('type', 'text') # text, file, or url
    
    if not text:
        return jsonify({"error": "No text provided"}), 400

    # 1. VirusTotal URL Scan
    if scan_type == 'url':
        try:
            # Need to encode URL for VT API v3
            # ID is base64 representation of URL stripping padding
            url_id = base64.urlsafe_b64encode(text.encode()).decode().strip("=")
            
            headers = {
                "accept": "application/json",
                "x-apikey": VT_API_KEY
            }
            
            # First, request a scan (optional, but good if URL is new)
            # For simplicity in this demo, we'll consult the analysis report directly
            # Note: In prod, you'd POST to /urls first, then GET /analyses/{id}
            # Here we try fetching existing report for speed
            
            response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
            
            if response.status_code == 200:
                res_json = response.json()
                stats = res_json['data']['attributes']['last_analysis_stats']
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                
                score = 0
                findings = []
                
                if malicious > 0 or suspicious > 0:
                    score = min(99, (malicious * 20) + (suspicious * 10) + 40)
                    findings.append(f"Flagged by {malicious} security vendors as malicious.")
                else:
                    score = 10
                    findings.append("No security vendors flagged this URL.")
                    
                return jsonify({
                    "score": score,
                    "type": "URL Scan",
                    "summary": f"VirusTotal Analysis: {malicious} malicious, {suspicious} suspicious.",
                    "findings": findings
                })
            elif response.status_code == 404:
                # URL not found in VT, implies it might be new or safe, or needs submission
                return jsonify({
                    "score": 25,
                    "type": "URL Scan",
                    "summary": "URL not found in VirusTotal database. Proceed with caution.",
                    "findings": ["URL has not been analyzed by VirusTotal before."]
                })
            else:
                # API Error
                print(f"VT Error: {response.text}")
                return jsonify({"error": "External Scanning API unavailable"}), 503
                
        except Exception as e:
            print(f"VT Exception: {e}")
            return jsonify({"error": str(e)}), 500

    # 2. Hybrid Analysis (ML + Heuristics)
    if not model or not vectorizer:
        return jsonify({
            "score": 0,
            "type": "Error",
            "summary": "AI Model not loaded on server.",
            "findings": []
        })

    try:
        # A. ML Prediction
        vec_text = vectorizer.transform([text])
        prob = model.predict_proba(vec_text)[0]
        phishing_probability = prob[1] * 100
        
        # B. Heuristic Signals
        findings = []
        details = []
        
        # 1. Urgency Detection
        urgency_patterns = [
            r'immediately', r'urgent', r'action required', r'suspend', r'24 hours', 
            r'limited time', r'unauthorized access', r'verify your account', r'locked'
        ]
        urgency_hits = [p.replace(r'', '') for p in urgency_patterns if re.search(p, text, re.IGNORECASE)]
        if urgency_hits:
            findings.append(f"Urgency indicators found: '{', '.join(urgency_hits[:3])}'")
            phishing_probability += 10 # Penalize for urgency
            details.append("Uses high-pressure language to force quick action.")

        # 2. Link Analysis
        links = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', text)
        if len(links) > 2:
            findings.append(f"Contains {len(links)} external links.")
            details.append("Multiple external links detected, which is common in phishing to hide the true destination.")
            
        # 3. Sensitive Keywords
        sensitive_patterns = [r'password', r'credit card', r'social security', r'bank account', r'update payment']
        sensitive_hits = [p for p in sensitive_patterns if re.search(p, text, re.IGNORECASE)]
        if sensitive_hits:
            findings.append("Requests sensitive information.")
            phishing_probability += 15
            details.append("Directly asks for sensitive credentials or financial data.")

        # C. Final Synthesis
        risk_score = min(99, round(phishing_probability))
        
        if risk_score > 60:
            type_res = "Phishing"
            tone = "Critical"
        elif risk_score > 30:
            type_res = "Suspicious"
            tone = "Warning"
        else:
            type_res = "Safe"
            tone = "Info"

        # D. Dynamic Summary Generation
        if type_res == "Safe":
            dynamic_summary = "This email appears legitimate. The language is neutral, and our AI did not detect significant malicious patterns or known phishing signatures."
        else:
            reason = " and ".join(details[:2]) if details else "detected suspicious content patterns"
            dynamic_summary = f"**{tone}:** This email is flagged as {type_res} ({risk_score}% Risk). Key reasons include: {reason}. The AI identified {len(findings)} specific threat indicators."

        return jsonify({
            "score": risk_score,
            "type": type_res,
            "summary": dynamic_summary,
            "findings": findings
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/chat', methods=['POST'])
def chat():
    data = request.json
    question = data.get('question', '').lower()
    context = data.get('context', {})
    
    if not question:
        return jsonify({"answer": "Please ask a question."})
        
    score = context.get('score', 0)
    findings = context.get('findings', [])
    summary = context.get('summary', '')
    
    # Rule-based Intent Matching
    
    # 1. RISK / SAFETY
    if any(w in question for w in ['safe', 'risk', 'dangerous', 'malicious', 'bad']):
        if score > 50:
            return jsonify({"answer": f"I consider this HIGH RISK ({score}%). It exhibits clear signs of phishing. Do not interact with it."})
        elif score > 20:
            return jsonify({"answer": f"It is suspicious ({score}% risk). Proceed with caution and verify the sender."})
        else:
            return jsonify({"answer": f"It appears safe ({score}% risk), but always stay vigilant."})
            
    # 2. REASONING / WHY
    if any(w in question for w in ['why', 'reason', 'what found']):
        if findings:
            bullet_points = ". ".join(findings)
            return jsonify({"answer": f"I flagged this because: {bullet_points}. {summary}"})
        else:
            return jsonify({"answer": "I didn't find specific threats, but the language model analyzed the overall tone and patterns."})

    # 3. LINKS
    if 'link' in question or 'url' in question:
        # We don't store exact links in context yet, but we have findings
        link_findings = [f for f in findings if 'link' in f.lower() or 'url' in f.lower()]
        if link_findings:
            return jsonify({"answer": f"Regarding links: {link_findings[0]}. Never click links in unexpected emails."})
        else:
            return jsonify({"answer": "I didn't detect a high volume of suspicious links, but hover over them to see the real destination before clicking."})

    # 4. SENDER
    if 'sender' in question or 'who' in question or 'from' in question:
        return jsonify({"answer": "Check the 'From' address carefully. Attackers often use slightly misspelled domains (e.g., @paypa1.com) or generic providers like Gmail for official business."})

    # 5. ACTION
    if 'do' in question or 'action' in question:
        if score > 50:
            return jsonify({"answer": "Delete this email immediately. do not reply, do not click links, and do not download attachments."})
        else:
            return jsonify({"answer": "If you are expecting this, it's likely fine. If not, contact the sender via a separate verified channel to confirm."})

    # 6. CONVERSATIONAL / PHATIC
    if any(w in question for w in ['thank', 'thanks', 'cool', 'ok', 'okay', 'good', 'great', 'awesome']):
        return jsonify({"answer": "You're welcome! Stay safe. Let me know if you need to analyze anything else."})
        
    if any(w in question for w in ['hi', 'hello', 'hey', 'greetings']):
        return jsonify({"answer": "Hello! I am ready to explain the security risks of this content. What would you like to know?"})

    # Fallback
    fallback_responses = [
        "I'm specifically trained to analyze security risks. Could you ask about the 'phishing' or 'sender' aspects?",
        "I didn't quite catch that. Try asking 'Is this safe?' or 'Why is it risky?'.",
        "My focus is on threat detection. Ask me about the findings or specific flags in this report."
    ]
    import random
    return jsonify({"answer": random.choice(fallback_responses)})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
