# PhishGuard - How to Run

This project consists of two parts: the **Frontend** (Website) and the **Backend** (Python AI Server). You need to run both for the full experience.

## Prerequisites
- Python installed.
- Internet connection (for Firebase Login & AI Dataset downloading).

## Step 1: Start the Backend (AI Server)
The backend runs the Machine Learning model to analyze emails.

1. Open a terminal.
2. Go to the Backend folder:
   ```bash
   cd Backend
   ```
3. Install dependencies (first time only):
   ```bash
   pip install -r requirements.txt
   ```
4. Run the server:
   ```bash
   python app.py
   ```
   *You should see: `Running on http://127.0.0.1:5000`*

## Step 2: Start the Frontend (Website)
The frontend is the user interface.

1. Open a **new** terminal (keep the backend running).
2. Go to the project root folder (where `index.html` is).
3. Start a simple python web server:
   ```bash
   python -m http.server 5500
   ```
   *You should see: `Serving HTTP on :: port 5500`*

## Step 3: Open in Browser
1. Open your web browser (Chrome/Edge).
2. Go to: **[http://localhost:5500](http://localhost:5500)**

## Troubleshooting Login
- **Firebase Error?**: Firebase is a cloud service. It is "always on" as long as you have the internet. You do **not** need to run a local Firebase server.
- **Login Button not working?**: Check the browser console (F12) for errors. Ensure you are running on `localhost` (not opening the file directly).
