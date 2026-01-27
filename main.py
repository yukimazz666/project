from flask import Flask, render_template, request, redirect, url_for
from PyPDF2 import PdfReader
import re

app = Flask(__name__)

# ---------- HOME ----------
@app.route("/")
def home():
    return render_template("home.html")

# ---------- LOGIN ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username == "admin" and password == "1234":
            return redirect(url_for("index"))
        else:
            return "❌ Invalid credentials"

    return render_template("login.html")

# ---------- MAIN APP ----------
@app.route("/index", methods=["GET", "POST"])
def index():
    result = ""

    if request.method == "POST":
        action = request.form.get("action")

        # ----- PDF CHECK -----
        if action == "analyze_file":
            file = request.files.get("file")

            if not file or file.filename == "":
                result = "❌ Please upload a PDF file"
            elif not file.filename.lower().endswith(".pdf"):
                result = "❌ Only PDF files are allowed"
            else:
                result = check_pdf_spam(file)

        # ----- URL CHECK -----
        elif action == "classify_url":
            url = request.form.get("url")

            if not url:
                result = "❌ Please enter a URL"
            else:
                result = check_url_threat(url)

    return render_template("index.html", result=result)

# ---------- PDF CHECK ----------
def check_pdf_spam(file):
    spam_keywords = [
        "free money", "win prize", "click here", "urgent",
        "limited offer", "lottery", "congratulations"
    ]

    try:
        reader = PdfReader(file)
        text = ""

        for page in reader.pages:
            if page.extract_text():
                text += page.extract_text().lower()

        spam_count = sum(1 for word in spam_keywords if word in text)

        return "❌ SPAM PDF" if spam_count >= 2 else "✅ SAFE PDF"

    except:
        return "❌ Cannot read PDF"

# ---------- URL CHECK ----------
def check_url_threat(url):
    url = url.lower()

    suspicious_keywords = [
        "login", "verify", "update", "secure", "account",
        "bank", "free", "offer", "bonus", "click"
    ]

    suspicious_domains = [
        "bit.ly", "tinyurl", "goo.gl", "t.co"
    ]

    score = 0

    for word in suspicious_keywords:
        if word in url:
            score += 1

    for domain in suspicious_domains:
        if domain in url:
            score += 2

    if re.search(r"https?://\d+\.\d+\.\d+\.\d+", url):
        score += 3

    if score >= 4:
        return "❌ MALICIOUS URL (High Risk)"
    elif score >= 2:
        return "⚠️ SUSPICIOUS URL"
    else:
        return "✅ SAFE URL"

# ---------- RUN ----------
if __name__ == "__main__":
    app.run(debug=True)
