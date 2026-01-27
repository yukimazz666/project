from flask import Flask, render_template, request
from PyPDF2 import PdfReader
import re

app = Flask(__name__)

# ---------------- URL CHECK ----------------
def is_valid_url(url):
    regex = re.compile(
        r'^(https?:\/\/)?'
        r'([A-Za-z0-9.-]+)\.([A-Za-z]{2,})'
        r'(\/.*)?$'
    )
    return re.match(regex, url)

# ---------------- PDF SPAM CHECK ----------------
def check_pdf_spam(file):
    spam_keywords = [
        "free money", "win prize", "click here", "urgent",
        "limited offer", "lottery", "congratulations",
        "verify account", "act now", "claim reward"
    ]

    try:
        reader = PdfReader(file)
        text = ""

        for page in reader.pages:
            extracted = page.extract_text()
            if extracted:
                text += extracted.lower()

        spam_count = sum(1 for word in spam_keywords if word in text)

        if spam_count >= 2:
            return "❌ PDF analyzed: SPAM FILE"
        else:
            return "✅ PDF analyzed: NOT SPAM"

    except Exception as e:
        return "❌ Unable to read PDF file"

# ---------------- ROUTE ----------------
@app.route("/", methods=["GET", "POST"])
def home():
    result = ""

    if request.method == "POST":

        # URL CHECK
        if "classify_url" in request.form:
            url = request.form.get("url", "").strip()

            if not url:
                result = "❌ URL cannot be empty"
            elif not is_valid_url(url):
                result = "❌ Invalid URL format"
            elif "login" in url or "secure" in url:
                result = f"⚠️ URL analyzed ({url}): MALICIOUS"
            else:
                result = f"✅ URL analyzed ({url}): SAFE"

        # PDF CHECK
        elif "analyze_file" in request.form:
            file = request.files.get("file")

            if not file or file.filename == "":
                result = "❌ Please upload a PDF file"
            elif not file.filename.lower().endswith(".pdf"):
                result = "❌ Only PDF files are allowed"
            else:
                result = check_pdf_spam(file)

    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
