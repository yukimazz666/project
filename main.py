from flask import Flask, render_template, request, redirect, url_for, flash, session
from PyPDF2 import PdfReader
import re
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.secret_key = "super-secret-key"

# ---------- DATABASE ----------
def get_db():
    return sqlite3.connect("users.db")

def create_table():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT,
            password TEXT
        )
    """)
    db.commit()
    db.close()

create_table()

# ---------- HOME ----------
@app.route("/")
def home():
    return render_template("home.html")


@app.route("/start")
def start():
    if "user" in session:
        return redirect(url_for("check"))   # already logged in
    else:
        return redirect(url_for("login"))   # not logged in

# ---------- REGISTER ----------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = generate_password_hash(request.form["password"])

        try:
            db = get_db()
            cursor = db.cursor()
            cursor.execute(
                "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                (username, email, password)
            )
            db.commit()
            db.close()
            flash("Registration successful!", "success")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("⚠ Username or Email already exists!", "danger")

    return render_template("register.html")

# ---------- LOGIN ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        db = get_db()
        cursor = db.cursor()

        cursor.execute(
            "SELECT password FROM users WHERE username = ?",
            (username,)
        )
        user = cursor.fetchone()
        db.close()

        if user and check_password_hash(user[0], password):
            session["user"] = username 
            return redirect(url_for("check"))
        else:
            flash("❌ Invalid username or password", "danger")

    return render_template("login.html")


@app.route("/index")
def index():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("index.html")



@app.route("/logout", methods=["GET"])
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))



# ---------- check ----------
@app.route("/check", methods=["GET", "POST"])
def check():
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

        if "user" not in session:
            return redirect(url_for("login"))



    return render_template("check.html", result=result)

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
