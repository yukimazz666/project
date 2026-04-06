from flask import Flask, render_template, request, redirect, url_for, flash, session
from PyPDF2 import PdfReader
import requests
import re
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
import os
import socket



app = Flask(__name__)

if os.environ.get("RENDER"):
    app.config.update(
        SESSION_COOKIE_SAMESITE="None",
        SESSION_COOKIE_SECURE=True
    )
else:
    app.config.update(
        SESSION_COOKIE_SAMESITE="None",
        SESSION_COOKIE_SECURE=True
    )


app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")




oauth = OAuth(app)

# ---------- DATABASE ----------
def get_db():
    return sqlite3.connect("users.db", check_same_thread=False)

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

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")


if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
    raise RuntimeError("Google OAuth environment variables not set")

google = oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid email profile"
    }
) 


@app.route("/login/google")
def login_google():
    redirect_uri = url_for("google_authorized", _external=True)

    return google.authorize_redirect(redirect_uri)
                                    
@app.route("/login/google/authorized")
def google_authorized():
         
    token = google.authorize_access_token()
    
    resp = google.get("https://openidconnect.googleapis.com/v1/userinfo")
    user_info = resp.json()
    if not user_info:
        return "Google login failed", 400
    
    session["user"] = user_info["email"]
    session["name"] = user_info.get("name")
    
    return """
        <script>
            window.opener.location.href = "/index";
            window.close();
        </script>
        """ 



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
            return redirect(url_for("index"))
        else:
            flash("❌ Invalid username or password", "danger")

        if "user" in session:
            return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/index")
def index():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("index.html")







# ---------- check ----------
@app.route("/check", methods=["GET", "POST"])
def check():
    if "user" not in session:
            return redirect(url_for("login"))


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
            elif not is_valid_url(url):
                result = "❌ Invalid URL format"

            elif not domain_exists(url):
                result = "❌ Domain does not exist"

            elif not website_is_live(url):
                result = "⚠ Domain exists but website is not reachable"

            else:
                safety = check_url_malicious(url)
                result = f"🌐 Domain is valid and reachable\n{safety}"

        


    return render_template("check.html", result=result)

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))



def domain_exists(url):
    try:
        domain = re.sub(r'https?://', '', url).split('/')[0]
        socket.gethostbyname(domain)
        return True
    except:
        return False

# ---------- PDF CHECK ----------

def check_pdf_spam(file):
    spam_keywords = [
        "free money", "win prize", "click here", "urgent",
        "limited offer", "lottery", "congratulations",
        "verify account", "password", "bank", "payment"
    ]

    suspicious_patterns = [
        r'c[l1]ick\s*h[e3]r[e3]',     # click here variations
        r'fr[e3]{2}\s*m[o0]n[e3]y',   # free money
        r'pa[y]m[e3]nt\s*ur[g]?ent'
    ]

    risk_score = 0
    found_reasons = []

    try:
        reader = PdfReader(file)
        text = ""

        # ---------- TEXT EXTRACTION ----------
        for page in reader.pages:
            if page.extract_text():
                text += page.extract_text().lower()

        # ---------- KEYWORD CHECK ----------
        for word in spam_keywords:
            if word in text:
                risk_score += 1
                found_reasons.append(f"Spam keyword detected: '{word}'")

        # ---------- OBFUSCATED TEXT CHECK ----------
        for pattern in suspicious_patterns:
            if re.search(pattern, text):
                risk_score += 2
                found_reasons.append("Obfuscated spam text detected")

        # ---------- URL EXTRACTION ----------
        urls = re.findall(r'https?://[^\s]+', text)
        if urls:
            risk_score += len(urls)
            found_reasons.append(f"Contains {len(urls)} embedded link(s)")

        # ---------- JAVASCRIPT CHECK ----------
        if "/JavaScript" in str(reader.metadata) or "/JS" in str(reader.metadata):
            risk_score += 5
            found_reasons.append("Embedded JavaScript detected")

        # ---------- FINAL DECISION ----------
        if risk_score >= 6:
            status = "❌ HIGH RISK PDF"
        elif risk_score >= 3:
            status = "⚠ SUSPICIOUS PDF"
        else:
            status = "✅ SAFE PDF"

        explanation = "\n".join(found_reasons) if found_reasons else "No threats detected"

        return f"{status}\nRisk Score: {risk_score}\nDetails:\n{explanation}"
    except Exception as e:
        return f"❌ Error analyzing PDF: {str(e)}"

    
SAFE_BROWSING_API_KEY = os.environ.get("SAFE_BROWSING_API_KEY")

# ---------- URL CHECK ----------
def check_url_malicious(url):
   
    if not SAFE_BROWSING_API_KEY:
        return "⚠ URL scanning not configured"
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"

    payload = {
        "client": {
            "clientId": "threatguard",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    response = requests.post(endpoint, json=payload)
    data = response.json()

    return "❌ Malicious URL detected" if "matches" in data else "✅ URL is safe"

def is_valid_url(url):
    regex = re.compile(
        r'^(https?:\/\/)?'  # http:// or https://
        r'([\w\-]+\.)+[\w\-]+'  # domain
        r'(\:[0-9]+)?'  # port
        r'(\/\S*)?$'  # path
    )
    return re.match(regex, url)
    
def website_is_live(url):
    try:
        if not url.startswith("http"):
            url = "http://" + url
            
        response = requests.get(url, timeout=5)
        return response.status_code < 400
    except:
        return False
# ---------- RUN ----------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

