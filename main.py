
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from database import create_table, add_user, get_user
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")

# Create database table when app starts
create_table()


@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = generate_password_hash(request.form["password"])

        try:
            add_user(username, email, password)
            flash("Registration successful!", "success")
            return redirect(url_for("login"))
        except:
            flash("⚠ Username already exists!", "danger")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = get_user(username)

        if user and check_password_hash(user[0], password):
            session["user"] = username
            return redirect(url_for("index"))
        else:
            flash("❌ Invalid username or password", "danger")

    return render_template("login.html")


@app.route("/index")
def index():
    if "user" not in session:
        return redirect(url_for("login"))
    return "Login successful! Welcome " + session["user"]


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
