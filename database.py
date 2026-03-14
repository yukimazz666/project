
import sqlite3

DB_NAME = "users.db"

def get_db():
    return sqlite3.connect(DB_NAME, check_same_thread=False)

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

def add_user(username, email, password):
    db = get_db()
    cursor = db.cursor()

    cursor.execute(
        "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
        (username, email, password)
    )

    db.commit()
    db.close()

def get_user(username):
    db = get_db()
    cursor = db.cursor()

    cursor.execute(
        "SELECT password FROM users WHERE username = ?",
        (username,)
    )

    user = cursor.fetchone()
    db.close()

    return user
