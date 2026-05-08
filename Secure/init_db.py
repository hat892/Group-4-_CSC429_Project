import sqlite3
import hashlib

def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

conn = sqlite3.connect('secure.db')
cursor = conn.cursor()

# Drop existing tables so we start fresh
cursor.execute("DROP TABLE IF EXISTS users")
cursor.execute("DROP TABLE IF EXISTS trainees")

# USERS TABLE
cursor.execute("""
CREATE TABLE users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role     TEXT NOT NULL CHECK(role IN ('student','admin'))
)
""")

# TRAINEES TABLE  — username links back to users
cursor.execute("""
CREATE TABLE trainees (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT UNIQUE NOT NULL,
    name       TEXT,
    birth      TEXT,
    mobile     TEXT,
    email      TEXT,
    university TEXT,
    gpa        TEXT
)
""")

# Optional: seed a default admin account
cursor.execute(
    "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
    ("admin", hash_password("admin123"), "admin")
)

conn.commit()
conn.close()
print("Database created successfully!")
