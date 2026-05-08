import re
import os
import sqlite3
import bcrypt
import bleach
from flask import Flask, render_template, request, redirect, session

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Part 5)
app.config['SESSION_COOKIE_SECURE'] = True # Cookie only travels over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True # prevents JavaScript from reading the session cookie.

# ── DB ───────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect('secure.db')
    conn.row_factory = sqlite3.Row
    return conn


# ── TRAINEE ─────────────────────────────────────────

def get_trainee(username):
    conn = get_db()
    # Part 1) To prevent the SQL injection, we used a parameterized query
    # We used ? instead of inserting the username directly into the SQL statement.
    # In which the username will be sent seperatly, and will never be interpreted as SQL
    # So when "' OR 1=1 -- " is sent it will be treated as a string not SQL
    row = conn.execute(
        "SELECT * FROM trainees WHERE username = ?",
        (username,)
    ).fetchone()
    conn.close()
    return row


# ── VALIDATION ──────────────────────────────────────

USERNAME_RE = re.compile(r'^[A-Za-z0-9]{3,20}$')

def validate_username(u):
    if not u:
        return "Username is required."
    if not USERNAME_RE.match(u):
        return "Username must be 3–20 letters/numbers."
    return None

def validate_password(p):
    if not p:
        return "Password is required."
    if len(p) < 6:
        return "Password must be at least 6 characters."
    if not any(c.isdigit() for c in p):
        return "Password must contain at least one number."
    return None


# ── HOME ─────────────────────────────────────────────

@app.route('/')
def home():
    return redirect('/login')


# ───────────────────────── LOGIN (SECURE) ────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        

        # Check Part 1
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        conn.close()

        # Check Part 2
        if not user or not bcrypt.checkpw(password.encode(), user['password'].encode()):
            return render_template('login.html',
                                   error="Invalid username or password",
                                   username=username)

        if user['role'] != 'student':
            return render_template('login.html',
                                   error="Use admin login page",
                                   username=username)

        session['username'] = user['username']
        session['role'] = user['role']

        if get_trainee(username):
            return redirect('/dashboard')
        return redirect('/coop')

    return render_template('login.html')


# ───────────────────────── ADMIN LOGIN ───────────────

@app.route('/adminLogin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        conn.close()

        # bcrypt check
        if not user or not bcrypt.checkpw(password.encode(), user['password'].encode()):
            return render_template('adminLogin.html',
                                   error="Invalid credentials",
                                   username=username)

        if user['role'] != 'admin':
            return render_template('adminLogin.html',
                                   error="Not admin account",
                                   username=username)

        session['username'] = user['username']
        session['role'] = user['role']

        return redirect('/admin')

    return render_template('adminLogin.html')


# ───────────────────────── REGISTER ──────────────────

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        role = request.form.get('role', 'student')

        errors = []

        if validate_username(username):
            errors.append(validate_username(username))

        if validate_password(password):
            errors.append(validate_password(password))

        if password != confirm:
            errors.append("Passwords do not match")

        if role not in ['student', 'admin']:
            errors.append("Invalid role")

        if errors:
            return render_template('register.html',
                                   errors=errors,
                                   username=username,
                                   role=role)
        
        # Part 2) To encrypt our passwords we used bycrypt because it is safer than MD5,and it is a known hashing algorithm made
        # especially for authentication security. Bycrypt works by adding Salt, which is random data added to the password before hashing
        # which makes brute-force and rainbow table attacks much harder.
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()

        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, hashed, role)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            return render_template('register.html',
                                   errors=["Username already exists"],
                                   username=username,
                                   role=role)
        finally:
            conn.close()

        return redirect('/login')

    return render_template('register.html')


# ───────────────────────── COOP ──────────────────────

@app.route('/coop', methods=['GET', 'POST'])
def coop():

    # Part 4) We added access control checks using sessions and roles.
    # This ensures students cannot access admin pages
    
    if 'username' not in session or session.get('role') != 'student':
        return redirect('/login')

    username = session['username']

    if get_trainee(username):
        return redirect('/dashboard')

    if request.method == 'POST':
        # Part 3) Now we used bleach to sanitize the form's values,
        # So rather than seeing "<script>alert('hacked')</script>" as a
        # code it will see it as plain text
        # Bleach removes dangerous HTML and script tags before saving the data.
        
        name       = bleach.clean(request.form['name'])
        birth      = bleach.clean(request.form['birth'])
        mobile     = bleach.clean(request.form['mobile'])
        email      = bleach.clean(request.form['email'])
        university = bleach.clean(request.form['university'])
        gpa        = bleach.clean(request.form['gpa'])

        conn = get_db()
        conn.execute("""
            INSERT INTO trainees (username, name, birth, mobile, email, university, gpa)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            username,
            name,
            birth,
            mobile,
            email,
            university,
            gpa
        ))
        conn.commit()
        conn.close()

        return redirect('/dashboard')

    return render_template('coop.html')


# ───────────────────────── DASHBOARD ─────────────────

@app.route('/dashboard')
def dashboard():

    # Part 4) Access control only allow students
    if 'username' not in session or session.get('role') != 'student':
        return redirect('/login')

    trainee = get_trainee(session['username'])

    if not trainee:
        return redirect('/coop')

    return render_template('dashboard.html', trainee=trainee)


# ───────────────────────── ADMIN ─────────────────────

@app.route('/admin')
def admin():
    # Part 4) Access control only allow admins 
    if 'username' not in session or session.get('role') != 'admin':
        return redirect('/adminLogin')

    conn = get_db()
    trainees = conn.execute("SELECT * FROM trainees").fetchall()
    conn.close()

    total = len(trainees)
    universities = len(set(t['university'] for t in trainees)) if total else 0

    gpas = []
    for t in trainees:
        try:
            gpas.append(float(t['gpa']))
        except:
            pass

    avg_gpa = round(sum(gpas) / len(gpas), 2) if gpas else "N/A"

    return render_template('Admin_page.html',
                           trainees=trainees,
                           total=total,
                           universities=universities,
                           avg_gpa=avg_gpa)


# ───────────────────────── LOGOUT ────────────────────

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


# Part 5) The :ssl_context='adhoc', will generate a temporary SSL certificate and run using HTTPS
if __name__ == '__main__':
    app.run(debug=True, port=5001 , ssl_context='adhoc')
