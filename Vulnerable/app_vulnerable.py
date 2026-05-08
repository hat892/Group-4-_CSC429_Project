import re
import hashlib
import os
import sqlite3
from flask import Flask, render_template, request, redirect, session

app = Flask(__name__)
app.secret_key = os.urandom(24)
 # Part 5) Since this is the vulnerable code, there is no encryption on session tokens and it will be http

# ── helpers ────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect('vulnerable.db')
    conn.row_factory = sqlite3.Row
    return conn

# Part 2) for a weak password hashing technique MD5 was used, it's known for its speed not security
# So it can be cracked instantly using for example rainbow table attacks
def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()        

def get_trainee(username):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM trainees WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    return row

# ── validation helpers ─────────────────────────────────────────────────────

USERNAME_RE = re.compile(r'^[A-Za-z0-9]{3,20}$')

def validate_username(u):
    """3–20 chars, letters and numbers only."""
    if not u:
        return "Username is required."
    if not USERNAME_RE.match(u):
        return "Username must be 3–20 characters and contain only letters and numbers."
    return None

def validate_password(p):
    """At least 6 chars and contains a digit."""
    if not p:
        return "Password is required."
    if len(p) < 6:
        return "Password must be at least 6 characters."
    if not any(c.isdigit() for c in p):
        return "Password must contain at least one number."
    return None


# ── routes ─────────────────────────────────────────────────────────────────

@app.route('/')
def home():
    return redirect('/login')


# STUDENT LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
       
        
        conn = get_db()
        # Part 1) The first vulnerablity we have is the "SQL injection"
        # Whatever the user enters in the username field becomes part of the query
        # So if the user enters for example  "' OR 1=1 -- ", the attacker will be able to enter the system without the need for a password
        query = f"SELECT * FROM users WHERE username = '{username}'"
        user = conn.execute(query).fetchone()
       

        if not user:
            return render_template('login.html',
                                   error="Account not found. Check your username and password.",
                                   username=username)

       

        session['username'] = user['username']
        session['role']     = user['role']

        if get_trainee(username):
            return redirect('/dashboard')
        return redirect('/coop')

    return render_template('login.html')


# ADMIN LOGIN  (separate route — form posts here)
@app.route('/adminLogin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
       
       
        conn = get_db()
        # Return to Part 1 for explanation
        query = f"SELECT * FROM users WHERE username = '{username}'"
        user = conn.execute(query).fetchone()
           
        if not user:
            return render_template('adminLogin.html',
                                   error="Account not found. Check your username and password.",
                                   username=username)

   

        session['username'] = user['username']
        session['role']     = user['role']
        return redirect('/admin')

    return render_template('adminLogin.html')


# LOGOUT
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


# REGISTER
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username         = request.form.get('username', '').strip()
        password         = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        role             = request.form.get('role', 'student')

        errors = []

        u_err = validate_username(username)
        if u_err:
            errors.append(u_err)

        p_err = validate_password(password)
        if p_err:
            errors.append(p_err)

        if password and confirm_password != password:
            errors.append("Passwords do not match.")

        if role not in ('student', 'admin'):
            errors.append("Invalid role selected.")

        if errors:
            return render_template('register.html',
                                   errors=errors,
                                   username=username,
                                   role=role)

        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, hash_password(password), role)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return render_template('register.html',
                                   errors=["Username is already taken. Please choose another."],
                                   username=username,
                                   role=role)
        conn.close()

        # Redirect to the right login page based on role
        if role == 'admin':
            return redirect('/adminLogin')
        return redirect('/login')

    return render_template('register.html')


# COOP FORM
@app.route('/coop', methods=['GET', 'POST'])
def coop():
    # here is not security check for role, any logged in user can access this page, but only students will see the form and be able to submit it
    username = session['username']
    if get_trainee(username):
        return redirect('/dashboard')

    if request.method == 'POST':
        # Part 3) Raw form values are directly submitted to the database
        # When displayed later in the Flask template, embedded HTML or JavaScript may execute.
        # Many problems could happen for example if the hacker entered  "<script>alert('hacked')</script>"
        # The browser will execute it and the user will get a alert, much more dangerous things could happen such as
        # The hacker stealing cookies or redirecting the user or even modifying the page's content    
        name       = request.form['name']
        birth      = request.form['birth']
        mobile     = request.form['mobile']
        email      = request.form['email']
        university = request.form['university']
        gpa        = request.form['gpa']


        conn = get_db()
        conn.execute("""
            INSERT INTO trainees (username, name, birth, mobile, email, university, gpa)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (username, name, birth, mobile, email, university, gpa))
        conn.commit()
        conn.close()

        return redirect('/dashboard')

    return render_template('coop.html')


# STUDENT DASHBOARD
@app.route('/dashboard')
def dashboard():
   # Part 4) There is no security check for role, any logged in user can access this page

    trainee = get_trainee(session['username'])
    if not trainee:
        return redirect('/coop')

    return render_template('dashboard.html', trainee=trainee)


# ADMIN DASHBOARD
@app.route('/admin')
def admin():

    # Continuing part 4), even students can see the admin dashboard since there is no role check
    

    conn = get_db()
    trainees = conn.execute("SELECT * FROM trainees").fetchall()

    total        = len(trainees)
    universities = len(set(t['university'] for t in trainees)) if total else 0

    gpas = []
    for t in trainees:
        try:
            gpas.append(float(t['gpa']))
        except (ValueError, TypeError):
            pass
    avg_gpa = round(sum(gpas) / len(gpas), 2) if gpas else 'N/A'

    conn.close()

    return render_template('Admin_page.html',
                           trainees=trainees,
                           total=total,
                           universities=universities,
                           avg_gpa=avg_gpa)


if __name__ == '__main__':
    app.run(debug=True, port=5000)