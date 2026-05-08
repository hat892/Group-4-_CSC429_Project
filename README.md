# CSC429-project


## Overview
This project is a secure web application developed using Flask and SQLite. The application includes user registration, login, dashboard access, and an admin page. The project demonstrates common web security vulnerabilities and how to mitigate them using secure coding practices.

The project contains:
- Vulnerable Version
- Secure Version

Security topics covered:
- SQL Injection
- Weak Password Storage
- Cross-Site Scripting (XSS)
- Access Control (RBAC)
- Encryption and HTTPS

---

# Technologies Used

- Python
- Flask
- SQLite
- bcrypt
- bleach

---


# Steps to Run the Application

## 1. Install Required Packages

```bash
pip install flask bcrypt bleach cryptography
```

---

## 2. Create the Database

```bash
python init_db.py
```

---

## 3. Run the Vulnerable Application

```bash
python app_vulnerable.py
```

Open in browser:

```text
http://127.0.0.1:5000
```

---

## 4. Run the Secure Application

```bash
python app_secure.py
```

Open in browser:

```text
https://127.0.0.1:5001
```

Note:
The secure version uses HTTPS with a self-signed certificate (`ssl_context='adhoc'`), so the browser may show a warning during testing.

---

# Security Vulnerabilities and Mitigation

## 1. SQL Injection

### Vulnerable Version

The vulnerable version used f-strings to build SQL queries:

```python
query = f"SELECT * FROM users WHERE username = '{username}'"
```

Attackers could enter:

```text
' OR 1=1 --
```

to bypass authentication.

### Mitigation

Parameterized queries were implemented:

```python
conn.execute(
    "SELECT * FROM users WHERE username = ?",
    (username,)
)
```

This prevents user input from changing the SQL query.

---

## 2. Weak Password Storage

### Vulnerable Version

Passwords were stored using MD5 hashing:

```python
hashlib.md5(password.encode()).hexdigest()
```

MD5 is insecure because it is fast and does not include salting (adding a random value to the password before hashing), making it vulnerable to brute-force and rainbow table attacks (precomputed tables of common password hashes used by attackers).

### Mitigation

bcrypt was implemented for secure password hashing:

```python
bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```

bcrypt uses salting and is intentionally slow, making password attacks much harder.

---

## 3. Cross-Site Scripting (XSS)

### Vulnerable Version

User input was stored without sanitization.

Example attack:

```html
<script>alert('XSS')</script>
```

### Mitigation

Input sanitization was added using bleach:

```python
bleach.clean(user_input)
```

This removes harmful scripts from user input.

---

## 4. Access Control (RBAC)

### Vulnerable Version

The admin page did not check the user role before granting access. Any user who knew the `/admin` URL could access the admin page.

### Mitigation

Role-Based Access Control (RBAC) was implemented:

```python
if session.get('role') != 'admin':
    return redirect('/adminLogin')
```

Only admins can access the admin page.

---

## 5. Encryption and Secure Communication

### Mitigation

The secure version uses:
- HTTPS (`ssl_context='adhoc'`)
- Secure cookies
- HttpOnly session cookies

```python
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
```

This improves session protection and secure communication.

---

# How to Test Security Features

## SQL Injection Test

In the vulnerable login page, enter:

```text
' OR 1=1 --
```

The login bypassed.

In the secure version, the attack fails because parameterized queries are used.

---

## XSS Test

In the vulnerable coop form, enter:

```html
<script>alert('XSS')</script>
```

The script may execute in the browser.

In the secure version, the input is sanitized using bleach.

---

## Access Control Test

using a normal student account.

- Vulnerable version: Access allowed.
- Secure version: Access denied.

---

## Weak Password Storge Test

we take the encryption password from SQL
and use a crackstation website to check the decryption 


## Encryption Test
we test it from website settings in develop section to see if the link secure or no



# Author

This project was developed for the CSC429 Web Security course to demonstrate secure coding practices and mitigation of common web vulnerabilities.
