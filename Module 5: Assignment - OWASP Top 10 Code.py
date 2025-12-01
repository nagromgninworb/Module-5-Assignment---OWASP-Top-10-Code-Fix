Module 5: Assignment - OWASP Top 10 Code Fix

This is my full writeup for all 10 OWASP Top 10 examples.
I explained the vulnerability, what the risk is, and then
I showed the fixed code and why the fix actually fixws it.


1. BROKEN ACCESS CONTROL (Node.js IDOR)

Original vulnerable code:

app.get('/profile/:userId', (req, res) => {
    User.findById(req.params.userId, (err, user) => {
        if (err) return res.status(500).send(err);
        res.json(user);
    });
});

What’s wrong:

This route trusts whatever userId is in the URL. Anyone can change
/profile/1, /profile/2, etc. and see other people’s data. This is an
IDOR problem (Insecure Direct Object Reference). No auth check at all.

Fixed code:

function requireAuth(req, res, next) {
    if (!req.user) return res.status(401).json({ message: 'Login required' });
    next();
}

app.get('/profile/:userId', requireAuth, (req, res) => {
    if (req.user.id !== req.params.userId && req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Forbidden' });
    }
    User.findById(req.params.userId, (err, user) => {
        if (err) return res.status(500).send(err);
        if (!user) return res.status(404).send('Not found');
        res.json(user);
    });
});

Why the fix works:

I added authentication and an authorization check so users can only
see their own profile (unless admin). This stops IDOR completely.



2. BROKEN ACCESS CONTROL (Flask IDOR)


Original code:

@app.route('/account/<user_id>')
def get_account(user_id):
    user = db.query(User).filter_by(id=user_id).first()
    return jsonify(user.to_dict())

What’s wrong:

Same issue as above. Anyone can request any account number.

Fixed code:

from flask_login import login_required, current_user
from flask import abort, jsonify

@app.route('/account/<int:user_id>')
@login_required
def get_account(user_id):
    if current_user.id != user_id and not getattr(current_user, 'is_admin', False):
        abort(403)
    user = db.session.query(User).filter_by(id=user_id).first()
    if not user: abort(404)
    return jsonify(user.to_dict())

Why the fix works:

Now you must be logged in AND authorized to view that account.
This prevents attackers from guessing IDs.



3. CRYPTOGRAPHIC FAILURES (Java MD5)


Original code:

MessageDigest md = MessageDigest.getInstance("MD5");

What’s wrong:

MD5 is broken and way too fast. No salt, no work factor. Passwords
would get cracked instantly.

Fixed code:

import org.mindrot.jbcrypt.BCrypt;

public class PasswordUtils {
    public static String hashPassword(String password) {
        return BCrypt.hashpw(password, BCrypt.gensalt(12));
    }
    public static boolean checkPassword(String plain, String hash) {
        return BCrypt.checkpw(plain, hash);
    }
}

Why it works:

BCrypt uses salt + a slow hashing cost. This is how OWASP recommends
passwords be stored.



4. CRYPTOGRAPHIC FAILURES (Python SHA-1)


Original code:

hashlib.sha1(password.encode()).hexdigest()

What’s wrong:

SHA-1 is broken, too fast, no salt, no iteration count.

Fixed code:

import os, hashlib, base64

def hash_password(password):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 150000)
    return base64.b64encode(salt).decode() + '$' + base64.b64encode(dk).decode()

def verify_password(password, stored):
    salt_b64, hash_b64 = stored.split('$')
    salt = base64.b64decode(salt_b64)
    real = base64.b64decode(hash_b64)
    check = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 150000)
    return hashlib.compare_digest(check, real)

Why it works:

PBKDF2 adds salt and thousands of iterations, making brute forcing
much harder. This is OWASP-approved.



5. INJECTION (Java SQL Injection)


Original code:

String query = "SELECT * FROM users WHERE username = '" + username + "'";

What’s wrong:

Classic SQL injection. User input goes straight into SQL.

Fixed code:

String sql = "SELECT * FROM users WHERE username = ?";
PreparedStatement ps = connection.prepareStatement(sql);
ps.setString(1, username);
ResultSet rs = ps.executeQuery();

Why it works:

Prepared statements keep the SQL structure separate from the data,
blocking injection attacks.



6. INJECTION (Node.js NoSQL Injection)


Original code:

db.collection('users').findOne({ username: req.query.username })

What’s wrong:

Attackers can pass MongoDB operator objects like {"$ne": null}.

Fixed code:

app.get('/user', requireAuth, (req, res) => {
    const u = req.query.username;
    if (typeof u !== 'string' || !/^[A-Za-z0-9_]{3,30}$/.test(u)) {
        return res.status(400).json({ message: 'Invalid username' });
    }
    db.collection('users').findOne(
        { username: u },
        { projection: { passwordHash: 0 } },
        (err, user) => {
            if (err) return res.status(500).send('DB error');
            if (!user) return res.status(404).send('Not found');
            res.json(user);
        }
    );
});

Why it works:

Input is validated and forced to a safe format. No more object-based
injections. Projection also prevents leaking password hashes.



7. INSECURE DESIGN (Flask password reset)


Original code:

user.password = new_password

What’s wrong:

Anyone with an email can reset any account. No token, no validation,
no email flow, and the password is stored in plaintext.

Fixed code:

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import generate_password_hash
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

@app.route('/reset-password', methods=['POST'])
def reset_password():
    token = request.form.get('token')
    new_pw = request.form.get('new_password')
    try:
        data = serializer.loads(token, max_age=3600)
        user_id = data.get('user_id')
    except (BadSignature, SignatureExpired):
        abort(400)
    user = User.query.get(user_id)
    user.password_hash = generate_password_hash(new_pw)
    db.session.commit()
    return 'Password reset'

Why it works:

Now the reset uses a signed token with expiration, and the password
is hashed instead of plaintext. This is proper reset workflow design.



8. SOFTWARE AND DATA INTEGRITY FAILURES (Untrusted CDN)


Original code:

<script src="https://cdn.example.com/lib.js"></script>

What’s wrong:

If the CDN is compromised, malicious JS loads into the app.

Fixed code:

<script src="https://cdn.example.com/lib-1.2.3.min.js"
        integrity="sha384-BASE64HASH"
        crossorigin="anonymous"></script>

OR host locally:
<script src="/static/lib-1.2.3.min.js"></script>

Why it works:

SRI guarantees the file hasn’t been tampered with. Hosting locally
gives full control.



9. SSRF — Server-Side Request Forgery


Original code:

url = input("Enter URL:")
requests.get(url)

What’s wrong:

Attacker can force server to hit internal IPs or cloud metadata URLs.

Fixed code:

import ipaddress, requests
from urllib.parse import urlparse

ALLOWED = {"example.com", "api.example.com"}

def safe_get(url):
    p = urlparse(url)
    if p.scheme not in ("http","https"): raise ValueError()
    if p.hostname not in ALLOWED: raise ValueError()
    return requests.get(url, timeout=5, allow_redirects=False)

Why it works:

Strict allowlist and URL validation prevents internal network access
and blocks malicious domains.



10. IDENTIFICATION & AUTHENTICATION FAILURES


Original code:

if (inputPassword.equals(user.getPassword())) {

What’s wrong:

User passwords are stored in plaintext. One breach = all passwords leaked.

Fixed code:

import org.mindrot.jbcrypt.BCrypt;

if (BCrypt.checkpw(inputPassword, user.getPasswordHash())) {
    // login success
}

Why it works:

Now the app uses hashed passwords instead of storing real ones. BCrypt
protects passwords if the database leaks.

The End
