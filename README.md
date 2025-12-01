For this assignment, I went through all ten OWASP Top 10 examples and fixed the vulnerable code. For each one, I explained what the problem was, why it’s a security risk, and then showed the corrected version and why it fixes the issue. I kept everything simple and straight to the point.

Broken Access Control (Node.js)
Issue:
The route trusted whatever userId was in the URL. Anyone could change the ID and pull another user’s profile. This is an IDOR problem.

Fix:
I added an authentication check and made sure the logged-in user can only view their own profile unless they’re admin.

Why it’s fixed:
Now it checks who is calling it. Users can’t guess IDs and access someone else’s data.

Broken Access Control (Flask)
Issue:
There was no login check at all. Anyone could request /account/any_id and see someone else’s information.

Fix:
I used login_required and added a check so only the actual owner or an admin can access that account.

Why it’s fixed:
Authorization is enforced and ID guessing is blocked.

Cryptographic Failures (Java MD5)
Issue:
MD5 is weak and extremely fast. It has no salt and is not safe for storing passwords.

Fix:
I switched the hashing to BCrypt with a work factor.

Why it’s fixed:
BCrypt includes salt and slows down brute forcing. This is the proper way to hash passwords.

Cryptographic Failures (Python SHA-1)
Issue:
SHA-1 is weak, fast, and has no salt or iteration count.

Fix:
I used PBKDF2 with SHA-256, salt, and a high number of iterations.

Why it’s fixed:
This is actually designed for password hashing and makes guessing or cracking much harder.

Injection (Java SQL Injection)
Issue:
The SQL query was built using string concatenation with user input. This allows SQL injection.

Fix:
I replaced the query with a PreparedStatement and set the username as a parameter.

Why it’s fixed:
Prepared statements separate SQL structure from the user input and stop injection.

Injection (Node.js NoSQL Injection)
Issue:
MongoDB queries were made directly from user input. Attackers can pass in objects with operators.

Fix:
I validated the username and restricted it to a safe pattern.

Why it’s fixed:
Invalid or malicious objects can’t be passed into the query anymore.

Insecure Design (Flask password reset)
Issue:
Anyone could reset a password just by knowing someone’s email. No verification, no token, and the password was stored in plaintext.

Fix:
I added a signed, time-limited reset token and hashed the new password.

Why it’s fixed:
The reset flow now verifies identity, and the stored password is secure.

Software and Data Integrity Failures (Untrusted CDN)
Issue:
A script was loaded from a CDN with no integrity check. If that CDN gets compromised, malicious JS loads into the app.

Fix:
I used SRI (Subresource Integrity) or hosting the file locally.

Why it’s fixed:
The browser verifies the script hasn’t been modified.

SSRF (Server-Side Request Forgery)
Issue:
The server took any URL from user input and fetched it. Attackers can use this to hit internal systems.

Fix:
I validated the URL, restricted it to allowed domains, and blocked unsafe schemes.

Why it’s fixed:
It prevents requests to internal networks and unsafe endpoints.

Identification and Authentication Failures
Issue:
Passwords were being compared in plaintext. That means the real password was being stored in plaintext.

Fix:
I switched it to BCrypt password hashing and used the hashed version for login checks.

Why it’s fixed:
Passwords are no longer stored in plaintext, and leaks don’t reveal real credentials.

Summary:
I went through all ten OWASP issues, explained the risk, fixed the code, and explained why each fix works. All fixes follow what OWASP recommends to remove the vulnerabilities.
