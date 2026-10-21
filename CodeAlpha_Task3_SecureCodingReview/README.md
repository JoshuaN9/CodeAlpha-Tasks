# CodeAlpha SECURE CODING REIVEW
# Overview
A Python security review project developed as part of the CodeAlpha Cyber Security Internship. The project demonstrates manual source-code review, identification of common authentication vulnerabilities, secure coding remediation, and local verification testing.

# Project Objectives
- Identify SQL injection vulnerabilities.
- Explain the risks of weak password hashing.
- Improve database constraints and account initialization.
- Demonstrate safer password verification.
- Test authentication behavior and document findings.

# Project Structure
```bash
CodeAlpha_Task1_SecureCodingReview/
├── README.md
├── vulnerable_app.py
├── secure_app.py
├── security_review.md
├── screenshots/
└── reports/
```

# Requirements
- Python 3.10 or later recommended.
- No third-party packages are required for the demonstration application.

# Run the Demonstration
Check the Python version:
powershell
python --version

Check the secure application's syntax:
powershell
python -m py_compile secure_app.py

Run the application:
powershell
python secure_app.py

Choose option `1` to register a test account or option `2` to log in.

# Security Findings
The original application demonstrates:
- SQL injection through string-concatenated queries.
- Unsuitable MD5 password hashing.
- Predictable default credentials.
- Missing username uniqueness enforcement.
- Missing brute-force protections.
The corrected version introduces parameterized queries, salted scrypt password hashing, unique usernames, generic authentication errors, and password-length validation.

# Verification
Five local tests passed:
1. Valid login.
2. Incorrect password rejection.
3. SQL injection attempt rejection.
4. Duplicate username rejection.
5. Short password rejection.
Testing was limited to the documented scenarios and does not guarantee complete security.

# Limitations
This is an educational demonstration, not a production-ready authentication system. Rate limiting, monitoring, secure deployment, and additional operational controls would be required for real-world use.

# Author
Developed for the CodeAlpha Cyber Security Internship.