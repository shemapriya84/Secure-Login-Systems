# SecureGate — Secure Login System

## Requirements
- Python 3.10 or newer
- VS Code or another code editor

## Setup

1. Open this folder in VS Code.
2. Create and activate a virtual environment (recommended).

Windows:
```bash
python -m venv .venv
.venv\\Scripts\\activate
```

macOS/Linux:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

3. Install packages:
```bash
pip install -r requirements.txt
```

4. Start the app:
```bash
python app.py
```

5. Open http://127.0.0.1:5000 in your browser and register a test account.

The SQLite database `users.db` is created automatically when the app starts.

## Security notes
- Uses Werkzeug scrypt password hashing.
- Uses parameterized SQL statements.
- Uses Flask-WTF CSRF protection.
- Uses session cookies with HttpOnly and SameSite=Lax.
- Limits repeated login/registration requests (in-memory limiter for development).
- `debug=True` and the development secret key are for local development only. Before deployment, set a strong random `SECRET_KEY`, set `COOKIE_SECURE=1` when using HTTPS, disable debug mode, and use a persistent rate-limit backend.
- Optional 2FA is not included in this starter version.
