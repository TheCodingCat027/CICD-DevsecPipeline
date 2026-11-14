"""
Vulnerable Flask demo application.
WARNING: This app contains INTENTIONAL security vulnerabilities for testing.
DO NOT deploy. See demo-app/README.md and seeded-vulnerabilities.md.
"""
import hashlib  # noqa: S324 - intentional weak hash for V6
import sqlite3
import os
from flask import Flask, request, jsonify
from config import DATABASE_URL, SECRET_KEY, DEBUG

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY

def get_db():
    """Get a database connection."""
    db_path = DATABASE_URL.replace('sqlite:///', '')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the database with schema."""
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            notes TEXT
        )
    ''')
    conn.commit()
    conn.close()

@app.route('/health')
def health():
    """Health check endpoint."""
    return jsonify({'status': 'ok', 'service': 'demo-app-vulnerable'})

@app.route('/users')
def get_users():
    """
    Search users by name.
    V2: SQL injection - user input is concatenated directly into query string.
    """
    name = request.args.get('name', '')
    conn = get_db()
    # V2: SQL INJECTION - never do this in production!
    # Semgrep rule: python.lang.security.audit.formatted-sql-query.formatted-sql-query
    query = "SELECT id, username, notes FROM users WHERE username = '" + name + "'"
    cursor = conn.execute(query)
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(users)

@app.route('/login', methods=['POST'])
def login():
    """
    Login endpoint.
    V6: Weak password hashing using MD5.
    """
    data = request.get_json() or {}
    username = data.get('username', '')
    password = data.get('password', '')

    # V6: WEAK HASHING - MD5 is cryptographically broken, never use for passwords!
    # Semgrep rule: python.lang.security.audit.md5-used-as-password.md5-used-as-password
    password_hash = hashlib.md5(password.encode()).hexdigest()  # noqa: S324

    conn = get_db()
    cursor = conn.execute(
        'SELECT id, username FROM users WHERE username = ? AND password_hash = ?',
        (username, password_hash)
    )
    user = cursor.fetchone()
    conn.close()

    if user:
        return jsonify({'status': 'ok', 'user_id': user['id']})
    return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401

@app.route('/register', methods=['POST'])
def register():
    """Register a new user."""
    data = request.get_json() or {}
    username = data.get('username', '')
    password = data.get('password', '')
    notes = data.get('notes', '')

    if not username or not password:
        return jsonify({'error': 'username and password required'}), 400

    # V6: Same weak hashing on registration
    password_hash = hashlib.md5(password.encode()).hexdigest()  # noqa: S324

    conn = get_db()
    try:
        conn.execute(
            'INSERT INTO users (username, password_hash, notes) VALUES (?, ?, ?)',
            (username, password_hash, notes)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'error': 'username already exists'}), 409
    conn.close()
    return jsonify({'status': 'created'}), 201

if __name__ == '__main__':
    init_db()
    # V7: debug=True exposes the Werkzeug debugger - never in production!
    # Semgrep rule: python.flask.security.audit.debug-enabled.debug-enabled
    app.run(host='0.0.0.0', port=5000, debug=True)  # noqa - intentional V7
