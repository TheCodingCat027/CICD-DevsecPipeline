"""
Fixed Flask demo application - secure version.
All vulnerabilities from demo-app/vulnerable/ have been remediated.
"""
import hashlib
import sqlite3
import os
from flask import Flask, request, jsonify
from config import DATABASE_URL, SECRET_KEY, DEBUG

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY

def get_db():
    """Get a database connection."""
    db_path = DATABASE_URL.replace('sqlite:///', '')
    if db_path == ':memory:':
        conn = sqlite3.connect(':memory:')
    else:
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

def hash_password(password: str) -> str:
    """Fixed V6: Use scrypt for secure password hashing."""
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
    return salt.hex() + ':' + dk.hex()

def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against a scrypt hash."""
    try:
        salt_hex, dk_hex = stored_hash.split(':', 1)
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
        return dk.hex() == dk_hex
    except Exception:
        return False

@app.route('/health')
def health():
    """Health check endpoint."""
    return jsonify({'status': 'ok', 'service': 'demo-app-fixed'})

@app.route('/users')
def get_users():
    """
    Search users by name.
    Fixed V2: Parameterized query prevents SQL injection.
    """
    name = request.args.get('name', '')
    conn = get_db()
    # Fixed V2: Parameterized query
    cursor = conn.execute(
        'SELECT id, username, notes FROM users WHERE username = ?',
        (name,)
    )
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(users)

@app.route('/login', methods=['POST'])
def login():
    """Login endpoint - Fixed V6: uses scrypt hashing."""
    data = request.get_json() or {}
    username = data.get('username', '')
    password = data.get('password', '')

    conn = get_db()
    cursor = conn.execute(
        'SELECT id, username, password_hash FROM users WHERE username = ?',
        (username,)
    )
    user = cursor.fetchone()
    conn.close()

    if user and verify_password(password, user['password_hash']):
        return jsonify({'status': 'ok', 'user_id': user['id']})
    return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401

@app.route('/register', methods=['POST'])
def register():
    """Register a new user - Fixed V6: uses scrypt hashing."""
    data = request.get_json() or {}
    username = data.get('username', '')
    password = data.get('password', '')
    notes = data.get('notes', '')

    if not username or not password:
        return jsonify({'error': 'username and password required'}), 400

    password_hash = hash_password(password)

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
    # Fixed V7: debug=False, read from env
    app.run(host='0.0.0.0', port=5000, debug=DEBUG)
