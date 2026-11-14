"""
Functional tests for the vulnerable app.
Tests the API behavior (not the security flaws).
The same tests must pass for the fixed app.
"""
import os
import sys
import importlib
from pathlib import Path
import pytest
import json
import sqlite3
import hashlib

_VULN_DIR = str(Path(__file__).parent.parent.resolve())

def _load_app():
    if _VULN_DIR not in sys.path:
        sys.path.insert(0, _VULN_DIR)
    for mod in ['app', 'config']:
        if mod in sys.modules:
            del sys.modules[mod]
    return importlib.import_module('app')

@pytest.fixture
def client():
    """Create a test client with a fresh in-memory database."""
    app_module = _load_app()
    app_module.DATABASE_URL = ':memory:'
    app_module.app.config['TESTING'] = True

    conn = sqlite3.connect(':memory:')
    conn.row_factory = sqlite3.Row
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            notes TEXT
        )
    ''')
    conn.commit()

    conn.execute(
        'INSERT INTO users (username, password_hash, notes) VALUES (?, ?, ?)',
        ('testuser', hashlib.md5(b'testpass').hexdigest(), 'test notes')
    )
    conn.commit()

    original_get_db = app_module.get_db

    def patched_get_db():
        return conn

    app_module.get_db = patched_get_db

    with app_module.app.test_client() as client:
        yield client

    app_module.get_db = original_get_db

def test_health(client):
    """Health endpoint returns ok."""
    resp = client.get('/health')
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert data['status'] == 'ok'

def test_users_search(client):
    """Users endpoint returns results for known user."""
    resp = client.get('/users?name=testuser')
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert isinstance(data, list)

def test_login_valid(client):
    """Login succeeds with correct credentials."""
    resp = client.post('/login',
                       data=json.dumps({'username': 'testuser', 'password': 'testpass'}),
                       content_type='application/json')
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert data['status'] == 'ok'

def test_login_invalid(client):
    """Login fails with wrong credentials."""
    resp = client.post('/login',
                       data=json.dumps({'username': 'testuser', 'password': 'wrongpass'}),
                       content_type='application/json')
    assert resp.status_code == 401
