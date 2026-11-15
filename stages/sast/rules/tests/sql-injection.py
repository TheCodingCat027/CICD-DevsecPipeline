import sqlite3

# Test SQL injection rule

def bad_concat(conn, name):
    # ruleid: p2-sql-injection-string-concat
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    conn.execute(query + "")

def bad_format(conn, name):
    # ruleid: p2-sql-injection-string-concat
    conn.execute("SELECT * FROM users WHERE name = '%s'" % name)

def good_parameterized(conn, name):
    # ok: p2-sql-injection-string-concat
    conn.execute("SELECT * FROM users WHERE name = ?", (name,))

def good_parameterized_list(conn, name):
    # ok: p2-sql-injection-string-concat
    conn.execute("SELECT * FROM users WHERE name = ?", [name])
