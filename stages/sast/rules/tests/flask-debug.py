from flask import Flask
app = Flask(__name__)

def bad_debug_true():
    # ruleid: p2-flask-debug-enabled
    app.run(debug=True)

def bad_debug_true_kwargs():
    # ruleid: p2-flask-debug-enabled
    app.run(host='0.0.0.0', port=5000, debug=True)

def good_debug_false():
    # ok: p2-flask-debug-enabled
    app.run(debug=False)

def good_debug_env():
    # ok: p2-flask-debug-enabled
    import os
    app.run(debug=os.environ.get('DEBUG', 'false') == 'true')
