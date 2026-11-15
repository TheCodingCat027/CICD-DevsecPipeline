import hashlib

def bad_md5(password):
    # ruleid: p2-weak-password-hash
    return hashlib.md5(password.encode()).hexdigest()

def bad_sha1(password):
    # ruleid: p2-weak-password-hash
    return hashlib.sha1(password.encode()).hexdigest()

def good_sha256(data):
    # ok: p2-weak-password-hash
    return hashlib.sha256(data).hexdigest()

def good_scrypt(password, salt):
    # ok: p2-weak-password-hash
    return hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
