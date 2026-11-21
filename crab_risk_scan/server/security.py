"""Password hashing and bearer secrets. Standard library only."""
import base64
import hashlib
import hmac
import re
import secrets

SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 64 * 1024 * 1024
MIN_PASSWORD = 10
MAX_PASSWORD = 1024
TOKEN_PREFIX = "crab_"
USERNAME = re.compile(r"[a-z0-9][a-z0-9._@-]{0,63}")
_DUMMY = None


def _b64(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def validate_password(password):
    if not isinstance(password, str) or not MIN_PASSWORD <= len(password) <= MAX_PASSWORD:
        raise ValueError(f"password must be {MIN_PASSWORD} to {MAX_PASSWORD} characters")
    return password


def normalize_username(username):
    name = username.strip().lower() if isinstance(username, str) else ""
    if not USERNAME.fullmatch(name):
        raise ValueError("username must be 1-64 characters: letters, digits, '.', '_', '@' or '-'")
    return name


def hash_password(password):
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                             maxmem=SCRYPT_MAXMEM, dklen=32)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_b64(salt)}${_b64(derived)}"


def verify_password(password, encoded):
    """Constant-time password check. Malformed hashes never match."""
    try:
        scheme, n, r, p, salt, expected = encoded.split("$")
        n, r, p = int(n), int(r), int(p)
        if scheme != "scrypt" or not (2 <= n <= 2 ** 20 and 1 <= r <= 32 and 1 <= p <= 16):
            return False
        derived = hashlib.scrypt(password.encode("utf-8")[:4 * MAX_PASSWORD], salt=_unb64(salt), n=n, r=r, p=p,
                                 maxmem=SCRYPT_MAXMEM, dklen=len(_unb64(expected)))
        return hmac.compare_digest(derived, _unb64(expected))
    except (ValueError, TypeError, AttributeError):
        return False


def burn_password_check(password):
    """Spend the same time as a real check for unknown users."""
    global _DUMMY
    if _DUMMY is None:
        _DUMMY = hash_password(secrets.token_urlsafe(16))
    verify_password(password, _DUMMY)


def new_secret(prefix=""):
    return prefix + secrets.token_urlsafe(32)


def digest(secret):
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def same(left, right):
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def generated_password():
    return secrets.token_urlsafe(18)
