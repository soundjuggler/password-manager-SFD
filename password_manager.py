"""
Basic command-line password manager (college learning project).

Stage 1: Master-password authentication only.
  - Register: create auth_salt + auth_hash (+ kdf_salt for later stages)
  - Login: verify master password with hmac.compare_digest

Security idea (WHY):
  We never store the master password itself. We store a slow hash of it
  (PBKDF2-HMAC-SHA256). On login we re-hash the attempt and compare.
  That way a stolen config.json does not reveal the password in plain text.
"""

import getpass
import hashlib
import hmac
import json
import os

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Toggle later (Stage 4) for step-by-step demo output. Never print secrets.
DEBUG = False

CONFIG_FILE = "config.json"

# WHY 600_000 iterations: PBKDF2 deliberately slows hashing so brute-force
# guessing is expensive. Assignment requires this exact count.
PBKDF2_ITERATIONS = 600_000

# WHY 16 bytes: 128 bits of randomness is standard for salts; os.urandom
# draws from the OS CSPRNG so salts are unpredictable.
SALT_SIZE = 16

# WHY SHA-256: strong, widely used hash; used inside PBKDF2 as required.
HASH_ALGORITHM = "sha256"

# Maximum login tries before we stop (assignment: 3 attempts).
MAX_LOGIN_ATTEMPTS = 3


# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------

def generate_salt():
    """
    Return 16 random bytes for use as a salt.

    WHY: A unique salt per purpose (auth vs key derivation) means the same
    master password produces different outputs for hashing and for encryption
    keys. If one salt leaked or one use was broken, the other is not reused.
    """
    return os.urandom(SALT_SIZE)


def hash_password(password, salt):
    """
    Hash a password with PBKDF2-HMAC-SHA256 and the given salt.

    Returns raw digest bytes (not hex). Callers decide how to store it.

    WHY PBKDF2 (not plain SHA-256):
      Plain SHA-256 is fast — attackers can try billions of guesses per second.
      PBKDF2 repeats the HMAC many times so each guess is slow.

    WHY we pass salt:
      Without a salt, two users with the same password get the same hash
      (and rainbow tables work). With a random salt, identical passwords
      produce different hashes.
    """
    # password must be bytes for hashlib; encode as UTF-8.
    password_bytes = password.encode("utf-8")
    return hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password_bytes,
        salt,
        PBKDF2_ITERATIONS,
    )


# ---------------------------------------------------------------------------
# Config I/O (auth material only in Stage 1)
# ---------------------------------------------------------------------------

def save_config(auth_salt, auth_hash, kdf_salt):
    """
    Write salts and auth hash to config.json as hex strings.

    WHY hex: binary salts/hashes are not JSON-friendly as raw bytes;
    hex is readable and easy to round-trip with bytes.fromhex().

    WHY we save kdf_salt now even though Stage 1 does not encrypt yet:
      The design says two separate salts. Creating kdf_salt at register time
      means Stage 2 can derive the Fernet key without re-registering.
      We never save the derived key itself — only the salt needed to remake it.
    """
    data = {
        "auth_salt": auth_salt.hex(),
        "auth_hash": auth_hash.hex(),
        "kdf_salt": kdf_salt.hex(),
    }
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def load_config():
    """
    Load config.json and return (auth_salt, auth_hash, kdf_salt) as bytes.

    Returns None if the file is missing (first-run case).
    """
    if not os.path.exists(CONFIG_FILE):
        return None

    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    return (
        bytes.fromhex(data["auth_salt"]),
        bytes.fromhex(data["auth_hash"]),
        bytes.fromhex(data["kdf_salt"]),
    )


# ---------------------------------------------------------------------------
# Register / Login
# ---------------------------------------------------------------------------

def register():
    """
    First-run setup: ask for a master password twice, create salts + auth hash.

    WHY confirm twice: typos on a master password would lock the user out
    forever once we encrypt the vault (Stage 2+), because we cannot recover it.
    """
    print("=== First-time setup ===")
    print("Create a master password (at least 8 characters).")
    print("This password unlocks your vault. It is never stored in plain text.")

    while True:
        # WHY getpass: the password is not echoed to the screen (shoulder-surfing).
        password = getpass.getpass("Master password: ")
        confirm = getpass.getpass("Confirm master password: ")

        if password != confirm:
            print("Passwords do not match. Try again.")
            continue

        if len(password) < 8:
            print("Password must be at least 8 characters. Try again.")
            continue

        break

    # Two DIFFERENT salts for two DIFFERENT jobs (auth vs encryption key).
    auth_salt = generate_salt()
    kdf_salt = generate_salt()

    # Only the auth path is used in Stage 1. kdf_salt is saved for Stage 2.
    auth_hash = hash_password(password, auth_salt)

    save_config(auth_salt, auth_hash, kdf_salt)
    print("Master password registered. Config saved to", CONFIG_FILE)
    # Do not keep the password longer than needed; local var ends with function.
    return True


def login():
    """
    Ask for the master password (up to 3 tries) and verify against auth_hash.

    Returns True on success, False on failure.

    WHY verify BEFORE any key derivation / vault decrypt (Stage 2+):
      Wrong password should fail early. We do not derive the encryption key
      or open data.enc until authentication succeeds.
    """
    config = load_config()
    if config is None:
        print("No config found. Run registration first.")
        return False

    auth_salt, auth_hash, _kdf_salt = config

    print("=== Login ===")
    for attempt in range(1, MAX_LOGIN_ATTEMPTS + 1):
        password = getpass.getpass(
            f"Master password (attempt {attempt}/{MAX_LOGIN_ATTEMPTS}): "
        )

        # Re-hash the attempt with the SAME auth_salt used at registration.
        attempt_hash = hash_password(password, auth_salt)

        # WHY hmac.compare_digest, never == :
        #   == can short-circuit and leak timing info about how many bytes
        #   matched. compare_digest is constant-time for equal-length digests.
        if hmac.compare_digest(attempt_hash, auth_hash):
            print("Login successful.")
            return True

        print("Incorrect password.")

    print("Too many failed attempts. Exiting.")
    return False


# ---------------------------------------------------------------------------
# Entry point (Stage 1: auth only)
# ---------------------------------------------------------------------------

def main():
    """
    Stage 1 flow:
      - No config.json  -> register()
      - Has config.json -> login()
    Vault encryption and the menu come in later stages.
    """
    if not os.path.exists(CONFIG_FILE):
        register()
        # After first register, also log in once so the user sees the path.
        # (Optional for Stage 1; keeps the demo clear.)
        print()
        login()
    else:
        login()


if __name__ == "__main__":
    main()
