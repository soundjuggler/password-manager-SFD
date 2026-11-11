# BASIC COMMAND-LINE PASSWORD MANAGER (COLLEGE LEARNING PROJECT).
#
# STAGE 1: MASTER-PASSWORD AUTHENTICATION (HASH + VERIFY).
# STAGE 2: SEPARATE ENCRYPTION KEY + ENCRYPTED VAULT (data.enc).
#
# SECURITY IDEA (WHY):
#   AUTH: THE MASTER PASSWORD IS HASHED (PBKDF2) AND VERIFIED — NEVER STORED.
#   ENCRYPTION: A DIFFERENT SALT DERIVES A Fernet KEY THAT EXISTS ONLY IN
#   MEMORY WHILE LOGGED IN. SITE PASSWORDS ARE ENCRYPTED (MUST BE READABLE
#   AGAIN), NOT HASHED. THE KEY IS NEVER WRITTEN TO DISK.

import base64
import getpass
import hashlib
import hmac
import json
import os

from cryptography.fernet import Fernet

# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------

# TOGGLE LATER (STAGE 4) FOR STEP-BY-STEP DEMO OUTPUT. NEVER PRINT SECRETS.
DEBUG = False

CONFIG_FILE = "config.json"
DATA_FILE = "data.enc"

# WHY 600_000 ITERATIONS: PBKDF2 DELIBERATELY SLOWS HASHING SO BRUTE-FORCE
# GUESSING IS EXPENSIVE. ASSIGNMENT REQUIRES THIS EXACT COUNT.
PBKDF2_ITERATIONS = 600_000

# WHY 16 BYTES: 128 BITS OF RANDOMNESS IS STANDARD FOR SALTS; os.urandom
# DRAWS FROM THE OS CSPRNG SO SALTS ARE UNPREDICTABLE.
SALT_SIZE = 16

# WHY SHA-256: STRONG, WIDELY USED HASH; USED INSIDE PBKDF2 AS REQUIRED.
HASH_ALGORITHM = "sha256"

# WHY 32 BYTES: Fernet NEEDS A 256-BIT KEY (THEN URL-SAFE BASE64-ENCODED).
KEY_SIZE = 32

# MAXIMUM LOGIN TRIES BEFORE WE STOP (ASSIGNMENT: 3 ATTEMPTS).
MAX_LOGIN_ATTEMPTS = 3


# ---------------------------------------------------------------------------
# CRYPTO HELPERS
# ---------------------------------------------------------------------------

def generate_salt():
    # RETURN 16 RANDOM BYTES FOR USE AS A SALT.
    #
    # WHY: A UNIQUE SALT PER PURPOSE (AUTH VS KEY DERIVATION) MEANS THE SAME
    # MASTER PASSWORD PRODUCES DIFFERENT OUTPUTS FOR HASHING AND FOR ENCRYPTION
    # KEYS. IF ONE SALT LEAKED OR ONE USE WAS BROKEN, THE OTHER IS NOT REUSED.
    return os.urandom(SALT_SIZE)


def hash_password(password, salt):
    # HASH A PASSWORD WITH PBKDF2-HMAC-SHA256 AND THE GIVEN SALT.
    # RETURNS RAW DIGEST BYTES (NOT HEX). CALLERS DECIDE HOW TO STORE IT.
    #
    # WHY PBKDF2 (NOT PLAIN SHA-256):
    #   PLAIN SHA-256 IS FAST — ATTACKERS CAN TRY BILLIONS OF GUESSES PER SECOND.
    #   PBKDF2 REPEATS THE HMAC MANY TIMES SO EACH GUESS IS SLOW.
    #
    # WHY WE PASS salt:
    #   WITHOUT A SALT, TWO USERS WITH THE SAME PASSWORD GET THE SAME HASH
    #   (AND RAINBOW TABLES WORK). WITH A RANDOM SALT, IDENTICAL PASSWORDS
    #   PRODUCE DIFFERENT HASHES.
    password_bytes = password.encode("utf-8")
    return hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password_bytes,
        salt,
        PBKDF2_ITERATIONS,
    )


def derive_key(password, kdf_salt):
    # DERIVE A Fernet ENCRYPTION KEY FROM THE MASTER PASSWORD + kdf_salt.
    # RETURNS URL-SAFE BASE64-ENCODED 32-BYTE KEY (WHAT Fernet EXPECTS).
    #
    # WHY A SEPARATE SALT FROM auth_salt:
    #   AUTHENTICATION HASH AND ENCRYPTION KEY MUST NOT BE INTERCHANGEABLE.
    #   USING kdf_salt HERE MEANS KNOWING (OR CRACKING) THE STORED auth_hash
    #   DOES NOT DIRECTLY GIVE YOU THE VAULT KEY.
    #
    # WHY THE KEY IS NEVER SAVED:
    #   ANYONE WITH THE KEY CAN DECRYPT THE VAULT. WE REMAKE IT FROM THE
    #   MASTER PASSWORD ONLY AFTER A SUCCESSFUL LOGIN, AND KEEP IT IN MEMORY.
    key_bytes = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password.encode("utf-8"),
        kdf_salt,
        PBKDF2_ITERATIONS,
        dklen=KEY_SIZE,
    )
    # Fernet REQUIRES THE KEY AS URL-SAFE BASE64 OF EXACTLY 32 RAW BYTES.
    return base64.urlsafe_b64encode(key_bytes)


# ---------------------------------------------------------------------------
# CONFIG I/O
# ---------------------------------------------------------------------------

def save_config(auth_salt, auth_hash, kdf_salt):
    # WRITE SALTS AND AUTH HASH TO config.json AS HEX STRINGS.
    #
    # WHY HEX: BINARY SALTS/HASHES ARE NOT JSON-FRIENDLY AS RAW BYTES;
    # HEX IS READABLE AND EASY TO ROUND-TRIP WITH bytes.fromhex().
    #
    # WHY WE SAVE kdf_salt BUT NEVER THE DERIVED KEY:
    #   THE SALT LETS US REMAKE THE KEY AFTER LOGIN. SAVING THE KEY ITSELF
    #   WOULD DEFEAT ENCRYPTION — ANYONE READING THE DISK COULD DECRYPT.
    data = {
        "auth_salt": auth_salt.hex(),
        "auth_hash": auth_hash.hex(),
        "kdf_salt": kdf_salt.hex(),
    }
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def load_config():
    # LOAD config.json AND RETURN (auth_salt, auth_hash, kdf_salt) AS BYTES.
    # RETURNS None IF THE FILE IS MISSING (FIRST-RUN CASE).
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
# VAULT I/O (ENCRYPTED BLOB) -> data.enc
# ---------------------------------------------------------------------------
# WHAT data.enc IS DOING AT STAGE 2:
#   IT HOLDS THE ENTIRE PASSWORD VAULT AS ONE Fernet CIPHERTEXT FILE.
#   RIGHT NOW THE VAULT IS AN EMPTY JSON OBJECT {} THAT WAS ENCRYPTED DURING
#   register(). THERE ARE NO SITE ENTRIES YET (THAT COMES IN STAGE 3).
#   ON LOGIN WE derive_key() THEN load_vault() TO DECRYPT IT BACK INTO A DICT.
#   OPENING data.enc IN A TEXT EDITOR SHOULD LOOK LIKE GIBBERISH — THAT IS
#   THE POINT. PLAINTEXT NEVER SITS ON DISK.

def save_vault(vault, key):
    # ENCRYPT THE WHOLE VAULT DICT AS ONE JSON BLOB AND WRITE data.enc.
    #
    # WHY ENCRYPT THE WHOLE VAULT AS ONE BLOB:
    #   ONE Fernet TOKEN FOR EVERYTHING IS SIMPLE AND TAMPER-EVIDENT.
    #   Fernet ALSO AUTHENTICATES CIPHERTEXT (DETECTS MODIFICATION).
    #
    # WHY ENCRYPT SITE PASSWORDS (NOT HASH THEM):
    #   HASHES ARE ONE-WAY — WE COULD NEVER SHOW THE USER THEIR SAVED PASSWORD.
    #   ENCRYPTION IS REVERSIBLE WITH THE KEY, SO ENTRIES STAY RETRIEVABLE.
    fernet = Fernet(key)
    # json.dumps TURNS THE DICT INTO TEXT; ENCODE TO BYTES FOR Fernet.
    plaintext = json.dumps(vault).encode("utf-8")
    token = fernet.encrypt(plaintext)
    with open(DATA_FILE, "wb") as f:
        f.write(token)


def load_vault(key):
    # DECRYPT data.enc AND RETURN THE VAULT AS A PYTHON DICT.
    # IF data.enc IS MISSING, RETURN AN EMPTY VAULT DICT (AND CREATE THE FILE).
    # FULL InvalidToken / CORRUPTION HANDLING IS EXPANDED IN STAGE 4.
    if not os.path.exists(DATA_FILE):
        vault = {}
        save_vault(vault, key)
        return vault

    with open(DATA_FILE, "rb") as f:
        token = f.read()

    fernet = Fernet(key)
    plaintext = fernet.decrypt(token)
    return json.loads(plaintext.decode("utf-8"))


# ---------------------------------------------------------------------------
# REGISTER / LOGIN
# ---------------------------------------------------------------------------

def register():
    # FIRST-RUN SETUP: MASTER PASSWORD, SALTS, AUTH HASH, EMPTY ENCRYPTED VAULT.
    #
    # WHY CONFIRM TWICE: TYPOS ON A MASTER PASSWORD WOULD LOCK THE USER OUT
    # FOREVER, BECAUSE WE CANNOT RECOVER AN ENCRYPTED VAULT WITHOUT THE PASSWORD.
    print("First time setup")
    print("Pick a master password (at least 8 characters).")
    print("You'll need this every time you open the vault.")

    while True:
        # WHY getpass: THE PASSWORD IS NOT ECHOED TO THE SCREEN (SHOULDER-SURFING).
        password = getpass.getpass("Master password: ")
        confirm = getpass.getpass("Confirm it: ")

        if password != confirm:
            print("Those didn't match, try again.")
            continue

        if len(password) < 8:
            print("Too short — needs to be at least 8 characters.")
            continue

        break

    # TWO DIFFERENT SALTS FOR TWO DIFFERENT JOBS (AUTH VS ENCRYPTION KEY).
    auth_salt = generate_salt()
    kdf_salt = generate_salt()

    auth_hash = hash_password(password, auth_salt)
    save_config(auth_salt, auth_hash, kdf_salt)

    # CREATE AN EMPTY ENCRYPTED VAULT NOW (STAGE 2).
    # KEY EXISTS ONLY IN MEMORY HERE — WE DO NOT WRITE IT ANYWHERE.
    key = derive_key(password, kdf_salt)
    save_vault({}, key)

    print("Done. Saved config.json and an empty data.enc.")
    return True


def login():
    # ASK FOR THE MASTER PASSWORD (UP TO 3 TRIES) AND VERIFY AGAINST auth_hash.
    # ON SUCCESS: RETURN THE MASTER PASSWORD STRING (NEEDED TO DERIVE THE KEY).
    # ON FAILURE: RETURN None.
    #
    # WHY RETURN THE PASSWORD ONLY AFTER A MATCHING HASH:
    #   CALLERS MUST NOT DERIVE THE KEY OR OPEN data.enc ON A WRONG PASSWORD.
    #   WE STOP BEFORE KEY DERIVATION WHEN VERIFICATION FAILS.
    config = load_config()
    if config is None:
        print("No config.json found — run setup first.")
        return None

    auth_salt, auth_hash, _kdf_salt = config

    print("Login")
    for attempt in range(1, MAX_LOGIN_ATTEMPTS + 1):
        password = getpass.getpass(
            f"Master password (attempt {attempt}/{MAX_LOGIN_ATTEMPTS}): "
        )

        attempt_hash = hash_password(password, auth_salt)

        # WHY hmac.compare_digest, NEVER == :
        #   == CAN SHORT-CIRCUIT AND LEAK TIMING INFO ABOUT HOW MANY BYTES
        #   MATCHED. compare_digest IS CONSTANT-TIME FOR EQUAL-LENGTH DIGESTS.
        if hmac.compare_digest(attempt_hash, auth_hash):
            print("You're in.")
            return password

        print("Wrong password.")

    print("Too many tries. Exiting.")
    return None


# ---------------------------------------------------------------------------
# ENTRY POINT (STAGE 2: AUTH + VAULT OPEN/CLOSE DEMO)
# ---------------------------------------------------------------------------

def main():
    # STAGE 2 FLOW:
    #   - NO config.json -> register() (ALSO CREATES EMPTY data.enc)
    #   - ELSE          -> login()
    #   - ONLY AFTER LOGIN SUCCEEDS: derive_key() THEN load_vault()
    #
    # MENU (ADD/VIEW/LIST/DELETE) COMES IN STAGE 3.
    if not os.path.exists(CONFIG_FILE):
        register()
        print()

    password = login()
    if password is None:
        return

    # AUTH PASSED — NOW IT IS SAFE TO DERIVE THE KEY AND TOUCH THE VAULT.
    config = load_config()
    _auth_salt, _auth_hash, kdf_salt = config
    key = derive_key(password, kdf_salt)
    vault = load_vault(key)

    # STAGE 2 SMOKE-CHECK: SHOW COUNT ONLY — NEVER PRINT SECRETS OR THE KEY.
    print(f"Vault unlocked ({len(vault)} entries).")


if __name__ == "__main__":
    main()
