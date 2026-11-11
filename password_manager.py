# BASIC COMMAND-LINE PASSWORD MANAGER (COLLEGE LEARNING PROJECT)

# STAGE 1: MASTER-PASSWORD AUTHENTICATION (HASH + VERIFY)
# STAGE 2: SEPARATE ENCRYPTION KEY + ENCRYPTED VAULT (data.enc)
# STAGE 3: MENU SHELL (1-5) — ENTRY FUNCTIONS ADDED LATER

import base64
import getpass
import hashlib
import hmac
import json
import os

from cryptography.fernet import Fernet

CONFIG_FILE = "config.json"
DATA_FILE = "data.enc"

PBKDF2_ITERATIONS = 600_000 # 600_000 ITERATIONS (BRIEF)
SALT_SIZE = 16 # 128 BITS FOR SALTS
HASH_ALGORITHM = "sha256" # SHA-256 STRONG GOOD HASH USED INSIDE PBKDF2
KEY_SIZE = 32 # FERNET NEEDS A 256-BIT KEY
MAX_LOGIN_ATTEMPTS = 3 # MAX LOGIN ATTEMPTS BEFORE CLOSE


### SALT HELPER FUNCTIONS

# RETURN 16 RANDOM BYTES FOR THE SALT
def generate_salt():
    return os.urandom(SALT_SIZE)


# HASHES THE PASSWORD WITH PBKDF2-HMAC-SHA256 AND THE SALT
# RETURNS RAW BYTES
def hash_password(password, salt):
    password_bytes = password.encode("utf-8")
    return hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password_bytes,
        salt,
        PBKDF2_ITERATIONS,
    )


# Fernet ENCRYPTION KEY FROM THE MASTER PASSWORD + kdf_salt
# RETURNS URL-SAFE BASE64-ENCODED 32-BYTE KEY
def derive_key(password, kdf_salt):
    key_bytes = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password.encode("utf-8"),
        kdf_salt,
        PBKDF2_ITERATIONS,
        dklen=KEY_SIZE,
    )
    # Fernet REQUIRES THE KEY AS URL-SAFE BASE64 OF EXACTLY 32 RAW BYTES
    return base64.urlsafe_b64encode(key_bytes)


### INPUT AND OUTPUT CONFIG FILE

# WRITE THE SALTS AND AUTH HASH TO config.json AS HEX STRINGS
def save_config(auth_salt, auth_hash, kdf_salt):
    data = {
        "auth_salt": auth_salt.hex(),
        "auth_hash": auth_hash.hex(),
        "kdf_salt": kdf_salt.hex(),
    }
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


# LOAD config.json AND RETURN THE (auth_salt, auth_hash, kdf_salt) AS BYTES
# IF FIRST RUN CASE IT WILL RETURN NONE BECAUSE THE FILE IS MISSING
def load_config():
    if not os.path.exists(CONFIG_FILE):
        return None

    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    return (
        bytes.fromhex(data["auth_salt"]),
        bytes.fromhex(data["auth_hash"]),
        bytes.fromhex(data["kdf_salt"]),
    )


### VAULT INPUT OUTPUT
# data.enc HOLDS THE WHOLE VAULT AS ONE Fernet CIPHERTEXT
# EVERY ADD OR DELETE WILL RE-ENCRYPT AND OVERWRITE data.enc TOODOO!!!!!!
def save_vault(vault, key):
    fernet = Fernet(key)
    plaintext = json.dumps(vault).encode("utf-8") # DICT -> TEXT -> BYTES
    token = fernet.encrypt(plaintext)
    with open(DATA_FILE, "wb") as f:
        f.write(token)


# DECRYPT data.enc AND RETURN THE VAULT AS A DICT
# IF data.enc IS MISSING IT CREATES AN EMPTY VAULT FILE
def load_vault(key):
    if not os.path.exists(DATA_FILE):
        vault = {}
        save_vault(vault, key)
        return vault

    with open(DATA_FILE, "rb") as f:
        token = f.read()

    fernet = Fernet(key)
    plaintext = fernet.decrypt(token)
    return json.loads(plaintext.decode("utf-8"))


### REGISTER / LOGIN

# FIRST RUN: MASTER PASSWORD SALTS AUTH HASH EMPTY ENCRYPTED VAULT
def register():
    print("First time setup")
    print("Pick a master password (at least 8 characters).")
    password = getpass.getpass("Master password: ")
    getpass.getpass("Confirm password: ")
    auth_salt = generate_salt()
    kdf_salt = generate_salt()
    auth_hash = hash_password(password, auth_salt)
    save_config(auth_salt, auth_hash, kdf_salt)

    # EMPTY VAULT CREATED
    key = derive_key(password, kdf_salt)
    save_vault({}, key)

    print("Done. Saved config.json and an empty data.enc.")
    return True


# UP TO 3 TRIES
# ON SUCCESS RETURN THE MASTER PASSWORD
# ON FAILURE RETURN None
# DO NOT DERIVE THE KEY OR TOUCH data.enc UNTIL AUTH PASSES
def login():
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

        # WHY hmac.compare_digest NOT == : AVOIDS TIMING LEAKS
        if hmac.compare_digest(attempt_hash, auth_hash):
            print("You're in.")
            return password

        print("Wrong password.")

    print("Too many tries. Exiting.")
    return None


### MENU STAGE 3 TOODOO!!!!!!

# MENU AFTER LOGIN: 1 ADD  2 VIEW  3 LIST  4 DELETE  5 EXIT
def main_menu():
    while True:
        print()
        print("1. Add entry")
        print("2. View entry")
        print("3. List sites")
        print("4. Delete entry")
        print("5. Exit")
        choice = input("Choice (1-5): ").strip()

        if choice == "5":
            print("Bye.")
            break


### MAIN FLOW

# NO config.json -> register()
# ELSE -> login()
# ONLY AFTER LOGIN: derive_key() THEN load_vault() THEN main_menu()
def main():
    if not os.path.exists(CONFIG_FILE):
        register()
        print()

    password = login()
    if password is None:
        return

    # AUTH PASSED SAFE TO GET THE KEY AND OPEN THE VAULT
    config = load_config()
    _auth_salt, _auth_hash, kdf_salt = config
    key = derive_key(password, kdf_salt)
    vault = load_vault(key)

    print(f"Vault unlocked ({len(vault)} entries).")
    main_menu()


if __name__ == "__main__":
    main()
