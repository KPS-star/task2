import argparse
import json
import os
import base64
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VAULT_FILE = "vault.json"


# -------- KEY DERIVATION --------
def derive_key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    return kdf.derive(master_password.encode())


# -------- ENCRYPT --------
def encrypt_data(key, data):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, json.dumps(data).encode(), None)
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }


# -------- DECRYPT --------
def decrypt_data(key, enc_data):
    aesgcm = AESGCM(key)
    nonce = base64.b64decode(enc_data["nonce"])
    ciphertext = base64.b64decode(enc_data["ciphertext"])
    data = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(data.decode())


# -------- LOAD VAULT --------
def load_vault(master_password):
    if not os.path.exists(VAULT_FILE):
        salt = os.urandom(16)
        return {"salt": base64.b64encode(salt).decode(), "entries": {}}

    with open(VAULT_FILE, "r") as f:
        return json.load(f)


# -------- SAVE VAULT --------
def save_vault(vault):
    with open(VAULT_FILE, "w") as f:
        json.dump(vault, f, indent=4)


# -------- ADD PASSWORD --------
def add_entry(master_password):
    vault = load_vault(master_password)
    salt = base64.b64decode(vault["salt"])
    key = derive_key(master_password, salt)

    site = input("Website: ")
    username = input("Username: ")
    password = getpass.getpass("Password: ")

    encrypted = encrypt_data(key, {
        "username": username,
        "password": password
    })

    vault["entries"][site] = encrypted
    save_vault(vault)
    print("✅ Password saved")


# -------- GET PASSWORD --------
def get_entry(master_password):
    vault = load_vault(master_password)
    salt = base64.b64decode(vault["salt"])
    key = derive_key(master_password, salt)

    site = input("Website: ")
    if site not in vault["entries"]:
        print("❌ No entry found")
        return

    data = decrypt_data(key, vault["entries"][site])
    print("Username:", data["username"])
    print("Password:", data["password"])


# -------- LIST SITES --------
def list_entries(master_password):
    vault = load_vault(master_password)
    print("📌 Stored Websites:")
    for site in vault["entries"]:
        print("-", site)


# -------- MAIN --------
parser = argparse.ArgumentParser(description="Simple Password Manager")
sub = parser.add_subparsers(dest="command")

sub.add_parser("add")
sub.add_parser("get")
sub.add_parser("list")

args = parser.parse_args()
master = getpass.getpass("Master Password: ")

if args.command == "add":
    add_entry(master)
elif args.command == "get":
    get_entry(master)
elif args.command == "list":
    list_entries(master)
else:
    print("Use: add | get | list")