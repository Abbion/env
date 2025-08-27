import os
import sys
import hashlib
import getpass
import json
import base64
import argparse
import pyperclip
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

G_authenticated = False
G_session_password = None
MASTER_PASSWORD_HASH = None
ENCRIPTION_LENGTH = None
SALT_LENGTH = None
NONCE_LENGTH = None
RETURN_TO_MENU_INFO_TEXT = "Press Enter to return to menu..."
VAULT_PATH = "vault.json"

def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()

def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())

def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=ENCRIPTION_LENGTH,
        salt=salt,
        iterations=200_000,
    )

    return kdf.derive(master_password.encode())

def encrypt_password(plain_text: str, master_password: str) -> dict:
    salt = os.urandom(SALT_LENGTH)
    key = derive_key(master_password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_LENGTH)
    ciphertext = aesgcm.encrypt(nonce, plain_text.encode(), None)

    return {
        "salt": _b64e(salt),
        "nonce": _b64e(nonce),
        "ct": _b64e(ciphertext),
    }

def decrypt_password(bundle: dict, master_password: str) -> str:
    key = derive_key(master_password, _b64d(bundle["salt"]))
    aesgcm = AESGCM(key)
    plain = aesgcm.decrypt(_b64d(bundle["nonce"]), _b64d(bundle["ct"]), None)
    return plain.decode()

def store_credentials(account: str, bundle: dict):
    data = {}

    if os.path.exists(VAULT_PATH):
        with open(VAULT_PATH, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = {}

    data[account] = bundle

    with open(VAULT_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def load_credentials(account: str) -> dict | None:
    data = {}

    if not os.path.exists(VAULT_PATH):
        return None
    try:
        with open(VAULT_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        return None
    
    return data.get(account)

def remove_credentials(account: str):
    data = {}

    if os.path.exists(VAULT_PATH):
        with open(VAULT_PATH, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = {}

    if account in data:
        del data[account]

    with open(VAULT_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def load_configuration():
    global MASTER_PASSWORD_HASH, ENCRIPTION_LENGTH, SALT_LENGTH, NONCE_LENGTH

    with open('config.json', 'r') as file: 
        config_data = json.load(file)
        MASTER_PASSWORD_HASH = config_data['config']['master_password_hash']
        ENCRIPTION_LENGTH = int(config_data['config']['encription_length'])
        SALT_LENGTH = int(config_data['config']['salt_lenth'])
        NONCE_LENGTH = int(config_data['config']['nonce'])

def check_master_password():
    global G_authenticated, G_session_password
    
    if G_authenticated:
        return True

    password = getpass.getpass("Enter master password: ")
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    if password_hash == MASTER_PASSWORD_HASH:
        print("Access granted")
        G_authenticated = True
        G_session_password = password
        return True
    else:
        print("Access denied")
        return False

def get_accounts() -> list | None:
    if not os.path.exists(VAULT_PATH):
        print("No stored accounts yet")
        input(RETURN_TO_MENU_INFO_TEXT)
        return

    data = []

    with open(VAULT_PATH, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            print("Vault file is corrupted")
            input(RETURN_TO_MENU_INFO_TEXT)
            return

    return list(data.keys())

def save_new_password():
    clear_screen()

    if not check_master_password():
        input(RETURN_TO_MENU_INFO_TEXT)
        return

    account_name = input("Account / service name: ").strip()
    if not account_name:
        print("Account name cannot be empty")
        input(RETURN_TO_MENU_INFO_TEXT)
        return

    saved_accounts = get_accounts()

    if account_name in saved_accounts:
        print("Account alread has a password")
        input(RETURN_TO_MENU_INFO_TEXT)
        return

    account_password = getpass.getpass(f"Password for '{account_name}': ")
    bundle = encrypt_password(account_password, G_session_password)
    store_credentials(account_name, bundle)

    print("Password saved")

    input(RETURN_TO_MENU_INFO_TEXT)

def get_password():
    clear_screen()

    if not check_master_password():
        input(RETURN_TO_MENU_INFO_TEXT)
        return

    saved_accounts = get_accounts()

    if saved_accounts == None:
        print("No account list found")
        input(RETURN_TO_MENU_INFO_TEXT)
        return

    print("\n=== Stored Accounts ===")
    for i, acc in enumerate(saved_accounts, start=1):
        print(f"[{i}] {acc}")

    num_of_accounts = len(saved_accounts)
    selected_account = input(f"Choose account from [1] to [{num_of_accounts}]: ")

    if not selected_account.isnumeric():
        print("Input was not a number")
        input(RETURN_TO_MENU_INFO_TEXT)
        return

    selected_account = int(selected_account)

    if selected_account > num_of_accounts or selected_account < 1:
        print("Selected acount is not a number or the number is out of bounds\n")
        input(RETURN_TO_MENU_INFO_TEXT)
        return

    selected_account_name = saved_accounts[selected_account - 1]
    bundle = load_credentials(selected_account_name)

    if bundle == None:
        print(f"Credentials for {selected_account_name} were not found")
        input(RETURN_TO_MENU_INFO_TEXT)

    selected_account_password = decrypt_password(bundle, G_session_password)

    pyperclip.copy(selected_account_password)
    print("Password copied to clipboard")

    input(RETURN_TO_MENU_INFO_TEXT)

def remove_password():
    clear_screen()
    print("REMOVING ACCOUNT!")

    if not check_master_password():
        input(RETURN_TO_MENU_INFO_TEXT)
        return

    saved_accounts = get_accounts()

    if saved_accounts == None:
        print("No account list found")
        input(RETURN_TO_MENU_INFO_TEXT)
        return
    
    account_name = input("Account / service name: ").strip()

    if account_name not in saved_accounts:
        print("Account not found")
        input(RETURN_TO_MENU_INFO_TEXT)
        return

    confirmation = input(f"Are you sure you want to REMOVE { account_name } password? [Y/N]: ")

    if confirmation.lower() == "y":
        remove_credentials(account_name)

def main():
    load_configuration()

    while True:
        clear_screen()
        print("\n=== Password Manager ===")
        print("1. Save new password")
        print("2. Get password")
        print("3. Remove account")
        print("4. Exit")

        menu_option = input("Choose an option [1-4]: ").strip()

        if menu_option == "1":
            save_new_password()
        elif menu_option == "2":
            get_password()
        elif menu_option == "3":
            remove_password()
        elif menu_option == "4":
            print("Exiting...")
            sys.exit(0)
        else:
            print("Invalid option, please try again")
    
if __name__ == "__main__":
    main()