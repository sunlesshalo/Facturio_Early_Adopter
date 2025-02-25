import os
import json
from replit import db
from cryptography.fernet import Fernet

print("CONFIG_KEY:", os.environ.get("CONFIG_KEY"))


def get_fernet():
    config_key = os.environ.get("CONFIG_KEY")
    if not config_key:
        raise Exception("CONFIG_KEY environment variable is not set.")
    return Fernet(config_key.encode())

def decrypt_data(encrypted_data):
    f = get_fernet()
    plaintext = f.decrypt(encrypted_data)
    return json.loads(plaintext.decode("utf-8"))

# Decrypt and print the user record
user_record_raw = db.get("user_record")
if user_record_raw:
    try:
        decrypted_record = decrypt_data(user_record_raw.encode("utf-8"))
        print("User Record:")
        print(json.dumps(decrypted_record, indent=2, ensure_ascii=False))
    except Exception as e:
        print("Eroare la decriptarea user record:", e)
else:
    print("Nu a fost găsit user record.")

# Decrypt and print the credentials record
credentials_raw = db.get("credentials")
if credentials_raw:
    try:
        decrypted_credentials = decrypt_data(credentials_raw.encode("utf-8"))
        print("\nCredential Record:")
        print(json.dumps(decrypted_credentials, indent=2, ensure_ascii=False))
    except Exception as e:
        print("Eroare la decriptarea credentialelor:", e)
else:
    print("\nNu au fost găsite credentiale.")

# Retrieve and print the invoices
invoices_raw = db.get("invoices")
if invoices_raw:
    try:
        invoices = json.loads(invoices_raw)
        print("\nFacturi înregistrate:")
        print(json.dumps(invoices, indent=2, ensure_ascii=False))
    except Exception as e:
        print("Eroare la parsarea facturilor:", e)
else:
    print("Nu au fost găsite facturi.")
