from cryptography.fernet import Fernet
import secrets

# Generate a new master key (Fernet key is URL-safe base64-encoded 32 bytes)
master_key = Fernet.generate_key()
print(f"CONFIG_KEY: {master_key.decode()}")  # Save this key securely!
print(f"FLASK_SECRET_KEY: {Fernet.generate_key().decode()}")


csrf_token = secrets.token_urlsafe(64)
print(f"WTF_CSRF_SECRET_KEY: {csrf_token}")