import os
import json
import stripe
from replit import db
from cryptography.fernet import Fernet

def get_fernet():
    config_key = os.environ.get("CONFIG_KEY")
    if not config_key:
        raise Exception("CONFIG_KEY environment variable is not set.")
    return Fernet(config_key.encode())

def clear_user_data():
    user_record_raw = db.get("user_record")
    if user_record_raw:
        try:
            f = get_fernet()
            encrypted_bytes = user_record_raw.encode("utf-8")
            user_record = json.loads(f.decrypt(encrypted_bytes).decode("utf-8"))
        except Exception as e:
            print("Error decrypting user record. It may be corrupted or already cleared:", e)
            user_record = {}

        webhook = user_record.get("stripe_webhook")
        if webhook and isinstance(webhook, dict):
            webhook_id = webhook.get("id")
            if webhook_id:
                stripe.api_key = user_record.get("stripe_api_key", os.environ.get("STRIPE_API_KEY", ""))
                try:
                    stripe.WebhookEndpoint.delete(webhook_id)
                    print(f"Confirmation: Deleted Stripe webhook: {webhook_id}")
                except Exception as e:
                    print(f"Error deleting Stripe webhook {webhook_id}: {e}")
            else:
                print("No webhook ID found in the user record.")
        else:
            print("No Stripe webhook found in the user record.")

        del db["user_record"]
        print("User record deleted from the database.")
    else:
        print("No user record found.")

if __name__ == "__main__":
    clear_user_data()
