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
    # Retrieve the encrypted user record from the DB.
    user_record_raw = db.get("user_record")
    if user_record_raw:
        try:
            # Decrypt the record
            f = get_fernet()
            encrypted_bytes = user_record_raw.encode("utf-8")
            user_record = json.loads(f.decrypt(encrypted_bytes).decode("utf-8"))
        except Exception as e:
            print("Error decrypting user record. It may be corrupted or already cleared:", e)
            # In case decryption fails, we can't safely extract webhook info.
            user_record = {}

        # Delete Stripe test webhook if it exists.
        test_webhook = user_record.get("stripe_test_webhook")
        if test_webhook and isinstance(test_webhook, dict):
            webhook_id = test_webhook.get("id")
            if webhook_id:
                # Set API key to the stored test key or fallback to env variable.
                stripe.api_key = user_record.get("stripe_test_api_key", os.environ.get("STRIPE_TEST_API_KEY", ""))
                try:
                    stripe.WebhookEndpoint.delete(webhook_id)
                    print(f"Confirmation: Deleted Stripe test webhook: {webhook_id}")
                except Exception as e:
                    print(f"Error deleting Stripe test webhook {webhook_id}: {e}")
            else:
                print("No test webhook ID found in the user record.")
        else:
            print("No Stripe test webhook found in the user record.")

        # Delete Stripe live webhook if it exists.
        live_webhook = user_record.get("stripe_live_webhook")
        if live_webhook and isinstance(live_webhook, dict):
            webhook_id = live_webhook.get("id")
            if webhook_id:
                stripe.api_key = user_record.get("stripe_live_api_key", os.environ.get("STRIPE_LIVE_API_KEY", ""))
                try:
                    stripe.WebhookEndpoint.delete(webhook_id)
                    print(f"Confirmation: Deleted Stripe live webhook: {webhook_id}")
                except Exception as e:
                    print(f"Error deleting Stripe live webhook {webhook_id}: {e}")
            else:
                print("No live webhook ID found in the user record.")
        else:
            print("No Stripe live webhook found in the user record.")

        # Remove the user record from the database.
        del db["user_record"]
        print("User record deleted from the database.")
    else:
        print("No user record found.")

    # Optionally, clear other related keys (e.g., legacy Stripe webhook key)
    if "stripe_webhook" in db:
        del db["stripe_webhook"]
        print("Stripe webhook key deleted from the database.")

# Example usage:
if __name__ == "__main__":
    clear_user_data()
