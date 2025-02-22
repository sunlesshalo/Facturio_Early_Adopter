import os
import json
import stripe
from replit import db

def clear_user_data():
    # Retrieve the user record from the DB.
    user_record_raw = db.get("user_record")
    if user_record_raw:
        # Load the record from JSON if it's stored as a string.
        user_record = json.loads(user_record_raw) if isinstance(user_record_raw, str) else user_record_raw

        # Delete Stripe test webhook if it exists.
        if "stripe_test_webhook" in user_record:
            test_webhook = user_record["stripe_test_webhook"]
            webhook_id = test_webhook.get("id")
            if webhook_id:
                # Set API key to the stored test key or fallback to env variable.
                stripe.api_key = user_record.get("stripe_test_api_key", os.environ.get("STRIPE_TEST_API_KEY", ""))
                try:
                    stripe.WebhookEndpoint.delete(webhook_id)
                    print(f"Deleted Stripe test webhook: {webhook_id}")
                except Exception as e:
                    print(f"Error deleting Stripe test webhook {webhook_id}: {e}")

        # Delete Stripe live webhook if it exists.
        if "stripe_live_webhook" in user_record:
            live_webhook = user_record["stripe_live_webhook"]
            webhook_id = live_webhook.get("id")
            if webhook_id:
                # Set API key to the stored live key or fallback to env variable.
                stripe.api_key = user_record.get("stripe_live_api_key", os.environ.get("STRIPE_LIVE_API_KEY", ""))
                try:
                    stripe.WebhookEndpoint.delete(webhook_id)
                    print(f"Deleted Stripe live webhook: {webhook_id}")
                except Exception as e:
                    print(f"Error deleting Stripe live webhook {webhook_id}: {e}")

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
