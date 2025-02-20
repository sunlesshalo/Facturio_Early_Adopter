from replit import db

# Remove the user record if it exists.
if "user_record" in db:
    del db["user_record"]

# Optionally, clear other related keys, such as the Stripe webhook.
if "stripe_webhook" in db:
    del db["stripe_webhook"]

