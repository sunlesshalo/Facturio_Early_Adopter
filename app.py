"""
Consolidated Facturio Application
-----------------------------------
This file merges all functionalities from the original onboarding and Facturio.app files.
It gathers and stores the following user-provided values during onboarding:
  - SmartBill email
  - SmartBill token
  - Tax code ("cif")
  - Default invoice series
  - Stripe API keys (test and live)
  - Stripe webhook secrets (created for both keys)
  - App secret key

These values are stored in a unified user record (encrypted and stored in Replit DB under the key "user_record")
and the credentials (encrypted and stored under the key "credentials")
and are used in all subsequent API calls.
"""

import os
import base64
import logging
import requests
import json
import stripe
import bcrypt
from cryptography.fernet import Fernet

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from replit import db  # Replit's built-in simple database

from config import config_defaults

from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required

# ----------------------------------------------------------------------
# Encryption Helper Functions
# ----------------------------------------------------------------------
def get_fernet():
    config_key = os.environ.get("CONFIG_KEY")
    if not config_key:
        raise Exception("CONFIG_KEY environment variable is not set.")
    return Fernet(config_key.encode())

def encrypt_data(data_dict):
    f = get_fernet()
    plaintext = json.dumps(data_dict).encode("utf-8")
    encrypted = f.encrypt(plaintext)
    return encrypted

def decrypt_data(encrypted_data):
    f = get_fernet()
    plaintext = f.decrypt(encrypted_data)
    return json.loads(plaintext.decode("utf-8"))

def set_user_record(data):
    """
    Encrypts the user record and stores it in Replit DB under the key "user_record".
    """
    try:
        encrypted = encrypt_data(data)
        db["user_record"] = encrypted.decode("utf-8")
    except Exception as e:
        logger.error("Error encrypting and storing user record: %s", e)
        raise

def get_user_record():
    """
    Retrieves and decrypts the user record from Replit DB.
    Returns None if not found.
    """
    try:
        encrypted_raw = db.get("user_record")
    except Exception as e:
        logger.info("user_record key not found in DB (exception caught): %s", e)
        return None

    if not encrypted_raw:
        logger.info("user_record key not found in Replit DB. Onboarding might be incomplete.")
        return None

    try:
        encrypted_bytes = encrypted_raw.encode("utf-8")
        return decrypt_data(encrypted_bytes)
    except Exception as e:
        logger.error("Error decrypting user record: %s", e)
        return None

def set_credentials(data):
    """
    Encrypts and stores the credentials in Replit DB under the key "credentials".
    """
    try:
        encrypted = encrypt_data(data)
        db["credentials"] = encrypted.decode("utf-8")
    except Exception as e:
        logger.error("Error encrypting and storing credentials: %s", e)
        raise

def get_credentials():
    """
    Retrieves and decrypts the credentials from Replit DB.
    Returns None if not found.
    """
    try:
        encrypted_raw = db.get("credentials")
    except Exception as e:
        logger.info("credentials key not found in DB (exception caught): %s", e)
        return None

    if not encrypted_raw:
        logger.info("credentials key not found in Replit DB. Onboarding might be incomplete.")
        return None

    try:
        encrypted_bytes = encrypted_raw.encode("utf-8")
        return decrypt_data(encrypted_bytes)
    except Exception as e:
        logger.error("Error decrypting credentials: %s", e)
        return None

# ----------------------------------------------------------------------
# Password Helper Functions
# ----------------------------------------------------------------------
def hash_password(plain_password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(plain_password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def check_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

# ----------------------------------------------------------------------
# Configuration and Global Constants
# ----------------------------------------------------------------------
CUSTOM_INSTANCE_URL = os.environ.get("CUSTOM_INSTANCE_URL", "https://your-instance-url")

# ----------------------------------------------------------------------
# Logging Configuration
# ----------------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------
# Create Flask App and Setup Flask-Login
# ----------------------------------------------------------------------
app = Flask(__name__)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, user_record):
        self.id = id
        self.user_record = user_record

    def get_id(self):
        return self.id

@login_manager.user_loader
def load_user(user_id):
    user_record = get_user_record()
    if user_record and user_record.get("smartbill_email") == user_id:
        return User(user_id, user_record)
    return None

app.secret_key = os.environ.get("FLASK_SECRET_KEY", "default_secret_key")

# Fixed parameters for SmartBill API calls
SMARTBILL_BASE_URL = "https://ws.smartbill.ro/SBORO/api/"
SMARTBILL_SERIES_TYPE = "f"

# ----------------------------------------------------------------------
# Helper Function for SmartBill Auth Header
# ----------------------------------------------------------------------
def get_smartbill_auth_header(username, token):
    auth_string = f"{username}:{token}"
    encoded_auth = base64.b64encode(auth_string.encode("utf-8")).decode("utf-8")
    header = {"Authorization": f"Basic {encoded_auth}"}
    logger.debug("Constructed Auth Header: %s", header)
    return header

# ----------------------------------------------------------------------
# Consolidated Root Endpoint
# ----------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    if not db.get("user_record"):
        return render_template("index.html")
    if session.get("user_email"):
        return redirect(url_for("dashboard"))
    return "Welcome to Facturio's Stripe-SmartBill Integration Service. Please log in at /login."

# ----------------------------------------------------------------------
# Onboarding Endpoint for HTML Form Submission (Handles Credentials)
# ----------------------------------------------------------------------
@app.route("/onboarding", methods=["GET", "POST"])
def onboarding():
    if request.method == "POST":
        smartbill_email = request.form.get("smartbill_email", "").strip()
        smartbill_token = request.form.get("smartbill_token", "").strip()
        cif = request.form.get("cif", "").strip()  # renamed field
        default_series = request.form.get("default_series", "").strip()
        stripe_test_api_key = request.form.get("stripe_test_api_key", "").strip()
        stripe_live_api_key = request.form.get("stripe_live_api_key", "").strip()
        password = request.form.get("password", "").strip()  # Although provided, we ignore it

        if not (smartbill_email and smartbill_token and cif and default_series and stripe_test_api_key and stripe_live_api_key):
            flash("Toate câmpurile sunt obligatorii.")
            logger.error("Onboarding failed: Missing required fields.")
            return redirect(url_for("onboarding"))

        # Instead of using the provided password, set the initial password to "factur10"
        initial_password = "factur10"
        password_hash = hash_password(initial_password)

        # Build and encrypt the credentials dictionary
        credentials = {
            "smartbill_email": smartbill_email,
            "password_hash": password_hash
        }
        set_credentials(credentials)
        logger.debug("Stored encrypted credentials.")

        # Build the user record (integration settings) and encrypt it
        user_record = {
            "smartbill_email": smartbill_email,
            "smartbill_token": smartbill_token,
            "cif": cif,
            "default_series": default_series,
            "stripe_test_api_key": stripe_test_api_key,
            "stripe_live_api_key": stripe_live_api_key
        }
        set_user_record(user_record)
        logger.debug("Stored encrypted user record.")

        # Verify that data was stored successfully by attempting to retrieve them
        if get_user_record() is None or get_credentials() is None:
            logger.error("Failed to store user_record or credentials in Replit DB.")
            flash("Eroare la salvarea datelor. Vă rugăm încercați din nou.")
            return redirect(url_for("onboarding"))
        else:
            logger.info("User record and credentials successfully stored in Replit DB.")

        flash("Onboarding completat cu succes! Parola inițială este 'factur10'. Vă rugăm să o schimbați după logare.")
        return redirect(url_for("dashboard"))

    return render_template("onboarding.html")

@app.route("/dashboard")
@login_required
def dashboard():
    user_record = get_user_record()
    if not user_record:
        flash("Vă rugăm să vă logați și să completați onboarding-ul.")
        logger.error("Dashboard access failed: user_record missing or failed to decrypt.")
        return redirect(url_for("login"))
    return render_template(
        "dashboard.html",
        smartbill_email=user_record.get("smartbill_email", "N/A"),
        cif=user_record.get("cif", "N/A"),
        default_series=user_record.get("default_series", "N/A"),
        smartbill_token=user_record.get("smartbill_token", ""),
        stripe_test_api_key=user_record.get("stripe_test_api_key", ""),
        stripe_live_api_key=user_record.get("stripe_live_api_key", "")
    )


# ----------------------------------------------------------------------
# API Endpoints
# ----------------------------------------------------------------------
@app.route("/api/get_series", methods=["POST"])
def api_get_series():
    data = request.get_json()
    smartbill_email = data.get("smartbill_email", "").strip()
    smartbill_token = data.get("smartbill_token", "").strip()
    cif = data.get("cif", "").strip()

    if not (smartbill_email and smartbill_token and cif):
        logger.warning("Missing required fields in JSON payload.")
        return jsonify({"status": "error", "message": "Toate câmpurile sunt obligatorii"}), 400

    series_url = f"{SMARTBILL_BASE_URL}series"
    headers = {"Content-Type": "application/json"}
    headers.update(get_smartbill_auth_header(smartbill_email, smartbill_token))
    params = {"cif": cif, "type": SMARTBILL_SERIES_TYPE}

    try:
        response = requests.get(series_url, headers=headers, params=params)
        response.raise_for_status()
        resp_data = response.json()
    except requests.exceptions.HTTPError as errh:
        logger.error("HTTP Error: %s", errh)
        return jsonify({"status": "error", "message": f"Eroare HTTP: {errh}"}), response.status_code if response else 500
    except requests.exceptions.RequestException as err:
        logger.error("Request Exception: %s", err)
        return jsonify({"status": "error", "message": f"Eroare de conexiune: {err}"}), 500
    except ValueError as errv:
        logger.error("JSON parsing error: %s", errv)
        return jsonify({"status": "error", "message": "Răspuns invalid din partea SmartBill"}), 500

    series_list = resp_data.get("list", [])
    if not series_list:
        logger.warning("No invoice series found in response.")
        return jsonify({"status": "error", "message": "Nu s-au găsit serii de facturare."}), 404

    return jsonify({"status": "success", "series_list": series_list}), 200

@app.route("/api/set_default_series", methods=["POST"])
def api_set_default_series():
    data = request.get_json()
    smartbill_email = data.get("smartbill_email", "").strip()
    smartbill_token = data.get("smartbill_token", "").strip()
    cif = data.get("cif", "").strip()
    default_series = data.get("default_series", "").strip()
    stripe_api_key = data.get("stripe_api_key", "").strip()
    stripe_webhook_secret = data.get("stripe_webhook_secret", "").strip()

    if not (smartbill_email and smartbill_token and cif and default_series):
        return jsonify({"status": "error", "message": "Missing one or more required SmartBill fields"}), 400

    # Check if credentials exist; if not, create them.
    if not get_credentials():
        initial_password = "factur10"
        password_hash = hash_password(initial_password)
        credentials = {
            "smartbill_email": smartbill_email,
            "password_hash": password_hash
        }
        set_credentials(credentials)
        logger.debug("Stored encrypted credentials via API.")

    # Retrieve the existing user record (if any) and update it
    existing_record = get_user_record() or {}
    existing_record.update({
        "smartbill_email": smartbill_email,
        "smartbill_token": smartbill_token,
        "cif": cif,
        "default_series": default_series,
    })
    if stripe_api_key:
        existing_record["stripe_api_key"] = stripe_api_key
    if stripe_webhook_secret:
        existing_record["stripe_webhook_secret"] = stripe_webhook_secret

    set_user_record(existing_record)
    logger.info("User record updated (encrypted): %s", existing_record)

    return jsonify({"status": "success", "user_record": existing_record}), 200

@app.route("/api/stripe_create_webhooks", methods=["POST"])
def api_stripe_create_webhooks():
    data = request.get_json()
    stripe_test_key = data.get("stripe_test_key", "").strip()
    stripe_live_key = data.get("stripe_live_key", "").strip()
    if not stripe_test_key or not stripe_live_key:
        return jsonify({"status": "error", "message": "Both Stripe API keys are required"}), 400

    if not stripe_test_key.startswith("sk_test"):
        return jsonify({"status": "error", "message": "Test key must start with sk_test"}), 400
    if not (stripe_live_key.startswith("sk_live") or stripe_live_key.startswith("rk_live")):
        return jsonify({"status": "error", "message": "Live key must start with sk_live or rk_live"}), 400

    user_record = get_user_record()
    if not user_record:
        logger.error("User record not found. Cannot create Stripe webhooks.")
        return jsonify({"status": "error", "message": "Onboarding incomplete"}), 400

    if not CUSTOM_INSTANCE_URL:
        logger.error("CUSTOM_INSTANCE_URL not set.")
        return jsonify({"status": "error", "message": "CUSTOM_INSTANCE_URL not set"}), 500

    webhook_url = f"{CUSTOM_INSTANCE_URL.rstrip('/')}/stripe-webhook"

    # Create Test Webhook
    try:
        stripe.api_key = stripe_test_key
        webhook_test = stripe.WebhookEndpoint.create(
            enabled_events=["checkout.session.completed"],
            url=webhook_url,
            description="Facturio Early Adopter Program (Test)"
        )
        webhook_test_data = {
            "id": webhook_test.get("id"),
            "secret": webhook_test.get("secret"),
            "livemode": webhook_test.get("livemode")
        }
    except Exception as e:
        logger.error("Error creating test webhook: %s", e)
        return jsonify({"status": "error", "message": f"Error creating test webhook: {str(e)}"}), 500

    # Create Live Webhook
    try:
        stripe.api_key = stripe_live_key
        webhook_live = stripe.WebhookEndpoint.create(
            enabled_events=["checkout.session.completed"],
            url=webhook_url,
            description="Facturio Early Adopter Program (Live)"
        )
        webhook_live_data = {
            "id": webhook_live.get("id"),
            "secret": webhook_live.get("secret"),
            "livemode": webhook_live.get("livemode")
        }
    except Exception as e:
        logger.error("Error creating live webhook: %s", e)
        return jsonify({"status": "error", "message": f"Error creating live webhook: {str(e)}"}), 500

    user_record["stripe_test_api_key"] = stripe_test_key
    user_record["stripe_live_api_key"] = stripe_live_key
    user_record["stripe_test_webhook"] = webhook_test_data
    user_record["stripe_live_webhook"] = webhook_live_data
    set_user_record(user_record)
    logger.info("Stripe webhooks created and stored successfully.")
    return jsonify({"status": "success", "message": "Stripe webhooks created successfully"}), 200

# ----------------------------------------------------------------------
# Authentication, Login, Logout, and Change Password Endpoints
# ----------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        logger.debug("Attempting login for email: %s", email)

        credentials = get_credentials()
        logger.debug("Retrieved encrypted credentials from DB.")
        if not credentials:
            flash("Utilizatorul nu există. Vă rugăm să completați onboarding-ul.")
            logger.error("Login failed: Credentials not found in DB.")
            return redirect(url_for("login"))

        if email != credentials.get("smartbill_email"):
            flash("Utilizatorul nu există. Vă rugăm să completați onboarding-ul.")
            logger.error("Login failed: Email mismatch. Input: %s, Stored: %s", email, credentials.get("smartbill_email"))
            return redirect(url_for("login"))

        stored_hash = credentials.get("password_hash")
        if not stored_hash or not check_password(password, stored_hash):
            flash("Parola incorectă!")
            logger.error("Login failed: Incorrect password for email: %s", email)
            return redirect(url_for("login"))

        user_record = get_user_record() or {}
        user = User(email, user_record)
        login_user(user)
        session["user_email"] = email
        logger.info("User logged in successfully: %s", email)
        flash("Logare cu succes!")
        return redirect(url_for("dashboard"))

    return render_template("login.html")

@app.route("/logout")
def logout():
    logout_user()
    flash("Ați fost deconectat.")
    logger.info("User logged out.")
    return redirect(url_for("login"))

@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    credentials = get_credentials()
    logger.debug("Retrieved encrypted credentials for change_password.")
    if not credentials:
        flash("Vă rugăm să vă logați.")
        logger.error("Change password failed: No credentials found in DB.")
        return redirect(url_for("login"))
    if request.method == "POST":
        new_password = request.form.get("new_password", "").strip()
        if not new_password:
            flash("Vă rugăm să introduceți o parolă nouă.")
            logger.error("Change password failed: New password not provided.")
            return redirect(url_for("change_password"))
        new_hash = hash_password(new_password)
        credentials["password_hash"] = new_hash
        set_credentials(credentials)
        logger.debug("Updated encrypted credentials after password change.")
        flash("Parola a fost actualizată cu succes!")
        return redirect(url_for("dashboard"))

    return render_template("change_password.html")

# ----------------------------------------------------------------------
# Facturio Integration Endpoint (Stripe Webhook)
# ----------------------------------------------------------------------
from services.utils import build_payload
from services.smartbill import create_smartbill_invoice
from services.idempotency import is_event_processed, mark_event_processed, remove_event
from services.notifications import notify_admin
from services.email_sender import send_invoice_email

@app.route("/stripe-webhook", methods=["POST"])
def stripe_webhook():
    payload = request.get_data()
    sig_header = request.headers.get("Stripe-Signature")

    user_record = get_user_record()
    if not user_record:
        logger.error("User record not found. Onboarding incomplete.")
        return jsonify(success=False, error="Onboarding incomplete"), 400

    test_webhook_data = user_record.get("stripe_test_webhook", {})
    live_webhook_data = user_record.get("stripe_live_webhook", {})
    test_webhook_secret = test_webhook_data.get("secret")
    live_webhook_secret = live_webhook_data.get("secret")

    if not (test_webhook_secret or live_webhook_secret):
        logger.error("No Stripe webhook secrets found in user record.")
        return jsonify(success=False, error="Stripe webhook secret missing"), 400

    event = None
    for secret in [test_webhook_secret, live_webhook_secret]:
        if secret:
            try:
                event = stripe.Webhook.construct_event(payload, sig_header, secret)
                break
            except Exception as e:
                continue

    if not event:
        logger.error("Webhook signature verification failed with both secrets.")
        return jsonify(success=False, error="Invalid signature"), 400

    event_id = event.get("id")
    if is_event_processed(event_id):
        logger.info("Duplicate event received: %s. Ignoring.", event_id)
        return jsonify(success=True, message="Duplicate event"), 200

    mark_event_processed(event_id)
    try:
        if event.get("type") == "checkout.session.completed":
            session_obj = event["data"]["object"]
            dynamic_config = {
                "SMARTBILL_USERNAME": user_record.get("smartbill_email"),
                "smartbill_token": user_record.get("smartbill_token"),
                "companyVatCode": user_record.get("cif"),
                "seriesName": user_record.get("default_series"),
                "stripe_api_key": user_record.get("stripe_api_key")
            }
            merged_config = {**config_defaults, **dynamic_config}
            final_payload = build_payload(session_obj, merged_config)
            logger.info("Final payload built: %s", json.dumps(final_payload, indent=2))
            invoice_response = create_smartbill_invoice(final_payload, merged_config)
            logger.info("SmartBill Invoice Response: %s", json.dumps(invoice_response, indent=2))
        else:
            logger.info("Unhandled event type: %s", event.get("type"))
    except Exception as e:
        logger.exception("Error processing event %s: %s", event_id, e)
        notify_admin(e)
        remove_event(event_id)
        return jsonify(success=False, error="Internal server error"), 500

    return jsonify(success=True), 200

# ----------------------------------------------------------------------
# Run the Application
# ----------------------------------------------------------------------
if __name__ == "__main__":
    port = 8080
    app.run(host="0.0.0.0", port=port)
