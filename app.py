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
  - Stripe webhook secrets (for both test and live keys)

These values are stored in a unified user record (encrypted and stored in Replit DB under the key "user_record")
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

# --- Import Flask components and config defaults ---
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from config import config_defaults  # Ensure this file exists with your default configuration
from forms import OnboardingForm, LoginForm, ChangePasswordForm
from replit import db  # Replit's built-in simple database

# Use an in-memory substitute if REPLIT_DB_URL isn’t defined (useful for local testing)
if "REPLIT_DB_URL" not in os.environ:
    logging.warning("REPLIT_DB_URL not set. Running in local mode with an in-memory DB.")
    class InMemoryDB(dict):
        def get(self, key):
            return self[key] if key in self else None
    db = InMemoryDB()

# Configure logging.
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger(__name__)

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
        value = encrypted.decode("utf-8")
        db["user_record"] = value
    except Exception as e:
        logger.error("Error encrypting and storing user record: %s", e)
        raise

def get_user_record():
    """
    Retrieves the encrypted user record from Replit DB, decrypts it, and returns the dictionary.
    Returns None if the key isn’t found.
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

# ----------------------------------------------------------------------
# Configuration and Global Constants
# ----------------------------------------------------------------------
CUSTOM_INSTANCE_URL = os.environ.get("CUSTOM_INSTANCE_URL", "https://your-instance-url")

# ----------------------------------------------------------------------
# Create Flask App and Setup Flask-Login
# ----------------------------------------------------------------------
app = Flask(__name__)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Redirect unauthorized users to login
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "default_secret_key")
# Ensure CSRF protection is configured:
app.config["WTF_CSRF_SECRET_KEY"] = os.environ.get("WTF_CSRF_SECRET_KEY")

class User(UserMixin):
    def __init__(self, id, user_record):
        self.id = id
        self.user_record = user_record

    def get_id(self):
        return self.id

@login_manager.user_loader
def load_user(user_id):
    user_record = get_user_record()
    # Use smartbill_email as unique identifier
    if user_record and user_record.get("smartbill_email") == user_id:
        return User(user_id, user_record)
    return None

# Fixed parameters for SmartBill API calls
SMARTBILL_BASE_URL = "https://ws.smartbill.ro/SBORO/api/"
SMARTBILL_SERIES_TYPE = "f"

# ----------------------------------------------------------------------
# Helper Functions for Passwords and Headers
# ----------------------------------------------------------------------
def hash_password(plain_password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(plain_password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def check_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def get_smartbill_auth_header(username, token):
    auth_string = f"{username}:{token}"
    encoded_auth = base64.b64encode(auth_string.encode("utf-8")).decode("utf-8")
    header = {"Authorization": f"Basic {encoded_auth}"}
    logger.debug("Constructed Auth Header: %s", header)
    return header

# ----------------------------------------------------------------------
# Endpoints
# ----------------------------------------------------------------------

@app.route("/", methods=["GET"])
def index():
    user_record = get_user_record()
    # If no user record exists, create one with default placeholder values.
    if not user_record:
        default_record = {
            "smartbill_email": None,
            "smartbill_token": None,
            "cif": None,
            "default_series": None,
            "stripe_test_api_key": None,
            "stripe_live_api_key": None,
            "stripe_test_webhook": None,
            "stripe_live_webhook": None  # This will eventually store a dict with keys like "id", "secret", "livemode"
        }
        try:
            set_user_record(default_record)
            user_record = default_record
            logger.info("Initialized default user_record with placeholder values.")
        except Exception as e:
            logger.error("Error initializing default user record: %s", e)
            flash("Eroare la inițializarea datelor. Vă rugăm încercați din nou.")
            return "Internal server error", 500

    # Onboarding is considered incomplete if there is no valid live Stripe webhook secret.
    # Here we assume that a valid live webhook secret is stored under the key "secret" in the "stripe_live_webhook" dict.
    live_webhook = user_record.get("stripe_live_webhook")
    if not live_webhook or not live_webhook.get("secret"):
        form = OnboardingForm()
        return render_template("index.html", form=form)

    # If the user record is complete, redirect the user to the login page.
    return redirect(url_for("login"))



# --------------------------
# Onboarding Endpoint
# --------------------------
@app.route("/onboarding", methods=["GET", "POST"])
def onboarding():
    form = OnboardingForm()
    # On GET, initialize the user_record if it doesn't exist.
    if request.method == "GET":
        if not db.get("user_record"):
            default_record = {
                "smartbill_email": None,
                "smartbill_token": None,
                "cif": None,
                "default_series": None,
                "stripe_test_api_key": None,
                "stripe_live_api_key": None,
                "stripe_test_webhook": None,
                "stripe_live_webhook": None
            }
            try:
                set_user_record(default_record)
                logger.info("Initialized user_record with default placeholder values.")
            except Exception as e:
                logger.error("Failed to initialize user_record: %s", e)
                flash("Eroare la inițializarea datelor. Vă rugăm încercați din nou.")
    if form.validate_on_submit():
        smartbill_email = form.smartbill_email.data.strip()
        smartbill_token = form.smartbill_token.data.strip()
        cif = form.cif.data.strip()
        default_series = form.default_series.data.strip()
        stripe_test_api_key = form.stripe_test_api_key.data.strip()
        stripe_live_api_key = form.stripe_live_api_key.data.strip()

        # Double-check required fields (Flask-WTF should handle missing values, too)
        if not (smartbill_email and smartbill_token and cif and default_series and stripe_test_api_key and stripe_live_api_key):
            flash("Toate câmpurile sunt obligatorii.")
            logger.error("Onboarding failed: Missing required fields.")
            return redirect(url_for("onboarding"))

        new_record = {
            "smartbill_email": smartbill_email,
            "smartbill_token": smartbill_token,
            "cif": cif,
            "default_series": default_series,
            "stripe_test_api_key": stripe_test_api_key,
            "stripe_live_api_key": stripe_live_api_key,
            "stripe_test_webhook": None,
            "stripe_live_webhook": None
        }
        try:
            set_user_record(new_record)
            logger.info("User record updated successfully with onboarding data.")
        except Exception as e:
            logger.error("Failed to update user record: %s", e)
            flash("Eroare la salvarea datelor. Vă rugăm încercați din nou.")
            return redirect(url_for("onboarding"))

        user = User(smartbill_email, new_record)
        login_user(user)
        session["user_email"] = smartbill_email
        flash("Onboarding completat cu succes!")
        return redirect(url_for("dashboard"))

    return render_template("onboarding.html", form=form)


# --------------------------
# Dashboard Endpoint (Reads user record)
# --------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    user_record = get_user_record()
    if not user_record:
        flash("Vă rugăm să vă logați și să completați onboarding-ul.")
        logger.error("Dashboard access failed: user_record missing or failed to decrypt.")
        return redirect(url_for("login"))
    return render_template("dashboard.html", 
                           smartbill_email=user_record.get("smartbill_email", "N/A"),
                           company_tax_code=user_record.get("cif", "N/A"),
                           default_series=user_record.get("default_series", "N/A"),
                           smartbill_token=user_record.get("smartbill_token", ""),
                           stripe_test_api_key=user_record.get("stripe_test_api_key", ""),
                           stripe_live_api_key=user_record.get("stripe_live_api_key", ""))

# --------------------------
# API Endpoint: Get Invoice Series from SmartBill
# --------------------------
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

# --------------------------
# API Endpoint: Update Default Series & Store Webhook Secrets
# --------------------------
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

    try:
        set_user_record(existing_record)
        logger.info("User record updated and re-encrypted: %s", existing_record)
    except Exception as e:
        logger.error("Failed to update encrypted user record: %s", e)
        return jsonify({"status": "error", "message": "Failed to update user record"}), 500

    return jsonify({"status": "success", "user_record": existing_record}), 200

# --------------------------
# API Endpoint: Create Stripe Webhooks
# --------------------------
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

    webhook_test_url = f"{CUSTOM_INSTANCE_URL.rstrip('/')}/stripe-webhook-test"
    webhook_live_url = f"{CUSTOM_INSTANCE_URL.rstrip('/')}/stripe-webhook"

    # --- Create (or re-use) Test Webhook ---
    stripe.api_key = stripe_test_key
    try:
        existing_test_webhooks = stripe.WebhookEndpoint.list(limit=100)
    except Exception as e:
        logger.error("Error listing test webhooks: %s", e)
        return jsonify({"status": "error", "message": f"Error listing test webhooks: {str(e)}"}), 500

    webhook_test = None
    for wh in existing_test_webhooks.data:
        if wh.url == webhook_test_url and wh.description == "Facturio Early Adopter Program (Test)":
            webhook_test = wh
            break
    if webhook_test is None:
        try:
            webhook_test = stripe.WebhookEndpoint.create(
                enabled_events=["checkout.session.completed"],
                url=webhook_test_url,
                description="Facturio Early Adopter Program (Test)"
            )
        except Exception as e:
            logger.error("Error creating test webhook: %s", e)
            return jsonify({"status": "error", "message": f"Error creating test webhook: {str(e)}"}), 500

    webhook_test_data = {
        "id": webhook_test.get("id"),
        "secret": webhook_test.get("secret"),
        "livemode": webhook_test.get("livemode")
    }

    # --- Create (or re-use) Live Webhook ---
    stripe.api_key = stripe_live_key
    try:
        existing_live_webhooks = stripe.WebhookEndpoint.list(limit=100)
    except Exception as e:
        logger.error("Error listing live webhooks: %s", e)
        return jsonify({"status": "error", "message": f"Error listing live webhooks: {str(e)}"}), 500

    webhook_live = None
    for wh in existing_live_webhooks.data:
        if wh.url == webhook_live_url and wh.description == "Facturio Early Adopter Program (Live)":
            webhook_live = wh
            break
    if webhook_live is None:
        try:
            webhook_live = stripe.WebhookEndpoint.create(
                enabled_events=["checkout.session.completed"],
                url=webhook_live_url,
                description="Facturio Early Adopter Program (Live)"
            )
        except Exception as e:
            logger.error("Error creating live webhook: %s", e)
            return jsonify({"status": "error", "message": f"Error creating live webhook: {str(e)}"}), 500

    webhook_live_data = {
        "id": webhook_live.get("id"),
        "secret": webhook_live.get("secret"),
        "livemode": webhook_live.get("livemode")
    }


    # --- Update user record with new webhook info ---
    user_record["stripe_test_api_key"] = stripe_test_key
    user_record["stripe_live_api_key"] = stripe_live_key
    user_record["stripe_test_webhook"] = webhook_test_data
    user_record["stripe_live_webhook"] = webhook_live_data
    try:
        set_user_record(user_record)
    except Exception as e:
        logger.error("Error updating user record with webhook info: %s", e)
        return jsonify({"status": "error", "message": "Failed to update user record with webhook info"}), 500

    logger.info("Stripe webhooks created and stored successfully.")
    return jsonify({"status": "success", "message": "Stripe webhooks created successfully"}), 200


# --------------------------
# Authentication, Login, Logout, and Change Password Endpoints
# (Credentials are handled separately.)
# --------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.strip()
        password = form.password.data.strip()
        logger.debug("Attempting login for email: %s", email)

        credentials_raw = db.get("credentials")
        logger.debug("Retrieved credentials from DB: %s", credentials_raw)
        if not credentials_raw:
            flash("Utilizatorul nu există. Vă rugăm să completați onboarding-ul.")
            logger.error("Login failed: Credentials not found in DB.")
            return redirect(url_for("login"))

        credentials = json.loads(credentials_raw)
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
        flash("Logare cu succes!")
        return redirect(url_for("dashboard"))
    return render_template("login.html", form=form)


@app.route("/logout")
def logout():
    logout_user()
    flash("Ați fost deconectat.")
    logger.info("User logged out.")
    return redirect(url_for("login"))

@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()
    credentials_raw = db.get("credentials")
    if not credentials_raw:
        flash("Vă rugăm să vă logați.")
        logger.error("Change password failed: No credentials found in DB.")
        return redirect(url_for("login"))
    credentials = json.loads(credentials_raw)
    if form.validate_on_submit():
        new_password = form.new_password.data.strip()
        if not new_password:
            flash("Vă rugăm să introduceți o parolă nouă.")
            logger.error("Change password failed: New password not provided.")
            return redirect(url_for("change_password"))
        new_hash = hash_password(new_password)
        credentials["password_hash"] = new_hash
        db["credentials"] = json.dumps(credentials)
        logger.debug("Updated credentials after password change: %s", db.get("credentials"))
        flash("Parola a fost actualizată cu succes!")
        return redirect(url_for("dashboard"))
    return render_template("change_password.html", form=form)


# --------------------------
# Facturio Integration Endpoint (Stripe Webhook)
# --------------------------
from services.utils import build_payload
from services.smartbill import create_smartbill_invoice
from services.idempotency import is_event_processed, mark_event_processed, remove_event
from services.notifications import notify_admin
from services.email_sender import send_invoice_email

@app.route("/stripe-webhook-test", methods=["POST"])
def stripe_webhook_test():
    payload = request.get_data()
    sig_header = request.headers.get("Stripe-Signature")
    user_record = get_user_record()
    if not user_record:
        logger.error("User record not found. Onboarding incomplete.")
        return jsonify(success=False, error="Onboarding incomplete"), 400

    test_webhook_data = user_record.get("stripe_test_webhook", {})
    test_webhook_secret = test_webhook_data.get("secret")
    if not test_webhook_secret:
        logger.error("Stripe test webhook secret not found in user record.")
        return jsonify(success=False, error="Stripe test webhook secret missing"), 400

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, test_webhook_secret)
    except Exception as e:
        logger.error("Webhook signature verification failed for test endpoint: %s", e)
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


@app.route("/stripe-webhook-live", methods=["POST"])
def stripe_webhook_live():
    payload = request.get_data()
    sig_header = request.headers.get("Stripe-Signature")
    user_record = get_user_record()
    if not user_record:
        logger.error("User record not found. Onboarding incomplete.")
        return jsonify(success=False, error="Onboarding incomplete"), 400

    live_webhook_data = user_record.get("stripe_live_webhook", {})
    live_webhook_secret = live_webhook_data.get("secret")
    if not live_webhook_secret:
        logger.error("Stripe live webhook secret not found in user record.")
        return jsonify(success=False, error="Stripe live webhook secret missing"), 400

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, live_webhook_secret)
    except Exception as e:
        logger.error("Webhook signature verification failed for live endpoint: %s", e)
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
