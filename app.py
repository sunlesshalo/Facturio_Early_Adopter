"""
Consolidated Facturio Application
-----------------------------------
This file merges all functionalities from the original onboarding and Facturio.app files.
It gathers and stores the following user-provided values during onboarding:
  - SmartBill email
  - SmartBill token
  - Tax code ("cif")
  - Default invoice series
  - Stripe API key 
  - Stripe webhook secret

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
import re

# Define regex for email validation
EMAIL_REGEX = r"^[\w\.-]+@[\w\.-]+\.\w+$"

# --- New Imports for Rate Limiting and CSRF Protection ---
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, CSRFError

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from replit import db  # Replit's built-in simple database

from config import config_defaults

from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required

# --- Import forms for Flask-WTF validation ---
from forms import OnboardingForm, LoginForm, ChangePasswordForm

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

# --- Initialize Flask-Limiter for Rate Limiting and Brute-force Protection ---
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[]
)

# --- Initialize CSRF Protection with custom error handling ---
csrf = CSRFProtect(app)

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    logger.error("CSRF error: %s", e)
    return jsonify({"status": "error", "message": "CSRF validation failed"}), 400

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Set the secret key and enable CSRF protection
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "default_secret_key")
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
    if user_record and user_record.get("smartbill_email") == user_id:
        return User(user_id, user_record)
    return None

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
    try:
        form = OnboardingForm()  # Instantiate the form for CSRF protection
        if not db.get("user_record"):
            return render_template("index.html", form=form)
        if session.get("user_email"):
            return redirect(url_for("dashboard"))
        return render_template("index.html", form=form)
    except Exception as e:
        logger.exception("Unexpected error in index endpoint: %s", e)
        return render_template("index.html", form=OnboardingForm())

# ----------------------------------------------------------------------
# Onboarding Endpoint for HTML Form Submission (Handles Credentials)
# ----------------------------------------------------------------------
@app.route("/onboarding", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def onboarding():
    try:
        form = OnboardingForm()
        if form.validate_on_submit():
            smartbill_email = form.smartbill_email.data.strip()
            smartbill_token = form.smartbill_token.data.strip()
            cif = form.cif.data.strip()  # renamed field
            default_series = form.default_series.data.strip()

            # Input validations
            if not (smartbill_email and smartbill_token and cif and default_series):
                flash("Toate câmpurile sunt obligatorii.")
                logger.error("Onboarding failed: Missing required fields.")
                return redirect(url_for("onboarding"))
            if not re.match(EMAIL_REGEX, smartbill_email):
                flash("Email invalid.")
                logger.error("Onboarding failed: Invalid SmartBill email format.")
                return redirect(url_for("onboarding"))
            if not cif.isdigit():
                flash("CIF invalid. Trebuie să conțină doar cifre.")
                logger.error("Onboarding failed: CIF contains non-digit characters.")
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
                "default_series": default_series
            }
            set_user_record(user_record)
            logger.debug("Stored encrypted user record.")

            if get_user_record() is None or get_credentials() is None:
                logger.error("Failed to store user_record or credentials in Replit DB.")
                flash("Eroare la salvarea datelor. Vă rugăm încercați din nou.")
                return redirect(url_for("onboarding"))
            else:
                logger.info("User record and credentials successfully stored in Replit DB.")

            flash("Onboarding completat cu succes! Parola inițială este 'factur10'. Vă rugăm să o schimbați după logare.")
            return redirect(url_for("dashboard"))
        return render_template("onboarding.html", form=form)
    except Exception as e:
        logger.exception("Unexpected error in onboarding endpoint: %s", e)
        flash("Eroare internă. Vă rugăm încercați din nou.")
        return redirect(url_for("onboarding"))

@app.route("/dashboard")
@login_required
def dashboard():
    try:
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
    except Exception as e:
        logger.exception("Unexpected error in dashboard endpoint: %s", e)
        flash("Eroare internă.")
        return redirect(url_for("login"))

# ----------------------------------------------------------------------
# API Endpoints
# ----------------------------------------------------------------------
@app.route("/api/get_series", methods=["POST"])
@limiter.limit("20 per minute")
def api_get_series():
    try:
        data = request.get_json()
        smartbill_email = data.get("smartbill_email", "").strip()
        smartbill_token = data.get("smartbill_token", "").strip()
        cif = data.get("cif", "").strip()

        # Input validations
        if not (smartbill_email and smartbill_token and cif):
            logger.warning("Missing required fields in JSON payload.")
            return jsonify({"status": "error", "message": "Toate câmpurile sunt obligatorii"}), 400
        if not re.match(EMAIL_REGEX, smartbill_email):
            logger.error("Invalid SmartBill email format in API get_series.")
            return jsonify({"status": "error", "message": "Email invalid."}), 400
        if not cif.isdigit():
            logger.error("Invalid CIF in API get_series; must be digits.")
            return jsonify({"status": "error", "message": "CIF invalid."}), 400

        series_url = f"{SMARTBILL_BASE_URL}series"
        headers = {"Content-Type": "application/json"}
        headers.update(get_smartbill_auth_header(smartbill_email, smartbill_token))
        params = {"cif": cif, "type": SMARTBILL_SERIES_TYPE}

        try:
            response = requests.get(series_url, headers=headers, params=params)
            response.raise_for_status()
            resp_data = response.json()
        except requests.exceptions.HTTPError as errh:
            logger.error("HTTP Error in api_get_series: %s", errh)
            return jsonify({"status": "error", "message": f"Eroare HTTP: {errh}"}), response.status_code if response else 500
        except requests.exceptions.RequestException as err:
            logger.error("Request Exception in api_get_series: %s", err)
            return jsonify({"status": "error", "message": f"Eroare de conexiune: {err}"}), 500
        except ValueError as errv:
            logger.error("JSON parsing error in api_get_series: %s", errv)
            return jsonify({"status": "error", "message": "Răspuns invalid din partea SmartBill"}), 500

        series_list = resp_data.get("list", [])
        if not series_list:
            logger.warning("No invoice series found in response in api_get_series.")
            return jsonify({"status": "error", "message": "Nu s-au găsit serii de facturare."}), 404

        return jsonify({"status": "success", "series_list": series_list}), 200
    except Exception as e:
        logger.exception("Unexpected error in api_get_series endpoint: %s", e)
        return jsonify({"status": "error", "message": "Internal server error"}), 500

@app.route("/api/set_default_series", methods=["POST"])
@limiter.limit("20 per minute")
def api_set_default_series():
    try:
        data = request.get_json()
        smartbill_email = data.get("smartbill_email", "").strip()
        smartbill_token = data.get("smartbill_token", "").strip()
        cif = data.get("cif", "").strip()
        default_series = data.get("default_series", "").strip()
        stripe_api_key = data.get("stripe_api_key", "").strip()
        stripe_webhook_secret = data.get("stripe_webhook_secret", "").strip()

        # Input validations
        if not (smartbill_email and smartbill_token and cif and default_series):
            return jsonify({"status": "error", "message": "Missing one or more required SmartBill fields"}), 400
        if not re.match(EMAIL_REGEX, smartbill_email):
            logger.error("Invalid SmartBill email format in api_set_default_series.")
            return jsonify({"status": "error", "message": "Email invalid."}), 400
        if not cif.isdigit():
            logger.error("Invalid CIF in api_set_default_series; must be digits.")
            return jsonify({"status": "error", "message": "CIF invalid."}), 400

        if not get_credentials():
            initial_password = "factur10"
            password_hash = hash_password(initial_password)
            credentials = {
                "smartbill_email": smartbill_email,
                "password_hash": password_hash
            }
            set_credentials(credentials)
            logger.debug("Stored encrypted credentials via API in set_default_series.")

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
        logger.info("User record updated (encrypted) in set_default_series: %s", existing_record)

        return jsonify({"status": "success", "user_record": existing_record}), 200
    except Exception as e:
        logger.exception("Unexpected error in api_set_default_series endpoint: %s", e)
        return jsonify({"status": "error", "message": "Internal server error"}), 500

@app.route("/api/stripe_create_webhooks", methods=["POST"])
@limiter.limit("10 per minute")
def api_stripe_create_webhooks():
    try:
        data = request.get_json()
        new_stripe_api_key = data.get("stripe_api_key", "").strip()
        if not new_stripe_api_key:
            return jsonify({"status": "error", "message": "Stripe API key is required"}), 400
        if not (new_stripe_api_key.startswith("sk_test") or new_stripe_api_key.startswith("sk_live") or new_stripe_api_key.startswith("rk_live")):
            return jsonify({"status": "error", "message": "Stripe API key must start with sk_test, sk_live or rk_live"}), 400

        user_record = get_user_record()
        if not user_record:
            logger.error("User record not found in api_stripe_create_webhooks. Cannot create Stripe webhook.")
            return jsonify({"status": "error", "message": "Onboarding incomplete"}), 400

        if not CUSTOM_INSTANCE_URL:
            logger.error("CUSTOM_INSTANCE_URL not set in api_stripe_create_webhooks.")
            return jsonify({"status": "error", "message": "CUSTOM_INSTANCE_URL not set"}), 500

        webhook_url = f"{CUSTOM_INSTANCE_URL.rstrip('/')}/stripe-webhook"

        previous_stripe_api_key = user_record.get("stripe_api_key")
        previous_webhook = user_record.get("stripe_webhook")

        # If API key is unchanged and a webhook with a stored secret exists,
        # check its description and avoid creating a new webhook if it matches.
        if previous_stripe_api_key == new_stripe_api_key and previous_webhook and previous_webhook.get("secret"):
            try:
                stripe.api_key = new_stripe_api_key
                retrieved_webhook = stripe.WebhookEndpoint.retrieve(previous_webhook.get("id"))
                if retrieved_webhook and retrieved_webhook.get("description") == "Facturio Early Adopter Program":
                    logger.info("Webhook already exists with same API key and description. Not creating a new webhook.")
                    return jsonify({"status": "success", "message": "Stripe webhook already exists"}), 200
            except Exception as e:
                logger.error("Error retrieving existing webhook: %s", e)
                # If retrieval fails, proceed to create a new webhook.

        # If API key has changed and an existing webhook is stored, attempt deletion.
        if previous_stripe_api_key and new_stripe_api_key != previous_stripe_api_key and previous_webhook:
            try:
                stripe.api_key = previous_stripe_api_key
                stripe.WebhookEndpoint.delete(previous_webhook.get("id"))
                logger.info("Deleted previous webhook with id in api_stripe_create_webhooks: %s", previous_webhook.get("id"))
            except Exception as e:
                logger.error("Error deleting previous webhook in api_stripe_create_webhooks: %s", e)
                # Proceed to create a new webhook even if deletion fails.

        # Create a new webhook using the new Stripe API key.
        stripe.api_key = new_stripe_api_key
        try:
            webhook = stripe.WebhookEndpoint.create(
                enabled_events=["checkout.session.completed"],
                url=webhook_url,
                description="Facturio Early Adopter Program"
            )
            webhook_data = {
                "id": webhook.get("id"),
                "secret": webhook.get("secret"),
                "livemode": webhook.get("livemode")
            }
        except Exception as e:
            logger.error("Error creating webhook in api_stripe_create_webhooks: %s", e)
            return jsonify({"status": "error", "message": f"Error creating webhook: {str(e)}"}), 500

        # Update the user record with the new Stripe API key and new webhook data.
        user_record["stripe_api_key"] = new_stripe_api_key
        user_record["stripe_webhook"] = webhook_data
        set_user_record(user_record)
        logger.info("Stripe webhook created and stored successfully with new Stripe key in api_stripe_create_webhooks.")
        return jsonify({"status": "success", "message": "Stripe webhook updated successfully"}), 200
    except Exception as e:
        logger.exception("Unexpected error in api_stripe_create_webhooks endpoint: %s", e)
        return jsonify({"status": "error", "message": "Internal server error"}), 500


# ----------------------------------------------------------------------
# Authentication, Login, Logout, and Change Password Endpoints
# ----------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    try:
        form = LoginForm()
        if form.validate_on_submit():
            email = form.email.data.strip()
            password = form.password.data.strip()
            logger.debug("Attempting login for email: %s", email)

            # Validate email format
            if not re.match(EMAIL_REGEX, email):
                flash("Email invalid.")
                logger.error("Login failed: Invalid email format.")
                return redirect(url_for("login"))

            credentials = get_credentials()
            logger.debug("Retrieved encrypted credentials from DB in login.")
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
        return render_template("login.html", form=form)
    except Exception as e:
        logger.exception("Unexpected error in login endpoint: %s", e)
        flash("Eroare internă la logare.")
        return redirect(url_for("login"))

@app.route("/logout")
def logout():
    try:
        logout_user()
        flash("Ați fost deconectat.")
        logger.info("User logged out.")
        return redirect(url_for("login"))
    except Exception as e:
        logger.exception("Unexpected error in logout endpoint: %s", e)
        flash("Eroare internă la deconectare.")
        return redirect(url_for("login"))

@app.route("/change_password", methods=["GET", "POST"])
@login_required
@limiter.limit("5 per minute")
def change_password():
    try:
        form = ChangePasswordForm()
        credentials = get_credentials()
        logger.debug("Retrieved encrypted credentials for change_password in endpoint.")
        if not credentials:
            flash("Vă rugăm să vă logați.")
            logger.error("Change password failed: No credentials found in DB.")
            return redirect(url_for("login"))
        if form.validate_on_submit():
            new_password = form.new_password.data.strip()
            if not new_password:
                flash("Vă rugăm să introduceți o parolă nouă.")
                logger.error("Change password failed: New password not provided.")
                return redirect(url_for("change_password"))
            new_hash = hash_password(new_password)
            credentials["password_hash"] = new_hash
            set_credentials(credentials)
            logger.debug("Updated encrypted credentials after password change in endpoint.")
            flash("Parola a fost actualizată cu succes!")
            return redirect(url_for("dashboard"))
        return render_template("change_password.html", form=form)
    except Exception as e:
        logger.exception("Unexpected error in change_password endpoint: %s", e)
        flash("Eroare internă la schimbarea parolei.")
        return redirect(url_for("change_password"))

# ----------------------------------------------------------------------
# Facturio Integration Endpoint (Stripe Webhook)
# ----------------------------------------------------------------------
from services.utils import build_payload
from services.smartbill import create_smartbill_invoice
from services.idempotency import is_event_processed, mark_event_processed, remove_event
from services.notifications import notify_admin
from services.email_sender import send_invoice_email

@app.route("/stripe-webhook", methods=["POST"])
@csrf.exempt
@limiter.limit("100 per minute")
def stripe_webhook():
    try:
        payload = request.get_data()
        sig_header = request.headers.get("Stripe-Signature")

        user_record = get_user_record()
        if not user_record:
            logger.error("User record not found in stripe_webhook. Onboarding incomplete.")
            return jsonify(success=False, error="Onboarding incomplete"), 400

        webhook_data = user_record.get("stripe_webhook")
        if not webhook_data or not webhook_data.get("secret"):
            logger.error("No Stripe webhook secret found in user record in stripe_webhook.")
            return jsonify(success=False, error="Stripe webhook secret missing"), 400

        try:
            event = stripe.Webhook.construct_event(payload, sig_header, webhook_data.get("secret"))
        except Exception as e:
            logger.error("Webhook signature verification failed in stripe_webhook: %s", e)
            return jsonify(success=False, error="Invalid signature"), 400

        event_id = event.get("id")
        if is_event_processed(event_id):
            logger.info("Duplicate event received in stripe_webhook: %s. Ignoring.", event_id)
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
                logger.info("Final payload built in stripe_webhook: %s", json.dumps(final_payload, indent=2))
                invoice_response = create_smartbill_invoice(final_payload, merged_config)
                logger.info("SmartBill Invoice Response in stripe_webhook: %s", json.dumps(invoice_response, indent=2))
            else:
                logger.info("Unhandled event type in stripe_webhook: %s", event.get("type"))
        except Exception as e:
            logger.exception("Error processing event %s in stripe_webhook: %s", event_id, e)
            notify_admin(e)
            remove_event(event_id)
            return jsonify(success=False, error="Internal server error"), 500

        return jsonify(success=True), 200
    except Exception as e:
        logger.exception("Unexpected error in stripe_webhook endpoint: %s", e)
        return jsonify(success=False, error="Internal server error"), 500

# ----------------------------------------------------------------------
# Run the Application
# ----------------------------------------------------------------------
if __name__ == "__main__":
    port = 8080
    app.run(host="0.0.0.0", port=port)
