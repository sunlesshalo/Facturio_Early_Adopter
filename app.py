"""
Consolidated Facturio Application
-----------------------------------
This file merges all functionalities from the original onboarding and Facturio.app files.
It gathers and stores the following user-provided values during onboarding:
  - SmartBill email
  - SmartBill token
  - Company tax code (used as login password and as companyVatCode)
  - Default invoice series
  - Stripe API key
  - Stripe webhook secret
  - App secret key

These values are stored in a unified user record (as JSON under the key "user_record" in Replit DB)
and are used in all subsequent API calls.
"""

import base64
import logging
import requests
import json
import stripe
import os

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from replit import db  # Replit's built-in simple database

from config import config_defaults

# ----------------------------------------------------------------------
# Configuration and Global Constants
# ----------------------------------------------------------------------
# All static configuration values now come from config_defaults.
# INSTANCE_URL is still taken from environment.
INSTANCE_URL = os.environ.get("INSTANCE_URL", "https://your-instance-url")

# ----------------------------------------------------------------------
# Logging Configuration
# ----------------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG,  # Log all messages at DEBUG level and higher
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------
# Create Flask App
# ----------------------------------------------------------------------
app = Flask(__name__)
# Initially, we set a temporary secret; it will be updated from the user record after onboarding.
app.secret_key = "temporary_secret_key"

# Fixed parameters for SmartBill API calls
SMARTBILL_BASE_URL = "https://ws.smartbill.ro/SBORO/api/"
SMARTBILL_SERIES_TYPE = "f"  # Default series type

# ----------------------------------------------------------------------
# Helper Functions
# ----------------------------------------------------------------------
def get_smartbill_auth_header(username, token):
    """
    Constructs the HTTP Basic Authentication header for SmartBill.
    """
    auth_string = f"{username}:{token}"
    encoded_auth = base64.b64encode(auth_string.encode("utf-8")).decode("utf-8")
    header = {"Authorization": f"Basic {encoded_auth}"}
    logger.debug("Constructed Auth Header: %s", header)
    return header

def get_user_record():
    """
    Retrieves the unified user record from the database.
    The record is stored as JSON under the key "user_record".
    """
    try:
        raw = db.get("user_record")
        if raw:
            return json.loads(raw)
        else:
            return None
    except Exception as e:
        logger.error("Error retrieving user record: %s", e)
        return None

# ----------------------------------------------------------------------
# Before Request: Update app.secret_key if onboarding is complete
# ----------------------------------------------------------------------
@app.before_request
def update_secret_key():
    """
    If a user record exists and contains an app secret key,
    update app.secret_key with the stored value.
    """
    user_record = get_user_record()
    if user_record and user_record.get("app_secret_key"):
        if app.secret_key != user_record.get("app_secret_key"):
            app.secret_key = user_record.get("app_secret_key")
            logger.info("Updated app.secret_key from stored user record.")

# ----------------------------------------------------------------------
# Consolidated Root Endpoint
# ----------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    """
    Root endpoint:
      - If no user record exists, renders the onboarding form (index.html).
      - If a user record exists but the user is not logged in, displays a welcome message.
      - If the user is logged in, redirects to the dashboard.
    """
    if not db.get("user_record"):
        return render_template("index.html")
    if session.get("user_email"):
        return redirect(url_for("dashboard"))
    return "Welcome to Facturio's Stripe-SmartBill Integration Service. Please log in at /login."

# ----------------------------------------------------------------------
# Onboarding API Endpoints
# ----------------------------------------------------------------------
@app.route("/api/get_series", methods=["POST"])
def api_get_series():
    """
    Expects a JSON payload with:
      - smartbill_email: SmartBill email (username)
      - smartbill_token: SmartBill API token
      - cif: Company's tax code
    Calls the SmartBill API to retrieve invoice series.
    """
    data = request.get_json()
    smartbill_email = data.get("smartbill_email", "").strip()
    smartbill_token = data.get("smartbill_token", "").strip()
    cif = data.get("cif", "").strip()

    if not smartbill_email or not smartbill_token or not cif:
        logger.warning("Missing required fields in JSON payload.")
        return jsonify({"status": "error", "message": "Toate câmpurile sunt obligatorii"}), 400

    series_url = f"{SMARTBILL_BASE_URL}series"
    headers = {"Content-Type": "application/json"}
    headers.update(get_smartbill_auth_header(smartbill_email, smartbill_token))
    params = {"cif": cif, "type": SMARTBILL_SERIES_TYPE}

    logger.debug("Sending GET request to %s", series_url)
    logger.debug("Headers: %s", headers)
    logger.debug("Parameters: %s", params)

    try:
        response = requests.get(series_url, headers=headers, params=params)
        logger.debug("Received response with status code: %s", response.status_code)
        logger.debug("Response text: %s", response.text)
        response.raise_for_status()
        resp_data = response.json()
        logger.debug("Parsed JSON: %s", resp_data)
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
    logger.debug("Extracted series list: %s", series_list)
    if not series_list:
        logger.warning("No invoice series found in response.")
        return jsonify({"status": "error", "message": "Nu s-au găsit serii de facturare."}), 404

    return jsonify({"status": "success", "series_list": series_list}), 200

@app.route("/api/set_default_series", methods=["POST"])
def api_set_default_series():
    """
    Expects a JSON payload with the following required fields:
      - smartbill_email: SmartBill email
      - smartbill_token: SmartBill API token
      - cif: Company tax code (used for login and as companyVatCode)
      - default_series: Chosen invoice series
    Optional fields:
      - stripe_api_key
      - stripe_webhook_secret
      - app_secret_key
    Saves these values into a unified user record.
    """
    data = request.get_json()
    smartbill_email = data.get("smartbill_email", "").strip()
    smartbill_token = data.get("smartbill_token", "").strip()
    cif = data.get("cif", "").strip()
    default_series = data.get("default_series", "").strip()
    stripe_api_key = data.get("stripe_api_key", "").strip()
    stripe_webhook_secret = data.get("stripe_webhook_secret", "").strip()
    app_secret_key = data.get("app_secret_key", "").strip()

    # Require only the SmartBill-related fields.
    if not (smartbill_email and smartbill_token and cif and default_series):
        return jsonify({"status": "error", "message": "Missing one or more required SmartBill fields"}), 400

    # Build the user record using the provided SmartBill values.
    user_record = {
        "smartbill_email": smartbill_email,
        "smartbill_token": smartbill_token,
        "company_tax_code": cif,  # Used for login and as companyVatCode
        "default_series": default_series,
    }

    # Include Stripe-related fields if provided.
    if stripe_api_key:
        user_record["stripe_api_key"] = stripe_api_key
    if stripe_webhook_secret:
        user_record["stripe_webhook_secret"] = stripe_webhook_secret
    if app_secret_key:
        user_record["app_secret_key"] = app_secret_key

    db["user_record"] = json.dumps(user_record)
    logger.info("User record created: %s", user_record)

    return jsonify({"status": "success", "user_record": user_record}), 200

@app.route("/api/stripe_create_webhook", methods=["POST"])
def api_stripe_create_webhook():
    """
    Creates a new Stripe webhook endpoint using the provided Stripe API key.
    The webhook URL is built from INSTANCE_URL.
    This endpoint updates the unified user record with the Stripe API key and webhook secret.
    """
    data = request.get_json()
    provided_stripe_key = data.get("stripe_key", "").strip()
    if not provided_stripe_key:
        return jsonify({"status": "error", "message": "Stripe key is required"}), 400

    user_record = get_user_record()
    if not user_record:
        logger.error("User record not found. Cannot create Stripe webhook.")
        return jsonify({"status": "error", "message": "Onboarding incomplete"}), 400

    # Update the user record with the Stripe API key if it's missing.
    if not user_record.get("stripe_api_key"):
        user_record["stripe_api_key"] = provided_stripe_key
        db["user_record"] = json.dumps(user_record)
    stripe_api_key = user_record.get("stripe_api_key")
    if not stripe_api_key:
        return jsonify({"status": "error", "message": "Stripe API key missing"}), 400

    instance_url = INSTANCE_URL
    if not instance_url:
        logger.error("INSTANCE_URL not set.")
        return jsonify({"status": "error", "message": "INSTANCE_URL not set"}), 500

    webhook_url = f"{instance_url}stripe-webhook"
    logger.debug("Using webhook URL: %s", webhook_url)

    stripe.api_key = stripe_api_key
    try:
        webhook = stripe.WebhookEndpoint.create(
            enabled_events=["checkout.session.completed"],
            url=webhook_url,
            description="Facturio Early Adopter Program"
        )
        webhook_data = {
            "id": webhook.get("id"),
            "secret": webhook.get("secret")
        }
        # Store webhook data separately.
        db["stripe_webhook"] = json.dumps(webhook_data)
        # ALSO update the user record with the webhook secret.
        user_record["stripe_webhook_secret"] = webhook_data.get("secret")
        db["user_record"] = json.dumps(user_record)
        logger.info("Stripe webhook created and stored: %s", webhook_data)
        return jsonify({"status": "success", "webhook": webhook_data}), 200
    except Exception as e:
        logger.error("Stripe webhook creation error: %s", e)
        return jsonify({"status": "error", "message": str(e)}), 500



# ----------------------------------------------------------------------
# Authentication, Dashboard, and Account Management Endpoints
# ----------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Login endpoint:
      - GET: Renders the login form.
      - POST: Validates credentials against the unified user record.
      Expects the user to enter:
         - Email (SmartBill email)
         - Password (company tax code)
    """
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()  # Expected to be the company tax code

        user_data_raw = db.get("user_record")
        if not user_data_raw:
            flash("Utilizatorul nu există. Vă rugăm să completați onboarding-ul.")
            return redirect(url_for("login"))
        user_record = json.loads(user_data_raw)
        if email != user_record.get("smartbill_email"):
            flash("Utilizatorul nu există. Vă rugăm să completați onboarding-ul.")
            return redirect(url_for("login"))
        if password != user_record.get("company_tax_code"):
            flash("Parola incorectă!")
            return redirect(url_for("login"))
        if "default_series" not in user_record:
            flash("Onboarding incomplet! Vă rugăm să finalizați onboarding-ul SmartBill.")
            return redirect(url_for("index"))

        session["user_email"] = email
        flash("Logare cu succes!")
        return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    """
    Logout endpoint: Clears the session.
    """
    session.clear()
    flash("Ați fost deconectat.")
    return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    """
    Dashboard endpoint: Displays user details from the unified user record.
    """
    user_data_raw = db.get("user_record")
    if not user_data_raw:
        flash("Vă rugăm să vă logați și să completați onboarding-ul.")
        return redirect(url_for("login"))
    user_record = json.loads(user_data_raw)
    email = user_record.get("smartbill_email", "N/A")
    default_series = user_record.get("default_series", "N/A")
    cui = user_record.get("company_tax_code", "N/A")
    return render_template("dashboard.html", email=email, cui=cui, default_series=default_series)

@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    """
    Allows the logged-in user to change their company tax code.
    """
    user_data_raw = db.get("user_record")
    if not user_data_raw:
        flash("Vă rugăm să vă logați.")
        return redirect(url_for("login"))
    user_record = json.loads(user_data_raw)
    if request.method == "POST":
        new_password = request.form.get("new_password", "").strip()
        if not new_password:
            flash("Vă rugăm să introduceți o parolă nouă.")
            return redirect(url_for("change_password"))
        user_record["company_tax_code"] = new_password
        db["user_record"] = json.dumps(user_record)
        flash("Parola a fost actualizată cu succes!")
        return redirect(url_for("dashboard"))
    return render_template("change_password.html")

@app.route("/status")
def status():
    """
    Status endpoint: Confirms that the app is running.
    """
    return "Onboarding SmartBill App is running."

# ----------------------------------------------------------------------
# Facturio Integration Endpoint (Stripe Webhook)
# ----------------------------------------------------------------------
# The following helper functions are assumed to be defined in their respective modules:
# - build_payload (from services.utils)
# - create_smartbill_invoice, delete_smartbill_invoice (from services.smartbill)
# - is_event_processed, mark_event_processed, remove_event (from services.idempotency)
# - notify_admin (from services.notifications)
# - send_invoice_email (from services.email_sender)
from services.utils import build_payload
from services.smartbill import create_smartbill_invoice
from services.idempotency import is_event_processed, mark_event_processed, remove_event
from services.notifications import notify_admin
from services.email_sender import send_invoice_email

@app.route("/stripe-webhook", methods=["POST"])
def stripe_webhook():
    """
    Stripe webhook endpoint:
      - Processes "checkout.session.completed" events.
      - Retrieves dynamic configuration from the unified user record.
      - Builds payload for the SmartBill API and creates an invoice.
      - Sends an email notification.
    """
    payload = request.get_data()
    sig_header = request.headers.get("Stripe-Signature")

    user_record = get_user_record()
    if not user_record:
        logger.error("User record not found. Onboarding incomplete.")
        return jsonify(success=False, error="Onboarding incomplete"), 400

    stored_stripe_webhook_secret = user_record.get("stripe_webhook_secret")
    if not stored_stripe_webhook_secret:
        logger.error("Stripe webhook secret not found in user record.")
        return jsonify(success=False, error="Stripe webhook secret missing"), 400

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, stored_stripe_webhook_secret)
    except Exception as e:
        logger.error("Webhook signature verification failed: %s", e)
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
                "companyVatCode": user_record.get("company_tax_code"),
                "seriesName": user_record.get("default_series"),
                "APP_PASSWORD": user_record.get("company_tax_code"),
                "stripe_api_key": user_record.get("stripe_api_key")
            }
            merged_config = {**config_defaults, **dynamic_config}
            final_payload = build_payload(session_obj, merged_config)
            logger.info("Final payload built: %s", json.dumps(final_payload, indent=2))
            invoice_response = create_smartbill_invoice(final_payload, merged_config)
            logger.info("SmartBill Invoice Response: %s", json.dumps(invoice_response, indent=2))

            # Email functionality is disabled.
            """
            email_payload = {
                "companyVatCode": dynamic_config["companyVatCode"],
                "seriesName": dynamic_config["seriesName"],
                "number": invoice_response.get("number"),
                "type": "factura",
                "subject": base64.b64encode("Invoice Notification".encode("utf-8")).decode("utf-8"),
                "to": session_obj.get("customer_details", {}).get("email"),
                "bodyText": base64.b64encode("Your invoice has been created successfully.".encode("utf-8")).decode("utf-8"),
                "emailConfig": {
                    "mailFrom": dynamic_config["SMARTBILL_USERNAME"],
                    "password": dynamic_config["APP_PASSWORD"],
                    "smtpServer": "smtp.gmail.com",
                    "smtpPort": 587,
                    "useTLS": True
                }
            }
            try:
                send_invoice_email(email_payload)
            except Exception as email_err:
                logger.error("Failed to send invoice email: %s", email_err)
                notify_admin(email_err)
            """
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
