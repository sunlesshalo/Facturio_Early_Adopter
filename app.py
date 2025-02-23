import os
import base64
import logging
import logging.config
import json
import requests
import stripe
import bcrypt
from cryptography.fernet import Fernet

# --- New Imports for Rate Limiting & Request Context ---
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import uuid

# --- Flask & Extensions ---
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, g
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_wtf.csrf import CSRFProtect, CSRFError

# --- Local Modules ---
from config import config_defaults  # Ensure this file exists with your default configuration
from forms import OnboardingForm, LoginForm, ChangePasswordForm
from replit import db  # Replit's built-in simple database

# =============================================================================
# Logging Configuration
# =============================================================================

class RedactFilter(logging.Filter):
    """
    Filter that redacts sensitive substrings in log messages.
    It forces string formatting if needed to avoid issues with record arguments.
    """
    SENSITIVE_PATTERNS = [
        "smartbill_token",
        "stripe_test_api_key",
        "stripe_live_api_key",
        "stripe_webhook_secret",
        "password",
        "secret",
        "token"
    ]

    def filter(self, record):
        try:
            # Force evaluation of the message if formatting arguments exist
            if record.args:
                message = record.msg % record.args
                # Clear args so no further formatting is attempted downstream
                record.args = ()
            else:
                message = record.msg
            # Redact sensitive patterns
            for pattern in self.SENSITIVE_PATTERNS:
                message = message.replace(pattern, "[REDACTED]")
            record.msg = message
        except Exception as e:
            # If any error occurs, pass the record unmodified
            pass
        return True

class RequestContextFilter(logging.Filter):
    """
    Filter to add request context (e.g., request_id) to log records.
    """
    def filter(self, record):
        try:
            from flask import has_request_context, g
            if has_request_context() and hasattr(g, 'request_id'):
                record.request_id = g.request_id
            else:
                record.request_id = None
        except Exception:
            record.request_id = None
        return True

class JsonFormatter(logging.Formatter):
    """
    Formatter that outputs logs as JSON strings.
    """
    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "request_id") and record.request_id:
            log_record["request_id"] = record.request_id
        return json.dumps(log_record)

LOG_LEVEL = os.environ.get("LOG_LEVEL", "DEBUG")

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
         "json": {
              "()": JsonFormatter,
              "datefmt": "%Y-%m-%dT%H:%M:%S"
         }
    },
    "filters": {
         "redact": {"()": RedactFilter},
         "request_context": {"()": RequestContextFilter}
    },
    "handlers": {
         "console": {
              "class": "logging.StreamHandler",
              "level": LOG_LEVEL,
              "formatter": "json",
              "filters": ["redact", "request_context"]
         },
         "file": {
              "class": "logging.handlers.RotatingFileHandler",
              "level": LOG_LEVEL,
              "formatter": "json",
              "filters": ["redact", "request_context"],
              "filename": "app.log",
              "maxBytes": 10 * 1024 * 1024,  # 10MB
              "backupCount": 5,
         }
    },
    "root": {
         "level": LOG_LEVEL,
         "handlers": ["console", "file"]
    }
}

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger(__name__)
# Global dictionary to track failed login attempts by IP address
failed_login_attempts = {}

# =============================================================================
# Environment Variable Enforcement
# =============================================================================
required_env_vars = ["FLASK_SECRET_KEY", "WTF_CSRF_SECRET_KEY", "CONFIG_KEY", "CUSTOM_INSTANCE_URL"]
missing_vars = [var for var in required_env_vars if not os.environ.get(var)]
if missing_vars:
    logger.critical("Missing required environment variables: %s", ", ".join(missing_vars))
    raise Exception("Missing required environment variables: " + ", ".join(missing_vars))

# =============================================================================
# Database Initialization
# =============================================================================
# Use an in-memory substitute if REPLIT_DB_URL isn’t defined (useful for local testing)
if "REPLIT_DB_URL" not in os.environ:
    logger.warning("REPLIT_DB_URL not set. Running in local mode with an in-memory DB.")
    class InMemoryDB(dict):
        def get(self, key):
            return self[key] if key in self else None
    db = InMemoryDB()

# =============================================================================
# Encryption Helper Functions
# =============================================================================
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
    try:
        encrypted = encrypt_data(data)
        value = encrypted.decode("utf-8")
        db["user_record"] = value
    except Exception as e:
        logger.error("Error encrypting and storing user record: %s", e)
        raise

def get_user_record():
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
    try:
        logger.debug("set_credentials: Received credentials to encrypt: %s", data)
        encrypted = encrypt_data(data)
        encrypted_str = encrypted.decode("utf-8")
        logger.debug("set_credentials: Encrypted credentials: %s", encrypted_str)
        db["credentials"] = encrypted_str
        logger.info("set_credentials: Successfully stored encrypted credentials in DB.")
    except Exception as e:
        logger.error("set_credentials: Error encrypting and storing credentials: %s", e)
        raise

def get_credentials():
    try:
        credentials_raw = db.get("credentials")
        logger.debug("get_credentials: Retrieved raw credentials from DB: %s", credentials_raw)
    except Exception as e:
        logger.error("get_credentials: Exception when retrieving credentials: %s", e)
        return None

    if not credentials_raw:
        logger.error("get_credentials: Credentials key not found in DB.")
        return None

    try:
        encrypted_bytes = credentials_raw.encode("utf-8")
        credentials = decrypt_data(encrypted_bytes)
        logger.debug("get_credentials: Successfully decrypted credentials: %s", credentials)
        return credentials
    except Exception as e:
        logger.error("get_credentials: Error decrypting credentials: %s", e)
        try:
            credentials = json.loads(credentials_raw)
            logger.debug("get_credentials: Parsed plaintext credentials: %s", credentials)
        except Exception as e2:
            logger.error("get_credentials: Error parsing plaintext credentials: %s", e2)
            raise Exception("Credentials decryption failed and plaintext parsing failed.") from e2
        try:
            set_credentials(credentials)
            logger.info("get_credentials: Migrated plaintext credentials to encrypted credentials.")
        except Exception as e3:
            logger.error("get_credentials: Error re-encrypting credentials: %s", e3)
            raise Exception("Credentials decryption failed and re-encryption failed.") from e3
        return credentials

# =============================================================================
# Create Flask App and Setup Flask-Login
# =============================================================================
app = Flask(__name__)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[]
)

csrf = CSRFProtect(app)

# =============================================================================
# Input Validation and Error Handling Helpers
# =============================================================================
def validate_json_payload(payload, required_fields):
    if not isinstance(payload, dict):
        raise ValueError("Invalid JSON payload: expected a JSON object.")
    sanitized = {}
    errors = {}
    for field in required_fields:
        value = payload.get(field)
        if value is None:
            errors[field] = "Field is required."
        elif not isinstance(value, str):
            errors[field] = "Field must be a string."
        elif not value.strip():
            errors[field] = "Field cannot be empty."
        else:
            sanitized[field] = value.strip()
    if errors:
        error_messages = "; ".join([f"{k}: {v}" for k, v in errors.items()])
        raise ValueError("Validation errors: " + error_messages)
    return sanitized

@app.errorhandler(ValueError)
def handle_value_error(error):
    logger.error("Validation error occurred: %s", error)
    return jsonify({"status": "error", "message": str(error)}), 400

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    logger.error("CSRF error: %s", e)
    return jsonify({"status": "error", "message": "CSRF validation failed"}), 400

login_manager = LoginManager(app)
login_manager.login_view = 'login'
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

# -----------------------------------------------------------------------------
# Request Context: assign a unique request_id to each request for context in logs.
# -----------------------------------------------------------------------------
@app.before_request
def assign_request_id():
    g.request_id = str(uuid.uuid4())

# =============================================================================
# Endpoints
# =============================================================================
@app.route("/", methods=["GET"])
def index():
    user_record = get_user_record()
    if not user_record:
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
            user_record = default_record
            logger.info("Initialized default user_record with placeholder values.")
        except Exception as e:
            logger.error("Error initializing default user record: %s", e)
            flash("Eroare la inițializarea datelor. Vă rugăm încercați din nou.")
            return "Internal server error", 500

    live_webhook = user_record.get("stripe_live_webhook")
    if not live_webhook or not live_webhook.get("secret"):
        form = OnboardingForm()
        return render_template("index.html", form=form)

    return redirect(url_for("login"))

@app.route("/onboarding", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def onboarding():
    form = OnboardingForm()
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

@app.route("/api/get_series", methods=["POST"])
@limiter.limit("20 per minute")
def api_get_series():
    try:
        data = request.get_json()
        validated_data = validate_json_payload(data, ["smartbill_email", "smartbill_token", "cif"])
    except ValueError as ve:
        logger.error("Validation error in /api/get_series: %s", ve)
        return jsonify({"status": "error", "message": str(ve)}), 400

    smartbill_email = validated_data["smartbill_email"]
    smartbill_token = validated_data["smartbill_token"]
    cif = validated_data["cif"]

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
@limiter.limit("20 per minute")
def api_set_default_series():
    try:
        data = request.get_json()
        validated_data = validate_json_payload(data, ["smartbill_email", "smartbill_token", "cif", "default_series"])
    except ValueError as ve:
        logger.error("Validation error in /api/set_default_series: %s", ve)
        return jsonify({"status": "error", "message": str(ve)}), 400

    smartbill_email = validated_data["smartbill_email"]
    smartbill_token = validated_data["smartbill_token"]
    cif = validated_data["cif"]
    default_series = validated_data["default_series"]

    # Process optional fields as before
    data = request.get_json()
    stripe_api_key = data.get("stripe_api_key", "").strip()
    stripe_webhook_secret = data.get("stripe_webhook_secret", "").strip()

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

@app.route("/api/stripe_create_webhooks", methods=["POST"])
@limiter.limit("10 per minute")
def api_stripe_create_webhooks():
    try:
        data = request.get_json()
        validated_data = validate_json_payload(data, ["stripe_test_key", "stripe_live_key"])
    except ValueError as ve:
        logger.error("Validation error in /api/stripe_create_webhooks: %s", ve)
        return jsonify({"status": "error", "message": str(ve)}), 400

    stripe_test_key = validated_data["stripe_test_key"]
    stripe_live_key = validated_data["stripe_live_key"]

    user_record = get_user_record()
    if not user_record:
        logger.error("User record not found. Cannot create Stripe webhooks.")
        return jsonify({"status": "error", "message": "Onboarding incomplete"}), 400

    if not os.environ.get("CUSTOM_INSTANCE_URL"):
        logger.error("CUSTOM_INSTANCE_URL not set.")
        return jsonify({"status": "error", "message": "CUSTOM_INSTANCE_URL not set"}), 500

    CUSTOM_INSTANCE_URL = os.environ.get("CUSTOM_INSTANCE_URL", "https://your-instance-url")
    webhook_test_url = f"{CUSTOM_INSTANCE_URL.rstrip('/')}/stripe-webhook-test"
    webhook_live_url = f"{CUSTOM_INSTANCE_URL.rstrip('/')}/stripe-webhook"

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

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.strip()
        password = form.password.data.strip()
        remote_ip = request.remote_addr
        logger.debug("Attempting login for email: %s from IP: %s", email, remote_ip)

        credentials = get_credentials()
        logger.debug("Retrieved credentials: %s", credentials)
        if not credentials:
            failed_login_attempts[remote_ip] = failed_login_attempts.get(remote_ip, 0) + 1
            attempts = failed_login_attempts[remote_ip]
            logger.error("Login failed: credentials not found for email: %s from IP: %s (attempt %d)", email, remote_ip, attempts)
            if attempts >= 3:
                logger.warning("Potential brute force activity detected from IP %s: %d failed login attempts", remote_ip, attempts)
            flash("Utilizatorul nu există. Vă rugăm să completați onboarding-ul.")
            return redirect(url_for("login"))

        if email != credentials.get("smartbill_email"):
            failed_login_attempts[remote_ip] = failed_login_attempts.get(remote_ip, 0) + 1
            attempts = failed_login_attempts[remote_ip]
            logger.error("Login failed: email mismatch. Provided: %s, expected: %s from IP: %s (attempt %d)", email, credentials.get("smartbill_email"), remote_ip, attempts)
            if attempts >= 3:
                logger.warning("Potential brute force activity detected from IP %s: %d failed login attempts", remote_ip, attempts)
            flash("Utilizatorul nu există. Vă rugăm să completați onboarding-ul.")
            return redirect(url_for("login"))

        stored_hash = credentials.get("password_hash")
        if not stored_hash or not check_password(password, stored_hash):
            failed_login_attempts[remote_ip] = failed_login_attempts.get(remote_ip, 0) + 1
            attempts = failed_login_attempts[remote_ip]
            logger.error("Login failed: incorrect password for email: %s from IP: %s (attempt %d)", email, remote_ip, attempts)
            if attempts >= 3:
                logger.warning("Potential brute force activity detected from IP %s: %d failed login attempts", remote_ip, attempts)
            flash("Parola incorectă!")
            return redirect(url_for("login"))

        # Successful login: reset failed login counter for this IP
        failed_login_attempts.pop(remote_ip, None)
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
@limiter.limit("5 per minute")
def change_password():
    form = ChangePasswordForm()
    credentials = get_credentials()
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
        logger.debug("Updated credentials after password change: %s", db.get("credentials"))

        flash("Parola a fost actualizată cu succes!")
        return redirect(url_for("dashboard"))
    return render_template("change_password.html", form=form)

# =============================================================================
# Facturio Integration Endpoint (Stripe Webhook)
# =============================================================================
from services.utils import build_payload
from services.smartbill import create_smartbill_invoice
from services.idempotency import is_event_processed, mark_event_processed, remove_event
from services.notifications import notify_admin
from services.email_sender import send_invoice_email

@csrf.exempt
@app.route("/stripe-webhook-test", methods=["POST"])
@limiter.limit("100 per minute")
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

@csrf.exempt
@app.route("/stripe-webhook-live", methods=["POST"])
@limiter.limit("100 per minute")
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

# =============================================================================
# Run the Application
# =============================================================================
if __name__ == "__main__":
    port = 8080
    app.run(host="0.0.0.0", port=port)
