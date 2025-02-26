import os
import json
import stripe
import base64
import requests
import logging
from replit import db
from cryptography.fernet import Fernet
from config import config_defaults

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_fernet():
    config_key = os.environ.get("CONFIG_KEY")
    if not config_key:
        raise Exception("CONFIG_KEY environment variable is not set.")
    return Fernet(config_key.encode())

def clear_user_data():
    # First, clear the credentials record regardless of user record existence
    if "credentials" in db:
        try:
            del db["credentials"]
            logger.info("Credentials record deleted from database.")
        except Exception as e:
            logger.error("Error deleting credentials record: %s", e)
    else:
        logger.info("No credentials record found in database.")

    # Then, clear invoices if present
    if "invoices" in db:
        invoices_raw = db["invoices"]
        try:
            invoices = json.loads(invoices_raw)
        except Exception as e:
            logger.error("Error parsing invoices JSON: %s", e)
            invoices = []
        if invoices:
            logger.info("Found invoices in database; proceeding to delete them.")
            # If possible, attempt deletion via SmartBill API
            try:
                f = get_fernet()
                user_record_raw = db.get("user_record")
                if user_record_raw:
                    user_record = json.loads(f.decrypt(user_record_raw.encode("utf-8")).decode("utf-8"))
                    smartbill_username = user_record.get("smartbill_email")
                    smartbill_token = user_record.get("smartbill_token")
                    cif = user_record.get("cif")
                    default_series = user_record.get("default_series")
                    if not smartbill_username or not smartbill_token:
                        logger.warning("SmartBill credentials missing in user record. Cannot delete SmartBill invoices.")
                    elif not cif or not default_series:
                        logger.warning("Missing 'cif' or 'default_series' in user record. Cannot delete SmartBill invoices.")
                    else:
                        auth_string = f"{smartbill_username}:{smartbill_token}"
                        encoded_auth = base64.b64encode(auth_string.encode("utf-8")).decode("utf-8")
                        headers = {
                            "Content-Type": "application/json",
                            "Authorization": f"Basic {encoded_auth}"
                        }
                        base_endpoint = "https://ws.smartbill.ro/SBORO/api/invoice"
                        # Iterate over the invoices in reverse order (newest first)
                        for invoice in reversed(invoices):
                            if isinstance(invoice, dict):
                                if "event_number" in invoice:
                                    invoice_number = invoice["event_number"]
                                elif "invoice_id" in invoice:
                                    invoice_number = invoice["invoice_id"]
                                elif "number" in invoice:
                                    invoice_number = invoice["number"]
                                else:
                                    invoice_number = str(invoice)
                            else:
                                invoice_number = str(invoice)
                            if not invoice_number:
                                logger.warning("Invoice without a number found; cannot build deletion URL.")
                                continue

                            delete_url = f"{base_endpoint}?cif={cif}&seriesname={default_series}&number={invoice_number}"
                            try:
                                response = requests.delete(delete_url, headers=headers)
                                if response.status_code in (200, 201, 204):
                                    logger.info("Invoice %s deleted from SmartBill.", invoice_number)
                                else:
                                    logger.error("Error deleting invoice %s. Status code: %s. Response: %s",
                                                 invoice_number, response.status_code, response.text)
                            except Exception as e:
                                logger.error("Error sending deletion request for invoice %s: %s", invoice_number, e)
                else:
                    logger.info("User record not found; skipping SmartBill invoice deletion.")
            except Exception as e:
                logger.error("Error processing invoices deletion: %s", e)
        else:
            logger.info("No invoices found in db.")
        try:
            del db["invoices"]
            logger.info("Invoices removed from database.")
        except Exception as e:
            logger.error("Error deleting invoices key: %s", e)
    else:
        logger.info("No invoices key found in db.")

    # Delete Stripe webhook if exists in user record
    if "user_record" in db:
        try:
            user_record_raw = db.get("user_record")
            if user_record_raw:
                f = get_fernet()
                user_record = json.loads(f.decrypt(user_record_raw.encode("utf-8")).decode("utf-8"))
                stripe_api_key = user_record.get("stripe_api_key")
                stripe_webhook = user_record.get("stripe_webhook")
                if stripe_api_key and stripe_webhook and stripe_webhook.get("id"):
                    stripe.api_key = stripe_api_key
                    stripe.WebhookEndpoint.delete(stripe_webhook.get("id"))
                    logger.info("Deleted Stripe webhook with id: %s", stripe_webhook.get("id"))
            else:
                logger.info("User record empty, skipping Stripe webhook deletion.")
        except Exception as e:
            logger.error("Error deleting Stripe webhook in clear_user_data: %s", e)

    # Finally, clear the user record if it exists
    if "user_record" in db:
        try:
            del db["user_record"]
            logger.info("User record deleted from database.")
        except Exception as e:
            logger.error("Error deleting user record: %s", e)
    else:
        logger.info("User record not found.")

if __name__ == "__main__":
    clear_user_data()
