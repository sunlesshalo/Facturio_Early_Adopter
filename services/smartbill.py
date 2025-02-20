import requests
import json
import logging
import base64
from config import config_defaults  # Import config defaults

logger = logging.getLogger(__name__)

def create_smartbill_invoice(payload, config):
    """
    Creates a new invoice using the SmartBill API.
    Reads the endpoint from config_defaults and uses dynamic credentials from config.
    """
    # Retrieve the endpoint from configuration defaults.
    endpoint = config_defaults.get("SMARTBILL_INVOICE_ENDPOINT")
    if not endpoint:
        logger.error("SMARTBILL_INVOICE_ENDPOINT is missing in the configuration.")
        raise ValueError("SMARTBILL_INVOICE_ENDPOINT is missing in the configuration.")

    # Retrieve SmartBill credentials from the dynamic configuration (stored in the unified user record).
    smartbill_username = config.get("SMARTBILL_USERNAME")
    smartbill_token = config.get("smartbill_token")
    if not (smartbill_username and smartbill_token):
        logger.error("SmartBill credentials are missing in the configuration.")
        raise ValueError("SmartBill credentials are missing in the configuration.")

    # Construct the Basic Authentication header.
    auth_string = f"{smartbill_username}:{smartbill_token}"
    encoded_auth = base64.b64encode(auth_string.encode("utf-8")).decode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Basic {encoded_auth}"
    }

    logger.debug("Sending invoice creation payload to %s", endpoint)
    logger.debug("Payload for invoice creation: %s", json.dumps(payload, indent=2))

    try:
        response = requests.post(endpoint, headers=headers, json=payload)
        logger.debug("HTTP response status: %s", response.status_code)
        logger.debug("HTTP response text: %s", response.text)
        response.raise_for_status()
        invoice_data = response.json()
        logger.info("Invoice created successfully: %s", json.dumps(invoice_data, indent=2))
        return invoice_data
    except requests.exceptions.HTTPError as errh:
        logger.error("HTTP error during invoice creation: %s", errh)
        raise
    except requests.exceptions.RequestException as err:
        logger.error("Error during invoice creation: %s", err)
        raise
