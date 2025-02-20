import requests
import json
import logging

logger = logging.getLogger(__name__)

def create_smartbill_invoice(payload):
    """
    Creates a new invoice using the SmartBill API.

    Expects:
      - payload: A dictionary containing all invoice details, including the key
                 "SMARTBILL_INVOICE_ENDPOINT" from the merged configuration.

    Returns:
      - A dictionary with the SmartBill API response.

    Raises:
      - ValueError if the endpoint is missing.
      - HTTP or request exceptions if the API call fails.
    """
    # Retrieve the endpoint from the payload
    endpoint = payload.get("SMARTBILL_INVOICE_ENDPOINT")
    if not endpoint:
        logger.error("SMARTBILL_INVOICE_ENDPOINT is missing in the configuration.")
        raise ValueError("SMARTBILL_INVOICE_ENDPOINT is missing in the configuration.")

    headers = {
        "Content-Type": "application/json"
    }

    logger.debug("Sending invoice creation payload to %s", endpoint)
    try:
        response = requests.post(endpoint, headers=headers, json=payload)
        response.raise_for_status()
        invoice_data = response.json()
        logger.info("Invoice created successfully: %s", invoice_data)
        return invoice_data
    except requests.exceptions.HTTPError as errh:
        logger.error("HTTP error during invoice creation: %s", errh)
        raise
    except requests.exceptions.RequestException as err:
        logger.error("Error during invoice creation: %s", err)
        raise

def delete_smartbill_invoice(invoice_number, config):
    """
    Deletes an invoice using the SmartBill API.

    Expects:
      - invoice_number: The number of the invoice to delete.
      - config: A configuration dictionary that must include "SMARTBILL_INVOICE_ENDPOINT".

    Returns:
      - A dictionary with the SmartBill API response from the deletion request.

    Raises:
      - ValueError if the configuration or endpoint is missing.
      - HTTP or request exceptions if the API call fails.

    Note:
      This implementation assumes that the deletion endpoint can be constructed
      by appending the invoice number to the base endpoint.
    """
    if config is None:
        raise ValueError("Configuration must be provided for deleting the invoice.")

    endpoint = config.get("SMARTBILL_INVOICE_ENDPOINT")
    if not endpoint:
        logger.error("SMARTBILL_INVOICE_ENDPOINT is missing in the configuration.")
        raise ValueError("SMARTBILL_INVOICE_ENDPOINT is missing in the configuration.")

    # Construct deletion endpoint (assumed to be base endpoint + '/' + invoice_number)
    delete_endpoint = f"{endpoint}/{invoice_number}"

    headers = {
        "Content-Type": "application/json"
    }

    logger.debug("Sending invoice deletion request to %s", delete_endpoint)
    try:
        response = requests.delete(delete_endpoint, headers=headers)
        response.raise_for_status()
        deletion_data = response.json()
        logger.info("Invoice deleted successfully: %s", deletion_data)
        return deletion_data
    except requests.exceptions.HTTPError as errh:
        logger.error("HTTP error during invoice deletion: %s", errh)
        raise
    except requests.exceptions.RequestException as err:
        logger.error("Error during invoice deletion: %s", err)
        raise
