# File: services/utils.py

import logging
from datetime import datetime, timezone
from .geocoding import resolve_county_and_city

logger = logging.getLogger(__name__)

def extract_client_details(stripe_data):
    """
    Extracts client details from the Stripe event data.
    If no tax IDs are provided, a default VAT code is used.
    """
    customer_details = stripe_data.get('customer_details', {})
    tax_ids = customer_details.get('tax_ids', [])
    vat_code = tax_ids[0].get('value', '0000000000000') if tax_ids else '0000000000000'

    return {
        'name': customer_details.get('name', 'Unknown Client'),
        'email': customer_details.get('email', 'unknown@example.com'),
        'vatCode': vat_code,
        'address': customer_details.get('address', {})
    }

def remove_empty_values(data):
    if isinstance(data, dict):
        return {k: remove_empty_values(v) for k, v in data.items() if v != ""}
    elif isinstance(data, list):
        return [remove_empty_values(item) for item in data if item != ""]
    else:
        return data

def build_payload(stripe_data, config):
    """
    Constructs the final invoice payload for SmartBill.
    Payment details are always included.
    """
    client = extract_client_details(stripe_data)
    client_address = client.get('address', {})

    # Retrieve the dynamic smartbill email from config.
    smartbill_email = config.get("SMARTBILL_USERNAME") or config.get("smartbill_email")
    if not smartbill_email:
        raise ValueError("SmartBill email not provided in the configuration.")

    # Pass the dynamic smartbill email to resolve_county_and_city.
    county, city = resolve_county_and_city(client_address, smartbill_email)

    address_parts = [
        client_address.get('line1', ''),
        client_address.get('line2', ''),
        client_address.get('postal_code', '')
    ]
    full_address = ', '.join([part for part in address_parts if part])
    is_taxpayer = client['vatCode'].startswith('RO')
    issue_timestamp = stripe_data.get('created')
    issue_date = datetime.fromtimestamp(issue_timestamp, tz=timezone.utc).strftime('%Y-%m-%d')

    product = {
        'name': 'Placeholder Product',
        'code': '',
        'productDescription': '',
        'isDiscount': False,
        'measuringUnitName': config['measuringUnitName'],
        'currency': config['currency'],
        'quantity': 1,
        'price': stripe_data.get('amount_total', 0) / 100,  # Convert from cents.
        'isTaxIncluded': config['isTaxIncluded'],
        'taxName': config['taxName'],
        'taxPercentage': config['taxPercentage'],
        'saveToDb': config['saveToDb'],
        'isService': config['isService']
    }

    payload = {
        "companyVatCode": config['companyVatCode'],
        "client": {
            "name": client['name'],
            "vatCode": client['vatCode'],
            "isTaxPayer": is_taxpayer,
            "address": full_address,
            "city": city,
            "county": county,
            "country": client_address.get('country', 'Unknown Country'),
            "email": client['email'],
            "saveToDb": config['saveToDb']
        },
        "issueDate": issue_date,
        "seriesName": config['seriesName'],
        "isDraft": False,
        "dueDate": issue_date,
        "deliveryDate": "",
        "products": [product],
    }

    payload["payment"] = {
        "value": stripe_data.get('amount_total', 0) / 100,
        "paymentSeries": "",
        "type": "Card",
        "isCash": False
    }

    payload = remove_empty_values(payload)
    logger.debug("Built payload: %s", payload)
    return payload
