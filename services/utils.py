import stripe
from datetime import datetime, timezone
from .geocoding import resolve_county_and_city

def extract_client_details(stripe_data):
    """
    Extracts client details from the Stripe event data.
    If no tax IDs are provided, checks custom fields for CUI, CIF or CNP.
    If none are found, a default VAT code is used.
    """
    customer_details = stripe_data.get('customer_details', {})
    tax_ids = customer_details.get('tax_ids', [])
    vat_code = None
    if tax_ids:
        vat_code = tax_ids[0].get('value')
        print("DEBUG: Found tax_ids, using vat_code:", vat_code)
    if not vat_code or vat_code.strip() == "":
        custom_fields = stripe_data.get('custom_fields', [])
        print("DEBUG: No valid vat_code found in tax_ids; checking custom_fields:", custom_fields)
        for field in custom_fields:
            key = field.get('key', '').lower()
            if key in ['cui', 'cif', 'cnp']:
                value = field.get('text', {}).get('value')
                if value and str(value).strip() != "":
                    vat_code = str(value).strip()
                    print("DEBUG: Found vat_code in custom_fields with key '{}':".format(key), vat_code)
                    break
    if not vat_code or vat_code.strip() == "":
        vat_code = '0000000000000'
        print("DEBUG: No vat_code found in custom_fields; defaulting to:", vat_code)

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
    Payment details are omitted for now.
    """
    client = extract_client_details(stripe_data)
    client_address = client.get('address', {})

    smartbill_email = config.get("SMARTBILL_USERNAME") or config.get("smartbill_email")
    if not smartbill_email:
        raise ValueError("SmartBill email not provided in the configuration.")

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

    product_price = stripe_data.get('amount_subtotal', stripe_data.get('amount_total', 0)) / 100
    print("DEBUG: Product price determined as:", product_price)

    payment_link_id = stripe_data.get("payment_link")
    if payment_link_id:
        service_name = get_service_name_from_payment_link(payment_link_id, config)
        print("DEBUG: Service name resolved from payment link ({}): {}".format(payment_link_id, service_name))
    else:
        service_name = "Service Payment"
        print("DEBUG: No payment link provided; defaulting service name to:", service_name)

    product = {
        'name': service_name,
        'code': '',
        'productDescription': '',
        'isDiscount': False,
        'measuringUnitName': config['measuringUnitName'],
        'currency': config['currency'],
        'quantity': 1,
        'price': product_price,
        'isTaxIncluded': config['isTaxIncluded'],
        'taxName': config['taxName'],
        'taxPercentage': config['taxPercentage'],
        'saveToDb': config['saveToDb'],
        'isService': config['isService']
    }
    print("DEBUG: Main product line constructed:", product)

    products = [product]

    discount_info = get_promotion_discount_info(stripe_data, config)
    print("DEBUG: Discount info retrieved:", discount_info)
    if discount_info:
        if discount_info.get("discountType") == 2:
            discount_percentage = discount_info.get("discountPercentage")
            print("DEBUG: Percentage discount detected: {}%".format(discount_percentage))
            computed_discount_amount = round(product_price * (discount_percentage / 100), 2)
            print("DEBUG: Computed discount amount (percentage based):", computed_discount_amount)
            discount_line = {
                "name": "Discount",
                "isDiscount": True,
                "numberOfItems": 1,
                "discountType": 2,
                "discountPercentage": discount_percentage,
                "measuringUnitName": config['measuringUnitName'],
                "currency": config['currency'],
                "quantity": 1,
                "price": computed_discount_amount,
                "isTaxIncluded": config['isTaxIncluded'],
                "taxName": config['taxName'],
                "taxPercentage": config['taxPercentage'],
                "saveToDb": config['saveToDb'],
                "isService": config['isService']
            }
            print("DEBUG: Discount line constructed (percentage):", discount_line)
        elif discount_info.get("discountType") == 1:
            discount_value = discount_info.get("discountValue") / 100.0
            print("DEBUG: Fixed amount discount detected:", discount_value)
            discount_line = {
                "name": "Discount",
                "isDiscount": True,
                "numberOfItems": 1,
                "discountType": 1,
                "discountValue": discount_value,
                "measuringUnitName": config['measuringUnitName'],
                "currency": config['currency'],
                "quantity": 1,
                "price": discount_value,
                "isTaxIncluded": config['isTaxIncluded'],
                "taxName": config['taxName'],
                "taxPercentage": config['taxPercentage'],
                "saveToDb": config['saveToDb'],
                "isService": config['isService']
            }
            print("DEBUG: Discount line constructed (fixed amount):", discount_line)
        else:
            discount_line = None
            print("DEBUG: Discount info did not match expected types; no discount line created.")

        if discount_line:
            products.append(discount_line)
            print("DEBUG: Discount line appended to products.")

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
        "products": products,
    }

    print("DEBUG: Built payload:", payload)
    return payload

def get_promotion_discount_info(stripe_data, config):
    print("DEBUG: Starting promotion discount verification.")
    discounts = stripe_data.get("discounts", [])
    print("DEBUG: Discounts found in stripe data:", discounts)
    if discounts:
        discount_obj = discounts[0]
        print("DEBUG: Using first discount object:", discount_obj)
        promo_code_id = discount_obj.get("promotion_code")
        print("DEBUG: Promotion code ID retrieved:", promo_code_id)
        if promo_code_id:
            stripe.api_key = config.get("stripe_api_key")
            try:
                promo_data = stripe.PromotionCode.retrieve(promo_code_id)
                print("DEBUG: Retrieved promo_data:", promo_data)
                coupon = promo_data.get("coupon")
                print("DEBUG: Coupon retrieved from promo_data:", coupon)
                if coupon:
                    if coupon.get("percent_off") is not None:
                        print("DEBUG: Percentage discount found: {}%".format(coupon.get("percent_off")))
                        return {
                            "discountType": 2,
                            "discountPercentage": coupon.get("percent_off")
                        }
                    elif coupon.get("amount_off") is not None:
                        print("DEBUG: Fixed amount discount found:", coupon.get("amount_off"))
                        return {
                            "discountType": 1,
                            "discountValue": coupon.get("amount_off")
                        }
                else:
                    print("DEBUG: No coupon found in promo_data; checking total_details for discount info.")
                    total_details = stripe_data.get("total_details", {})
                    amount_discount = total_details.get("amount_discount")
                    amount_subtotal = stripe_data.get("amount_subtotal")
                    if amount_discount is not None and amount_subtotal:
                        discount_percentage = (amount_discount / amount_subtotal) * 100
                        print("DEBUG: Computed discount percentage from total_details: {}%".format(discount_percentage))
                        return {
                            "discountType": 2,
                            "discountPercentage": discount_percentage
                        }
            except Exception as e:
                print("ERROR: Error retrieving promotion code:", e)
    print("DEBUG: No valid discount information found in stripe data.")
    return None

def get_service_name_from_payment_link(payment_link_id, config):
    try:
        stripe.api_key = config.get("stripe_api_key")
        payment_link = stripe.PaymentLink.retrieve(
            payment_link_id,
            expand=["line_items.data.price.product"]
        )
        line_items = payment_link.get("line_items", {}).get("data", [])
        if line_items:
            product_obj = line_items[0]["price"]["product"]
            service_name = product_obj.get("name")
            if service_name:
                return service_name
    except Exception as e:
        print("ERROR: Error retrieving service name from payment link:", e)
    return "Service Payment"
