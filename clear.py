import os
import json
import stripe
import base64
import requests
from replit import db
from cryptography.fernet import Fernet
from config import config_defaults

def get_fernet():
    config_key = os.environ.get("CONFIG_KEY")
    if not config_key:
        raise Exception("CONFIG_KEY environment variable is not set.")
    return Fernet(config_key.encode())

def clear_user_data():
    user_record_raw = db.get("user_record")
    if user_record_raw:
        try:
            f = get_fernet()
            encrypted_bytes = user_record_raw.encode("utf-8")
            user_record = json.loads(f.decrypt(encrypted_bytes).decode("utf-8"))
        except Exception as e:
            print("Eroare la decriptarea user record. Poate fi corupt sau deja șters:", e)
            user_record = {}

        # Delete Stripe webhook if exists
        webhook = user_record.get("stripe_webhook")
        if webhook and isinstance(webhook, dict):
            webhook_id = webhook.get("id")
            if webhook_id:
                stripe.api_key = user_record.get("stripe_api_key", os.environ.get("STRIPE_API_KEY", ""))
                try:
                    stripe.WebhookEndpoint.delete(webhook_id)
                    print(f"Confirmare: Webhook-ul Stripe a fost șters: {webhook_id}")
                except Exception as e:
                    print(f"Eroare la ștergerea webhook-ului {webhook_id}: {e}")
            else:
                print("Nu s-a găsit ID-ul webhook-ului în user record.")
        else:
            print("Nu s-a găsit webhook-ul Stripe în user record.")

        # Delete SmartBill invoices through an API call
        if "invoices" in db:
            invoices = db["invoices"]
            if invoices:
                smartbill_username = user_record.get("smartbill_email")
                smartbill_token = user_record.get("smartbill_token")
                cif = user_record.get("cif")
                default_series = user_record.get("default_series")
                if not smartbill_username or not smartbill_token:
                    print("SmartBill credentials lipsesc în user record. Nu se pot șterge facturile SmartBill.")
                elif not cif or not default_series:
                    print("Parametrii CIF sau default_series lipsesc în user record. Nu se pot șterge facturile SmartBill.")
                else:
                    # Build the authorization header for SmartBill API
                    auth_string = f"{smartbill_username}:{smartbill_token}"
                    encoded_auth = base64.b64encode(auth_string.encode("utf-8")).decode("utf-8")
                    headers = {
                        "Content-Type": "application/json",
                        "Authorization": f"Basic {encoded_auth}"
                    }
                    # Use the known deletion endpoint base
                    base_endpoint = "https://ws.smartbill.ro/SBORO/api/invoice"
                    for invoice in invoices:
                        # Determine the invoice number:
                        if isinstance(invoice, dict):
                            if "invoice_id" in invoice:
                                full_invoice_id = invoice["invoice_id"]
                                if full_invoice_id.startswith(default_series):
                                    invoice_number = full_invoice_id[len(default_series):]
                                else:
                                    invoice_number = full_invoice_id
                            elif "number" in invoice:
                                invoice_number = invoice["number"]
                            else:
                                invoice_number = str(invoice)
                        else:
                            invoice_number = str(invoice)
                        if not invoice_number:
                            print("Factura fără număr găsită; nu se poate construi URL-ul de ștergere.")
                            continue

                        # Construct the deletion URL using the required format
                        delete_url = f"{base_endpoint}?cif={cif}&seriesName={default_series}&number={invoice_number}"
                        try:
                            response = requests.delete(delete_url, headers=headers)
                            if response.status_code in (200, 201, 204):
                                print(f"Confirmare: Factura SmartBill {invoice_number} a fost ștearsă.")
                            else:
                                print(f"Eroare la ștergerea facturii {invoice_number}. Cod status: {response.status_code}. Răspuns: {response.text}")
                        except Exception as e:
                            print(f"Eroare la efectuarea cererii de ștergere pentru factura {invoice_number}: {e}")
            else:
                print("Nu s-au găsit facturi înregistrate în db.")
            # Delete invoices from db
            del db["invoices"]
            print("Facturile înregistrate au fost șterse din baza de date.")
        else:
            print("Nu s-au găsit facturi în baza de date.")

        # Finally, delete the user record from the database
        del db["user_record"]
        print("User record șters din baza de date.")
    else:
        print("Nu s-a găsit user record.")

if __name__ == "__main__":
    clear_user_data()
