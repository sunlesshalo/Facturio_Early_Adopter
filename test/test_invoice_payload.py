import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import unittest
from datetime import datetime, timezone
from services.utils import build_payload  # Updated import

class TestInvoicePayload(unittest.TestCase):
    def setUp(self):
        # Standard configuration for tests.
        self.config = {
            "companyVatCode": "40670956",
            "seriesName": "RO",
            "measuringUnitName": "buc",
            "currency": "RON",
            "taxName": "Normala",
            "taxPercentage": 19,
            "saveToDb": False,
            "isService": True,
            "isTaxIncluded": False,
            "TEST_MODE": False,  # Although not used, can remain for testing purposes.
            "SMARTBILL_USERNAME": "test@example.com"  # Added dynamic SmartBill email.
        }
        # A standard Stripe session dictionary.
        self.standard_session = {
            "created": int(datetime(2025, 2, 17, tzinfo=timezone.utc).timestamp()),
            "amount_total": 20000,  # 20,000 cents => 200.00 RON
            "customer_details": {
                "name": "Test Client",
                "email": "client@example.com",
                "tax_ids": [{"value": "RO12345678"}],
                "address": {
                    "line1": "Str. Example 123",
                    "line2": "Ap. 4",
                    "postal_code": "400275",
                    "city": "Cluj-Napoca",
                    "country": "RO",
                    "state": "Cluj"  # Already valid
                }
            }
        }

    def test_standard_payload(self):
        payload = build_payload(self.standard_session, self.config)
        self.assertAlmostEqual(payload["products"][0]["price"], 200.00)
        self.assertEqual(payload["issueDate"], "2025-02-17")
        self.assertEqual(payload["client"]["email"], "client@example.com")

    def test_missing_tax_ids(self):
        session = self.standard_session.copy()
        customer_details = session["customer_details"].copy()
        customer_details.pop("tax_ids", None)
        session["customer_details"] = customer_details
        payload = build_payload(session, self.config)
        self.assertEqual(payload["client"]["vatCode"], "0000000000000")

    def test_invalid_amount_total(self):
        session = self.standard_session.copy()
        session["amount_total"] = "not a number"
        with self.assertRaises(Exception):
            build_payload(session, self.config)

    def test_zero_product_quantity(self):
        payload = build_payload(self.standard_session, self.config)
        quantity = payload["products"][0].get("quantity", 0)
        self.assertGreater(quantity, 0)

    def test_timestamp_conversion(self):
        session = self.standard_session.copy()
        session["created"] = "invalid_timestamp"
        with self.assertRaises(Exception):
            build_payload(session, self.config)

if __name__ == '__main__':
    unittest.main()
