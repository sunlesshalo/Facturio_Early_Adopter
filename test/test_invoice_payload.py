import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import unittest
from datetime import datetime, timezone
from unittest.mock import patch
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

    @patch('services.utils.get_promotion_discount_info')
    def test_discount_percentage(self, mock_get_discount):
        # Set up discount info for percentage discount
        mock_get_discount.return_value = {"discountType": 2, "discountPercentage": 10}
        payload = build_payload(self.standard_session, self.config)
        # There should be two products: main product and discount line
        self.assertEqual(len(payload["products"]), 2)
        discount_line = payload["products"][1]
        expected_discount = round(200.00 * (10 / 100), 2)
        self.assertEqual(discount_line["isDiscount"], True)
        self.assertEqual(discount_line.get("discountType"), 2)
        self.assertAlmostEqual(discount_line.get("price"), expected_discount)

    @patch('services.utils.get_promotion_discount_info')
    def test_discount_fixed(self, mock_get_discount):
        # Set up discount info for fixed discount (discountValue in cents)
        mock_get_discount.return_value = {"discountType": 1, "discountValue": 500}
        payload = build_payload(self.standard_session, self.config)
        # There should be two products: main product and discount line
        self.assertEqual(len(payload["products"]), 2)
        discount_line = payload["products"][1]
        expected_discount = 500 / 100.0  # 5.0
        self.assertEqual(discount_line["isDiscount"], True)
        self.assertEqual(discount_line.get("discountType"), 1)
        self.assertAlmostEqual(discount_line.get("price"), expected_discount)
        self.assertAlmostEqual(discount_line.get("discountValue"), expected_discount)

    @patch('services.utils.get_service_name_from_payment_link')
    def test_service_name_resolution(self, mock_get_service_name):
        # Set up service name resolution via payment_link
        mock_get_service_name.return_value = "Test Service"
        session = self.standard_session.copy()
        session["payment_link"] = "dummy_link"
        payload = build_payload(session, self.config)
        self.assertEqual(payload["products"][0]["name"], "Test Service")

if __name__ == '__main__':
    unittest.main()
