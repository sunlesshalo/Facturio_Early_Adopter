# config.py
"""
Consolidated Facturio Application Configuration
-----------------------------------
This file provides the default configuration values for the Facturio app.
It is imported by app.py and merged with dynamic values from the user record.
"""

config_defaults = {
    "SMARTBILL_INVOICE_ENDPOINT": "https://ws.smartbill.ro/SBORO/api/invoice",
    "measuringUnitName": "buc",
    "currency": "RON",
    "isTaxIncluded": True,
    "taxName": "TVA",
    "taxPercentage": 19,
    "saveToDb": True,
    "isService": False
}
