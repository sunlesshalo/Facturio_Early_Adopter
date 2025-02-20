# File: idempotency.py
"""
Idempotency storage for webhook event IDs using Replit DB.
This replaces our in-memory set.
Note: Replit DB is available in the Replit environment.
"""

from replit import db

def is_event_processed(event_id):
    """
    Check if the given event_id has already been processed.
    Returns True if processed, False otherwise.
    """
    return f"processed:{event_id}" in db

def mark_event_processed(event_id):
    """
    Mark the event_id as processed.
    """
    db[f"processed:{event_id}"] = True

def remove_event(event_id):
    """
    Remove the event_id from the store (e.g., if processing fails and you want to allow reprocessing).
    """
    key = f"processed:{event_id}"
    if key in db:
        del db[key]
