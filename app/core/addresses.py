"""
NetRunner OS - Address Book
Persistent storage for IP/MAC address pairs.
"""

import os
import json
import uuid

ADDRESSES_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    'data', 'addresses.json'
)


def _ensure_file():
    os.makedirs(os.path.dirname(ADDRESSES_FILE), exist_ok=True)
    if not os.path.exists(ADDRESSES_FILE):
        with open(ADDRESSES_FILE, 'w') as f:
            json.dump([], f)


def list_addresses():
    """Return all saved address entries."""
    _ensure_file()
    with open(ADDRESSES_FILE, 'r') as f:
        return json.load(f)


def _save_all(addresses):
    _ensure_file()
    with open(ADDRESSES_FILE, 'w') as f:
        json.dump(addresses, f, indent=2)


def add_address(name, ip, mac):
    """Add a new address entry. Returns the new entry."""
    addresses = list_addresses()
    entry = {
        "id": str(uuid.uuid4())[:8],
        "name": name,
        "ip": ip,
        "mac": mac
    }
    addresses.append(entry)
    _save_all(addresses)
    return entry


def delete_address(address_id):
    """Delete an address entry by ID. Returns True if deleted."""
    addresses = list_addresses()
    filtered = [a for a in addresses if a["id"] != address_id]
    if len(filtered) == len(addresses):
        return False
    _save_all(filtered)
    return True
