"""
NetRunner OS - Address Book
Persistent storage for IP/MAC address pairs.
"""

import os
import json
import re
import uuid

ADDRESSES_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    'data', 'addresses.json'
)

# ── Validation ──────────────────────────────────────────────────────────────

_IP_RE = re.compile(
    r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
)
_MAC_RE = re.compile(
    r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$'
)


def validate_ip(ip):
    """Return (ok, error_message) for an IPv4 address string."""
    if not ip or not ip.strip():
        return False, 'IP address is required.'
    m = _IP_RE.match(ip.strip())
    if not m:
        return False, 'Invalid IP format. Expected: 0-255.0-255.0-255.0-255'
    for octet in m.groups():
        if int(octet) > 255:
            return False, 'Each IP octet must be between 0 and 255.'
    return True, ''


def validate_mac(mac):
    """Return (ok, error_message) for a MAC address string. Empty is OK."""
    if not mac or not mac.strip():
        return True, ''  # MAC is optional
    if not _MAC_RE.match(mac.strip()):
        return False, 'Invalid MAC format. Expected: aa:bb:cc:dd:ee:ff'
    return True, ''


# ── Storage helpers ─────────────────────────────────────────────────────────

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
    """Add a new address entry. Raises ValueError on bad format."""
    ok, err = validate_ip(ip)
    if not ok:
        raise ValueError(err)
    ok, err = validate_mac(mac)
    if not ok:
        raise ValueError(err)

    addresses = list_addresses()
    entry = {
        "id": str(uuid.uuid4())[:8],
        "name": name,
        "ip": ip.strip(),
        "mac": mac.strip() if mac else ''
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
