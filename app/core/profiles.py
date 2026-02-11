"""
NetRunner OS - JSON Profile System
Replaces SQLite. Manages named profiles with rewrite rules, labels, replay settings, etc.
"""

import os
import json
import time
import uuid
from datetime import datetime

PROFILES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'data', 'profiles')

def _ensure_dir():
    os.makedirs(PROFILES_DIR, exist_ok=True)

def _profile_path(profile_id):
    return os.path.join(PROFILES_DIR, f"{profile_id}.json")

def _default_profile(name="Untitled Profile"):
    return {
        "id": str(uuid.uuid4())[:8],
        "name": name,
        "created": datetime.now().isoformat(),
        "modified": datetime.now().isoformat(),
        "labels": {},
        "rewrite_rules": {
            "ip_map": {},
            "mac_map": {},
            "port_map": {}
        },
        "replay_settings": {
            "interface": "",
            "speed": "original",
            "loop": False,
            "loop_count": 1,
            "ttl": None,
            "vlan_id": None
        },
        "generator_presets": {}
    }

def list_profiles():
    """Return a list of all saved profiles (summary only)."""
    _ensure_dir()
    profiles = []
    for fname in os.listdir(PROFILES_DIR):
        if fname.endswith('.json'):
            try:
                with open(os.path.join(PROFILES_DIR, fname), 'r') as f:
                    data = json.load(f)
                profiles.append({
                    "id": data.get("id", fname.replace('.json', '')),
                    "name": data.get("name", "Untitled"),
                    "created": data.get("created", ""),
                    "modified": data.get("modified", ""),
                    "labels_count": len(data.get("labels", {})),
                    "rules_count": (
                        len(data.get("rewrite_rules", {}).get("ip_map", {})) +
                        len(data.get("rewrite_rules", {}).get("mac_map", {}))
                    )
                })
            except (json.JSONDecodeError, IOError):
                continue
    profiles.sort(key=lambda p: p.get("modified", ""), reverse=True)
    return profiles

def get_profile(profile_id):
    """Load a full profile by ID."""
    path = _profile_path(profile_id)
    if not os.path.exists(path):
        return None
    with open(path, 'r') as f:
        return json.load(f)

def save_profile(data):
    """Save a profile. If no ID, creates a new one. Returns the saved profile."""
    _ensure_dir()
    if not data.get("id"):
        data = {**_default_profile(data.get("name", "Untitled Profile")), **data}
        data["id"] = str(uuid.uuid4())[:8]
    data["modified"] = datetime.now().isoformat()
    if not data.get("created"):
        data["created"] = data["modified"]
    
    with open(_profile_path(data["id"]), 'w') as f:
        json.dump(data, f, indent=2)
    return data

def delete_profile(profile_id):
    """Delete a profile by ID. Returns True if deleted."""
    path = _profile_path(profile_id)
    if os.path.exists(path):
        os.remove(path)
        return True
    return False

def export_profile(profile_id):
    """Export a profile as a portable JSON dict."""
    return get_profile(profile_id)

def import_profile(data):
    """Import a profile from a JSON dict. Assigns a new ID to avoid collisions."""
    data["id"] = str(uuid.uuid4())[:8]
    data["name"] = data.get("name", "Imported Profile") + " (imported)"
    return save_profile(data)
