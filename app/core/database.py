import sqlite3
import json

DB_FILE = 'net_sim_studio.db'

def init_database():
    """Initializes the database and creates tables if they don't exist."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    # Asset Management Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            ip TEXT NOT NULL,
            mac TEXT NOT NULL
        )
    ''')
    # Replay Configurations Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS replay_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            interface TEXT,
            replay_speed TEXT,
            loop_replay BOOLEAN,
            loop_count INTEGER,
            ttl INTEGER,
            vlan_id INTEGER,
            ip_map TEXT,
            mac_map TEXT,
            port_map TEXT
        )
    ''')
    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn
