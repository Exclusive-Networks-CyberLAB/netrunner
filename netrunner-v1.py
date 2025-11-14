#
#    // START BOOT SEQUENCE: NETRUNNER_OS
#
#    $ [lOadINg... //]
#
#    _   _      _   _     _   _     _   _     _   _     _   _     _   _
#   / \ / \    / \ / \   / \ / \   / \ / \   / \ / \   / \ / \   / \ / \
#  ( N | E )  ( T | R ) ( U | N ) ( N | E ) ( R | _ ) ( O | S ) ( _ | > )
#   \_/ \_/    \_/ \_/   \_/ \_/   \_/ \_/   \_/ \_/   \_/ \_/   \_/ \_/
#
#    $ [pAckeT_iNjeCtOr.so // lOadEd]
#    $ [sImUlaTiOn_cOrE.so // lOadEd]
##   [Developed for CyberLAB 2025 - John Aziz (mainly Google Gemini)]
#
#    >> READY FOR JACK-IN


# Now, the rest of the imports can proceed safely
import os
import sys
from collections import deque, defaultdict
import subprocess
import importlib.util
import threading
import time
import sqlite3
import json
from flask import Flask, request, jsonify, render_template_string
from scapy.all import PcapReader, sendp, get_if_hwaddr, Ether, IP, TCP, UDP, ICMP, Raw, Dot1Q
from scapy.layers.inet import TCP, UDP, IP, ICMP
from scapy.layers.l2 import Ether, Dot1Q
from werkzeug.utils import secure_filename

# --- App Constants ---
PACKET_VIEWER_LIMIT = 500
ADVERSARY_HEURISTIC_THRESHOLD = 3 # Min "unique scan" score to be flagged
DB_FILE = 'net_sim_studio.db'

# --- Database Setup ---
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

# --- Flask App Setup ---
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# --- Global State for Active Task ---
# This single dictionary will manage the state for either replaying or generating.
active_task_status = {
    'is_running': False,
    'task_type': None, # 'replay' or 'generate'
    'message': 'Ready to start a task.',
    'progress': 0,
    'total': 0,
    'loop_count': 0,
    'packets_per_second': 0,
    'logs': deque(maxlen=100),
    'error': None
}

# --- Helper & Core Logic ---
def log_message(msg):
    """Helper to print to console and add to web UI log."""
    print(msg)
    active_task_status['logs'].append(f'[{time.strftime("%H:%M:%S")}] {msg}')

def replay_pcap_task(params: dict):
    """The core replay function."""
    try:
        log_message(f"[*] PCAP Replay Task Initialized.")
        log_message(f"    - Interface: {params['interface']}")
        log_message(f"    - Speed: {params['replay_speed']}, Loop: {params['loop_replay']}")
        if params['loop_replay']:
            loop_target = params['loop_count'] if params['loop_count'] > 0 else "Infinite"
            log_message(f"    - Loop Count: {loop_target}")
        if params['ttl']: log_message(f"    - Set TTL: {params['ttl']}")
        if params['vlan_id']: log_message(f"    - Set VLAN ID: {params['vlan_id']}")
        if params['ip_map']: log_message(f"    - IP Maps: {params['ip_map']}")
        if params['mac_map']: log_message(f"    - MAC Maps: {params['mac_map']}")
        if params['port_map']: log_message(f"    - Port Maps: {params['port_map']}")

        log_message("[*] Counting packets in PCAP file...")
        with PcapReader(params['filepath']) as pcap_reader_for_count:
            total_packets = sum(1 for _ in pcap_reader_for_count)
        active_task_status['total'] = total_packets
        log_message(f"[*] Found {total_packets} packets.")

        current_loop = 1
        
        while active_task_status['is_running']:
            active_task_status['loop_count'] = current_loop
            log_message(f"[*] Starting replay loop #{current_loop}...")
            
            packets = PcapReader(params['filepath'])
            last_packet_time = None
            pps_start_time = time.time()
            pps_packet_count = 0

            for i, packet in enumerate(packets):
                if not active_task_status['is_running']:
                    log_message("[!] Stop signal received. Halting replay.")
                    break

                active_task_status['progress'] = i + 1
                active_task_status['message'] = f"Loop {current_loop}: Sending packet {i+1} of {total_packets}"
                
                pps_packet_count += 1
                if time.time() - pps_start_time >= 1.0:
                    active_task_status['packets_per_second'] = pps_packet_count
                    pps_packet_count = 0
                    pps_start_time = time.time()

                if params['replay_speed'] == 'original':
                    if last_packet_time is None: last_packet_time = packet.time
                    delay = packet.time - last_packet_time
                    if delay > 0: time.sleep(float(delay))
                    last_packet_time = packet.time

                modified_packet = packet.copy()
                
                if params['vlan_id'] is not None:
                    if modified_packet.haslayer(Dot1Q): modified_packet.getlayer(Dot1Q).vlan = params['vlan_id']
                    elif modified_packet.haslayer(Ether):
                        payload = modified_packet[Ether].payload
                        modified_packet = Ether(src=modified_packet[Ether].src, dst=modified_packet[Ether].dst) / Dot1Q(vlan=params['vlan_id']) / payload

                if params['mac_map'] and modified_packet.haslayer(Ether):
                    ether_layer = modified_packet.getlayer(Ether)
                    if ether_layer.src in params['mac_map']: ether_layer.src = params['mac_map'][ether_layer.src]
                    if ether_layer.dst in params['mac_map']: ether_layer.dst = params['mac_map'][ether_layer.dst]

                if modified_packet.haslayer(IP):
                    ip_layer = modified_packet.getlayer(IP)
                    if params['ip_map']:
                        if ip_layer.src in params['ip_map']: ip_layer.src = params['ip_map'][ip_layer.src]
                        if ip_layer.dst in params['ip_map']: ip_layer.dst = params['ip_map'][ip_layer.dst]
                    if params['ttl'] is not None: ip_layer.ttl = params['ttl']
                    
                    if params['port_map']:
                        if ip_layer.haslayer(TCP):
                            tcp_layer = ip_layer.getlayer(TCP)
                            if str(tcp_layer.sport) in params['port_map']: tcp_layer.sport = params['port_map'][str(tcp_layer.sport)]
                            if str(tcp_layer.dport) in params['port_map']: tcp_layer.dport = params['port_map'][str(tcp_layer.dport)]
                        elif ip_layer.haslayer(UDP):
                            udp_layer = ip_layer.getlayer(UDP)
                            if str(udp_layer.sport) in params['port_map']: udp_layer.sport = params['port_map'][str(udp_layer.sport)]
                            if str(udp_layer.dport) in params['port_map']: udp_layer.dport = params['port_map'][str(udp_layer.dport)]
                    
                    if ip_layer.chksum is not None: del ip_layer.chksum
                    if ip_layer.haslayer(TCP) and ip_layer[TCP].chksum is not None: del ip_layer[TCP].chksum
                    elif ip_layer.haslayer(UDP) and ip_layer[UDP].chksum is not None: del ip_layer[UDP].chksum

                sendp(modified_packet, iface=params['interface'], verbose=0)
            
            if not params['loop_replay']: break
            if params['loop_count'] > 0 and current_loop >= params['loop_count']:
                log_message(f"[*] Reached specified loop count ({params['loop_count']}). Finishing task.")
                break
            
            current_loop += 1
            active_task_status['progress'] = 0
            time.sleep(1)

        if active_task_status['is_running']:
            log_message(f"[+] Replay finished.")
            active_task_status['message'] = "Replay finished."
        
    except Exception as e:
        log_message(f"[!!!] An error occurred during replay: {e}")
        active_task_status['error'] = str(e)
        active_task_status['message'] = f"Error: {e}"
    finally:
        active_task_status['is_running'] = False
        active_task_status['packets_per_second'] = 0
        log_message("[+] Replay thread finished.")

def generate_traffic_task(params: dict):
    """The core traffic generation function."""
    try:
        log_message("[*] Traffic Generation Task Initialized.")
        log_message(f"    - Interface: {params['interface']}, Count: {params['packet_count']}, Delay: {params['delay']}s")
        log_message(f"    - Protocol: {params['protocol'].upper()}")
        log_message(f"    - L3: {params['src_ip']} -> {params['dst_ip']}")
        log_message(f"    - L2: {params['src_mac'] or 'auto'} -> {params['dst_mac']}")
        if params['protocol'] in ['tcp', 'udp']:
            log_message(f"    - L4: {params['src_port']} -> {params['dst_port']}")
        if params['payload']:
            log_message(f"    - Payload: {params['payload'][:50]}...")

        src_mac = params['src_mac'] or get_if_hwaddr(params['interface'])
        log_message(f"[*] Determined Source MAC: {src_mac}")

        packet_template = Ether(src=src_mac, dst=params['dst_mac']) / IP(src=params['src_ip'], dst=params['dst_ip'])
        
        if params['protocol'] == 'tcp': packet_template /= TCP(sport=params['src_port'], dport=params['dst_port'])
        elif params['protocol'] == 'udp': packet_template /= UDP(sport=params['src_port'], dport=params['dst_port'])
        elif params['protocol'] == 'icmp': packet_template /= ICMP()
        
        if params['payload']: packet_template /= Raw(load=params['payload'])
            
        log_message("[*] Packet template built. Starting transmission.")
        log_message(f"    - Final Summary: {packet_template.summary()}")

        pps_start_time = time.time()
        pps_packet_count = 0

        for i in range(params['packet_count']):
            if not active_task_status['is_running']:
                log_message("[!] Stop signal received. Halting generation.")
                break

            active_task_status['progress'] = i + 1
            active_task_status['message'] = f"Sending packet {i+1} of {params['packet_count']}"
            
            sendp(packet_template, iface=params['interface'], verbose=0)
            
            pps_packet_count += 1
            if time.time() - pps_start_time >= 1.0:
                active_task_status['packets_per_second'] = pps_packet_count
                pps_packet_count = 0
                pps_start_time = time.time()

            time.sleep(params['delay'])

        if active_task_status['is_running']:
            log_message(f"[+] Generation finished.")
            active_task_status['message'] = "Generation finished."
        
    except Exception as e:
        log_message(f"[!!!] An error occurred during generation: {e}")
        active_task_status['error'] = str(e)
        active_task_status['message'] = f"Error: {e}"
    finally:
        active_task_status['is_running'] = False
        active_task_status['packets_per_second'] = 0
        log_message("[+] Generation thread finished.")

def start_task(task_function, params, task_type):
    """Generic function to start a background task."""
    global active_task_status
    if active_task_status['is_running']:
        return jsonify({'error': 'A task is already in progress.'}), 409

    active_task_status.update({
        'is_running': True,
        'task_type': task_type,
        'message': 'Initializing...',
        'progress': 0,
        'total': 0,
        'loop_count': 0,
        'packets_per_second': 0,
        'error': None
    })
    active_task_status['logs'].clear()
    
    thread = threading.Thread(target=task_function, args=(params,))
    thread.daemon = True
    thread.start()
    return jsonify({'message': f'{task_type.capitalize()} task started.'})

# --- HTML & JavaScript Frontend ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Simulation Studio</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap" rel="stylesheet">
    <style>
        @keyframes flicker {
            0%, 100% { opacity: 1; text-shadow: 0 0 5px #0AF8F8, 0 0 10px #0AF8F8; }
            50% { opacity: 0.8; text-shadow: 0 0 5px #0AF8F8; }
        }
        @keyframes subtle-glow {
            0%, 100% { box-shadow: 0 0 4px #0AF8F833; }
            50% { box-shadow: 0 0 8px #0AF8F866; }
        }
        @keyframes flicker-red {
            0%, 100% { opacity: 1; text-shadow: 0 0 5px #F000B8, 0 0 10px #F000B8; }
            50% { opacity: 0.8; text-shadow: 0 0 5px #F000B8; }
        }
        body { 
            font-family: 'Share Tech Mono', monospace;
            background-color: #02000c;
            background-image: 
                linear-gradient(rgba(2,0,12,0.9), rgba(2,0,12,0.9)),
                url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='20' height='20' viewBox='0 0 20 20'%3E%3Cg fill='%230AF8F8' fill-opacity='0.05'%3E%3Cpath d='M0 0h20v1H0zM0 2h20v1H0zM0 4h20v1H0zM0 6h20v1H0zM0 8h20v1H0zM0 10h20v1H0zM0 12h20v1H0zM0 14h20v1H0zM0 16h20v1H0zM0 18h20v1H0z'/%3E%3C/g%3E%3C/svg%3E");
            color: #E0E0E0;
        }
        .cp-container {
            background: #0A001A99;
            border: 1px solid #0AF8F855;
            box-shadow: inset 0 0 20px #0AF8F833;
        }
        .cp-header { animation: flicker 3s infinite; }
        .form-input, select {
            background-color: #1a1a2a; 
            border: 1px solid #33334a; 
            color: #d1d5db;
            transition: all 0.2s ease-in-out;
            border-radius: 0;
        }
        .form-input:focus, select:focus {
            background-color: #2a2a3a; 
            border-color: #0AF8F8;
            box-shadow: none; 
            outline: none;
            color: #0AF8F8;
        }
        .form-input.invalid {
            border-color: #F000B8;
            color: #F000B8;
        }
        .section-header {
            color: #0AF8F8; font-weight: 700; letter-spacing: 0.1em;
            text-shadow: 0 0 3px #0AF8F8;
        }
        .tab {
            padding: 0.75rem 1.5rem; border: 1px solid transparent; border-bottom: none;
            color: #005959; font-weight: 700; transition: all 0.2s;
            cursor: pointer; /* Ensure tabs are clickable */
        }
        .tab.active {
            color: #0AF8F8; background-color: #0AF8F811;
            border-color: #0AF8F855;
        }
        .cp-button {
            background-color: #0AF8F822; color: #0AF8F8;
            border: 1px solid #0AF8F888;
            padding: 0.5rem 1rem; font-weight: 700;
            transition: all 0.2s;
            border-radius: 0;
            cursor: pointer;
        }
        .cp-button:hover { background-color: #0AF8F844; }
        .add-map-btn {
            animation: subtle-glow 2s infinite;
        }
        .submit-btn {
             background: #0AF8F8;
             text-shadow: 0 0 5px #000; color: #000;
        }
        .submit-btn:hover { background: #65FFFF; }
        .submit-btn:disabled { background: #333; color: #666; border-color: #444; cursor: not-allowed;}
        .abort-btn {
            background-color: #F000B844; border-color: #F000B8; color: #F000B8;
        }
        .abort-btn:hover { background-color: #F000B866; }
        .discovered-list {
            padding-right: 1rem; /* Fix for scrollbar overlap */
        }
        /* Style for the packet viewer table */
        #packetViewer table, #discoveredHostsTable table {
            table-layout: fixed;
        }
        #packetViewer td, #packetViewer th, #discoveredHostsTable td, #discoveredHostsTable th {
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .adversary-tag {
            color: #F000B8;
            font-weight: 700;
            font-size: 0.7rem;
            margin-left: 8px;
            animation: flicker-red 1.5s infinite;
        }
        .add-host-btn {
            font-weight: 700;
            color: #0AF8F8;
            font-size: 1.25rem;
            cursor: pointer;
            transition: all 0.1s;
        }
        .add-host-btn:hover {
            color: #65FFFF;
            text-shadow: 0 0 5px #0AF8F8;
        }
    </style>
</head>
<body class="text-gray-300 flex items-center justify-center min-h-screen py-12">
    <div class="w-full max-w-6xl mx-auto p-4"> <!-- Increased max-width for packet viewer -->
        <div class="cp-container p-6 md:p-8">
            <div class="text-center mb-8">
                <h1 class="cp-header text-4xl font-bold text-cyan-400">
                    NetRunner OS
                </h1>
                <p class="text-cyan-700 mt-2">// Network Simulation Interface //</p>
            </div>

            <!-- Asset Manager -->
            <div class="mb-8">
                <h2 class="section-header mb-4">Asset Manager</h2>
                <div class="bg-black/50 p-4 border border-cyan-900/50">
                    <div class="grid grid-cols-1 md:grid-cols-4 gap-4 items-end">
                        <div class="md:col-span-1">
                            <label for="assetName" class="block text-xs font-semibold text-cyan-300 mb-1">// Asset Name</label>
                            <input type="text" id="assetName" placeholder="e.g., Test Server 1" class="w-full form-input p-2 text-sm">
                        </div>
                        <div class="md:col-span-1">
                            <label for="assetIp" class="block text-xs font-semibold text-cyan-300 mb-1">// Asset IP</label>
                            <input type="text" id="assetIp" placeholder="192.168.1.100" class="w-full form-input p-2 text-sm" data-validate="ip">
                        </div>
                        <div class="md:col-span-1">
                            <label for="assetMac" class="block text-xs font-semibold text-cyan-300 mb-1">// Asset MAC</label>
                            <input type="text" id="assetMac" placeholder="aa:bb:cc:dd:ee:ff" class="w-full form-input p-2 text-sm" data-validate="mac">
                        </div>
                        <div class="md:col-span-1">
                            <button id="addAssetBtn" class="w-full cp-button py-2 text-sm">Add Asset</button>
                        </div>
                    </div>
                    <div id="assetList" class="mt-4 max-h-24 overflow-y-auto"></div>
                </div>
            </div>
            
            <div class="border-b border-cyan-900/50 mb-8 flex justify-between items-center">
                <nav class="flex">
                    <button id="tab-replayer" class="tab active">// PCAP Replayer</button>
                    <button id="tab-generator" class="tab">// Traffic Generator</button>
                    <button id="tab-viewer" class="tab">// Packet Viewer</button>
                </nav>
            </div>

            <!-- Content Panes -->
            <div id="replayer-pane">
                <form id="replayerForm" class="space-y-8">
                    <div class="grid md:grid-cols-2 gap-6">
                        <div>
                            <label for="pcapFile" class="block text-sm font-semibold text-cyan-300 mb-2">// Select PCAP File</label>
                            <input type="file" id="pcapFile" name="pcapFile" required class="block w-full text-sm text-cyan-300 file:mr-4 file:py-2 file:px-4 file:border-0 file:text-sm file:font-semibold file:cp-button file:cursor-pointer">
                        </div>
                        <div>
                            <label for="replay_interface" class="block text-sm font-semibold text-cyan-300 mb-2">// Egress Interface</label>
                            <input type="text" id="replay_interface" name="interface" placeholder="e.g., eth0" required class="w-full form-input p-2">
                        </div>
                    </div>
                    <!-- Analysis Status -->
                    <div id="analysisStatus" class="hidden text-center p-2 text-yellow-400 font-bold"></div>
                    
                    <!-- Discovered Hosts (Replaces Endpoints) -->
                    <div id="discoveredHostsTable" class="hidden">
                        <h2 class="section-header">// Discovered Hosts //</h2>
                        <div class="bg-black/50 p-4 border border-cyan-900/50 max-h-48 overflow-y-auto">
                            <table class="w-full text-left text-sm">
                                <thead class="text-cyan-300">
                                    <tr>
                                        <th class="p-2">IP Address</th>
                                        <th class="p-2">Last-Seen MAC</th>
                                        <th class="p-2 w-16 text-center">Add</th>
                                    </tr>
                                </thead>
                                <tbody id="discoveredHostsBody" class="text-gray-300">
                                    <!-- JS will populate this -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                    
                    <div>
                        <h2 class="section-header">Advanced Replay Options</h2>
                        <div class="grid md:grid-cols-2 lg:grid-cols-4 gap-6 items-end">
                            <div><label class="block text-sm font-semibold text-cyan-300 mb-2">// Replay Speed</label><select name="replay_speed" class="w-full form-input p-2"><option value="original">Original Timing</option><option value="fast">As Fast As Possible</option></select></div>
                            <div class="flex items-center pb-2 space-x-4">
                                <label class="flex items-center space-x-3 cursor-pointer"><input type="checkbox" id="loopReplayCheckbox" name="loop_replay" class="form-checkbox h-5 w-5 bg-black border-cyan-700/50 text-cyan-400 focus:ring-cyan-500"><span class="font-semibold text-cyan-200">// Loop Replay</span></label>
                                <div id="loopCountContainer" class="hidden"><input type="number" name="loop_count" placeholder="Count" class="form-input p-2 w-24 text-sm"></div>
                            </div>
                            <div><label class="block text-sm font-semibold text-cyan-300 mb-2">// Set IP TTL</label><input type="number" name="ttl" placeholder="Optional" min="1" max="255" class="w-full form-input p-2"></div>
                            <div><label class="block text-sm font-semibold text-cyan-300 mb-2">// Set VLAN ID</label><input type="number" name="vlan_id" placeholder="Optional" min="1" max="4094" class="w-full form-input p-2"></div>
                        </div>
                    </div>
                    <div>
                        <h2 class="section-header">Packet Rewriting</h2>
                         <div class="grid md:grid-cols-2 gap-x-8 gap-y-6">
                            <div>
                                <h3 class="font-semibold mb-2 text-cyan-200">// IP Address Map</h3><div id="ipMappingsContainer"></div><button type="button" data-action="add-map" data-type="ip" class="mt-2 text-sm font-semibold text-cyan-300 hover:text-cyan-200 add-map-btn">+ Add IP Map</button>
                            </div>
                            <div>
                                <h3 class="font-semibold mb-2 text-cyan-200">// MAC Address Map</h3><div id="macMappingsContainer"></div><button type="button" data-action="add-map" data-type="mac" class="mt-2 text-sm font-semibold text-cyan-300 hover:text-cyan-200 add-map-btn">+ Add MAC Map</button>
                            </div>
                            <div class="md:col-span-2">
                                <h3 class="font-semibold mb-2 text-cyan-200">// TCP/UDP Port Map</h3><div id="portMappingsContainer"></div><button type="button" data-action="add-map" data-type="port" class="mt-2 text-sm font-semibold text-cyan-300 hover:text-cyan-200 add-map-btn">+ Add Port Map</button>
                            </div>
                         </div>
                    </div>
                    <!-- Configuration Management -->
                    <div class="mt-8">
                        <h2 class="section-header">Configuration Management</h2>
                        <div class="bg-black/50 p-4 border border-cyan-900/50">
                            <div class="grid grid-cols-1 md:grid-cols-3 gap-4 items-end">
                                <div>
                                    <label for="configName" class="block text-xs font-semibold text-cyan-300 mb-1">// Configuration Name</label>
                                    <input type="text" id="configName" placeholder="e.g., My Test Scenario" class="w-full form-input p-2 text-sm">
                                </div>
                                <div class="md:col-span-2">
                                    <button id="saveConfigBtn" class="w-full md:w-auto cp-button py-2 px-4 text-sm">Save Current Config</button>
                                </div>
                                <div>
                                    <label for="configSelect" class="block text-xs font-semibold text-cyan-300 mb-1">// Load Saved Config</label>
                                    <select id="configSelect" class="w-full form-input p-2 text-sm"></select>
                                </div>
                                <div class="md:col-span-2 flex items-end space-x-2">
                                    <button id="loadConfigBtn" class="cp-button py-2 px-4 text-sm">Load</button>
                                    <button id="deleteConfigBtn" class="cp-button abort-btn py-2 px-4 text-sm">Delete</button>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="pt-4"><button type="submit" class="w-full cp-button submit-btn py-3">Initiate Replay</button></div>
                </form>
            </div>
            
            <div id="viewer-pane" class="hidden">
                <div id="viewer-placeholder">
                    <h2 class="section-header text-center">// Packet Viewer //</h2>
                    <p class="text-center text-gray-400">
                        Please upload a PCAP file on the 
                        <strong class="text-cyan-400 cursor-pointer" id="viewer-nav-to-replayer">
                            // PCAP Replayer //
                        </strong>
                        tab to analyze and view packets.
                    </p>
                </div>
                <!-- Packet Viewer Table (Moved) -->
                <div id="packetViewer" class="hidden mt-6">
                    <h2 class="section-header">// Packet Viewer (First 500 Packets) //</h2>
                    <div class="bg-black/50 p-4 border border-cyan-900/50 max-h-[60vh] overflow-y-auto">
                        <table class="w-full text-left text-xs">
                            <thead class="text-cyan-300">
                                <tr>
                                    <th class="p-2 w-16">No.</th>
                                    <th class="p-2">Source</th>
                                    <th class="p-2">Destination</th>
                                    <th class="p-2 w-20">Protocol</th>
                                    <th class="p-2">Info</th>
                                </tr>
                            </thead>
                            <tbody id="packetViewerBody" class="text-gray-300">
                                <!-- JS will populate this -->
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <div id="generator-pane" class="hidden">
                 <form id="generatorForm" class="space-y-8">
                    <div>
                        <h2 class="section-header">Network Layers (L2/L3)</h2>
                        <div class="grid md:grid-cols-2 gap-x-6 gap-y-4">
                            <div>
                                <label class="block text-sm font-semibold text-cyan-300 mb-2">// Source IP</label>
                                <div class="flex"><select data-asset-target="src" class="asset-select form-input p-2 w-1/3"></select><input type="text" name="src_ip" required placeholder="10.0.0.5" class="w-2/3 form-input p-2" data-validate="ip"></div>
                            </div>
                            <div>
                                <label class="block text-sm font-semibold text-cyan-300 mb-2">// Destination IP</label>
                                <div class="flex"><select data-asset-target="dst" class="asset-select form-input p-2 w-1/3"></select><input type="text" name="dst_ip" required placeholder="10.0.0.10" class="w-2/3 form-input p-2" data-validate="ip"></div>
                            </div>
                            <div>
                                <label class="block text-sm font-semibold text-cyan-300 mb-2">// Source MAC (Optional)</label>
                                <div class="flex"><select data-asset-target="src" class="asset-select form-input p-2 w-1/3"></select><input type="text" name="src_mac" placeholder="auto-detect" class="w-2/3 form-input p-2" data-validate="mac"></div>
                            </div>
                            <div>
                                <label class="block text-sm font-semibold text-cyan-300 mb-2">// Destination MAC</label>
                                <div class="flex"><select data-asset-target="dst" class="asset-select form-input p-2 w-1/3"></select><input type="text" name="dst_mac" required value="ff:ff:ff:ff:ff:ff" class="w-2/3 form-input p-2" data-validate="mac"></div>
                            </div>
                        </div>
                    </div>
                    <div>
                        <h2 class="section-header">Transport Layer (L4) & Payload</h2>
                        <div class="grid md:grid-cols-2 gap-x-6 gap-y-4">
                            <div>
                               <label class="block text-sm font-semibold text-cyan-300 mb-2">// Protocol</label><select id="protocol" name="protocol" class="w-full form-input p-2"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option></select>
                            </div>
                            <div class="grid grid-cols-2 gap-4 port-fields">
                                <div><label class="block text-sm font-semibold text-cyan-300 mb-2">// Src Port</label><input type="number" name="src_port" value="1337" class="w-full form-input p-2"></div>
                                <div><label class="block text-sm font-semibold text-cyan-300 mb-2">// Dst Port</label><input type="number" name="dst_port" value="80" class="w-full form-input p-2"></div>
                            </div>
                        </div>
                        <div class="mt-4"><label class="block text-sm font-semibold text-cyan-300 mb-2">// Payload (Optional)</label><textarea name="payload" rows="3" placeholder="Inject data stream..." class="w-full form-input p-2"></textarea></div>
                    </div>
                    <div>
                        <h2 class="section-header">Transmission Control</h2>
                         <div class="grid md:grid-cols-3 gap-6">
                            <div><label class="block text-sm font-semibold text-cyan-300 mb-2">// Packet Count</label><input type="number" name="packet_count" value="100" required class="w-full form-input p-2"></div>
                            <div><label class="block text-sm font-semibold text-cyan-300 mb-2">// Delay (s)</label><input type="number" name="delay" value="0.1" step="0.01" required class="w-full form-input p-2"></div>
                            <div><label class="block text-sm font-semibold text-cyan-300 mb-2">// Interface</label><input type="text" name="interface" placeholder="e.g., eth0" required class="w-full form-input p-2"></div>
                         </div>
                    </div>
                    <div class="pt-4"><button type="submit" class="w-full cp-button submit-btn py-3">Generate Traffic</button></div>
                </form>
            </div>

            <!-- Shared Status Display -->
            <div id="statusContainer" class="mt-10 hidden">
                <div class="p-4 bg-black/50 border border-cyan-900/50">
                    <div class="flex justify-between items-center mb-3">
                        <h3 id="statusTitle" class="section-header">Task Status</h3>
                        <button id="stopBtn" class="cp-button abort-btn py-2 px-4 text-sm disabled:opacity-50 disabled:cursor-not-allowed">Abort</button>
                    </div>
                    <div class="w-full bg-gray-700/50 border border-cyan-900/50 h-2.5 mb-2"><div id="progressBar" class="bg-cyan-400 h-full transition-all duration-500" style="width: 0%"></div></div>
                    <p id="statusMessage" class="text-center text-cyan-300"></p>
                </div>
                <div class="mt-6"><canvas id="trafficChart"></canvas></div>
                <div class="mt-6">
                    <button id="toggleConsoleBtn" class="w-full text-left p-3 bg-black/50 hover:bg-gray-900/50 border border-cyan-900/50 font-semibold flex justify-between items-center transition-colors"><span>// System Log</span><span id="consoleArrow" class="transition-transform">▼</span></button>

                    <div id="consoleWrapper" class="hidden"><div id="consoleOutput" class="p-3 border border-t-0 border-cyan-900/50 text-sm bg-black max-h-64 overflow-y-auto"></div></div>

                </div>
            </div>
        </div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function () {
            let statusInterval, trafficChart, chartTime = 0, currentTab = 'replayer';
            const tabReplayer = document.getElementById('tab-replayer'), tabGenerator = document.getElementById('tab-generator');
            const replayerPane = document.getElementById('replayer-pane'), generatorPane = document.getElementById('generator-pane');
            
            const tabViewer = document.getElementById('tab-viewer');
            const viewerPane = document.getElementById('viewer-pane');
            const viewerPlaceholder = document.getElementById('viewer-placeholder');
            const viewerNavToReplayer = document.getElementById('viewer-nav-to-replayer');

            const replayerForm = document.getElementById('replayerForm'), generatorForm = document.getElementById('generatorForm');
            const statusContainer = document.getElementById('statusContainer'), statusTitle = document.getElementById('statusTitle');
            const stopBtn = document.getElementById('stopBtn'), progressBar = document.getElementById('progressBar');
            const statusMessage = document.getElementById('statusMessage'), toggleConsoleBtn = document.getElementById('toggleConsoleBtn');
            const consoleWrapper = document.getElementById('consoleWrapper'), consoleOutput = document.getElementById('consoleOutput');
            const consoleArrow = document.getElementById('consoleArrow');
            const pcapFileInput = document.getElementById('pcapFile');
            
            // --- NEW: Discovered Hosts Table ---
            const discoveredHostsTable = document.getElementById('discoveredHostsTable');
            const discoveredHostsBody = document.getElementById('discoveredHostsBody');
            
            const packetViewer = document.getElementById('packetViewer');
            const packetViewerBody = document.getElementById('packetViewerBody');
            const analysisStatus = document.getElementById('analysisStatus');

            // --- Config Management ---
            const configNameInput = document.getElementById('configName');
            const saveConfigBtn = document.getElementById('saveConfigBtn');
            const configSelect = document.getElementById('configSelect');
            const loadConfigBtn = document.getElementById('loadConfigBtn');
            const deleteConfigBtn = document.getElementById('deleteConfigBtn');
 
             // --- Asset Management ---
             let assets = []; // This will be populated from the DB
            const addAssetBtn = document.getElementById('addAssetBtn');
            const assetNameInput = document.getElementById('assetName');
            const assetIpInput = document.getElementById('assetIp');
            const assetMacInput = document.getElementById('assetMac');
            const assetListDiv = document.getElementById('assetList');
            
            async function fetchAssets() {
                try {
                    const response = await fetch('/api/assets');
                    if (!response.ok) throw new Error('Failed to fetch assets');
                    assets = await response.json();
                    renderAssets();
                } catch (error) {
                    console.error("Error fetching assets:", error);
                    assetListDiv.innerHTML = `<span class="text-pink-500">Error loading assets.</span>`;
                }
            }

            function populateAllAssetSelects() {
                const allSelects = document.querySelectorAll('.asset-select');
                allSelects.forEach(sel => {
                    const currentVal = sel.value;
                    sel.innerHTML = '<option value="">Select Asset...</option>';
                    assets.forEach(asset => { // No index needed for value
                        const option = document.createElement('option');
                        option.value = asset.id; // Use DB ID as value
                        option.textContent = asset.name;
                        sel.appendChild(option);
                    });
                    sel.value = currentVal;
                });
            }

            function renderAssets() {
                assetListDiv.innerHTML = '';
                assets.forEach(asset => {
                    const assetItem = document.createElement('div');
                    assetItem.className = 'text-xs flex justify-between items-center p-1 bg-black/30';
                    assetItem.innerHTML = `<span><strong class="text-cyan-300">${asset.name}:</strong> ${asset.ip} / ${asset.mac}</span><button data-id="${asset.id}" class="asset-delete-btn text-pink-500 font-bold text-lg">&times;</button>`;
                    assetListDiv.appendChild(assetItem);
                });
                populateAllAssetSelects();
                document.querySelectorAll('.asset-delete-btn').forEach(btn => {
                    btn.addEventListener('click', async (e) => {
                        const assetId = e.target.dataset.id;
                        try {
                            const response = await fetch(`/api/assets/${assetId}`, { method: 'DELETE' });
                            if (!response.ok) throw new Error('Failed to delete asset');
                            fetchAssets(); // Re-fetch to update the list
                        } catch (error) {
                            console.error("Error deleting asset:", error);
                            alert("Error deleting asset.");
                        }
                    });
                });
            }

            addAssetBtn.addEventListener('click', async () => {
                const name = assetNameInput.value.trim();
                const ip = assetIpInput.value.trim();
                const mac = assetMacInput.value.trim();
                if (name && ip && mac) {
                    try {
                        const response = await fetch('/api/assets', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ name, ip, mac })
                        });
                        if (!response.ok) {
                            const err = await response.json();
                            throw new Error(err.error || 'Failed to add asset');
                        }
                        assetNameInput.value = assetIpInput.value = assetMacInput.value = '';
                        fetchAssets(); // Re-fetch to update list
                    } catch (error) {
                        console.error("Error adding asset:", error);
                        alert(`Error: ${error.message}`);
                    }
                } else {
                    alert('Please fill out all asset fields.');
                }
            });

            document.body.addEventListener('change', (e) => {
                if (e.target.classList.contains('asset-select') && e.target.value !== '') {
                    const asset = assets.find(a => a.id == e.target.value);
                    if (!asset) return;
                    const inputGroup = e.target.parentElement;
                    const input = inputGroup.querySelector('input');
                    
                    if(e.target.closest('form').id === 'generatorForm'){
                         const targetBase = e.target.dataset.assetTarget; // src or dst
                         const form = e.target.closest('form');
                         form.querySelector(`input[name="${targetBase}_ip"]`).value = asset.ip;
                         form.querySelector(`input[name="${targetBase}_mac"]`).value = asset.mac;
                    } else {
                        // This is for the replayer map
                        const input = e.target.nextElementSibling; // The actual text input
                        const targetInputType = input.dataset.validate;
                        if (targetInputType === 'ip') input.value = asset.ip;
                        if (targetInputType === 'mac') input.value = asset.mac;
                    }
                    e.target.value = ''; // Reset select
                    validateAllInputs();
                }
            });

            // --- Config Management Logic ---
            async function fetchConfigs() {
                try {
                    const response = await fetch('/api/replay_configs');
                    if (!response.ok) throw new Error('Failed to fetch configs');
                    const configs = await response.json();
                    configSelect.innerHTML = '<option value="">Select a config...</option>';
                    configs.forEach(config => {
                        const option = document.createElement('option');
                        option.value = config.id;
                        option.textContent = config.name;
                        configSelect.appendChild(option);
                    });
                } catch (error) {
                    console.error("Error fetching configs:", error);
                    configSelect.innerHTML = '<option value="">Error loading configs</option>';
                }
            }

            saveConfigBtn.addEventListener('click', async () => {
                const name = configNameInput.value.trim();
                if (!name) {
                    alert('Please enter a name for the configuration.');
                    return;
                }

                const getMaps = (type) => {
                    const container = document.getElementById(`${type}MappingsContainer`);
                    return Array.from(container.children).map(row => ({
                        original: row.querySelector(`input[name="${type}_original"]`).value,
                        new: row.querySelector(`input[name="${type}_new"]`).value
                    })).filter(item => item.original && item.new);
                };

                const configData = {
                    name: name,
                    interface: replayerForm.elements['interface'].value,
                    replay_speed: replayerForm.elements['replay_speed'].value,
                    loop_replay: replayerForm.elements['loop_replay'].checked,
                    loop_count: replayerForm.elements['loop_count'].value ? parseInt(replayerForm.elements['loop_count'].value) : 0,
                    ttl: replayerForm.elements['ttl'].value ? parseInt(replayerForm.elements['ttl'].value) : null,
                    vlan_id: replayerForm.elements['vlan_id'].value ? parseInt(replayerForm.elements['vlan_id'].value) : null,
                    ip_map: getMaps('ip'),
                    mac_map: getMaps('mac'),
                    port_map: getMaps('port')
                };

                try {
                    const response = await fetch('/api/replay_configs', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(configData)
                    });
                    if (!response.ok) {
                        const err = await response.json();
                        throw new Error(err.error || 'Failed to save config');
                    }
                    alert('Configuration saved successfully!');
                    fetchConfigs();
                } catch (error) {
                    console.error("Error saving config:", error);
                    alert(`Error: ${error.message}`);
                }
            });

            loadConfigBtn.addEventListener('click', async () => {
                const configId = configSelect.value;
                if (!configId) {
                    alert('Please select a configuration to load.');
                    return;
                }
                try {
                    const response = await fetch(`/api/replay_configs/${configId}`);
                    if (!response.ok) throw new Error('Failed to load config');
                    const config = await response.json();

                    // Populate form fields
                    replayerForm.elements['interface'].value = config.interface || '';
                    replayerForm.elements['replay_speed'].value = config.replay_speed || 'original';
                    replayerForm.elements['loop_replay'].checked = config.loop_replay;
                    loopCountContainer.classList.toggle('hidden', !config.loop_replay);
                    replayerForm.elements['loop_count'].value = config.loop_count || '';
                    replayerForm.elements['ttl'].value = config.ttl || '';
                    replayerForm.elements['vlan_id'].value = config.vlan_id || '';
                    configNameInput.value = config.name;

                    // Clear and populate mapping containers
                    const populateMaps = (type, maps) => {
                        const container = document.getElementById(`${type}MappingsContainer`);
                        container.innerHTML = '';
                        if (maps) {
                            maps.forEach(item => {
                                addMappingRow(container, type, item.original);
                                const newRow = container.lastElementChild;
                                newRow.querySelector(`input[name="${type}_new"]`).value = item.new;
                            });
                        }
                    };
                    populateMaps('ip', config.ip_map);
                    populateMaps('mac', config.mac_map);
                    populateMaps('port', config.port_map);
                    
                    alert('Configuration loaded.');
                    validateAllInputs();
                } catch (error) {
                    console.error("Error loading config:", error);
                    alert('Error loading configuration.');
                }
            });

            deleteConfigBtn.addEventListener('click', async () => {
                const configId = configSelect.value;
                if (!configId) {
                    alert('Please select a configuration to delete.');
                    return;
                }
                if (!confirm('Are you sure you want to delete this configuration?')) return;

                try {
                    const response = await fetch(`/api/replay_configs/${configId}`, { method: 'DELETE' });
                    if (!response.ok) throw new Error('Failed to delete config');
                    alert('Configuration deleted.');
                    fetchConfigs();
                } catch (error) {
                    console.error("Error deleting config:", error);
                    alert('Error deleting configuration.');
                }
            });

            // --- Tab Switching Logic ---
            function switchTab(activeTab) {
                currentTab = activeTab;
                tabReplayer.classList.toggle('active', activeTab === 'replayer');
                tabGenerator.classList.toggle('active', activeTab === 'generator');
                tabViewer.classList.toggle('active', activeTab === 'viewer');
                
                replayerPane.classList.toggle('hidden', activeTab !== 'replayer');
                generatorPane.classList.toggle('hidden', activeTab !== 'generator');
                viewerPane.classList.toggle('hidden', activeTab !== 'viewer');
            }
            tabReplayer.addEventListener('click', () => switchTab('replayer'));
            tabGenerator.addEventListener('click', () => switchTab('generator'));
            tabViewer.addEventListener('click', () => switchTab('viewer'));
            viewerNavToReplayer.addEventListener('click', () => switchTab('replayer'));

            // --- Mapping Row Management ---
            function addMappingRow(container, type, val1 = '') {
                const p1 = `Original ${type.toUpperCase()}`, p2 = `New ${type.toUpperCase()}`;
                const row = document.createElement('div');
                row.className = 'grid grid-cols-[1fr_auto_1fr_auto] gap-2 items-center mb-2';
                
                if (type === 'port') {
                    row.innerHTML = `
                        <input type="number" name="port_original" placeholder="${p1}" value="${val1}" class="w-full form-input p-2 text-sm">
                        <span class="text-cyan-400 font-bold text-xl">-></span>
                        <input type="number" name="port_new" placeholder="${p2}" class="w-full form-input p-2 text-sm">
                        <button type="button" class="remove-btn text-pink-500 hover:text-pink-400 font-bold text-2xl">&times;</button>
                    `;
                } else {
                    row.innerHTML = `
                        <div class="flex w-full"><select data-asset-target="map" class="asset-select form-input p-2 w-1/3 text-sm"></select><input type="text" name="${type}_original" placeholder="${p1}" value="${val1}" class="w-2/3 form-input p-2 text-sm" data-validate="${type}"></div>
                        <span class="text-cyan-400 font-bold text-xl">-></span>
                        <div class="flex w-full"><select data-asset-target="map" class="asset-select form-input p-2 w-1/3 text-sm"></select><input type="text" name="${type}_new" placeholder="${p2}" class="w-2/3 form-input p-2 text-sm" data-validate="${type}"></div>
                        <button type="button" class="remove-btn text-pink-500 hover:text-pink-400 font-bold text-2xl">&times;</button>
                    `;
                }
                container.appendChild(row);
                populateAllAssetSelects();
                row.querySelector('.remove-btn').addEventListener('click', () => row.remove());
                validateAllInputs();
            }
            document.querySelectorAll('button[data-action="add-map"]').forEach(btn => {
                btn.addEventListener('click', () => {
                    const type = btn.dataset.type;
                    const container = document.getElementById(`${type}MappingsContainer`);
                    addMappingRow(container, type);
                });
            });

            // --- PCAP Analysis ---
            pcapFileInput.addEventListener('change', async (e) => {
                const file = e.target.files[0];
                if (!file) return;
                
                // --- NEW ANALYSIS UX ---
                // 1. Show analysis status message (our "progress bar")
                analysisStatus.textContent = 'Analyzing PCAP...';
                analysisStatus.classList.remove('hidden', 'text-red-500');
                
                // 2. Clear old data and hide sections
                discoveredHostsTable.classList.add('hidden');
                packetViewer.classList.add('hidden');
                viewerPlaceholder.classList.remove('hidden');
                
                discoveredHostsBody.innerHTML = '';
                packetViewerBody.innerHTML = '';

                const formData = new FormData();
                formData.append('pcapFile', file);

                try {
                    const response = await fetch('/analyze_pcap', { method: 'POST', body: formData });
                    const data = await response.json();

                    if (response.ok) {
                        // --- NEW: Populate Discovered Hosts Table ---
                        const adversary_ip = data.adversary;
                        data.hosts.forEach(host => {
                            const row = document.createElement('tr');
                            row.className = 'border-t border-cyan-900/50';
                            
                            let ipCell = `<td>${host.ip}</td>`;
                            if (host.ip === adversary_ip) {
                                ipCell = `<td>${host.ip} <span class="adversary-tag">// ADVERSARY?</span></td>`;
                            }
                            
                            row.innerHTML = `
                                ${ipCell}
                                <td class="p-2">${host.mac}</td>
                                <td class="p-2 text-center">
                                    <button type="button" data-ip="${host.ip}" data-mac="${host.mac}" class="add-host-btn">+</button>
                                </td>
                            `;
                            discoveredHostsBody.appendChild(row);
                        });
                        discoveredHostsTable.classList.remove('hidden');

                        // --- NEW PACKET VIEWER LOGIC ---
                        const escapeHTML = str => (str ?? '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
                        if (data.packets && data.packets.length > 0) {
                            data.packets.forEach(packet => {
                                const row = document.createElement('tr');
                                row.className = 'border-t border-cyan-900/50';
                                row.innerHTML = `
                                    <td class="p-2">${packet.num}</td>
                                    <td class="p-2">${escapeHTML(packet.src)}</td>
                                    <td class="p-2">${escapeHTML(packet.dst)}</td>
                                    <td class="p-2">${escapeHTML(packet.proto)}</td>
                                    <td class="p-2">${escapeHTML(packet.info)}</td>
                                `;
                                packetViewerBody.appendChild(row);
                            });
                            // Show the viewer table and hide the placeholder
                            packetViewer.classList.remove('hidden');
                            viewerPlaceholder.classList.add('hidden');
                        }
                        // --- END NEW LOGIC ---
                        
                        // 3. Hide analysis status
                        analysisStatus.classList.add('hidden');

                    } else {
                        throw new Error(data.error);
                    }
                } catch (error) {
                    // 3. Show error in analysis status
                    analysisStatus.textContent = `Error: ${error.message}`;
                    analysisStatus.classList.add('text-pink-500');
                    discoveredHostsBody.innerHTML = `<span class="text-pink-500">Error: ${error.message}</span>`;
                }
            });
            
            document.body.addEventListener('click', (e) => {
                // --- NEW: Add Host Button Logic ---
                if (e.target.classList.contains('add-host-btn')) {
                    const ip = e.target.dataset.ip;
                    const mac = e.target.dataset.mac;
                    
                    if (ip && ip !== 'N/A') {
                        addMappingRow(document.getElementById('ipMappingsContainer'), 'ip', ip);
                    }
                    if (mac && mac !== 'N/A') {
                        addMappingRow(document.getElementById('macMappingsContainer'), 'mac', mac);
                    }
                }
            });

            // --- Input Validation ---
            const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
            const macRegex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;

            function validateInput(input) {
                const type = input.dataset.validate;
                if (!type) return;
                
                const regex = type === 'ip' ? ipRegex : macRegex;
                // Allow empty for optional fields
                if (!input.value && !input.required) {
                    input.classList.remove('invalid');
                    return;
                }
                
                if (regex.test(input.value)) {
                    input.classList.remove('invalid');
                } else {
                    input.classList.add('invalid');
                }
            }
            
            function validateAllInputs() {
                 document.querySelectorAll('input[data-validate]').forEach(validateInput);
            }

            document.body.addEventListener('input', e => {
                if (e.target.matches('input[data-validate]')) {
                    validateInput(e.target);
                }
            });


            const protocolSelect = document.getElementById('protocol'), portFields = generatorPane.querySelector('.port-fields');
            function togglePortFields() { portFields.style.display = (protocolSelect.value === 'tcp' || protocolSelect.value === 'udp') ? 'grid' : 'none'; }
            protocolSelect.addEventListener('change', togglePortFields);

            const loopCheckbox = document.getElementById('loopReplayCheckbox');
            const loopCountContainer = document.getElementById('loopCountContainer');
            loopCheckbox.addEventListener('change', () => {
                loopCountContainer.classList.toggle('hidden', !loopCheckbox.checked);
            });

            function initChart() {
                const ctx = document.getElementById('trafficChart').getContext('2d');
                if (trafficChart) trafficChart.destroy();
                trafficChart = new Chart(ctx, {
                    type: 'line',
                    data: { labels: [], datasets: [{ label: 'Packets/sec', data: [], borderColor: '#0AF8F8', backgroundColor: '#0AF8F822', borderWidth: 1, tension: 0.4, fill: true, pointRadius: 0 }] },
                    options: { scales: { y: { beginAtZero: true, grid: { color: '#0AF8F822' }, ticks: { color: '#008a8a' } }, x: { grid: { color: '#0AF8F822' }, ticks: { color: '#008a8a' } } }, plugins: { legend: { display: false } } }
                });
            }

            toggleConsoleBtn.addEventListener('click', () => {
                const isHidden = consoleWrapper.classList.toggle('hidden');
                consoleArrow.style.transform = isHidden ? 'rotate(0deg)' : 'rotate(180deg)';
            });
            
            async function handleFormSubmit(e, form, endpoint, type) {
                e.preventDefault();
                validateAllInputs(); // Run validation before submit
                if (form.querySelector('.invalid')) {
                    alert('Please fix invalid fields (highlighted in red) before starting.');
                    return;
                }

                const submitBtn = form.querySelector('button[type="submit"]');
                submitBtn.disabled = true; stopBtn.disabled = false;
                submitBtn.textContent = 'Executing...';
                statusContainer.classList.remove('hidden');
                progressBar.style.width = '0%';
                statusMessage.classList.remove('text-red-400');
                consoleOutput.textContent = ''; chartTime = 0;
                initChart();
                statusTitle.textContent = `${type} Status`;
                trafficChart.data.datasets[0].label = `${type}d Packets/sec`;
                try {
                    const response = await fetch(endpoint, { method: 'POST', body: new FormData(form) });
                    const result = await response.json();
                    if (response.ok) { statusMessage.textContent = result.message; startStatusPolling(); } 
                    else { throw new Error(result.error || 'Unknown error.'); }
                } catch (error) {
                    statusMessage.textContent = `Error: ${error.message}`;
                    statusMessage.classList.add('text-pink-500');
                    submitBtn.disabled = false; stopBtn.disabled = true;
                    submitBtn.textContent = `Start ${type}`;
                }
            }
            replayerForm.addEventListener('submit', (e) => handleFormSubmit(e, replayerForm, '/replay', 'Replay'));
            generatorForm.addEventListener('submit', (e) => handleFormSubmit(e, generatorForm, '/generate', 'Generation'));
            
            stopBtn.addEventListener('click', async () => {
                stopBtn.disabled = true; stopBtn.textContent = 'Aborting...';
                try { await fetch('/stop', { method: 'POST' }); } 
                catch (error) { statusMessage.textContent = 'Error sending stop signal.'; }
            });

            function startStatusPolling() {
                if (statusInterval) clearInterval(statusInterval);
                statusInterval = setInterval(async () => {
                    try {
                        const response = await fetch('/status');
                        const status = await response.json();
                        statusMessage.textContent = status.message;
                        progressBar.style.width = `${(status.total > 0) ? (status.progress / status.total) * 100 : 0}%`;
                        if (trafficChart.data.labels.length > 30) {
                            trafficChart.data.labels.shift();
                            trafficChart.data.datasets[0].data.shift();
                        }
                        trafficChart.data.labels.push(chartTime++);
                        trafficChart.data.datasets[0].data.push(status.packets_per_second);
                        trafficChart.update('quiet');
                        consoleOutput.textContent = status.logs.join('\\n');
                        consoleOutput.scrollTop = consoleOutput.scrollHeight;
                        if (status.error) { statusMessage.classList.add('text-pink-500'); progressBar.classList.add('bg-pink-500'); stopStatusPolling(); }
                        if (!status.is_running) stopStatusPolling();
                    } catch (error) { statusMessage.textContent = 'Connection to backend lost.'; statusMessage.classList.add('text-pink-500'); stopStatusPolling(); }
                }, 1000);
            }

            function stopStatusPolling() {
                clearInterval(statusInterval); statusInterval = null;
                replayerForm.querySelector('button[type="submit"]').disabled = false;
                generatorForm.querySelector('button[type="submit"]').disabled = false;
                replayerForm.querySelector('button[type="submit"]').textContent = 'Initiate Replay';
                generatorForm.querySelector('button[type="submit"]').textContent = 'Generate Traffic';
                stopBtn.disabled = true; stopBtn.textContent = 'Abort';
            }
            
            // Initial setup
            initChart(); 
            switchTab('replayer');
            togglePortFields();
            fetchAssets(); // Fetch assets from DB on load
            fetchConfigs(); // Fetch configs from DB on load
            validateAllInputs(); // Run validation on page load
        });
    </script>
</body>
</html>
"""

# --- API Routes for Database Interaction ---

@app.route('/api/assets', methods=['GET'])
def get_assets():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM assets ORDER BY name")
    assets = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(assets)

@app.route('/api/assets', methods=['POST'])
def add_asset():
    data = request.json
    if not all(k in data for k in ['name', 'ip', 'mac']):
        return jsonify({'error': 'Missing required fields.'}), 400
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO assets (name, ip, mac) VALUES (?, ?, ?)", (data['name'], data['ip'], data['mac']))
        conn.commit()
        return jsonify({'id': cursor.lastrowid, 'message': 'Asset added successfully.'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'An asset with this name already exists.'}), 409
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/assets/<int:asset_id>', methods=['DELETE'])
def delete_asset(asset_id):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
        conn.commit()
        if cursor.rowcount == 0:
            return jsonify({'error': 'Asset not found.'}), 404
        return jsonify({'message': 'Asset deleted successfully.'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/replay_configs', methods=['GET'])
def get_replay_configs():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT id, name FROM replay_configs ORDER BY name")
    configs = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(configs)

@app.route('/api/replay_configs/<int:config_id>', methods=['GET'])
def get_replay_config_detail(config_id):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM replay_configs WHERE id = ?", (config_id,))
    config_row = cursor.fetchone()
    conn.close()
    if config_row is None:
        return jsonify({'error': 'Configuration not found.'}), 404
    
    config = dict(config_row)
    # Deserialize JSON map fields
    for key in ['ip_map', 'mac_map', 'port_map']:
        if config[key]:
            config[key] = json.loads(config[key])
    return jsonify(config)

@app.route('/api/replay_configs', methods=['POST'])
def add_replay_config():
    data = request.json
    if not data or 'name' not in data:
        return jsonify({'error': 'Configuration name is required.'}), 400

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO replay_configs (name, interface, replay_speed, loop_replay, loop_count, ttl, vlan_id, ip_map, mac_map, port_map)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data['name'],
            data.get('interface'),
            data.get('replay_speed'),
            data.get('loop_replay', False),
            data.get('loop_count'),
            data.get('ttl'),
            data.get('vlan_id'),
            json.dumps(data.get('ip_map', [])),
            json.dumps(data.get('mac_map', [])),
            json.dumps(data.get('port_map', []))
        ))
        conn.commit()
        return jsonify({'id': cursor.lastrowid, 'message': 'Configuration saved.'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'A configuration with this name already exists.'}), 409
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/replay_configs/<int:config_id>', methods=['DELETE'])
def delete_replay_config(config_id):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM replay_configs WHERE id = ?", (config_id,))
        conn.commit()
        if cursor.rowcount == 0:
            return jsonify({'error': 'Configuration not found.'}), 404
        return jsonify({'message': 'Configuration deleted successfully.'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

# --- Flask Routes ---

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/analyze_pcap', methods=['POST'])
def analyze_pcap():
    if 'pcapFile' not in request.files:
        return jsonify({'error': 'No file part in the request.'}), 400
    
    file = request.files['pcapFile']
    if file.filename == '':
        return jsonify({'error': 'No file selected.'}), 400

    try:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
        file.save(filepath)

        ip_to_mac_map = {}
        packet_summaries = []
        scan_scores = defaultdict(int)
        scanned_targets = defaultdict(set)
        
        with PcapReader(filepath) as pcap_reader:
            for i, packet in enumerate(pcap_reader):
                has_ip = packet.haslayer(IP)
                has_ether = packet.haslayer(Ether)

                if has_ip and has_ether:
                    ip_to_mac_map[packet[IP].src] = packet[Ether].src
                    ip_to_mac_map[packet[IP].dst] = packet[Ether].dst
                
                if len(packet_summaries) < PACKET_VIEWER_LIMIT:
                    num = i + 1
                    src = "N/A"
                    dst = "N/A"
                    proto = packet.name
                    info = packet.summary()
                    
                    if has_ip:
                        src = packet[IP].src
                        dst = packet[IP].dst
                    elif has_ether:
                        src = packet[Ether].src
                        dst = packet[Ether].dst

                    if packet.haslayer(TCP):
                        proto = "TCP"
                        dport = packet[TCP].dport
                        info = f"{packet[TCP].sport} -> {dport} [{str(packet[TCP].flags)}]"
                        # --- Adversary Heuristic ---
                        if has_ip:
                            target_tuple = (packet[IP].dst, dport)
                            if target_tuple not in scanned_targets[packet[IP].src]:
                                scan_scores[packet[IP].src] += 1
                                scanned_targets[packet[IP].src].add(target_tuple)

                    elif packet.haslayer(UDP):
                        proto = "UDP"
                        dport = packet[UDP].dport
                        info = f"{packet[UDP].sport} -> {dport}"
                        # --- Adversary Heuristic ---
                        if has_ip:
                            target_tuple = (packet[IP].dst, dport)
                            if target_tuple not in scanned_targets[packet[IP].src]:
                                scan_scores[packet[IP].src] += 1
                                scanned_targets[packet[IP].src].add(target_tuple)
                                
                    elif packet.haslayer(ICMP):
                        proto = "ICMP"
                        info = f"Type: {packet[ICMP].type} Code: {packet[ICMP].code}"

                    packet_summaries.append({
                        "num": num,
                        "src": src,
                        "dst": dst,
                        "proto": proto,
                        "info": info
                    })
        
        # --- Process Analysis Results ---
        
        # 1. Find potential adversary
        adversary_ip = None
        if scan_scores:
            potential_adversary = max(scan_scores, key=scan_scores.get)
            if scan_scores[potential_adversary] > ADVERSARY_HEURISTIC_THRESHOLD:
                adversary_ip = potential_adversary

        # 2. Build final hosts list
        discovered_hosts = []
        all_ips = set(ip_to_mac_map.keys())
        for ip in sorted(list(all_ips)):
            discovered_hosts.append({
                'ip': ip,
                'mac': ip_to_mac_map.get(ip, 'N/A')
            })
        
        # Clean up the temp file after analysis
        os.remove(filepath)

        return jsonify({
            'hosts': discovered_hosts,
            'adversary': adversary_ip,
            'packets': packet_summaries
        })
    except Exception as e:
        return jsonify({'error': f'Failed to analyze PCAP: {e}'}), 500

@app.route('/replay', methods=['POST'])
def start_replay_route():
    if 'pcapFile' not in request.files or request.files['pcapFile'].filename == '':
        return jsonify({'error': 'PCAP file is required.'}), 400
    
    file = request.files['pcapFile']
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    try:
        loop_replay = 'loop_replay' in request.form
        loop_count_str = request.form.get('loop_count')
        loop_count = int(loop_count_str) if loop_replay and loop_count_str and loop_count_str.isdigit() and int(loop_count_str) > 0 else 0

        params = {
            'filepath': filepath,
            'interface': request.form['interface'],
            'ip_map': {o: n for o, n in zip(request.form.getlist('ip_original'), request.form.getlist('ip_new')) if o and n},
            'mac_map': {o.lower(): n.lower() for o, n in zip(request.form.getlist('mac_original'), request.form.getlist('mac_new')) if o and n},
            'port_map': {p_o: int(p_n) for p_o, p_n in zip(request.form.getlist('port_original'), request.form.getlist('port_new')) if p_o and p_n},
            'replay_speed': request.form.get('replay_speed', 'original'),
            'loop_replay': loop_replay,
            'loop_count': loop_count,
            'ttl': int(ttl_str) if (ttl_str := request.form.get('ttl')) and ttl_str.isdigit() else None,
            'vlan_id': int(vlan_id_str) if (vlan_id_str := request.form.get('vlan_id')) and vlan_id_str.isdigit() else None
        }
    except (KeyError, ValueError) as e:
        return jsonify({'error': f'Invalid or missing parameter for replay: {e}'}), 400
        
    return start_task(replay_pcap_task, params, 'Replay')

@app.route('/generate', methods=['POST'])
def start_generation_route():
    try:
        params = {
            'src_ip': request.form['src_ip'],
            'dst_ip': request.form['dst_ip'],
            'src_mac': request.form.get('src_mac'),
            'dst_mac': request.form['dst_mac'],
            'protocol': request.form['protocol'],
            'src_port': int(request.form.get('src_port', 0)),
            'dst_port': int(request.form.get('dst_port', 0)),
            'payload': request.form.get('payload'),
            'packet_count': int(request.form['packet_count']),
            'delay': float(request.form['delay']),
            'interface': request.form['interface']
        }
    except (KeyError, ValueError) as e:
        return jsonify({'error': f'Invalid or missing parameter for generation: {e}'}), 400

    return start_task(generate_traffic_task, params, 'Generation')

@app.route('/stop', methods=['POST'])
def stop_task_route():
    global active_task_status
    if active_task_status['is_running']:
        active_task_status['is_running'] = False
        return jsonify({'message': 'Stop signal sent.'})
    return jsonify({'message': 'No task is currently running.'})

@app.route('/status')
def get_status_route():
    global active_task_status
    status_copy = active_task_status.copy()
    status_copy['logs'] = list(active_task_status['logs'])
    return jsonify(status_copy)


if __name__ == '__main__':
    init_database()
    print("="*50)
    print("NetRunner OS - Network Simulation Studio")
    print("[*] Database initialized.")
    print("Starting Flask server...")
    print("How to Run:")
    print("  1. Save this file as network_simulation_studio_v2.py")
    print("  2. Run with root privileges (needed for packet sending): sudo python3 network_simulation_studio_v2.py")
    print(f"  3. Open your web browser and go to http://127.0.0.1:9000")
    print("="*50)
    app.run(host='0.0.0.0', port=9000, debug=False)
