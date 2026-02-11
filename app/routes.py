import os
import threading
import json
from flask import Blueprint, request, jsonify, current_app, Response
import sqlite3
from werkzeug.utils import secure_filename
from scapy.all import PcapReader, Ether, IP, TCP, UDP, ICMP, Raw
from collections import defaultdict
from app.core.engine import replay_pcap_task, generate_traffic_task, active_task_status
from app.core.database import get_db_connection

bp = Blueprint('main', __name__)

PACKET_VIEWER_LIMIT = 1000 # Increased limit
ADVERSARY_HEURISTIC_THRESHOLD = 3

def start_task(task_function, params, task_type):
    """Generic function to start a background task."""
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

@bp.route('/analyze_pcap', methods=['POST'])
def analyze_pcap():
    if 'pcapFile' not in request.files:
        return jsonify({'error': 'No file part in the request.'}), 400
    
    file = request.files['pcapFile']
    if file.filename == '':
        return jsonify({'error': 'No file selected.'}), 400

    try:
        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
        file.save(filepath)

        ip_to_mac_map = {}
        packet_summaries = []
        scan_scores = defaultdict(int)
        scanned_targets = defaultdict(set)
        
        endpoints = defaultdict(lambda: {'tx_pkts': 0, 'rx_pkts': 0, 'tx_bytes': 0, 'rx_bytes': 0})
        conversations = defaultdict(lambda: {'pkts': 0, 'bytes': 0, 'start_time': float('inf'), 'end_time': 0})
        
        with PcapReader(filepath) as pcap_reader:
            for i, packet in enumerate(pcap_reader):
                has_ip = packet.haslayer(IP)
                has_ether = packet.haslayer(Ether)
                
                pkt_len = len(packet)
                ts = float(packet.time)

                if has_ip:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    
                    # Endpoints
                    endpoints[src_ip]['tx_pkts'] += 1
                    endpoints[src_ip]['tx_bytes'] += pkt_len
                    endpoints[dst_ip]['rx_pkts'] += 1
                    endpoints[dst_ip]['rx_bytes'] += pkt_len

                    # Conversations
                    conv_key = tuple(sorted([src_ip, dst_ip]))
                    c = conversations[conv_key]
                    c['pkts'] += 1
                    c['bytes'] += pkt_len
                    c['start_time'] = min(c['start_time'], ts)
                    c['end_time'] = max(c['end_time'], ts)

                if has_ip and has_ether:
                    ip_to_mac_map[packet[IP].src] = packet[Ether].src
                    ip_to_mac_map[packet[IP].dst] = packet[Ether].dst
                
                if len(packet_summaries) < PACKET_VIEWER_LIMIT:
                    num = i + 1
                    src = "N/A"
                    dst = "N/A"
                    proto = packet.name
                    info = packet.summary()
                    layers = []
                    
                    # Extract detailed layer info
                    if has_ether:
                        layers.append({
                            "name": "Ethernet",
                            "fields": {
                                "Source": packet[Ether].src,
                                "Destination": packet[Ether].dst,
                                "Type": packet[Ether].type
                            }
                        })
                        src = packet[Ether].src
                        dst = packet[Ether].dst

                    if has_ip:
                        layers.append({
                            "name": "IP",
                            "fields": {
                                "Source": packet[IP].src,
                                "Destination": packet[IP].dst,
                                "TTL": packet[IP].ttl,
                                "ID": packet[IP].id,
                                "Proto": packet[IP].proto
                            }
                        })
                        src = packet[IP].src
                        dst = packet[IP].dst

                    if packet.haslayer(TCP):
                        proto = "TCP"
                        dport = packet[TCP].dport
                        info = f"{packet[TCP].sport} -> {dport} [{str(packet[TCP].flags)}]"
                        layers.append({
                            "name": "TCP",
                            "fields": {
                                "Source Port": packet[TCP].sport,
                                "Dest Port": packet[TCP].dport,
                                "Seq": packet[TCP].seq,
                                "Ack": packet[TCP].ack,
                                "Flags": str(packet[TCP].flags),
                                "Window": packet[TCP].window
                            }
                        })
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
                        layers.append({
                            "name": "UDP",
                            "fields": {
                                "Source Port": packet[UDP].sport,
                                "Dest Port": packet[UDP].dport,
                                "Length": packet[UDP].len
                            }
                        })
                        # --- Adversary Heuristic ---
                        if has_ip:
                            target_tuple = (packet[IP].dst, dport)
                            if target_tuple not in scanned_targets[packet[IP].src]:
                                scan_scores[packet[IP].src] += 1
                                scanned_targets[packet[IP].src].add(target_tuple)
                                
                    elif packet.haslayer(ICMP):
                        proto = "ICMP"
                        info = f"Type: {packet[ICMP].type} Code: {packet[ICMP].code}"
                        layers.append({
                            "name": "ICMP",
                            "fields": {
                                "Type": packet[ICMP].type,
                                "Code": packet[ICMP].code
                            }
                        })
                    
                    if packet.haslayer(Raw):
                        payload_data = packet[Raw].load
                        # Hex dump preview (first 32 bytes)
                        hex_preview = payload_data[:32].hex()
                        layers.append({
                            "name": "Payload",
                            "fields": {
                                "Data (Hex)": hex_preview,
                                "Length": len(payload_data)
                            }
                        })

                    packet_summaries.append({
                        "num": num,
                        "src": src,
                        "dst": dst,
                        "proto": proto,
                        "info": info,
                        "layers": layers # Added detailed layers
                    })
        
        # --- Process Analysis Results ---
        adversary_ip = None
        if scan_scores:
            potential_adversary = max(scan_scores, key=scan_scores.get)
            if scan_scores[potential_adversary] > ADVERSARY_HEURISTIC_THRESHOLD:
                adversary_ip = potential_adversary

        discovered_hosts = []
        all_ips = set(ip_to_mac_map.keys())
        for ip in sorted(list(all_ips)):
            discovered_hosts.append({
                'ip': ip,
                'mac': ip_to_mac_map.get(ip, 'N/A')
            })
        
        # Clean up the temp file after analysis
        os.remove(filepath)

        # Format Statistics
        formatted_endpoints = [{'ip': k, **v} for k, v in endpoints.items()]
        formatted_conversations = []
        for (ip1, ip2), stats in conversations.items():
            duration = stats['end_time'] - stats['start_time']
            formatted_conversations.append({
                'ip_a': ip1,
                'ip_b': ip2,
                'pkts': stats['pkts'],
                'bytes': stats['bytes'],
                'duration': duration if duration > 0 else 0
            })

        return jsonify({
            'hosts': discovered_hosts,
            'adversary': adversary_ip,
            'packets': packet_summaries,
            'endpoints': formatted_endpoints,
            'conversations': formatted_conversations
        })
    except Exception as e:
        return jsonify({'error': f'Failed to analyze PCAP: {e}'}), 500

@bp.route('/replay', methods=['POST'])
def start_replay_route():
    if 'pcapFile' not in request.files or request.files['pcapFile'].filename == '':
        return jsonify({'error': 'PCAP file is required.'}), 400
    
    file = request.files['pcapFile']
    filename = secure_filename(file.filename)
    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    try:
        loop_replay = 'loop_replay' in request.form
        loop_count_str = request.form.get('loop_count')
        loop_count = int(loop_count_str) if loop_replay and loop_count_str and loop_count_str.isdigit() and int(loop_count_str) > 0 else 0
        
        ttl_str = request.form.get('ttl')
        vlan_id_str = request.form.get('vlan_id')

        params = {
            'filepath': filepath,
            'interface': request.form['interface'],
            'ip_map': {o: n for o, n in zip(request.form.getlist('ip_original'), request.form.getlist('ip_new')) if o and n},
            'mac_map': {o.lower(): n.lower() for o, n in zip(request.form.getlist('mac_original'), request.form.getlist('mac_new')) if o and n},
            'port_map': {p_o: int(p_n) for p_o, p_n in zip(request.form.getlist('port_original'), request.form.getlist('port_new')) if p_o and p_n},
            'replay_speed': request.form.get('replay_speed', 'original'),
            'loop_replay': loop_replay,
            'loop_count': loop_count,
            'ttl': int(ttl_str) if ttl_str and ttl_str.isdigit() else None,
            'vlan_id': int(vlan_id_str) if vlan_id_str and vlan_id_str.isdigit() else None
        }
    except (KeyError, ValueError) as e:
        return jsonify({'error': f'Invalid or missing parameter for replay: {e}'}), 400
        
    return start_task(replay_pcap_task, params, 'Replay')

@bp.route('/generate', methods=['POST'])
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

@bp.route('/stop', methods=['POST'])
def stop_task_route():
    if active_task_status['is_running']:
        active_task_status['is_running'] = False
        return jsonify({'message': 'Stop signal sent.'})
    return jsonify({'message': 'No task is currently running.'})

@bp.route('/status')
def get_status_route():
    status_copy = active_task_status.copy()
    status_copy['logs'] = list(active_task_status['logs'])
    return jsonify(status_copy)

# --- Asset Routes ---
@bp.route('/api/assets', methods=['GET'])
def get_assets():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM assets ORDER BY name")
    assets = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(assets)

@bp.route('/api/assets', methods=['POST'])
def add_asset():
    data = request.json
    if not all(k in data for k in ['name', 'ip', 'mac']):
        return jsonify({'error': 'Missing required fields.'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO assets (name, ip, mac) VALUES (?, ?, ?)", (data['name'], data['ip'], data['mac']))
        conn.commit()
        return jsonify({'id': cursor.lastrowid, 'message': 'Asset added successfully.'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@bp.route('/api/assets/<int:asset_id>', methods=['DELETE'])
def delete_asset(asset_id):
    conn = get_db_connection()
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

# --- Config Routes ---
@bp.route('/api/replay_configs', methods=['GET'])
def get_replay_configs():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name FROM replay_configs ORDER BY name")
    configs = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(configs)

@bp.route('/api/replay_configs/<int:config_id>', methods=['GET'])
def get_replay_config_detail(config_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM replay_configs WHERE id = ?", (config_id,))
    config_row = cursor.fetchone()
    conn.close()
    if config_row is None:
        return jsonify({'error': 'Configuration not found.'}), 404
    
    config = dict(config_row)
    for key in ['ip_map', 'mac_map', 'port_map']:
        if config[key]:
            config[key] = json.loads(config[key])
    return jsonify(config)

@bp.route('/api/replay_configs', methods=['POST'])
def add_replay_config():
    data = request.json
    if not data or 'name' not in data:
        return jsonify({'error': 'Configuration name is required.'}), 400

    conn = get_db_connection()
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
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@bp.route('/api/replay_configs/<int:config_id>', methods=['DELETE'])
def delete_replay_config(config_id):
    conn = get_db_connection()
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

@bp.route('/api/config/export', methods=['POST'])
def export_config():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM assets")
    assets = [dict(row) for row in cursor.fetchall()]
    
    cursor.execute("SELECT * FROM replay_configs")
    configs = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    
    export_data = {
        'assets': assets,
        'configs': configs
    }
    
    return Response(
        json.dumps(export_data, indent=2),
        mimetype='application/json',
        headers={'Content-Disposition': 'attachment;filename=netrunner_backup.json'}
    )

@bp.route('/api/config/import', methods=['POST'])
def import_config():
    if 'configFile' not in request.files:
        return jsonify({'error': 'No file part.'}), 400
        
    file = request.files['configFile']
    if file.filename == '':
        return jsonify({'error': 'No file selected.'}), 400

    try:
        data = json.load(file)
        assets = data.get('assets', [])
        configs = data.get('configs', [])
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        added_assets = 0
        added_configs = 0
        
        for asset in assets:
            try:
                cursor.execute("INSERT INTO assets (name, ip, mac) VALUES (?, ?, ?)", 
                             (asset['name'], asset['ip'], asset['mac']))
                added_assets += 1
            except sqlite3.IntegrityError:
                pass # Skip duplicates
                
        for config in configs:
            try:
                cursor.execute("""
                    INSERT INTO replay_configs (name, interface, replay_speed, loop_replay, loop_count, ttl, vlan_id, ip_map, mac_map, port_map)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    config['name'], config['interface'], config['replay_speed'], config['loop_replay'], 
                    config['loop_count'], config['ttl'], config['vlan_id'], 
                    config['ip_map'], config['mac_map'], config['port_map']
                ))
                added_configs += 1
            except sqlite3.IntegrityError:
                pass # Skip duplicates

        conn.commit()
        conn.close()
        
        return jsonify({'message': f'Imported {added_assets} assets and {added_configs} configs.'})
        
    except Exception as e:
        return jsonify({'error': f'Import failed: {e}'}), 500
