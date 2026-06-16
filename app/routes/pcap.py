"""
NetRunner OS - PCAP Analysis & Rewrite Routes
"""

import os
from flask import Blueprint, request, jsonify, current_app, send_file
from werkzeug.utils import secure_filename
from collections import defaultdict
from scapy.all import PcapReader, PcapWriter, Ether, IP, TCP, UDP, ICMP, Raw, Dot1Q

bp = Blueprint('pcap', __name__)

PACKET_VIEWER_LIMIT = 2000


@bp.route('/analyze_pcap', methods=['POST'])
def analyze_pcap():
    """Parse a PCAP and return packets, conversations, endpoints, and timeline."""
    if 'pcapFile' not in request.files:
        return jsonify({'error': 'No file part in the request.'}), 400

    file = request.files['pcapFile']
    if file.filename == '':
        return jsonify({'error': 'No file selected.'}), 400

    try:
        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
        file.save(filepath)
        # Store the filepath for later rewrite/replay
        current_app.config['LAST_PCAP'] = filepath

        ip_to_mac_map = {}
        packet_summaries = []
        endpoints = defaultdict(lambda: {'tx_pkts': 0, 'rx_pkts': 0, 'tx_bytes': 0, 'rx_bytes': 0, 'protocols': set()})
        conversations = defaultdict(lambda: {
            'pkts': 0, 'bytes': 0, 'protocols': set(),
            'start_time': float('inf'), 'end_time': 0
        })
        timeline = []

        with PcapReader(filepath) as pcap_reader:
            for i, packet in enumerate(pcap_reader):
                has_ip = packet.haslayer(IP)
                has_ether = packet.haslayer(Ether)
                pkt_len = len(packet)
                ts = float(packet.time)

                # Determine protocol
                proto = packet.name
                if packet.haslayer(TCP):
                    proto = "TCP"
                elif packet.haslayer(UDP):
                    proto = "UDP"
                elif packet.haslayer(ICMP):
                    proto = "ICMP"

                if has_ip:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst

                    # Endpoints
                    endpoints[src_ip]['tx_pkts'] += 1
                    endpoints[src_ip]['tx_bytes'] += pkt_len
                    endpoints[src_ip]['protocols'].add(proto)
                    endpoints[dst_ip]['rx_pkts'] += 1
                    endpoints[dst_ip]['rx_bytes'] += pkt_len
                    endpoints[dst_ip]['protocols'].add(proto)

                    # Conversations
                    conv_key = tuple(sorted([src_ip, dst_ip]))
                    c = conversations[conv_key]
                    c['pkts'] += 1
                    c['bytes'] += pkt_len
                    c['protocols'].add(proto)
                    c['start_time'] = min(c['start_time'], ts)
                    c['end_time'] = max(c['end_time'], ts)

                    # Timeline events (sampled for performance)
                    if i % max(1, i // 500 + 1) == 0 or i < 200:
                        timeline.append({
                            'ts': ts,
                            'src': src_ip,
                            'dst': dst_ip,
                            'proto': proto,
                            'len': pkt_len
                        })

                if has_ip and has_ether:
                    ip_to_mac_map[packet[IP].src] = packet[Ether].src
                    ip_to_mac_map[packet[IP].dst] = packet[Ether].dst

                # Packet summaries for viewer
                if len(packet_summaries) < PACKET_VIEWER_LIMIT:
                    src = "N/A"
                    dst = "N/A"
                    info = packet.summary()
                    layers = []

                    if has_ether:
                        layers.append({
                            "name": "Ethernet",
                            "fields": {
                                "Source": packet[Ether].src,
                                "Destination": packet[Ether].dst,
                                "Type": hex(packet[Ether].type)
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
                                "Protocol": packet[IP].proto
                            }
                        })
                        src = packet[IP].src
                        dst = packet[IP].dst

                    if packet.haslayer(TCP):
                        tcp = packet[TCP]
                        info = f"{tcp.sport} → {tcp.dport} [{str(tcp.flags)}]"
                        layers.append({
                            "name": "TCP",
                            "fields": {
                                "Source Port": tcp.sport,
                                "Dest Port": tcp.dport,
                                "Seq": tcp.seq,
                                "Ack": tcp.ack,
                                "Flags": str(tcp.flags),
                                "Window": tcp.window
                            }
                        })
                    elif packet.haslayer(UDP):
                        udp = packet[UDP]
                        info = f"{udp.sport} → {udp.dport} len={udp.len}"
                        layers.append({
                            "name": "UDP",
                            "fields": {
                                "Source Port": udp.sport,
                                "Dest Port": udp.dport,
                                "Length": udp.len
                            }
                        })
                    elif packet.haslayer(ICMP):
                        icmp = packet[ICMP]
                        info = f"Type={icmp.type} Code={icmp.code}"
                        layers.append({
                            "name": "ICMP",
                            "fields": {
                                "Type": icmp.type,
                                "Code": icmp.code,
                                "ID": icmp.id if hasattr(icmp, 'id') else "N/A"
                            }
                        })

                    if packet.haslayer(Raw):
                        payload = bytes(packet[Raw].load)
                        hex_dump = ' '.join(f'{b:02x}' for b in payload[:128])
                        layers.append({
                            "name": "Payload",
                            "fields": {
                                "Length": len(payload),
                                "Hex Preview": hex_dump
                            }
                        })

                    packet_summaries.append({
                        "num": i + 1,
                        "src": src,
                        "dst": dst,
                        "proto": proto,
                        "info": info,
                        "len": pkt_len,
                        "time": ts,
                        "layers": layers
                    })

        # Build response
        hosts = [{"ip": ip, "mac": mac} for ip, mac in ip_to_mac_map.items()]

        endpoint_list = []
        for ip, stats in endpoints.items():
            endpoint_list.append({
                "ip": ip,
                "mac": ip_to_mac_map.get(ip, "N/A"),
                "tx_pkts": stats['tx_pkts'],
                "rx_pkts": stats['rx_pkts'],
                "tx_bytes": stats['tx_bytes'],
                "rx_bytes": stats['rx_bytes'],
                "protocols": list(stats['protocols'])
            })
        endpoint_list.sort(key=lambda e: e['tx_pkts'] + e['rx_pkts'], reverse=True)

        conv_list = []
        for (a, b), stats in conversations.items():
            duration = stats['end_time'] - stats['start_time'] if stats['end_time'] > stats['start_time'] else 0
            conv_list.append({
                "addr_a": a,
                "addr_b": b,
                "pkts": stats['pkts'],
                "bytes": stats['bytes'],
                "protocols": list(stats['protocols']),
                "duration": round(duration, 3)
            })
        conv_list.sort(key=lambda c: c['pkts'], reverse=True)

        return jsonify({
            "packets": packet_summaries,
            "hosts": hosts,
            "endpoints": endpoint_list,
            "conversations": conv_list,
            "timeline": timeline,
            "total_packets": i + 1 if 'i' in dir() else 0,
            "filepath": filepath
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/rewrite_pcap', methods=['POST'])
def rewrite_pcap():
    """Apply rewrite rules to the last uploaded PCAP and return a downloadable file."""
    try:
        data = request.get_json()
        filepath = data.get('filepath') or current_app.config.get('LAST_PCAP')
        if not filepath or not os.path.exists(filepath):
            return jsonify({'error': 'No PCAP file found. Please upload one first.'}), 400

        ip_map = data.get('ip_map', {})
        mac_map = data.get('mac_map', {})
        port_map = data.get('port_map', {})
        ttl = data.get('ttl')
        vlan_id = data.get('vlan_id')

        output_filename = f"rewritten_{os.path.basename(filepath)}"
        output_path = os.path.join(current_app.config['UPLOAD_FOLDER'], output_filename)

        packet_count = 0
        with PcapReader(filepath) as reader:
            writer = PcapWriter(output_path, sync=True)
            for packet in reader:
                modified = packet.copy()

                # VLAN tagging
                if vlan_id is not None:
                    if modified.haslayer(Dot1Q):
                        modified.getlayer(Dot1Q).vlan = int(vlan_id)
                    elif modified.haslayer(Ether):
                        payload = modified[Ether].payload
                        modified = Ether(src=modified[Ether].src, dst=modified[Ether].dst) / Dot1Q(vlan=int(vlan_id)) / payload

                # MAC rewriting
                if mac_map and modified.haslayer(Ether):
                    eth = modified.getlayer(Ether)
                    if eth.src in mac_map:
                        eth.src = mac_map[eth.src]
                    if eth.dst in mac_map:
                        eth.dst = mac_map[eth.dst]

                # IP rewriting
                if modified.haslayer(IP):
                    ip_layer = modified.getlayer(IP)
                    if ip_map:
                        if ip_layer.src in ip_map:
                            ip_layer.src = ip_map[ip_layer.src]
                        if ip_layer.dst in ip_map:
                            ip_layer.dst = ip_map[ip_layer.dst]
                    if ttl is not None:
                        ip_layer.ttl = int(ttl)

                    # Port rewriting
                    if port_map:
                        if ip_layer.haslayer(TCP):
                            tcp = ip_layer.getlayer(TCP)
                            if str(tcp.sport) in port_map:
                                tcp.sport = int(port_map[str(tcp.sport)])
                            if str(tcp.dport) in port_map:
                                tcp.dport = int(port_map[str(tcp.dport)])
                        elif ip_layer.haslayer(UDP):
                            udp = ip_layer.getlayer(UDP)
                            if str(udp.sport) in port_map:
                                udp.sport = int(port_map[str(udp.sport)])
                            if str(udp.dport) in port_map:
                                udp.dport = int(port_map[str(udp.dport)])

                    # Recalculate checksums
                    if ip_layer.chksum is not None:
                        del ip_layer.chksum
                    if ip_layer.haslayer(TCP) and ip_layer[TCP].chksum is not None:
                        del ip_layer[TCP].chksum
                    elif ip_layer.haslayer(UDP) and ip_layer[UDP].chksum is not None:
                        del ip_layer[UDP].chksum

                writer.write(modified)
                packet_count += 1

            writer.close()

        return send_file(
            output_path,
            as_attachment=True,
            download_name=output_filename,
            mimetype='application/octet-stream'
        )

    except Exception as e:
        return jsonify({'error': str(e)}), 500
