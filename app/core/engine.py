"""
NetRunner OS - Core Engine
Handles PCAP replay and status tracking.
"""

import time
import threading
from collections import deque
from scapy.all import PcapReader, sendp, get_if_hwaddr, Ether, IP, TCP, UDP, ICMP, Raw, Dot1Q

# ── Global Task Status ───────────────────────────────────────────────────────

active_task_status = {
    'is_running': False,
    'task_type': None,
    'message': 'Ready.',
    'progress': 0,
    'total': 0,
    'loop_count': 0,
    'packets_per_second': 0,
    'logs': deque(maxlen=200),
    'error': None
}


def log_message(msg):
    """Log to console and web UI."""
    print(msg)
    active_task_status['logs'].append(f'[{time.strftime("%H:%M:%S")}] {msg}')


# ── PCAP Replay ──────────────────────────────────────────────────────────────

def replay_pcap_task(params: dict):
    """Replay a PCAP with optional rewrite rules applied on-the-fly."""
    try:
        log_message("[*] PCAP Replay Task Initialized.")
        log_message(f"    Interface: {params['interface']}")
        log_message(f"    Speed: {params['replay_speed']}, Loop: {params['loop_replay']}")

        if params['loop_replay']:
            loop_target = params['loop_count'] if params['loop_count'] > 0 else "Infinite"
            log_message(f"    Loop Count: {loop_target}")
        if params.get('ttl'):
            log_message(f"    Set TTL: {params['ttl']}")
        if params.get('vlan_id'):
            log_message(f"    Set VLAN ID: {params['vlan_id']}")
        if params.get('ip_map'):
            log_message(f"    IP Maps: {params['ip_map']}")
        if params.get('mac_map'):
            log_message(f"    MAC Maps: {params['mac_map']}")
        if params.get('port_map'):
            log_message(f"    Port Maps: {params['port_map']}")

        # Count packets
        log_message("[*] Counting packets...")
        with PcapReader(params['filepath']) as reader:
            total_packets = sum(1 for _ in reader)
        active_task_status['total'] = total_packets
        log_message(f"[*] Found {total_packets} packets.")

        current_loop = 1
        ip_map = params.get('ip_map', {})
        mac_map = params.get('mac_map', {})
        port_map = params.get('port_map', {})
        vlan_id = params.get('vlan_id')
        ttl = params.get('ttl')
        replay_speed = params.get('replay_speed', 'original')
        interface = params['interface']

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
                active_task_status['message'] = f"Loop {current_loop}: Sending packet {i+1}/{total_packets}"

                pps_packet_count += 1
                if time.time() - pps_start_time >= 1.0:
                    active_task_status['packets_per_second'] = pps_packet_count
                    pps_packet_count = 0
                    pps_start_time = time.time()

                # Original timing
                if replay_speed == 'original':
                    if last_packet_time is None:
                        last_packet_time = packet.time
                    delay = packet.time - last_packet_time
                    if delay > 0:
                        time.sleep(float(delay))
                    last_packet_time = packet.time

                modified = packet.copy()

                # VLAN
                if vlan_id is not None:
                    if modified.haslayer(Dot1Q):
                        modified.getlayer(Dot1Q).vlan = vlan_id
                    elif modified.haslayer(Ether):
                        payload = modified[Ether].payload
                        modified = Ether(src=modified[Ether].src, dst=modified[Ether].dst) / Dot1Q(vlan=vlan_id) / payload

                # MAC rewrite
                if mac_map and modified.haslayer(Ether):
                    eth = modified.getlayer(Ether)
                    if eth.src in mac_map:
                        eth.src = mac_map[eth.src]
                    if eth.dst in mac_map:
                        eth.dst = mac_map[eth.dst]

                # IP rewrite
                if modified.haslayer(IP):
                    ip_layer = modified.getlayer(IP)
                    if ip_map:
                        if ip_layer.src in ip_map:
                            ip_layer.src = ip_map[ip_layer.src]
                        if ip_layer.dst in ip_map:
                            ip_layer.dst = ip_map[ip_layer.dst]
                    if ttl is not None:
                        ip_layer.ttl = ttl

                    # Port rewrite
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

                sendp(modified, iface=interface, verbose=0)

            if not params['loop_replay']:
                break
            if params['loop_count'] > 0 and current_loop >= params['loop_count']:
                log_message(f"[*] Reached loop count ({params['loop_count']}).")
                break

            current_loop += 1
            active_task_status['progress'] = 0
            time.sleep(1)

        if active_task_status['is_running']:
            log_message("[+] Replay finished.")
            active_task_status['message'] = "Replay finished."

    except Exception as e:
        log_message(f"[!!!] Replay error: {e}")
        active_task_status['error'] = str(e)
        active_task_status['message'] = f"Error: {e}"
    finally:
        active_task_status['is_running'] = False
        active_task_status['packets_per_second'] = 0
        log_message("[+] Replay thread finished.")
