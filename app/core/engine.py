import time
import threading
from collections import deque
from scapy.all import PcapReader, sendp, get_if_hwaddr, Ether, IP, TCP, UDP, ICMP, Raw, Dot1Q

# Global State for Active Task
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
            
            # Pre-process maps for faster lookup
            ip_map = params['ip_map']
            mac_map = params['mac_map']
            port_map = params['port_map']
            vlan_id = params['vlan_id']
            ttl = params['ttl']
            replay_speed = params['replay_speed']
            interface = params['interface']

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

                if replay_speed == 'original':
                    if last_packet_time is None: last_packet_time = packet.time
                    delay = packet.time - last_packet_time
                    if delay > 0: time.sleep(float(delay))
                    last_packet_time = packet.time

                modified_packet = packet.copy()
                
                if vlan_id is not None:
                    if modified_packet.haslayer(Dot1Q): modified_packet.getlayer(Dot1Q).vlan = vlan_id
                    elif modified_packet.haslayer(Ether):
                        payload = modified_packet[Ether].payload
                        modified_packet = Ether(src=modified_packet[Ether].src, dst=modified_packet[Ether].dst) / Dot1Q(vlan=vlan_id) / payload

                if mac_map and modified_packet.haslayer(Ether):
                    ether_layer = modified_packet.getlayer(Ether)
                    if ether_layer.src in mac_map: ether_layer.src = mac_map[ether_layer.src]
                    if ether_layer.dst in mac_map: ether_layer.dst = mac_map[ether_layer.dst]

                if modified_packet.haslayer(IP):
                    ip_layer = modified_packet.getlayer(IP)
                    if ip_map:
                        if ip_layer.src in ip_map: ip_layer.src = ip_map[ip_layer.src]
                        if ip_layer.dst in ip_map: ip_layer.dst = ip_map[ip_layer.dst]
                    if ttl is not None: ip_layer.ttl = ttl
                    
                    if port_map:
                        if ip_layer.haslayer(TCP):
                            tcp_layer = ip_layer.getlayer(TCP)
                            if str(tcp_layer.sport) in port_map: tcp_layer.sport = port_map[str(tcp_layer.sport)]
                            if str(tcp_layer.dport) in port_map: tcp_layer.dport = port_map[str(tcp_layer.dport)]
                        elif ip_layer.haslayer(UDP):
                            udp_layer = ip_layer.getlayer(UDP)
                            if str(udp_layer.sport) in port_map: udp_layer.sport = port_map[str(udp_layer.sport)]
                            if str(udp_layer.dport) in port_map: udp_layer.dport = port_map[str(udp_layer.dport)]
                    
                    if ip_layer.chksum is not None: del ip_layer.chksum
                    if ip_layer.haslayer(TCP) and ip_layer[TCP].chksum is not None: del ip_layer[TCP].chksum
                    elif ip_layer.haslayer(UDP) and ip_layer[UDP].chksum is not None: del ip_layer[UDP].chksum

                sendp(modified_packet, iface=interface, verbose=0)
            
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
