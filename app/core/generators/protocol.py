"""
NetRunner OS - Protocol Traffic Generators
Generates realistic protocol conversations for NDR testing.
"""

import time
import random
import struct
from scapy.all import (
    Ether, IP, TCP, UDP, ICMP, Raw, DNS, DNSQR, DNSRR,
    sendp, get_if_hwaddr, RandShort
)
from app.core.engine import active_task_status, log_message


def generate(params):
    """Dispatch to the appropriate protocol generator."""
    proto = params.get('protocol', 'dns').lower()
    generators = {
        'dns': _gen_dns,
        'ftp': _gen_ftp,
        'smtp': _gen_smtp,
        'snmp': _gen_snmp,
        'ntp': _gen_ntp,
        'http': _gen_http,
        'icmp': _gen_icmp,
    }

    gen_func = generators.get(proto)
    if not gen_func:
        log_message(f"[!] Unknown protocol: {proto}")
        active_task_status['is_running'] = False
        return

    try:
        gen_func(params)
    except Exception as e:
        log_message(f"[!!!] Generator error: {e}")
        active_task_status['error'] = str(e)
    finally:
        active_task_status['is_running'] = False
        active_task_status['packets_per_second'] = 0
        log_message(f"[+] {proto.upper()} generation finished.")


def _base_packet(params):
    """Build base L2/L3 packet from params."""
    iface = params['interface']
    src_mac = params.get('src_mac') or get_if_hwaddr(iface)
    dst_mac = params.get('dst_mac', 'ff:ff:ff:ff:ff:ff')
    return (
        Ether(src=src_mac, dst=dst_mac) /
        IP(src=params['src_ip'], dst=params['dst_ip'])
    )


def _send_packets(packets, params):
    """Send a list of packets with delay and status tracking."""
    iface = params['interface']
    delay = params.get('delay', 0.5)
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
        active_task_status['message'] = f"Sending packet {i+1}/{total}"

        pps_count += 1
        if time.time() - pps_start >= 1.0:
            active_task_status['packets_per_second'] = pps_count
            pps_count = 0
            pps_start = time.time()

        if delay > 0:
            time.sleep(delay)


# ── DNS ──────────────────────────────────────────────────────────────────────

def _gen_dns(params):
    """Generate DNS query/response pairs."""
    log_message("[*] Generating DNS traffic...")
    count = params.get('count', 10)
    domain = params.get('domain', 'example.com')
    base = _base_packet(params)

    domains = [
        f"www.{domain}", f"mail.{domain}", f"api.{domain}",
        f"cdn.{domain}", f"login.{domain}", f"db.{domain}",
        f"ns1.{domain}", f"vpn.{domain}", f"ftp.{domain}",
        f"app.{domain}"
    ]

    packets = []
    for i in range(count):
        qname = random.choice(domains)
        # Query
        query = base / UDP(sport=RandShort(), dport=53) / DNS(
            rd=1, qd=DNSQR(qname=qname)
        )
        packets.append(query)
        log_message(f"    DNS Query: {qname}")

    _send_packets(packets, params)


# ── FTP ──────────────────────────────────────────────────────────────────────

def _gen_ftp(params):
    """Generate FTP login and file transfer simulation."""
    log_message("[*] Generating FTP traffic...")
    base = _base_packet(params)
    sport = random.randint(40000, 65000)

    ftp_commands = [
        ("220 Welcome to NetRunner FTP\r\n", None),
        (None, "USER admin\r\n"),
        ("331 Password required\r\n", None),
        (None, "PASS password123\r\n"),
        ("230 Login successful\r\n", None),
        (None, "PWD\r\n"),
        ('257 "/home/admin"\r\n', None),
        (None, "LIST\r\n"),
        ("150 Opening data connection\r\n", None),
        ("226 Transfer complete\r\n", None),
        (None, "RETR secret_data.txt\r\n"),
        ("150 Opening BINARY mode data connection\r\n", None),
        ("226 Transfer complete\r\n", None),
        (None, "QUIT\r\n"),
        ("221 Goodbye\r\n", None),
    ]

    packets = []
    # SYN
    packets.append(base / TCP(sport=sport, dport=21, flags='S'))
    # SYN-ACK
    packets.append(base / TCP(sport=21, dport=sport, flags='SA'))
    # ACK
    packets.append(base / TCP(sport=sport, dport=21, flags='A'))

    for server_resp, client_cmd in ftp_commands:
        if server_resp:
            packets.append(base / TCP(sport=21, dport=sport, flags='PA') / Raw(load=server_resp.encode()))
        if client_cmd:
            packets.append(base / TCP(sport=sport, dport=21, flags='PA') / Raw(load=client_cmd.encode()))

    _send_packets(packets, params)


# ── SMTP ─────────────────────────────────────────────────────────────────────

def _gen_smtp(params):
    """Generate SMTP email send sequence."""
    log_message("[*] Generating SMTP traffic...")
    base = _base_packet(params)
    sport = random.randint(40000, 65000)
    domain = params.get('domain', 'example.com')

    smtp_exchange = [
        (f"220 mail.{domain} ESMTP\r\n", None),
        (None, f"EHLO client.{domain}\r\n"),
        (f"250-mail.{domain}\r\n250-AUTH LOGIN PLAIN\r\n250 OK\r\n", None),
        (None, f"MAIL FROM:<admin@{domain}>\r\n"),
        ("250 OK\r\n", None),
        (None, f"RCPT TO:<user@{domain}>\r\n"),
        ("250 OK\r\n", None),
        (None, "DATA\r\n"),
        ("354 Start mail input\r\n", None),
        (None, f"Subject: Network Test\r\nFrom: admin@{domain}\r\n\r\nThis is a test email from NetRunner.\r\n.\r\n"),
        ("250 OK Message queued\r\n", None),
        (None, "QUIT\r\n"),
        ("221 Bye\r\n", None),
    ]

    packets = []
    packets.append(base / TCP(sport=sport, dport=25, flags='S'))
    packets.append(base / TCP(sport=25, dport=sport, flags='SA'))
    packets.append(base / TCP(sport=sport, dport=25, flags='A'))

    for server_resp, client_cmd in smtp_exchange:
        if server_resp:
            packets.append(base / TCP(sport=25, dport=sport, flags='PA') / Raw(load=server_resp.encode()))
        if client_cmd:
            packets.append(base / TCP(sport=sport, dport=25, flags='PA') / Raw(load=client_cmd.encode()))

    _send_packets(packets, params)


# ── SNMP ─────────────────────────────────────────────────────────────────────

def _gen_snmp(params):
    """Generate SNMP GET/SET/TRAP exchanges."""
    log_message("[*] Generating SNMP traffic...")
    count = params.get('count', 10)
    base = _base_packet(params)

    # Simple SNMP v1 GET request payloads (BER encoded stubs)
    community = b'public'
    packets = []

    for i in range(count):
        # SNMP GET request (simplified payload)
        snmp_payload = (
            b'\x30'  # SEQUENCE
            + b'\x26'
            + b'\x02\x01\x00'  # version: v1
            + b'\x04' + bytes([len(community)]) + community  # community string
            + b'\xa0\x19'  # GET-REQUEST
            + b'\x02\x01' + bytes([i % 256])  # request-id
            + b'\x02\x01\x00'  # error-status
            + b'\x02\x01\x00'  # error-index
            + b'\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01'  # OID: 1.3.6.1.2.1
            + b'\x05\x00'
        )
        pkt = base / UDP(sport=RandShort(), dport=161) / Raw(load=snmp_payload)
        packets.append(pkt)
        log_message(f"    SNMP GET #{i+1} (community: {community.decode()})")

    _send_packets(packets, params)


# ── NTP ──────────────────────────────────────────────────────────────────────

def _gen_ntp(params):
    """Generate NTP time sync requests."""
    log_message("[*] Generating NTP traffic...")
    count = params.get('count', 10)
    base = _base_packet(params)

    packets = []
    for i in range(count):
        # NTP client request (mode 3)
        ntp_payload = b'\x1b' + b'\x00' * 47
        pkt = base / UDP(sport=RandShort(), dport=123) / Raw(load=ntp_payload)
        packets.append(pkt)
        log_message(f"    NTP request #{i+1}")

    _send_packets(packets, params)


# ── HTTP ─────────────────────────────────────────────────────────────────────

def _gen_http(params):
    """Generate HTTP GET/POST requests with realistic headers."""
    log_message("[*] Generating HTTP traffic...")
    count = params.get('count', 10)
    base = _base_packet(params)
    domain = params.get('domain', 'example.com')
    sport = random.randint(40000, 65000)

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "curl/7.88.1",
    ]

    paths = ["/", "/api/v1/data", "/login", "/dashboard", "/search?q=test", "/status"]

    packets = []
    for i in range(count):
        path = random.choice(paths)
        ua = random.choice(user_agents)

        if random.random() > 0.3:
            # GET request
            http_req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {domain}\r\n"
                f"User-Agent: {ua}\r\n"
                f"Accept: text/html,application/json\r\n"
                f"Connection: keep-alive\r\n\r\n"
            )
        else:
            # POST request
            body = '{"username":"admin","action":"export"}'
            http_req = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {domain}\r\n"
                f"User-Agent: {ua}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n\r\n"
                f"{body}"
            )

        pkt = base / TCP(sport=sport + i, dport=80, flags='PA') / Raw(load=http_req.encode())
        packets.append(pkt)
        log_message(f"    HTTP {path}")

    _send_packets(packets, params)


# ── ICMP ─────────────────────────────────────────────────────────────────────

def _gen_icmp(params):
    """Generate ICMP echo requests (ping)."""
    log_message("[*] Generating ICMP traffic...")
    count = params.get('count', 10)
    base = _base_packet(params)

    packets = []
    for i in range(count):
        pkt = base / ICMP(type=8, code=0, id=random.randint(1, 65535), seq=i+1) / Raw(load=b'\x00' * 56)
        packets.append(pkt)

    _send_packets(packets, params)
