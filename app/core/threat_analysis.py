"""
NetRunner OS - Threat Analysis
Heuristic scoring of analysed traffic to surface likely adversary -> victim
streams. Detection fingerprints are aligned with the traffic the built-in
adversary simulations produce (see app/core/generators/adversary.py) so that
generated attacks are flagged and explained, while still behaving sensibly on
real-world captures.

No external threat intel is used - everything is derived locally from the
per-conversation signals collected during PCAP analysis.
"""

import math
import ipaddress
from collections import defaultdict

# ── Well-known port groupings ────────────────────────────────────────────────

LATERAL_PORTS = {445: "SMB", 139: "NetBIOS", 3389: "RDP", 5985: "WinRM",
                 135: "RPC", 22: "SSH"}
C2_WEB_PORTS = {80, 443, 8080, 8443, 8888}
KERBEROS_PORT = 88
DNS_PORT = 53
LLMNR_PORT = 5355
NBTNS_PORT = 137

# Score -> severity banding
SEV_BANDS = [(80, "critical"), (60, "high"), (40, "medium"), (0, "low")]

# Threats below this score are dropped from the report
MIN_SCORE = 30


# ── Helpers ──────────────────────────────────────────────────────────────────

def _is_internal(ip):
    """True for RFC1918 / loopback / link-local addresses."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def _is_multicast_or_broadcast(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_multicast or ip.endswith(".255") or ip == "255.255.255.255"


def _entropy(s):
    """Shannon entropy (bits/char) of a string."""
    if not s:
        return 0.0
    counts = defaultdict(int)
    for ch in s:
        counts[ch] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _severity(score):
    for threshold, label in SEV_BANDS:
        if score >= threshold:
            return label
    return "low"


def _stats(values):
    """Return (mean, coefficient_of_variation) for a list of numbers."""
    if len(values) < 2:
        return (values[0] if values else 0.0), 1.0
    mean = sum(values) / len(values)
    if mean == 0:
        return 0.0, 1.0
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    cv = math.sqrt(variance) / mean
    return mean, cv


def _intervals(timestamps):
    """Sorted inter-arrival gaps from a list of timestamps."""
    if len(timestamps) < 2:
        return []
    ts = sorted(timestamps)
    return [b - a for a, b in zip(ts, ts[1:]) if b - a > 0]


# ── Main entry point ─────────────────────────────────────────────────────────

def analyze_threats(flows, arp):
    """
    Score every conversation and return a ranked list of threat findings.

    `flows` is a dict keyed by a sorted (ip_a, ip_b) tuple. See
    routes/pcap.py for the exact shape it collects. `arp` carries ARP-layer
    observations that have no IP conversation of their own.
    """
    findings = []

    # Per-source aggregation for cross-conversation techniques (scan spread,
    # lateral movement, NTLM relay).
    src_lateral = defaultdict(lambda: {"targets": set(), "ports": set(), "pkts": 0})
    smb_initiators = defaultdict(set)   # host -> set of hosts it opened 445 to
    smb_receivers = defaultdict(set)    # host -> set of hosts that opened 445 to it

    for (a, b), f in flows.items():
        total_pkts = sum(d["pkts"] for d in f["dirs"].values())
        total_bytes = sum(d["bytes"] for d in f["dirs"].values())
        protocols = sorted(f["protocols"])
        base = {
            "pkts": total_pkts,
            "bytes": total_bytes,
            "protocols": protocols,
        }

        for (src, dst), d in f["dirs"].items():
            # Feed cross-conversation aggregations.
            lateral_hit = {p for p in d["ports"] if p in LATERAL_PORTS}
            if lateral_hit and _is_internal(src) and _is_internal(dst):
                agg = src_lateral[src]
                agg["targets"].add(dst)
                agg["ports"].update(lateral_hit)
                agg["pkts"] += d["pkts"]
            if 445 in d["ports"]:
                smb_initiators[src].add(dst)
                smb_receivers[dst].add(src)

        # ── Per-conversation detectors ──
        _detect_port_scan(a, b, f, base, findings)
        _detect_c2_beacon(a, b, f, base, findings)
        _detect_http_exfil(a, b, f, base, findings)
        _detect_dns(a, b, f, base, findings)
        _detect_icmp_tunnel(a, b, f, base, findings)
        _detect_kerberoast(a, b, f, base, findings)
        _detect_dcsync(a, b, f, base, findings)
        _detect_llmnr(a, b, f, base, findings)

    # ── Cross-conversation detectors ──
    _detect_lateral_movement(src_lateral, findings)
    _detect_ntlm_relay(smb_initiators, smb_receivers, findings)
    _detect_arp_spoof(arp, findings)

    # Rank and de-duplicate (same technique + adversary + victim).
    seen = set()
    ranked = []
    for fnd in sorted(findings, key=lambda x: x["score"], reverse=True):
        key = (fnd["technique"], fnd.get("adversary"), fnd.get("victim"))
        if key in seen:
            continue
        seen.add(key)
        fnd["severity"] = _severity(fnd["score"])
        ranked.append(fnd)

    return ranked[:50]


# ── Detectors ────────────────────────────────────────────────────────────────

def _add(findings, base, technique, mitre, adversary, victim, score, reasons):
    entry = dict(base)
    entry.update({
        "technique": technique,
        "mitre": mitre,
        "adversary": adversary,
        "victim": victim,
        "score": min(int(score), 100),
        "reasons": reasons,
    })
    findings.append(entry)


def _detect_port_scan(a, b, f, base, findings):
    """One host hitting many ports on a single target, mostly SYN."""
    for (src, dst), d in f["dirs"].items():
        unique_ports = len(d["ports"])
        if unique_ports < 8:
            continue
        # Scan = lots of SYNs, few completed handshakes.
        if d["syn"] < unique_ports * 0.7:
            continue
        rev = f["dirs"].get((dst, src), {})
        synack = rev.get("synack", 0)
        if synack > d["syn"] * 0.5:
            continue  # too many successful handshakes to be a stealth scan
        score = 55 + min(unique_ports, 40)
        reasons = [
            f"{src} probed {unique_ports} distinct ports on {dst}",
            f"{d['syn']} SYN packets with only {synack} SYN-ACK replies "
            f"(mostly unanswered = scanning)",
        ]
        _add(findings, base, "Port Scanning", "T1046", src, dst, score, reasons)


def _detect_c2_beacon(a, b, f, base, findings):
    """Regular, repeated web callbacks from an internal host to an external one."""
    for (src, dst), d in f["dirs"].items():
        if not (_is_internal(src) and not _is_internal(dst)):
            continue
        if not (set(d["ports"]) & C2_WEB_PORTS):
            continue
        beacons = len(d["syn_times"])
        if beacons < 5:
            continue
        gaps = _intervals(d["syn_times"])
        if not gaps:
            continue
        mean, cv = _stats(gaps)
        if cv > 0.35 or mean <= 0:
            continue  # irregular timing = normal browsing
        # Lower jitter + more beacons = higher confidence.
        score = 60 + min(beacons, 25) + int((0.35 - cv) * 40)
        port = next(iter(set(d["ports"]) & C2_WEB_PORTS))
        reasons = [
            f"{beacons} connections from {src} to external {dst}:{port}",
            f"Highly regular interval (~{mean:.1f}s, jitter {cv * 100:.0f}%) "
            f"consistent with automated beaconing",
        ]
        _add(findings, base, "C2 Beaconing", "T1071", dst, src, score, reasons)


def _detect_http_exfil(a, b, f, base, findings):
    """Large outbound payload from an internal host to an external host."""
    for (src, dst), d in f["dirs"].items():
        if not (_is_internal(src) and not _is_internal(dst)):
            continue
        if not (set(d["ports"]) & C2_WEB_PORTS):
            continue
        rev = f["dirs"].get((dst, src), {})
        out = d["payload"]
        inb = rev.get("payload", 0)
        if out < 20000 or out < inb * 3:
            continue
        kb = out / 1024
        score = 55 + min(int(kb / 20), 40)
        reasons = [
            f"{kb:.0f} KB uploaded from {src} to external {dst} "
            f"(inbound only {inb / 1024:.0f} KB)",
            "Large asymmetric outbound transfer typical of data exfiltration",
        ]
        _add(findings, base, "Data Exfiltration (HTTP)", "T1048", dst, src, score, reasons)


def _detect_dns(a, b, f, base, findings):
    """Distinguish DNS tunnelling/exfil from DGA beacon lookups."""
    qnames = f["dns_qnames"]
    if len(qnames) < 5:
        return

    # Signals
    long_label = 0
    random_slds = 0
    base_domains = set()
    for q in qnames:
        labels = [l for l in q.rstrip(".").split(".") if l]
        if not labels:
            continue
        if max(len(l) for l in labels) >= 25:
            long_label += 1
        base_domains.add(".".join(labels[-2:]) if len(labels) >= 2 else labels[-1])
        # "Random-looking" registrable label: high entropy, or moderate entropy
        # with an unusually high digit ratio (hallmark of DGA / hashed names).
        sld = labels[-2] if len(labels) >= 2 else labels[-1]
        ent = _entropy(sld)
        digit_ratio = sum(c.isdigit() for c in sld) / len(sld) if sld else 0
        if ent >= 3.3 or (ent >= 2.6 and digit_ratio >= 0.2 and len(sld) >= 8):
            random_slds += 1

    src = _pick_dns_client(f)
    dst = _pick_dns_server(f)

    # DNS exfiltration: data encoded in long subdomains of a fixed domain.
    if long_label >= 3 and len(base_domains) <= max(3, len(qnames) // 5):
        score = 60 + min(long_label * 2, 35)
        reasons = [
            f"{long_label} DNS queries with oversized labels (>=25 chars) "
            f"under {next(iter(base_domains))}",
            "Encoded data in subdomains is a hallmark of DNS tunnelling/exfil",
        ]
        _add(findings, base, "DNS Exfiltration", "T1048.003", src, dst, score, reasons)
        return

    # DGA: many distinct, random-looking registrable domains.
    if len(base_domains) >= 8 and random_slds >= max(5, len(qnames) // 3):
        score = 55 + min(len(base_domains), 35)
        reasons = [
            f"{len(base_domains)} distinct domains queried, "
            f"{random_slds} with random-looking (high-entropy/digit-heavy) names",
            "Large sets of algorithmic domains indicate DGA-based C2 lookup",
        ]
        _add(findings, base, "DGA Traffic", "T1568.002", src, dst, score, reasons)


def _detect_icmp_tunnel(a, b, f, base, findings):
    """Oversized ICMP echo payloads carrying tunnelled data."""
    if f["icmp_count"] < 3:
        return
    avg = f["icmp_size_sum"] / f["icmp_count"]
    if avg <= 100:
        return  # normal echo payloads are ~32-56 bytes
    src, dst = a, b
    # Prefer the internal host as the likely compromised endpoint.
    if _is_internal(b) and not _is_internal(a):
        src, dst = b, a
    score = 60 + min(int(avg / 20), 35)
    reasons = [
        f"{f['icmp_count']} ICMP packets with avg payload ~{avg:.0f} bytes "
        f"(normal is 32-56)",
        "Oversized ICMP payloads are used to tunnel/exfiltrate data",
    ]
    _add(findings, base, "ICMP Tunneling", "T1048.003", src, dst, score, reasons)


def _detect_kerberoast(a, b, f, base, findings):
    """A single host requesting many Kerberos service tickets in a burst."""
    for (src, dst), d in f["dirs"].items():
        if KERBEROS_PORT not in d["ports"]:
            continue
        requests = max(len(d["syn_times"]), d["ports"][KERBEROS_PORT])
        if requests < 8:
            continue
        score = 55 + min(requests, 35)
        reasons = [
            f"{requests} Kerberos requests from {src} to KDC {dst}:88 in a burst",
            "High volume of TGS requests from one host indicates Kerberoasting",
        ]
        _add(findings, base, "Kerberoasting", "T1558.003", src, dst, score, reasons)


def _detect_dcsync(a, b, f, base, findings):
    """AD replication (RPC) pulling large data from a DC to a non-DC host."""
    for (src, dst), d in f["dirs"].items():
        if 135 not in d["ports"]:
            continue
        rev = f["dirs"].get((dst, src), {})
        # Big server->client response is the replication data.
        if rev.get("payload", 0) < 3000:
            continue
        if not (_is_internal(src) and _is_internal(dst)):
            continue
        score = 55 + min(int(rev["payload"] / 2000), 30)
        reasons = [
            f"{src} performed RPC replication against {dst} (MS-DRSR / port 135)",
            f"{rev['payload'] / 1024:.0f} KB replication data returned - "
            f"directory replication from a non-DC host suggests DCSync",
        ]
        _add(findings, base, "DCSync", "T1003.006", src, dst, score, reasons)


def _detect_llmnr(a, b, f, base, findings):
    """Spoofed LLMNR / NBT-NS name resolution responses."""
    for (src, dst), d in f["dirs"].items():
        if not ({LLMNR_PORT, NBTNS_PORT} & set(d["ports"])):
            continue
        if not _is_multicast_or_broadcast(dst):
            continue
        port = next(iter({LLMNR_PORT, NBTNS_PORT} & set(d["ports"])))
        svc = "LLMNR" if port == LLMNR_PORT else "NBT-NS"
        score = 60 + min(d["pkts"], 30)
        reasons = [
            f"{src} sent {d['pkts']} {svc} packets to {dst} (multicast/broadcast)",
            "Unsolicited name-resolution responses indicate LLMNR/NBT-NS poisoning",
        ]
        _add(findings, base, "LLMNR/NBT-NS Poisoning", "T1557.001",
             src, dst, score, reasons)


def _detect_lateral_movement(src_lateral, findings):
    """One internal host reaching many internal hosts on admin/remote ports."""
    for src, agg in src_lateral.items():
        if len(agg["targets"]) < 5:
            continue
        port_names = ", ".join(sorted(LATERAL_PORTS[p] for p in agg["ports"]))
        score = 60 + min(len(agg["targets"]) * 2, 35)
        reasons = [
            f"{src} connected to {len(agg['targets'])} internal hosts "
            f"over {port_names}",
            "Fan-out across many hosts on remote-admin ports indicates "
            "lateral movement",
        ]
        _add(findings, {"pkts": agg["pkts"], "bytes": 0,
                        "protocols": ["TCP"]},
             "Lateral Movement", "T1021", src,
             f"{len(agg['targets'])} hosts", score, reasons)


def _detect_ntlm_relay(smb_initiators, smb_receivers, findings):
    """A host both receiving and forwarding SMB auth = relay pivot."""
    for host in set(smb_initiators) & set(smb_receivers):
        out_targets = smb_initiators[host]
        in_sources = smb_receivers[host] - {host}
        if not out_targets or len(in_sources) < 2:
            continue
        score = 55 + min(len(in_sources) * 3, 30)
        reasons = [
            f"{host} received SMB auth from {len(in_sources)} hosts and "
            f"forwarded SMB to {len(out_targets)} others",
            "Inbound auth relayed straight back out is the NTLM relay pattern",
        ]
        _add(findings, {"pkts": 0, "bytes": 0, "protocols": ["SMB"]},
             "NTLM Relay", "T1557.001", host,
             ", ".join(sorted(out_targets)), score, reasons)


def _detect_arp_spoof(arp, findings):
    """Duplicate IP->MAC bindings or floods of gratuitous ARP replies."""
    # One IP claimed by multiple MACs.
    for ip, macs in arp.get("ip_to_macs", {}).items():
        if len(macs) >= 2:
            score = 70 + min(len(macs) * 5, 25)
            reasons = [
                f"IP {ip} is claimed by {len(macs)} different MAC addresses: "
                f"{', '.join(sorted(macs))}",
                "Conflicting IP-to-MAC bindings indicate ARP cache poisoning",
            ]
            _add(findings, {"pkts": 0, "bytes": 0, "protocols": ["ARP"]},
                 "ARP Spoofing", "T1557.002", ", ".join(sorted(macs)),
                 ip, score, reasons)

    # A single MAC sending a flood of gratuitous replies.
    for mac, count in arp.get("gratuitous_by_mac", {}).items():
        if count >= 10:
            claimed = sorted(arp.get("mac_to_ips", {}).get(mac, []))
            score = 60 + min(count, 30)
            reasons = [
                f"{mac} sent {count} gratuitous ARP replies",
                f"Claiming {len(claimed)} IP(s): {', '.join(claimed) or 'n/a'}",
            ]
            _add(findings, {"pkts": count, "bytes": 0, "protocols": ["ARP"]},
                 "ARP Spoofing", "T1557.002", mac,
                 ", ".join(claimed) or "gateway", score, reasons)


# ── DNS role helpers ─────────────────────────────────────────────────────────

def _pick_dns_client(f):
    for (src, dst), d in f["dirs"].items():
        if DNS_PORT in d["ports"]:
            return src
    return f["a"]


def _pick_dns_server(f):
    for (src, dst), d in f["dirs"].items():
        if DNS_PORT in d["ports"]:
            return dst
    return f["b"]
