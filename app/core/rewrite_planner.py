"""
NetRunner OS - Rewrite Planner

Turns the addressing observed in a capture into a ready-to-apply rewrite plan
for a lab environment, so an operator doesn't have to eyeball every PCAP in
Wireshark before replaying it at an NDR sensor.

The usual recipe this encodes:
  * Pull the internal (RFC1918) hosts into the NDR's monitored lab range,
    preserving host octets (192.168.1.10 -> 10.99.0.10) so conversations stay
    intelligible.
  * Leave external IPs untouched - an outbound-to-C2 flow should still look
    external to the sensor.
  * Only rewrite MACs if the replay path has an active L2 device that cares.

Everything here is pure stdlib (ipaddress + collections). It takes the neutral
{ip, mac} / endpoint structures the PCAP parse already produces, so the same
logic backs both the web route and the CLI without importing scapy.
"""

import ipaddress
from collections import Counter, defaultdict


# A MAC that fronts at least this many distinct IPs is treated as a router /
# gateway (a routed capture shows one MAC in front of many IPs).
_GATEWAY_MIN_IPS = 3


# ── Classification ────────────────────────────────────────────────────────────

def classify_ip(ip):
    """Return 'internal', 'external', 'multicast', or 'other' for an IP string."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "other"
    if addr.is_multicast:
        return "multicast"
    if addr.is_loopback or addr.is_link_local or addr.is_unspecified:
        return "other"
    if addr.is_reserved:
        return "other"
    if ip == "255.255.255.255" or ip.endswith(".255"):
        return "other"
    if addr.is_private:
        return "internal"
    return "external"


def _subnet_24(ip):
    """Return the /24 (as 'a.b.c.0/24') an IPv4 address belongs to, else None."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version != 4:
        return None
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))


# ── Addressing summary ────────────────────────────────────────────────────────

def summarize_addressing(hosts, endpoints=None):
    """
    Build an addressing summary from observed data.

    `hosts`     - list of {"ip": str, "mac": str} IP<->MAC observations.
    `endpoints` - optional list of endpoint stat dicts (see routes/pcap.py) used
                  for top-talker ranking and protocol mix.

    Returns a dict with internal/external hosts, internal /24 groupings, the
    inferred gateway MAC, whether the capture looks routed, top talkers and the
    protocol mix - everything the UI and CLI need to explain the plan.
    """
    endpoints = endpoints or []

    internal, external, other = [], [], []
    for h in hosts:
        ip = h.get("ip", "")
        kind = classify_ip(ip)
        if kind == "internal":
            internal.append(h)
        elif kind == "external":
            external.append(h)
        else:
            other.append(h)

    # Group internal hosts into /24 buckets, sorted for stable lab allocation.
    subnet_map = defaultdict(list)
    for h in internal:
        net = _subnet_24(h["ip"])
        if net:
            subnet_map[net].append(h["ip"])
    subnets = [
        {"cidr": net, "host_count": len(ips),
         "hosts": sorted(ips, key=_ip_sort_key)}
        for net, ips in sorted(subnet_map.items(), key=lambda kv: _ip_sort_key(kv[0].split("/")[0]))
    ]

    gateway_mac, routed = _infer_gateway(hosts)

    return {
        "internal": [h["ip"] for h in internal],
        "external": [h["ip"] for h in external],
        "other": [h["ip"] for h in other],
        "internal_count": len(internal),
        "external_count": len(external),
        "subnets": subnets,
        "gateway_mac": gateway_mac,
        "routed": routed,
        "top_talkers": _top_talkers(endpoints),
        "protocol_mix": _protocol_mix(endpoints),
    }


def _infer_gateway(hosts):
    """
    Infer the gateway/router MAC and whether the capture is routed.

    A routed capture shows a single MAC fronting many IPs (the first-hop
    router), whereas a flat L2 segment shows a distinct MAC per IP.
    Returns (gateway_mac_or_None, routed_bool).
    """
    mac_to_ips = defaultdict(set)
    for h in hosts:
        mac = (h.get("mac") or "").lower()
        ip = h.get("ip")
        if not mac or mac in ("n/a", "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            continue
        if not ip:
            continue
        mac_to_ips[mac].add(ip)

    if not mac_to_ips:
        return None, False

    top_mac, top_ips = max(mac_to_ips.items(), key=lambda kv: len(kv[1]))
    if len(top_ips) >= _GATEWAY_MIN_IPS:
        return top_mac, True
    return None, False


def _top_talkers(endpoints, limit=5):
    ranked = sorted(
        endpoints,
        key=lambda e: e.get("tx_pkts", 0) + e.get("rx_pkts", 0),
        reverse=True,
    )
    return [
        {"ip": e["ip"],
         "packets": e.get("tx_pkts", 0) + e.get("rx_pkts", 0),
         "bytes": e.get("tx_bytes", 0) + e.get("rx_bytes", 0)}
        for e in ranked[:limit] if e.get("ip")
    ]


def _protocol_mix(endpoints):
    counter = Counter()
    for e in endpoints:
        for proto in e.get("protocols", []):
            counter[proto] += 1
    return [{"protocol": p, "endpoints": n} for p, n in counter.most_common()]


def _ip_sort_key(ip):
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        return 0


# ── Plan generation ───────────────────────────────────────────────────────────

def suggest_plan(addressing, lab_subnet, rewrite_macs=False,
                 lab_gateway_mac=None):
    """
    Produce a rewrite plan mapping the capture's internal /24s into `lab_subnet`.

    `addressing`    - output of summarize_addressing().
    `lab_subnet`    - target lab network, e.g. "10.99.0.0/16" or "10.99.0.0/24".
                      Internal /24s are laid out sequentially inside it and host
                      octets are preserved (192.168.1.10 -> 10.99.0.10).
    `rewrite_macs`  - only set True when the replay path has an active L2 device;
                      otherwise MAC rewrites are left empty by design.
    `lab_gateway_mac` - MAC to map the inferred capture gateway onto when
                        rewrite_macs is on.

    Returns {"ip_map", "mac_map", "subnet_map", "needs_mac_rewrite", "notes",
             "warnings"} where ip_map/mac_map plug straight into the rewrite and
    replay endpoints.
    """
    notes = []
    warnings = []

    try:
        base_net = ipaddress.ip_network(lab_subnet, strict=False)
    except ValueError as e:
        return {"ip_map": {}, "mac_map": {}, "subnet_map": [],
                "needs_mac_rewrite": False, "notes": [],
                "warnings": [f"Invalid lab subnet '{lab_subnet}': {e}"]}

    if base_net.version != 4:
        return {"ip_map": {}, "mac_map": {}, "subnet_map": [],
                "needs_mac_rewrite": False, "notes": [],
                "warnings": ["Lab subnet must be IPv4."]}

    base_int = int(base_net.network_address)
    # How many /24s the lab range can hold before the third octet overflows it.
    capacity = max(1, base_net.num_addresses // 256)

    ip_map = {}
    subnet_map = []
    for idx, sub in enumerate(addressing.get("subnets", [])):
        # Each internal /24 gets the next /24-aligned block inside the lab range.
        lab_block_int = base_int + (idx * 256)
        lab_prefix = ".".join(str(o) for o in _int_to_octets(lab_block_int)[:3])

        if idx >= capacity:
            warnings.append(
                f"{sub['cidr']} mapped to {lab_prefix}.0/24 which is outside "
                f"the {lab_subnet} range - widen the lab subnet (e.g. use a /16)."
            )

        for host_ip in sub["hosts"]:
            last_octet = host_ip.split(".")[-1]
            ip_map[host_ip] = f"{lab_prefix}.{last_octet}"

        subnet_map.append({
            "from": sub["cidr"],
            "to": f"{lab_prefix}.0/24",
            "host_count": sub["host_count"],
        })

    if ip_map:
        notes.append(
            f"Mapped {len(ip_map)} internal host(s) across "
            f"{len(subnet_map)} subnet(s) into {lab_subnet}, preserving host octets."
        )
    else:
        notes.append("No internal (RFC1918) hosts found - nothing to remap.")

    ext_count = addressing.get("external_count", 0)
    if ext_count:
        notes.append(
            f"Left {ext_count} external IP(s) untouched so outbound flows still "
            f"look external to the sensor."
        )

    # MAC handling.
    mac_map = {}
    needs_mac_rewrite = bool(rewrite_macs)
    gw = addressing.get("gateway_mac")
    if rewrite_macs:
        if gw and lab_gateway_mac:
            mac_map[gw] = lab_gateway_mac
            notes.append(
                f"Gateway MAC {gw} -> {lab_gateway_mac} (routed capture; L2 "
                f"device in path)."
            )
        elif gw and not lab_gateway_mac:
            warnings.append(
                "rewrite_macs is on and a gateway MAC was inferred, but no lab "
                "gateway MAC was supplied - MAC map left empty."
            )
        else:
            notes.append("No gateway MAC to remap; MAC map left empty.")
    else:
        if addressing.get("routed"):
            notes.append(
                "Routed capture detected (one MAC fronts many IPs). MAC rewrite "
                "is OFF - only enable it if your replay path has an active L2 "
                "device that filters on MAC."
            )
        else:
            notes.append(
                "Flat L2 segment - MAC rewrite not needed for a typical "
                "span/tap replay path."
            )

    return {
        "ip_map": ip_map,
        "mac_map": mac_map,
        "subnet_map": subnet_map,
        "needs_mac_rewrite": needs_mac_rewrite,
        "notes": notes,
        "warnings": warnings,
    }


def _int_to_octets(value):
    return [(value >> 24) & 0xFF, (value >> 16) & 0xFF,
            (value >> 8) & 0xFF, value & 0xFF]
