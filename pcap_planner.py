#!/usr/bin/env python3
"""
NetRunner OS - PCAP rewrite planner (CLI).

Analyzes a capture's addressing and prints a ready-to-apply rewrite plan that
maps the internal (RFC1918) hosts into a lab range, preserving host octets, and
leaves external IPs alone. Optionally writes the rewritten PCAP.

Shares the exact planning logic used by the web UI (app.core.rewrite_planner),
so the CLI and the API always agree.

Run from the repo root so the `app` package is importable:

    python3 pcap_planner.py capture.pcap --lab-subnet 10.99.0.0/16
    python3 pcap_planner.py capture.pcap --lab-subnet 10.99.0.0/16 --json
    python3 pcap_planner.py capture.pcap --lab-subnet 10.99.0.0/16 \\
        --rewrite-macs --lab-gw-mac 02:00:00:00:00:01 --write-pcap lab.pcap
"""
import argparse
import json
import sys
from collections import defaultdict


def _parse_capture(filepath):
    """Return (hosts, endpoints) in the shape summarize_addressing() expects."""
    from scapy.all import PcapReader, Ether, IP, TCP, UDP, ICMP

    ip_to_mac = {}
    stats = defaultdict(lambda: {'tx_pkts': 0, 'rx_pkts': 0,
                                 'tx_bytes': 0, 'rx_bytes': 0,
                                 'protocols': set()})

    with PcapReader(filepath) as reader:
        for pkt in reader:
            if not pkt.haslayer(IP):
                continue
            src, dst = pkt[IP].src, pkt[IP].dst
            plen = len(pkt)

            proto = 'IP'
            if pkt.haslayer(TCP):
                proto = 'TCP'
            elif pkt.haslayer(UDP):
                proto = 'UDP'
            elif pkt.haslayer(ICMP):
                proto = 'ICMP'

            stats[src]['tx_pkts'] += 1
            stats[src]['tx_bytes'] += plen
            stats[src]['protocols'].add(proto)
            stats[dst]['rx_pkts'] += 1
            stats[dst]['rx_bytes'] += plen
            stats[dst]['protocols'].add(proto)

            if pkt.haslayer(Ether):
                ip_to_mac[src] = pkt[Ether].src
                ip_to_mac[dst] = pkt[Ether].dst

    hosts = [{'ip': ip, 'mac': ip_to_mac.get(ip, 'N/A')} for ip in stats]
    endpoints = [{'ip': ip, **{k: (list(v) if isinstance(v, set) else v)
                               for k, v in s.items()}}
                 for ip, s in stats.items()]
    return hosts, endpoints


def _write_rewritten(filepath, out_path, ip_map, mac_map):
    """Apply ip_map/mac_map to a capture and write a new PCAP."""
    from scapy.all import PcapReader, PcapWriter, Ether, IP, TCP, UDP

    count = 0
    with PcapReader(filepath) as reader:
        writer = PcapWriter(out_path, sync=True)
        for pkt in reader:
            m = pkt.copy()
            if mac_map and m.haslayer(Ether):
                eth = m.getlayer(Ether)
                if eth.src in mac_map:
                    eth.src = mac_map[eth.src]
                if eth.dst in mac_map:
                    eth.dst = mac_map[eth.dst]
            if m.haslayer(IP):
                ip = m.getlayer(IP)
                if ip.src in ip_map:
                    ip.src = ip_map[ip.src]
                if ip.dst in ip_map:
                    ip.dst = ip_map[ip.dst]
                if ip.chksum is not None:
                    del ip.chksum
                if ip.haslayer(TCP) and ip[TCP].chksum is not None:
                    del ip[TCP].chksum
                elif ip.haslayer(UDP) and ip[UDP].chksum is not None:
                    del ip[UDP].chksum
            writer.write(m)
            count += 1
        writer.close()
    return count


def _print_report(addressing, plan):
    print("=" * 60)
    print("ADDRESSING SUMMARY")
    print("=" * 60)
    print(f"  Internal hosts : {addressing['internal_count']}")
    print(f"  External hosts : {addressing['external_count']}")
    print(f"  Path           : {'routed' if addressing['routed'] else 'flat L2 segment'}"
          + (f" (gateway MAC {addressing['gateway_mac']})" if addressing['gateway_mac'] else ""))
    if addressing['subnets']:
        print("  Internal /24s  :")
        for s in addressing['subnets']:
            print(f"    - {s['cidr']}  ({s['host_count']} host(s))")
    if addressing['top_talkers']:
        print("  Top talkers    :")
        for t in addressing['top_talkers']:
            print(f"    - {t['ip']:<16} {t['packets']} pkts")

    print()
    print("=" * 60)
    print("REWRITE PLAN")
    print("=" * 60)
    for m in plan['subnet_map']:
        print(f"  {m['from']:<18} -> {m['to']:<18} ({m['host_count']} host(s))")
    if plan['ip_map']:
        print(f"\n  IP map ({len(plan['ip_map'])} entries):")
        for orig, new in sorted(plan['ip_map'].items()):
            print(f"    {orig:<16} -> {new}")
    if plan['mac_map']:
        print(f"\n  MAC map ({len(plan['mac_map'])} entries):")
        for orig, new in plan['mac_map'].items():
            print(f"    {orig} -> {new}")
    if plan['notes']:
        print("\n  Notes:")
        for n in plan['notes']:
            print(f"    * {n}")
    if plan['warnings']:
        print("\n  Warnings:")
        for w in plan['warnings']:
            print(f"    ! {w}")


def main():
    parser = argparse.ArgumentParser(description="NetRunner PCAP rewrite planner")
    parser.add_argument("pcap", help="Input PCAP/PCAPNG file")
    parser.add_argument("--lab-subnet", required=True,
                        help="Target lab network, e.g. 10.99.0.0/16")
    parser.add_argument("--rewrite-macs", action="store_true",
                        help="Include MAC rewrites (only if an L2 device is in path)")
    parser.add_argument("--lab-gw-mac", default=None,
                        help="Lab gateway MAC to map the inferred gateway onto")
    parser.add_argument("--write-pcap", default=None,
                        help="Apply the plan and write the rewritten capture here")
    parser.add_argument("--json", action="store_true",
                        help="Emit machine-readable JSON instead of a report")
    args = parser.parse_args()

    try:
        from app.core.rewrite_planner import summarize_addressing, suggest_plan
    except ImportError as e:
        print(f"[FAIL] Could not import planner: {e}")
        print("       Run from the repo root with scapy installed.")
        return 1

    try:
        hosts, endpoints = _parse_capture(args.pcap)
    except Exception as e:
        print(f"[FAIL] Could not read {args.pcap}: {e}")
        return 1

    addressing = summarize_addressing(hosts, endpoints)
    plan = suggest_plan(addressing, args.lab_subnet,
                        rewrite_macs=args.rewrite_macs,
                        lab_gateway_mac=args.lab_gw_mac)

    if args.json:
        print(json.dumps({"addressing": addressing, "plan": plan}, indent=2))
    else:
        _print_report(addressing, plan)

    if args.write_pcap:
        try:
            n = _write_rewritten(args.pcap, args.write_pcap,
                                 plan['ip_map'], plan['mac_map'])
            print(f"\n[+] Wrote {n} rewritten packet(s) to {args.write_pcap}")
        except Exception as e:
            print(f"\n[FAIL] Could not write {args.write_pcap}: {e}")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
