#!/usr/bin/env python3
"""
Smoke test for the NetRunner traffic generator.

Proves that app.core.engine.generate_traffic_task actually:
  1. crafts packets in memory, and
  2. transmits them out the named interface (frames observed on the wire).

It does this by sniffing the SAME interface while running the real generator
function, then comparing what egressed against what was sent. Captured frames
are written to a .pcap so you can also eyeball them in Wireshark.

Run IN THE LAB (needs a real interface + raw-socket privileges), from the repo
root so the `app` package is importable:

    sudo python3 smoke_test_generator.py eth0
    sudo python3 smoke_test_generator.py eth0 --count 20 --proto udp

Exit code 0 = PASS (sent count matched captured count), 1 = FAIL.
"""
import argparse
import sys
import threading
import time

# Synthetic, non-routable test values (RFC 5737 TEST-NET-1) so the smoke test
# can't be confused with real lab traffic.
TEST_DST_IP = "192.0.2.123"
TEST_SRC_IP = "192.0.2.1"
TEST_DPORT = 40404
TEST_MARKER = b"NETRUNNER-SMOKE-TEST"


def main():
    parser = argparse.ArgumentParser(description="NetRunner traffic generator smoke test")
    parser.add_argument("interface", help="Interface to transmit/sniff on (e.g. eth0)")
    parser.add_argument("--count", type=int, default=10, help="Packets to send (default 10)")
    parser.add_argument("--proto", choices=["udp", "tcp", "icmp"], default="udp",
                        help="Protocol to generate (default udp)")
    parser.add_argument("--delay", type=float, default=0.05, help="Inter-packet delay seconds")
    parser.add_argument("--pcap", default="smoke_capture.pcap", help="Output capture file")
    args = parser.parse_args()

    try:
        from scapy.all import AsyncSniffer, wrpcap
        from app.core.engine import generate_traffic_task, active_task_status
    except ImportError as e:
        print(f"[FAIL] Could not import dependencies: {e}")
        print("       Run from the repo root with scapy installed.")
        return 1

    # BPF filter tight enough to capture only our crafted egress.
    if args.proto == "icmp":
        bpf = f"icmp and dst host {TEST_DST_IP}"
    else:
        bpf = f"{args.proto} and dst host {TEST_DST_IP} and dst port {TEST_DPORT}"

    print(f"[*] Interface : {args.interface}")
    print(f"[*] Protocol  : {args.proto.upper()}")
    print(f"[*] Count     : {args.count}")
    print(f"[*] BPF filter: {bpf}")

    captured = []
    sniffer = AsyncSniffer(iface=args.interface, filter=bpf,
                           prn=lambda p: captured.append(p), store=True)
    try:
        sniffer.start()
    except Exception as e:
        print(f"[FAIL] Could not start sniffer on {args.interface}: {e}")
        print("       Check the interface name and that you have raw-socket privileges (sudo).")
        return 1

    time.sleep(1.0)  # let the sniffer bind before we transmit

    params = {
        "src_ip": TEST_SRC_IP,
        "dst_ip": TEST_DST_IP,
        "src_mac": "",  # empty -> generator auto-detects the iface's real MAC
        "dst_mac": "ff:ff:ff:ff:ff:ff",  # broadcast guarantees egress in a lab segment
        "protocol": args.proto,
        "src_port": 31337,
        "dst_port": TEST_DPORT,
        "payload": TEST_MARKER.decode(),
        "packet_count": args.count,
        "delay": args.delay,
        "interface": args.interface,
    }

    # The real generator checks this flag; the web UI sets it via start_task().
    active_task_status["is_running"] = True
    active_task_status["error"] = None

    print("[*] Running the REAL generate_traffic_task()...")
    gen_thread = threading.Thread(target=generate_traffic_task, args=(params,))
    gen_thread.start()
    gen_thread.join()

    time.sleep(1.0)  # catch any in-flight frames
    sniffer.stop()

    sent = active_task_status.get("progress", 0)
    seen = len(captured)

    if active_task_status.get("error"):
        print(f"[FAIL] Generator reported an error: {active_task_status['error']}")
        return 1

    if captured:
        wrpcap(args.pcap, captured)
        print(f"[*] Wrote {seen} captured frame(s) to {args.pcap}")

    print("-" * 50)
    print(f"    Packets sent (generator)   : {sent}")
    print(f"    Packets seen on the wire   : {seen}")
    print("-" * 50)

    if seen >= sent and sent == args.count:
        print("[PASS] Generator crafted and transmitted packets out the interface.")
        return 0
    if seen == 0:
        print("[FAIL] Generator ran but NO frames were observed on the wire.")
        print("       The packets were built but did not egress (interface/privilege issue?).")
        return 1
    print(f"[WARN] Count mismatch: sent {sent}, captured {seen}. Frames egressed but "
          f"capture was lossy (try a larger --delay).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
