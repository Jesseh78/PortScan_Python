from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple

from .ports import COMMON_PORTS
from .scanner import resolve_target, scan_port, ScanResult
from .output import save_csv, save_json


def parse_ports(ports_arg: str | None) -> List[int]:
    """
    Accept:
    - "22,80,443"
    - "1-1024"
    - None => COMMON_PORTS
    """
    if not ports_arg:
        return list(COMMON_PORTS)

    ports_arg = ports_arg.strip()
    if "-" in ports_arg and "," not in ports_arg:
        start_s, end_s = ports_arg.split("-", 1)
        start, end = int(start_s), int(end_s)
        if start < 1 or end > 65535 or start > end:
            raise ValueError("Invalid port range. Use 1-65535 and start<=end.")
        return list(range(start, end + 1))

    parts = [p.strip() for p in ports_arg.split(",") if p.strip()]
    ports: List[int] = []
    for p in parts:
        v = int(p)
        if v < 1 or v > 65535:
            raise ValueError("Ports must be in 1-65535.")
        ports.append(v)
    return sorted(set(ports))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="py-port-scanner",
        description="Educational TCP port scanner (authorized use only)."
    )
    parser.add_argument("--target", required=True, help="IP or domain (e.g., 192.168.0.10 or example.com)")
    parser.add_argument("--ports", help='Ports list "22,80,443" or range "1-1024". Default: common ports.')
    parser.add_argument("--timeout", type=float, default=0.6, help="Socket timeout in seconds (default: 0.6)")
    parser.add_argument("--workers", type=int, default=200, help="Max concurrent workers (default: 200)")
    parser.add_argument("--banner", action="store_true", help="Try light banner grabbing (optional)")
    parser.add_argument("--out-csv", default="", help="Save results to CSV path (e.g., output/results.csv)")
    parser.add_argument("--out-json", default="", help="Save results to JSON path (e.g., output/results.json)")
    return parser


def run_scan(ip: str, ports: List[int], timeout: float, workers: int, banner: bool) -> List[ScanResult]:
    results: List[ScanResult] = []

    # Why ThreadPoolExecutor:
    # - scanning is IO-bound
    # - simpler than asyncio for MVP
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(scan_port, ip, port, timeout, banner): port for port in ports}

        for fut in as_completed(futures):
            r = fut.result()
            results.append(r)

    # Stable ordering for outputs
    results.sort(key=lambda x: x.port)
    return results


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    ip = resolve_target(args.target)
    ports = parse_ports(args.ports)

    results = run_scan(ip=ip, ports=ports, timeout=args.timeout, workers=args.workers, banner=args.banner)

    open_ports = [r for r in results if r.is_open]
    print(f"Target: {args.target} ({ip})")
    print(f"Scanned ports: {len(ports)} | Open: {len(open_ports)}")

    for r in open_ports:
        if r.banner:
            print(f"[OPEN] {r.port}  banner='{r.banner}'")
        else:
            print(f"[OPEN] {r.port}")

    if args.out_csv:
        save_csv(results, args.out_csv)
        print(f"Saved CSV: {args.out_csv}")

    if args.out_json:
        save_json(results, args.out_json)
        print(f"Saved JSON: {args.out_json}")


if __name__ == "__main__":
    main()
