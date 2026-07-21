"""
Port Scanner Main Entry Point (CLI & GUI)
Run without arguments to launch the Graphical UI, or pass CLI flags for terminal scans.
"""

import sys
import os
import argparse
import json
import csv
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from port_scanner import parse_ports, resolve_target, scan_single_port, main_gui

# UTF-8 stdout configuration for Windows terminals
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass


def run_cli_scan(target: str, ports_str: str, timeout: float, threads: int, grab_banner: bool, output_file: str | None):
    print("=" * 60)
    print("[*] Advanced Port Scanner 2.0 - CLI Mode")
    print("=" * 60)
    
    try:
        ip, host = resolve_target(target)
        port_list = parse_ports(ports_str)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

    host_info = f"{host} ({ip})" if host != ip else ip
    print(f"Target      : {host_info}")
    print(f"Total Ports : {len(port_list)}")
    print(f"Timeout     : {timeout}s")
    print(f"Threads     : {threads}")
    print(f"Grab Banner : {grab_banner}")
    print("-" * 60)
    print(f"{'PORT':<8} {'STATUS':<8} {'LATENCY':<12} {'SERVICE':<18} {'BANNER/DESC'}")
    print("-" * 60)

    start_t = datetime.now()
    results = []
    scanned = 0

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_single_port, ip, p, timeout, grab_banner): p for p in port_list}
        for future in as_completed(futures):
            scanned += 1
            res = future.result()
            if res:
                results.append(res)
                banner_txt = res['banner'] if res['banner'] else res['description']
                print(f"{res['port']:<8} {res['status']:<8} {str(res['latency_ms'])+' ms':<12} {res['service']:<18} {banner_txt[:40]}")

    results.sort(key=lambda x: x["port"])
    duration = (datetime.now() - start_t).total_seconds()
    
    print("-" * 60)
    print(f"[+] Scan complete in {duration:.2f}s. Found {len(results)} open ports.")
    print("=" * 60)

    if output_file:
        try:
            ext = os.path.splitext(output_file)[1].lower()
            if ext == ".json":
                export_data = {
                    "target_host": host,
                    "target_ip": ip,
                    "scan_date": datetime.now().isoformat(),
                    "duration_seconds": duration,
                    "open_ports_count": len(results),
                    "results": results
                }
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(export_data, f, indent=2)
            elif ext == ".csv":
                with open(output_file, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["Port", "Status", "Latency (ms)", "Service", "Description", "Banner"])
                    for r in results:
                        writer.writerow([r["port"], r["status"], r["latency_ms"], r["service"], r["description"], r["banner"]])
            else:
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write("Port Scan Results\n")
                    f.write(f"Target: {host} ({ip})\n")
                    f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("=" * 70 + "\n\n")
                    for r in results:
                        b = r["banner"] if r["banner"] else r["description"]
                        f.write(f"{r['port']:<8}{r['status']:<10}{str(r['latency_ms'])+' ms':<12}{r['service']:<18}{b}\n")
            print(f"[+] Saved results to: {output_file}")
        except Exception as e:
            print(f"[!] Failed to write output file: {e}")


def main():
    parser = argparse.ArgumentParser(description="Advanced Port Scanner (CLI & Graphical GUI)")
    parser.add_argument("-t", "--target", type=str, help="Target IP or domain name (e.g. 127.0.0.1 or scanme.nmap.org)")
    parser.add_argument("-p", "--ports", type=str, help="Ports to scan (e.g. 1-1024 or 22,80,443 or 80-90,8080)")
    parser.add_argument("--timeout", type=float, default=0.5, help="Socket timeout in seconds (default: 0.5)")
    parser.add_argument("--threads", type=int, default=100, help="Max concurrent scanning threads (default: 100)")
    parser.add_argument("-b", "--banner", action="store_true", help="Enable service banner grabbing")
    parser.add_argument("-o", "--output", type=str, help="Output file path (.json, .csv, .txt)")
    parser.add_argument("--gui", action="store_true", help="Launch Graphical UI")

    args = parser.parse_args()

    if args.target or args.ports:
        target = args.target if args.target else "127.0.0.1"
        ports = args.ports if args.ports else "1-1024"
        run_cli_scan(target, ports, args.timeout, args.threads, args.banner, args.output)
    else:
        # Default behavior: Launch Graphical UI
        main_gui()


if __name__ == "__main__":
    main()
