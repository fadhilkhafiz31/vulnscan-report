import argparse
import sys
import os
from .scanner import run_scan
from .parser import parse_nmap_xml
from .reporter import generate_html_report
from .utils import validate_target

def main():
    parser = argparse.ArgumentParser(
        description="Vulnerability scanner and report generator (Nmap-based)."
    )
    parser.add_argument("--target", required=True, help="Target IP or hostname")
    parser.add_argument(
        "--output",
        default="reports/report.html",
        help="Path to output HTML report",
    )
    parser.add_argument(
        "--profile",
        choices=["default", "fast", "full", "top100", "udp"],
        default="default",
        help="Scan profile: default (sV, T4), fast (F), full (all ports), top100 (top 100 ports), udp (UDP scan)"
    )
    args = parser.parse_args()

    if not validate_target(args.target):
        print(f"Error: Invalid target '{args.target}'. Please provide a valid IP address or hostname.")
        sys.exit(1)

    from .utils import check_nmap_installed
    if not check_nmap_installed():
        print("Error: Nmap is not installed or not found in PATH.")
        print("Please install Nmap from https://nmap.org/download.html")
        sys.exit(1)

    xml_output = None
    try:
        xml_output = run_scan(args.target, args.profile)
        results = parse_nmap_xml(xml_output)
        generate_html_report(results, args.output)
        print(f"[+] Report generated at {args.output}")
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)
    finally:
        if xml_output and os.path.exists(xml_output):
            try:
                os.remove(xml_output)
            except OSError as e:
                print(f"Warning: Could not remove temporary file {xml_output}: {e}")

if __name__ == "__main__":
    main()
