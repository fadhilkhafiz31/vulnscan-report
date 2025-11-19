import argparse
from .scanner import run_scan
from .parser import parse_nmap_xml
from .reporter import generate_html_report

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
    args = parser.parse_args()

    xml_output = run_scan(args.target)
    results = parse_nmap_xml(xml_output)
    generate_html_report(results, args.output)
    print(f"[+] Report generated at {args.output}")

if __name__ == "__main__":
    main()
