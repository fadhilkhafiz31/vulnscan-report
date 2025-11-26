from jinja2 import Environment, FileSystemLoader
from datetime import datetime
from pathlib import Path


def determine_severity(portid: str, service: str, state: str) -> str:
    """
    Determines severity level based on port number and service name.
    Returns 'High', 'Medium', 'Low', or None.
    """
    if state not in ['open', 'open|filtered']:
        return None
    
    try:
        port_num = int(portid)
    except (ValueError, TypeError):
        port_num = None
    
    service_lower = (service or "").lower()
    
    # High severity ports
    high_severity_ports = [22, 23, 445, 3389, 1433]
    if port_num in high_severity_ports:
        return "High"
    
    # High severity service keywords
    high_severity_keywords = ["msrpc", "microsoft-ds", "rdp", "telnet", "ssh", "sql"]
    if any(keyword in service_lower for keyword in high_severity_keywords):
        return "High"
    
    # Medium severity ports
    medium_severity_ports = [80, 443, 8080, 8000]
    if port_num in medium_severity_ports:
        return "Medium"
    
    # Everything else that is open
    return "Low"




def generate_html_report(results: dict, output_path: str) -> None:
    """
    Generates an HTML report with severity scoring.
    Enriches port data with severity information and calculates summary statistics.
    """
    hosts = results.get("hosts", [])
    
    # Initialize summary counters
    summary = {
        "total_hosts": len(hosts),
        "total_open_ports": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }
    
    # Enrich each host's ports with severity information
    for host in hosts:
        for port in host.get("ports", []):
            portid = port.get("portid", "")
            service = port.get("service", "")
            state = port.get("state", "")
            
            # Determine severity
            severity = determine_severity(portid, service, state)
            port["severity"] = severity
            
            # Update summary counts
            if state in ['open', 'open|filtered']:
                summary["total_open_ports"] += 1
                if severity == "High":
                    summary["high"] += 1
                elif severity == "Medium":
                    summary["medium"] += 1
                elif severity == "Low":
                    summary["low"] += 1
    
    # Render template with enriched data
    # Render template with enriched data
    template_dir = Path(__file__).parent / "templates"
    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template("report.html")
    rendered = template.render(
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        hosts=hosts,
        summary=summary,
    )

    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(rendered, encoding="utf-8")
