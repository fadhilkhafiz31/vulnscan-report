from jinja2 import Template
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


HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Vulnerability Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2 { color: #333; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; font-size: 14px; }
        th { background-color: #f2f2f2; }
        .host-block { margin-bottom: 40px; }
        .summary { background-color: #f9f9f9; padding: 15px; border-radius: 5px; margin-bottom: 30px; }
        .summary h2 { margin-top: 0; }
        .summary-item { margin: 5px 0; }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 12px;
            text-align: center;
            min-width: 60px;
        }
        .badge-high {
            background-color: #dc3545;
            color: white;
        }
        .badge-medium {
            background-color: #fd7e14;
            color: white;
        }
        .badge-low {
            background-color: #28a745;
            color: white;
        }
    </style>
</head>
<body>
    <h1>Vulnerability Scan Report</h1>
    <p>Generated: {{ generated_at }}</p>

    <div class="summary">
        <h2>Summary</h2>
        <div class="summary-item"><strong>Total Hosts:</strong> {{ summary.total_hosts }}</div>
        <div class="summary-item"><strong>Total Open Ports:</strong> {{ summary.total_open_ports }}</div>
        <div class="summary-item"><strong>High Severity:</strong> <span class="badge badge-high">{{ summary.high }}</span></div>
        <div class="summary-item"><strong>Medium Severity:</strong> <span class="badge badge-medium">{{ summary.medium }}</span></div>
        <div class="summary-item"><strong>Low Severity:</strong> <span class="badge badge-low">{{ summary.low }}</span></div>
    </div>

    {% for host in hosts %}
    <div class="host-block">
        <h2>Host: {{ host.addresses | join(', ') }}</h2>
        <table>
            <tr>
                <th>Port</th>
                <th>Protocol</th>
                <th>State</th>
                <th>Service</th>
                <th>Severity</th>
                <th>Notes</th>
            </tr>
            {% for port in host.ports %}
            <tr>
                <td>{{ port.portid }}</td>
                <td>{{ port.protocol }}</td>
                <td>{{ port.state }}</td>
                <td>{{ port.service or '-' }}</td>
                <td>
                    {% if port.severity %}
                        {% if port.severity == 'High' %}
                            <span class="badge badge-high">High</span>
                        {% elif port.severity == 'Medium' %}
                            <span class="badge badge-medium">Medium</span>
                        {% elif port.severity == 'Low' %}
                            <span class="badge badge-low">Low</span>
                        {% else %}
                            -
                        {% endif %}
                    {% else %}
                        -
                    {% endif %}
                </td>
                <td>
                    {% if port.state == 'open' %}
                        Review this service and ensure it is necessary and patched.
                    {% else %}
                        -
                    {% endif %}
                </td>
            </tr>
            {% endfor %}
        </table>
    </div>
    {% endfor %}
</body>
</html>
"""

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
    template = Template(HTML_TEMPLATE)
    rendered = template.render(
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        hosts=hosts,
        summary=summary,
    )

    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(rendered, encoding="utf-8")
