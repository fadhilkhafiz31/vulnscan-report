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
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background-color: #f3f4f6;
            color: #2c3e50;
            line-height: 1.6;
            padding: 20px;
        }

        .container {
            max-width: 1000px;
            margin: 40px auto;
            background-color: #ffffff;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            padding: 24px;
        }

        .header {
            border-bottom: 2px solid #e9ecef;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }

        .header h1 {
            color: #1a1a1a;
            font-size: 2rem;
            margin-bottom: 8px;
            font-weight: 700;
        }

        .header .subtitle {
            color: #6c757d;
            font-size: 0.95rem;
            margin-top: 4px;
        }

        .summary {
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            padding: 25px;
            border-radius: 8px;
            margin-bottom: 40px;
            border: 1px solid #dee2e6;
        }

        .summary h2 {
            color: #1a1a1a;
            font-size: 1.5rem;
            margin-bottom: 20px;
            font-weight: 600;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }

        .summary-item {
            background-color: #ffffff;
            padding: 12px 15px;
            border-radius: 6px;
            border-left: 4px solid #667eea;
        }

        .summary-item strong {
            display: block;
            color: #495057;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 5px;
        }

        .summary-item .value {
            color: #1a1a1a;
            font-size: 1.5rem;
            font-weight: 700;
        }

        .host-block {
            margin-bottom: 50px;
        }

        .host-block:last-child {
            margin-bottom: 0;
        }

        .host-block h2 {
            color: #1a1a1a;
            font-size: 1.4rem;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e9ecef;
            font-weight: 600;
        }

        table {
            border-collapse: collapse;
            width: 100%;
            margin-bottom: 30px;
            background-color: #ffffff;
            border-radius: 6px;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }

        thead {
            background-color: #e5e7eb;
        }

        th {
            padding: 14px 12px;
            text-align: left;
            font-weight: 700;
            font-size: 0.9rem;
            color: #1a1a1a;
            border: none;
        }

        tbody tr {
            border-bottom: 1px solid #e9ecef;
        }

        tbody tr:nth-child(even) {
            background-color: #f8f9fa;
        }

        tbody tr:hover {
            background-color: #e9ecef;
        }

        .severity-high {
            background-color: #ffe5e5 !important;
        }

        .severity-high:nth-child(even) {
            background-color: #ffd6d6 !important;
        }

        .severity-high:hover {
            background-color: #ffc7c7 !important;
        }

        .severity-medium {
            background-color: #fff4e0 !important;
        }

        .severity-medium:nth-child(even) {
            background-color: #ffe8cc !important;
        }

        .severity-medium:hover {
            background-color: #ffddb3 !important;
        }

        .severity-low {
            background-color: #e9f7ec !important;
        }

        .severity-low:nth-child(even) {
            background-color: #d4f0db !important;
        }

        .severity-low:hover {
            background-color: #bfe9ca !important;
        }

        td {
            padding: 12px;
            font-size: 0.9rem;
            color: #495057;
            border: none;
            vertical-align: middle;
        }

        .badge {
            display: inline-block;
            padding: 6px 12px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.75rem;
            text-align: center;
            min-width: 70px;
            letter-spacing: 0.3px;
        }

        .badge-high {
            background-color: #dc3545;
            color: #ffffff;
        }

        .badge-medium {
            background-color: #fd7e14;
            color: #ffffff;
        }

        .badge-low {
            background-color: #28a745;
            color: #ffffff;
        }

        .footer {
            text-align: center;
            padding: 20px;
            color: #6c757d;
            font-size: 0.85rem;
            border-top: 1px solid #e9ecef;
            margin-top: 40px;
        }

        @media print {
            body {
                background-color: #ffffff;
                padding: 0;
            }

            .container {
                box-shadow: none;
                padding: 20px;
            }

            .summary {
                background: #f8f9fa;
                border: 1px solid #dee2e6;
            }

            tbody tr:nth-child(even) {
                background-color: #f8f9fa;
            }

            .footer {
                border-top: 1px solid #dee2e6;
            }
        }

        @media (max-width: 768px) {
            .container {
                padding: 20px;
            }

            .summary-grid {
                grid-template-columns: 1fr;
            }

            table {
                font-size: 0.85rem;
            }

            th, td {
                padding: 8px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Vulnerability Scan Report</h1>
            <p class="subtitle">Generated: {{ generated_at }}</p>
        </div>

        <div class="summary">
            <h2>Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <strong>Total Hosts</strong>
                    <span class="value">{{ summary.total_hosts }}</span>
                </div>
                <div class="summary-item">
                    <strong>Total Open Ports</strong>
                    <span class="value">{{ summary.total_open_ports }}</span>
                </div>
                <div class="summary-item">
                    <strong>High Severity</strong>
                    <span class="value"><span class="badge badge-high">{{ summary.high }}</span></span>
                </div>
                <div class="summary-item">
                    <strong>Medium Severity</strong>
                    <span class="value"><span class="badge badge-medium">{{ summary.medium }}</span></span>
                </div>
                <div class="summary-item">
                    <strong>Low Severity</strong>
                    <span class="value"><span class="badge badge-low">{{ summary.low }}</span></span>
                </div>
            </div>
        </div>

        {% for host in hosts %}
        <div class="host-block">
            <h2>Host: {{ host.addresses | join(', ') }}</h2>
            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>State</th>
                        <th>Service</th>
                        <th>Severity</th>
                        <th>Notes</th>
                    </tr>
                </thead>
                <tbody>
                    {% for port in host.ports %}
                    <tr class="{% if port.severity %}severity-{{ port.severity|lower }}{% endif %}">
                        <td><strong>{{ port.portid }}</strong></td>
                        <td>{{ port.protocol }}</td>
                        <td>{{ port.state }}</td>
                        <td>{{ port.service or '-' }}</td>
                        <td>
                            {% if port.severity %}
                                <span class="badge badge-{{ port.severity|lower }}">{{ port.severity }}</span>
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
                </tbody>
            </table>
        </div>
        {% endfor %}

        <div class="footer">
            Generated by vulnscan-report
        </div>
    </div>
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
