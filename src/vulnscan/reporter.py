from jinja2 import Template
from datetime import datetime
from pathlib import Path

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
    </style>
</head>
<body>
    <h1>Vulnerability Scan Report</h1>
    <p>Generated: {{ generated_at }}</p>

    {% for host in hosts %}
    <div class="host-block">
        <h2>Host: {{ host.addresses | join(', ') }}</h2>
        <table>
            <tr>
                <th>Port</th>
                <th>Protocol</th>
                <th>State</th>
                <th>Service</th>
                <th>Notes</th>
            </tr>
            {% for port in host.ports %}
            <tr>
                <td>{{ port.portid }}</td>
                <td>{{ port.protocol }}</td>
                <td>{{ port.state }}</td>
                <td>{{ port.service or '-' }}</td>
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
    template = Template(HTML_TEMPLATE)
    rendered = template.render(
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        hosts=results.get("hosts", []),
    )

    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(rendered, encoding="utf-8")
