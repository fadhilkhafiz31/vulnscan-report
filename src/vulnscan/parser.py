from lxml import etree

def parse_nmap_xml(xml_path: str) -> dict:
    """
    Parses Nmap XML output and returns a structured Python dict.
    """
    tree = etree.parse(xml_path)
    root = tree.getroot()

    hosts_data = []

    for host in root.findall("host"):
        addresses = [addr.get("addr") for addr in host.findall("address")]
        ports_info = []

        ports = host.find("ports")
        if ports is not None:
            for port in ports.findall("port"):
                state_el = port.find("state")
                service_el = port.find("service")

                port_data = {
                    "portid": port.get("portid"),
                    "protocol": port.get("protocol"),
                    "state": state_el.get("state") if state_el is not None else None,
                    "service": service_el.get("name") if service_el is not None else None,
                }
                ports_info.append(port_data)

        hosts_data.append(
            {
                "addresses": addresses,
                "ports": ports_info,
            }
        )

    return {"hosts": hosts_data}
