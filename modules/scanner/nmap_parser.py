import xml.etree.ElementTree as ET

def parse_nmap_services(xml_file):
    open_ports = []
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        for port in root.findall(".//port"):
            state = port.find("state").get("state")
            if state == "open":
                port_num = port.get("portid")
                service = port.find("service").get("name")
                open_ports.append((int(port_num), service))
    except Exception as e:
        print("[-] Failed to parse Nmap XML:", e)
    
    return open_ports
