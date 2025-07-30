import os

def run_nmap_scan(target):
    print(f"[+] Scanning {target} with Nmap...")

    output_file = "results/nmap_output.xml"
    command = f"nmap -sS -sV -O -T4 -Pn -oX {output_file} {target}"
    os.system(command)

    open_ports = []
    http_services = []

    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(output_file)
        root = tree.getroot()

        for port in root.iter("port"):
            state = port.find("state").attrib["state"]
            if state == "open":
                portid = port.attrib["portid"]
                service = port.find("service").attrib.get("name", "")
                open_ports.append(portid)
                if "http" in service:
                    http_services.append(portid)

    except Exception as e:
        print(f"[!] Error parsing Nmap XML: {e}")
        return [], []

    return open_ports, http_services


