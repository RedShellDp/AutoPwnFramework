import nmap

def run_nmap_scan(target_ip):
    print(f"[+] Scanning {target_ip} with Nmap...")
    nm = nmap.PortScanner()
    nm.scan(hosts=target_ip, arguments='-sS -sV')

    open_ports = []
    http_services = []

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                state = nm[host][proto][port]['state']
                if state == 'open':
                    open_ports.append(str(port))
                    if port in [80, 443, 8080, 8000, 8888]:
                        http_services.append(str(port))

    return open_ports, http_services


