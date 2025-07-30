import subprocess
import os

def run_nuclei_scan(target, output_file="results/nuclei_output.txt", template_tags="cves,misconfiguration,exposed-panels"):
    print(f"[+] Running Nuclei scan on {target}...")

    os.makedirs("results", exist_ok=True)

    command = [
        "nuclei",
        "-u", target,
        "-tags", template_tags,
        "-o", output_file
    ]

    try:
        subprocess.run(command, check=True)
        print(f"[+] Nuclei scan completed. Results saved to {output_file}")
    except subprocess.CalledProcessError as e:
        print("[-] Nuclei scan failed:", e)
        with open(output_file, "w") as f:
            f.write(f"Nuclei scan failed: {e}")


