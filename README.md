# AutoPwnFramework

An automated penetration testing framework using Nmap, Nuclei, and Metasploit.

## 📌 Features

- Nmap scanning for target enumeration
- Vulnerability assessment using Nuclei
- Exploitation with Metasploit RPC integration
- Post-exploitation data collection
- Report generation in Markdown format

## 🛠️ Requirements

- Python 3.8+
- Nmap
- Nuclei
- Metasploit (with msfrpcd running)

## 🚀 Usage

```bash
python3 core.py --target <TARGET_IP> --lhost <YOUR_LOCAL_IP>
