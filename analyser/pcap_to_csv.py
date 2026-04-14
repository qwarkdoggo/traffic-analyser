import platform
import subprocess
import os

def get_tshark_path():
    """Определяет путь к tshark в зависимости от ОС"""
    if platform.system() == "Windows":
        return r"C:\Program Files\Wireshark\tshark.exe"
    else:
        return "tshark"

TSHARK_PATH = get_tshark_path()

def convert_pcap_to_csv(pcap_file, csv_file):
    if not os.path.exists(pcap_file):
        raise FileNotFoundError(f"PCAP file not found: {pcap_file}")

    cmd = [
        TSHARK_PATH,
        "-r", pcap_file,
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "quote=n",
        "-E", "occurrence=f",
        "-e", "frame.number",
        "-e", "frame.time_relative",
        "-e", "eth.src",
        "-e", "eth.dst",
        "-e", "_ws.col.Protocol",
        "-e", "tcp.dstport",
        "-e", "frame.len",
        "-e", "_ws.col.Info",
    ]

    try:
        with open(csv_file, "w", encoding="utf-8") as f:
            subprocess.run(cmd, stdout=f, check=True)
        print(f"[+] Successfully converted {pcap_file} to {csv_file}")
    except subprocess.CalledProcessError as e:
        print(f"[-] Error during tshark execution: {e}")
    except FileNotFoundError:
        print(f"[-] Tshark not found at {TSHARK_PATH}. Is it installed?")
