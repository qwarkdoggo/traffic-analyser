import subprocess
import os

TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"

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

    with open(csv_file, "w", encoding="utf-8") as f:
        subprocess.run(cmd, stdout=f, check=True)
