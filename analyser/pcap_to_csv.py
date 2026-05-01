import platform
import subprocess
import os
import shutil
import logging

logger = logging.getLogger(__name__)

def get_tshark_path():
    """Determine tshark path based on OS, checking multiple locations."""
    # First, try to find tshark in system PATH
    tshark_in_path = shutil.which("tshark")
    if tshark_in_path:
        logger.info(f"Found tshark in PATH: {tshark_in_path}")
        return tshark_in_path

    # Check OS-specific default locations
    if platform.system() == "Windows":
        possible_paths = [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
        ]
    else:
        possible_paths = [
            "/usr/bin/tshark",
            "/usr/local/bin/tshark",
            "/opt/wireshark/bin/tshark",
        ]

    for path in possible_paths:
        if os.path.exists(path):
            logger.info(f"Found tshark at: {path}")
            return path

    logger.warning("tshark not found in standard locations")
    return "tshark"  # Fallback to PATH search

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
            subprocess.run(cmd, stdout=f, check=True, stderr=subprocess.PIPE)
        logger.info(f"Successfully converted {pcap_file} to {csv_file}")
        print(f"[+] Successfully converted {pcap_file} to {csv_file}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error during tshark execution: {e.stderr.decode() if e.stderr else e}")
        print(f"[-] Error during tshark execution: {e}")
    except FileNotFoundError:
        logger.error(f"Tshark not found at {TSHARK_PATH}. Is it installed?")
        print(f"[-] Tshark not found at {TSHARK_PATH}. Is it installed?")
