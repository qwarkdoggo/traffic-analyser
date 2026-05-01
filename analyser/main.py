import os
import argparse
import logging
from pathlib import Path

from parser import load_traffic
from analyser_detections import detect_insecure_protocols
from pcap_to_csv import convert_pcap_to_csv
from report import save_report
from analyser_detections import (
    detect_insecure_protocols,
    detect_high_volume_sources,
    detect_port_scans_time_window,
)
from siem_integration import write_cef_log, send_to_syslog, send_to_wazuh_api
from argparse import ArgumentParser

# Configure audit logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(os.path.dirname(__file__), '..', 'data', 'analyser_audit.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

parser = ArgumentParser(description="Traffic analyser command line interface")
parser.add_argument(
    "--input",
    help="path to the input pcap file",
    default=None,
)
parser.add_argument(
    "--output",
    help="destination path for the generated report (ignored for json output)",
    default=None,
)
parser.add_argument(
    "--format",
    help="output format (json or table)",
    choices=["json", "table"],
    default="json",
)
parser.add_argument(
    "--threshold",
    help="packet count threshold for high volume alerts",
    type=int,
    default=100,
)
parser.add_argument(
    "--quiet",
    help="suppress informational output (useful when handling sensitive files)",
    action="store_true",
)
parser.add_argument(
    "--send-cef",
    help="send alerts in CEF format to a log file for SIEM agent monitoring",
    action="store_true",
)
parser.add_argument(
    "--send-syslog",
    help="send alerts via Syslog protocol",
    action="store_true",
)
parser.add_argument(
    "--syslog-host",
    help="Syslog server hostname (default: localhost)",
    default="localhost",
)
parser.add_argument(
    "--syslog-port",
    help="Syslog server port (default: 514)",
    type=int,
    default=514,
)
parser.add_argument(
    "--wazuh-url",
    help="Wazuh Manager API URL (e.g., https://wazuh-manager:55000)",
    default=None,
)
parser.add_argument(
    "--wazuh-token",
    help="Wazuh Manager API authentication token",
    default=None,
)

args = parser.parse_args()

if not args.quiet:
    print(f"Parsed arguments: {args}")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def validate_file_path(user_path):
    """Validate that the provided path is safe and within allowed directories."""
    if not user_path:
        return None

    try:
        user_path = Path(user_path).resolve()
        allowed_base = Path(BASE_DIR).resolve().parent

        # Ensure the resolved path is within allowed base directory
        user_path.relative_to(allowed_base)

        if not user_path.exists():
            raise FileNotFoundError(f"File does not exist: {user_path}")

        if not user_path.is_file():
            raise IsADirectoryError(f"Path is not a file: {user_path}")

        return str(user_path)
    except (ValueError, FileNotFoundError, IsADirectoryError) as e:
        raise ValueError(f"Invalid file path: {e}")

default_pcap = os.path.join(BASE_DIR, "..", "data", "traffic.pcap")

if args.input:
    try:
        PCAP_FILE = validate_file_path(args.input)
    except ValueError as e:
        print(f"[!] Error: {e}")
        exit(1)
else:
    PCAP_FILE = default_pcap

CSV_FILE  = os.path.join(BASE_DIR, "..", "data", "traffic.csv")
OUTPUT_JSON = os.path.join(BASE_DIR, "..", "data", "report.json")

if not args.quiet:
    print("Using PCAP:", PCAP_FILE)
    print("Exists:", os.path.exists(PCAP_FILE))

if os.path.exists(PCAP_FILE):
    print("[*] PCAP found, converting to CSV...")
    logger.info(f"Processing PCAP file: {PCAP_FILE}")
    convert_pcap_to_csv(PCAP_FILE, CSV_FILE)
else:
    print("[*] PCAP not found, using existing CSV")
    logger.warning(f"PCAP not found, using existing CSV: {CSV_FILE}")

packets = load_traffic(CSV_FILE)
logger.info(f"Loaded {len(packets)} packets from {CSV_FILE}")

alerts = []
alerts.extend(detect_insecure_protocols(packets))
alerts.extend(detect_high_volume_sources(packets, threshold=args.threshold))
alerts.extend(detect_port_scans_time_window(
    packets,
    port_threshold=20,
    time_window=5.0,
))

if not args.quiet:
    print(f"Detected {len(alerts)} alerts")
logger.info(f"Detection complete: {len(alerts)} alerts generated")

# SIEM Integration
CEF_LOG = os.path.join(BASE_DIR, "..", "data", "alerts.cef")

if args.send_cef:
    write_cef_log(alerts, CEF_LOG)
    logger.info(f"CEF alerts written to {CEF_LOG}")

if args.send_syslog:
    success = send_to_syslog(alerts, args.syslog_host, args.syslog_port)
    if success:
        logger.info(f"Alerts sent via Syslog to {args.syslog_host}:{args.syslog_port}")

if args.wazuh_url and args.wazuh_token:
    success = send_to_wazuh_api(alerts, args.wazuh_url, args.wazuh_token)
    if success:
        logger.info(f"Alerts sent to Wazuh API: {args.wazuh_url}")
elif args.wazuh_url or args.wazuh_token:
    logger.warning("Both --wazuh-url and --wazuh-token are required for API integration")
if args.format == "json":
    if args.output:
        print(f"[!] --output ignored for json format; using {OUTPUT_JSON}")
    output_path = OUTPUT_JSON
    save_report(alerts, output_path)
    logger.info(f"JSON report saved to {output_path}")
    print(f"Report saved to {output_path}")
elif args.format == "table":
    from report import format_alerts_table

    table_text = format_alerts_table(alerts)
    if args.output:
        output_path = args.output
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(table_text)
        logger.info(f"Table report saved to {output_path}")
        print(f"Table report written to {output_path}")
    else:
        print(table_text)
