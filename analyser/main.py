import os
import argparse
import logging
import socket
from pathlib import Path

from parser import load_traffic
from analyser_detections import (
    detect_insecure_protocols,
    detect_high_volume_sources,
    detect_port_scans_time_window,
    detect_malicious_ips,
    detect_reputation_based_anomalies,
)
from pcap_to_csv import convert_pcap_to_csv
from report import save_report
from siem_integration import write_cef_log, send_to_syslog, send_to_wazuh_api
from argparse import ArgumentParser

# Security modules
from security_config import get_config
from input_validation import InputValidator, validate_ip, validate_mac, validate_port
from ddos_detection import DDosDetector
from threat_intelligence import ThreatIntelligence

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

# Initialize security config
security_config = get_config()

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


def validate_output_path(user_path):
    """Validate that output path is safe for writing (can be new file)."""
    if not user_path:
        return None

    try:
        user_path = Path(user_path).resolve()
        allowed_base = Path(BASE_DIR).resolve().parent

        # Ensure the resolved path is within allowed base directory
        user_path.relative_to(allowed_base)

        # Parent directory must exist
        if not user_path.parent.exists():
            raise FileNotFoundError(f"Output directory does not exist: {user_path.parent}")

        if user_path.exists() and user_path.is_dir():
            raise IsADirectoryError(f"Output path is a directory, not a file: {user_path}")

        return str(user_path)
    except (ValueError, FileNotFoundError, IsADirectoryError) as e:
        raise ValueError(f"Invalid output path: {e}")


def validate_port(port):
    """Validate port number is in valid range."""
    if not isinstance(port, int):
        raise ValueError(f"Port must be an integer, got {type(port)}")
    if not (1 <= port <= 65535):
        raise ValueError(f"Port must be between 1-65535, got {port}")
    return port


def validate_threshold(value):
    """Validate threshold is positive."""
    if value < 0:
        raise ValueError(f"Threshold must be positive, got {value}")
    return value


def validate_host(host):
    """Validate hostname/IP address format."""
    import ipaddress
    import socket

    if not isinstance(host, str) or not host:
        raise ValueError("Host must be a non-empty string")

    # Check if it's a valid IP
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    # Check if it's a valid hostname
    try:
        socket.getaddrinfo(host, None)
        return host
    except (socket.gaierror, OSError):
        raise ValueError(f"Invalid hostname/IP: {host}")

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

# Validate CLI arguments
try:
    args.threshold = validate_threshold(args.threshold)
    args.syslog_port = validate_port(args.syslog_port)
    if args.syslog_host:
        args.syslog_host = validate_host(args.syslog_host)
except ValueError as e:
    print(f"[!] Invalid argument: {e}")
    logger.error(f"Invalid argument: {e}")
    exit(1)

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

# Initialize security modules
threat_intel = None
ddos_detector = None

if security_config.get("threat_intel_enabled"):
    try:
        threat_feeds_dir = security_config.get("threat_feeds_dir")
        threat_intel = ThreatIntelligence(feeds_dir=threat_feeds_dir)
        threat_intel.load_feeds()
        stats = threat_intel.get_stats()
        logger.info(f"Threat Intelligence loaded: {stats}")
        if not args.quiet:
            print(f"[+] Threat Intelligence DB: {stats}")
    except Exception as e:
        logger.warning(f"Failed to initialize threat intelligence: {e}")

if security_config.get("ddos_enabled"):
    try:
        request_threshold = security_config.get("ddos_request_threshold")
        time_window = security_config.get("ddos_time_window_seconds")
        alert_threshold = security_config.get("ddos_alert_threshold")
        ddos_detector = DDosDetector(request_threshold, time_window, alert_threshold)
        logger.info("DDoS detector initialized")
    except Exception as e:
        logger.warning(f"Failed to initialize DDoS detector: {e}")

alerts = []
alerts.extend(detect_insecure_protocols(packets))
alerts.extend(detect_high_volume_sources(packets, threshold=args.threshold))
alerts.extend(detect_port_scans_time_window(
    packets,
    port_threshold=20,
    time_window=5.0,
))

# Security-enhanced detections
if threat_intel:
    try:
        alerts.extend(detect_malicious_ips(packets, threat_intel))
        alerts.extend(detect_reputation_based_anomalies(packets, threat_intel, threshold=50))
    except Exception as e:
        logger.error(f"Error in threat intelligence detection: {e}")

if ddos_detector:
    try:
        ddos_alert = ddos_detector.check_distributed_sources(packets, threshold=50)
        if ddos_alert:
            alerts.append(ddos_alert)
        
        ddos_alert = ddos_detector.check_port_flood(packets, port_variation_threshold=100)
        if ddos_alert:
            alerts.append(ddos_alert)
    except Exception as e:
        logger.error(f"Error in DDoS detection: {e}")

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
        try:
            output_path = validate_output_path(args.output)
        except ValueError as e:
            print(f"[!] Error: {e}")
            logger.error(f"Invalid output path: {e}")
            exit(1)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(table_text)
        logger.info(f"Table report saved to {output_path}")
        print(f"Table report written to {output_path}")
    else:
        print(table_text)

# Cleanup
if threat_intel:
    try:
        threat_intel.close()
        logger.info("Threat intelligence database closed")
    except Exception as e:
        logger.warning(f"Error closing threat intelligence database: {e}")

logger.info("Analysis complete")
