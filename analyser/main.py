import os
<<<<<<< HEAD
=======
import argparse
>>>>>>> master

from parser import load_traffic
from analyser_detections import detect_insecure_protocols
from pcap_to_csv import convert_pcap_to_csv
from report import save_report
from analyser_detections import (
    detect_insecure_protocols,
    detect_high_volume_sources,
    detect_port_scans_time_window,
)
<<<<<<< HEAD

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

PCAP_FILE = os.path.join(BASE_DIR, "..", "data", "traffic.pcap")
CSV_FILE  = os.path.join(BASE_DIR, "..", "data", "traffic.csv")
OUTPUT_JSON = os.path.join(BASE_DIR, "..", "data", "report.json")

=======
from argparse import ArgumentParser

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

args = parser.parse_args()

if not args.quiet:
    print(f"Parsed arguments: {args}")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

default_pcap = os.path.join(BASE_DIR, "..", "data", "traffic.pcap")

if args.input:
    PCAP_FILE = args.input
else:
    PCAP_FILE = default_pcap

CSV_FILE  = os.path.join(BASE_DIR, "..", "data", "traffic.csv")
OUTPUT_JSON = os.path.join(BASE_DIR, "..", "data", "report.json")

if not args.quiet:
    print("Using PCAP:", PCAP_FILE)
    print("Exists:", os.path.exists(PCAP_FILE))

>>>>>>> master
if os.path.exists(PCAP_FILE):
    print("[*] PCAP found, converting to CSV...")
    convert_pcap_to_csv(PCAP_FILE, CSV_FILE)
else:
    print("[*] PCAP not found, using existing CSV")

packets = load_traffic(CSV_FILE)

alerts = []
alerts.extend(detect_insecure_protocols(packets))
<<<<<<< HEAD
alerts.extend(detect_high_volume_sources(packets))
alerts.extend(detect_port_scans_time_window(
    packets,
    port_threshold=20,
    time_window=5.0
))

print(f"Detected {len(alerts)} alerts")

save_report(alerts, OUTPUT_JSON)
print(f"Report saved to {OUTPUT_JSON}")
=======
alerts.extend(detect_high_volume_sources(packets, threshold=args.threshold))
alerts.extend(detect_port_scans_time_window(
    packets,
    port_threshold=20,
    time_window=5.0,
))

if not args.quiet:
    print(f"Detected {len(alerts)} alerts")
if args.format == "json":
    if args.output:
        print(f"[!] --output ignored for json format; using {OUTPUT_JSON}")
    output_path = OUTPUT_JSON
    save_report(alerts, output_path)
    print(f"Report saved to {output_path}")
elif args.format == "table":
    from report import format_alerts_table

    table_text = format_alerts_table(alerts)
    if args.output:
        output_path = args.output
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(table_text)
        print(f"Table report written to {output_path}")
    else:
        print(table_text)
>>>>>>> master
