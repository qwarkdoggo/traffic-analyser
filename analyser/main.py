import os

from parser import load_traffic
from analyser_detections import detect_insecure_protocols
from pcap_to_csv import convert_pcap_to_csv
from report import save_report

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

PCAP_FILE = os.path.join(BASE_DIR, "..", "data", "traffic.pcap")
CSV_FILE  = os.path.join(BASE_DIR, "..", "data", "traffic.csv")
OUTPUT_JSON = os.path.join(BASE_DIR, "..", "data", "report.json")

if os.path.exists(PCAP_FILE):
    print("[*] PCAP found, converting to CSV...")
    convert_pcap_to_csv(PCAP_FILE, CSV_FILE)
else:
    print("[*] PCAP not found, using existing CSV")

packets = load_traffic(CSV_FILE)

alerts = []
alerts.extend(detect_insecure_protocols(packets))

print(f"Detected {len(alerts)} alerts")

save_report(alerts, OUTPUT_JSON)
print(f"Report saved to {OUTPUT_JSON}")
