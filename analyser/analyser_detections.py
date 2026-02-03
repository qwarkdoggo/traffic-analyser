from collections import Counter

INSECURE_PROTOCOLS = {
    "HTTP": "MEDIUM",
    "FTP": "HIGH",
    "TELNET": "HIGH",
    "SMTP": "LOW",
    "POP3": "LOW",
    "IMAP": "LOW",
}

def detect_insecure_protocols(packets):
    alerts = []
    for p in packets:
        proto = p.get("Protocol", "").upper()
        if proto in INSECURE_PROTOCOLS:
            alerts.append ({
                "Type": "Insecure Protocol Detected",
                "Severity": INSECURE_PROTOCOLS[proto],
                "Source": p.get("Source"),
                "Destination": p.get("Destination"),
                "Protocol": proto,
                "Info" : p.get("Info")
            })
    return alerts
def detect_high_volume_sources(packets, threshold=100):
    counter = Counter(p.get("Source") for p in packets if p.get("Source"))
    alerts = []

    for src, count in counter.items():
        if count > threshold:
            alerts.append({
                "Type": "High Traffic Volume",
                "Severity": "MEDIUM",
                "Source": src,
                "Count": count,
            })
    return alerts
