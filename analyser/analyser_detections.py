from collections import Counter
from collections import defaultdict

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
def detect_port_scans(packets, port_threshold=20):
    """
    Detects potential port scanning activity
    One source contacting many destination ports
    """
    src_ports = defaultdict(set)

    for p in packets:
        src = p.get("Source")
        port = p.get("DestinationPort")

        if src and port:
            src_ports[src].add(port)
    alerts = []

    for src, ports in src_ports.items():
        if len(ports) >= port_threshold:
            alerts.append({
                "Type": "Port Scan Detected",
                "Severity": "HIGH",
                "Source": src,
                "Ports Count": len(ports),
                "PortsSample": sorted(list(ports))[:20] # as a sample can also be lower or higher
            })
    return alerts
def detect_port_scans_time_window(
    packets,
    port_threshold = 20,
    time_window = 5
):
    """
    Detects port scans within a sliding time window
    """
    src_activity = defaultdict(list)
    for p in packets:
        src = p.get("Source")
        port = p.get("DestinationPort")
        t = p.get("Time")

        if src and port and t is not None:
            src_activity[src].append((t, port))
    alerts = []
    
    for src, events in src_activity.items():
        events.sort()

        window_ports=set()
        window_start = [0][0]
        for t, port in events:
            if t - window_start <= time_window:
                window_ports.add(port)
            else:
                window_start = t
                window_ports = {port}
    
            if len(window_ports) >= port_threshold:
                alerts.append({
                    "Type": "Port Scan Detected",
                    "Severity": "HIGH",
                    "Source": src,
                    "Ports Count": len(window_ports),
                    "Time Window": time_window,
                    "PortsSample": sorted(list(window_ports))[:10]
                })
                break
    return alerts
