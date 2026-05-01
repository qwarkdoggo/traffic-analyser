from collections import Counter
from collections import defaultdict
import ipaddress
import logging

logger = logging.getLogger(__name__)

INSECURE_PROTOCOLS = {
    "HTTP": "MEDIUM",
    "FTP": "HIGH",
    "TELNET": "HIGH",
    "SMTP": "LOW",
    "POP3": "LOW",
    "IMAP": "LOW",
}


def _is_valid_ip(ip_str: str) -> bool:
    """Validate if string is a valid IPv4 or IPv6 address."""
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False


def _is_valid_mac(mac_str: str) -> bool:
    """Validate if string is a valid MAC address."""
    if not mac_str or not isinstance(mac_str, str):
        return False
    mac_str = mac_str.strip()
    return len(mac_str) == 17 and all(c in "0123456789abcdefABCDEF:-" for c in mac_str)


def detect_insecure_protocols(packets):
    alerts = []
    for p in packets:
        proto = p.get("Protocol", "").upper()
        source = p.get("Source", "")
        dest = p.get("Destination", "")

        # Validate MAC addresses
        if not _is_valid_mac(source) or not _is_valid_mac(dest):
            logger.debug(f"Skipping packet with invalid MAC: src={source}, dst={dest}")
            continue

        if proto in INSECURE_PROTOCOLS:
            alerts.append({
                "Type": "Insecure Protocol Detected",
                "Severity": INSECURE_PROTOCOLS[proto],
                "Source": source,
                "Destination": dest,
                "Protocol": proto,
                "Info": p.get("Info")
            })
    return alerts
def detect_high_volume_sources(packets, threshold=100):
    counter = Counter(p.get("Source") for p in packets if p.get("Source") and _is_valid_mac(p.get("Source", "")))
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

        if src and port and _is_valid_mac(src):
            try:
                port_num = int(port)
                if 0 < port_num <= 65535:
                    src_ports[src].add(port_num)
            except (ValueError, TypeError):
                logger.debug(f"Skipping invalid port: {port}")
                continue

    alerts = []

    for src, ports in src_ports.items():
        if len(ports) >= port_threshold:
            alerts.append({
                "Type": "Port Scan Detected",
                "Severity": "HIGH",
                "Source": src,
                "Ports Count": len(ports),
                "PortsSample": sorted(list(ports))[:20]
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

        if src and port and t is not None and _is_valid_mac(src):
            try:
                port_num = int(port)
                if 0 < port_num <= 65535:
                    src_activity[src].append((t, port_num))
            except (ValueError, TypeError):
                logger.debug(f"Skipping invalid port for time-window scan: {port}")
                continue

    alerts = []

    for src, events in src_activity.items():
        events.sort()

        if not events:
            continue

        window_ports = set()
        window_start = events[0][0]
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


def detect_malicious_ips(packets, threat_intel):
    """
    Detect packets from known malicious IPs using local threat intelligence.
    
    Args:
        packets: List of packet dictionaries
        threat_intel: ThreatIntelligence instance
        
    Returns:
        List of alerts for malicious IP detections
    """
    if not threat_intel:
        return []
    
    alerts = []
    checked_sources = set()
    
    for p in packets:
        source = p.get("Source", "")
        
        # Skip if already checked or invalid
        if not source or source in checked_sources:
            continue
        
        # Try to extract IP from MAC or use as-is
        checked_sources.add(source)
        
        is_malicious, reputation = threat_intel.is_malicious(source)
        
        if is_malicious and reputation:
            alerts.append({
                "Type": "Malicious IP Detected",
                "Severity": reputation.get("threat_level", "MEDIUM"),
                "Source": source,
                "Reputation Score": reputation.get("reputation_score", 0),
                "Threat Types": ", ".join(reputation.get("threat_types", [])),
                "Source Feed": reputation.get("source", "unknown"),
                "Info": f"IP reputation score: {reputation.get('reputation_score', 'unknown')}"
            })
    
    return alerts


def detect_reputation_based_anomalies(packets, threat_intel, threshold=50):
    """
    Detect anomalies based on IP reputation scores.
    
    Args:
        packets: List of packet dictionaries
        threat_intel: ThreatIntelligence instance
        threshold: Reputation score threshold (0-100)
        
    Returns:
        List of alerts for reputation-based anomalies
    """
    if not threat_intel:
        return []
    
    alerts = []
    source_scores = defaultdict(list)
    
    for p in packets:
        source = p.get("Source", "")
        if source:
            score = threat_intel.get_reputation_score(source)
            if score > 0:
                source_scores[source].append(score)
    
    # Alert on sources with average reputation score above threshold
    for source, scores in source_scores.items():
        avg_score = sum(scores) / len(scores)
        if avg_score > threshold:
            alerts.append({
                "Type": "High Reputation Score Anomaly",
                "Severity": "HIGH" if avg_score > 80 else "MEDIUM",
                "Source": source,
                "Average Reputation Score": round(avg_score, 2),
                "Packet Count": len(scores),
                "Max Score": max(scores),
            })
    
    return alerts
