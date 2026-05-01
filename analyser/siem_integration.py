import json
import logging
import socket
from datetime import datetime
from typing import List, Dict, Any
from urllib.parse import quote

logger = logging.getLogger(__name__)


def alert_to_cef(alert: Dict[str, Any], host_name: str = "traffic-analyser") -> str:
    """
    Convert alert to Common Event Format (CEF) for SIEM systems.
    CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    """
    timestamp = datetime.utcnow().strftime("%b %d %Y %H:%M:%S")

    alert_type = alert.get("Type", "Unknown")
    severity = _cef_severity(alert.get("Severity", "MEDIUM"))
    source = alert.get("Source", "unknown")
    dest = alert.get("Destination", "unknown")

    # Build CEF extension fields
    extensions = {
        "src": source,
        "dst": dest,
        "severity": alert.get("Severity", "MEDIUM"),
        "alertType": alert_type,
    }

    # Add optional fields
    if "Protocol" in alert:
        extensions["app"] = alert["Protocol"]
    if "Count" in alert:
        extensions["cnt"] = alert["Count"]
    if "Ports Count" in alert:
        extensions["devicePort"] = alert["Ports Count"]
    if "Info" in alert:
        extensions["msg"] = alert["Info"][:512]  # Limit message length

    extension_str = "|".join(f"{k}={v}" for k, v in extensions.items())

    cef_message = (
        f"CEF:0|SecurityLabs|TrafficAnalyser|1.0|{_get_signature_id(alert_type)}|"
        f"{alert_type}|{severity}|{extension_str}"
    )

    return f"{timestamp} {host_name} {cef_message}"


def alert_to_json(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Convert alert to JSON structure suitable for Wazuh API."""
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "type": alert.get("Type", "Unknown"),
        "severity": alert.get("Severity", "MEDIUM"),
        "source": alert.get("Source", "unknown"),
        "destination": alert.get("Destination", "unknown"),
        "protocol": alert.get("Protocol", ""),
        "info": alert.get("Info", ""),
        "metadata": {k: v for k, v in alert.items() if k not in ["Type", "Severity", "Source", "Destination", "Protocol", "Info"]},
    }


def write_cef_log(alerts: List[Dict[str, Any]], log_file: str) -> None:
    """Write alerts in CEF format to a log file for Wazuh Agent monitoring."""
    try:
        with open(log_file, "a", encoding="utf-8") as f:
            for alert in alerts:
                cef_message = alert_to_cef(alert)
                f.write(cef_message + "\n")
        logger.info(f"Wrote {len(alerts)} alerts in CEF format to {log_file}")
    except Exception as e:
        logger.error(f"Error writing CEF log: {e}")


def send_to_wazuh_api(alerts: List[Dict[str, Any]], wazuh_url: str, auth_token: str) -> bool:
    """
    Send alerts to Wazuh API.
    Requires: wazuh_url (e.g., "https://wazuh-manager:55000") and valid auth token.
    """
    import requests

    if not alerts:
        return True

    try:
        headers = {
            "Authorization": f"Bearer {auth_token}",
            "Content-Type": "application/json",
        }

        for alert in alerts:
            json_alert = alert_to_json(alert)
            response = requests.post(
                f"{wazuh_url}/events",
                json=json_alert,
                headers=headers,
                verify=False,  # Set to True in production with proper certificates
                timeout=10,
            )

            if response.status_code not in [200, 201]:
                logger.warning(
                    f"Failed to send alert to Wazuh: {response.status_code} - {response.text}"
                )
            else:
                logger.debug(f"Alert sent to Wazuh successfully")

        return True
    except ImportError:
        logger.error("requests library not installed. Install with: pip install requests")
        return False
    except Exception as e:
        logger.error(f"Error sending alerts to Wazuh API: {e}")
        return False


def send_to_syslog(alerts: List[Dict[str, Any]], syslog_host: str = "localhost", syslog_port: int = 514) -> bool:
    """Send alerts via Syslog protocol (RFC 3164) to Wazuh or other SIEM."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        for alert in alerts:
            cef_message = alert_to_cef(alert)
            # Syslog priority: facility (16=local0) * 8 + severity
            priority = 16 * 8 + _syslog_severity(alert.get("Severity", "MEDIUM"))

            syslog_msg = f"<{priority}>{cef_message}"
            sock.sendto(syslog_msg.encode("utf-8"), (syslog_host, syslog_port))

        logger.info(f"Sent {len(alerts)} alerts via Syslog to {syslog_host}:{syslog_port}")
        sock.close()
        return True
    except Exception as e:
        logger.error(f"Error sending alerts via Syslog: {e}")
        return False


def _get_signature_id(alert_type: str) -> str:
    """Map alert type to signature ID."""
    signatures = {
        "Insecure Protocol Detected": "10001",
        "High Traffic Volume": "10002",
        "Port Scan Detected": "10003",
    }
    return signatures.get(alert_type, "10999")


def _cef_severity(severity_str: str) -> int:
    """Convert severity string to CEF numeric value (0-10)."""
    mapping = {
        "LOW": 3,
        "MEDIUM": 5,
        "HIGH": 8,
        "CRITICAL": 10,
    }
    return mapping.get(severity_str.upper(), 5)


def _syslog_severity(severity_str: str) -> int:
    """Convert severity string to Syslog numeric value (0-7)."""
    mapping = {
        "LOW": 4,
        "MEDIUM": 5,
        "HIGH": 2,
        "CRITICAL": 0,
    }
    return mapping.get(severity_str.upper(), 5)
