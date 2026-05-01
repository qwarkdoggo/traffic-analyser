import json
import logging
import socket
from datetime import datetime
from typing import List, Dict, Any
from urllib.parse import quote
from input_validation import sanitize_alert

logger = logging.getLogger(__name__)


def _escape_cef_value(value: Any) -> str:
    """
    Escape special characters in CEF field values.
    CEF format uses pipe (|) and equals (=) as delimiters.
    Reference: ArcSight CEF Format
    """
    if value is None:
        return ""

    value_str = str(value)

    # Escape backslash first (it's the escape character)
    value_str = value_str.replace("\\", "\\\\")

    # Escape pipe (|), equals (=), and newlines
    value_str = value_str.replace("|", "\\|")
    value_str = value_str.replace("=", "\\=")
    value_str = value_str.replace("\n", "\\n")
    value_str = value_str.replace("\r", "\\r")

    return value_str


def alert_to_cef(alert: Dict[str, Any], host_name: str = "traffic-analyser") -> str:
    """
    Convert alert to Common Event Format (CEF) for SIEM systems.
    CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    """
    try:
        # Sanitize alert before processing
        alert = sanitize_alert(alert, strict=False)
    except Exception as e:
        logger.warning(f"Failed to sanitize alert: {e}")
    
    timestamp = datetime.utcnow().strftime("%b %d %Y %H:%M:%S")

    alert_type = alert.get("Type", "Unknown")
    severity = _cef_severity(alert.get("Severity", "MEDIUM"))
    source = alert.get("Source", "unknown")
    dest = alert.get("Destination", "unknown")

    # Build CEF extension fields with proper escaping
    extensions = {
        "src": _escape_cef_value(source),
        "dst": _escape_cef_value(dest),
        "severity": _escape_cef_value(alert.get("Severity", "MEDIUM")),
        "alertType": _escape_cef_value(alert_type),
    }

    # Add optional fields with escaping
    if "Protocol" in alert:
        extensions["app"] = _escape_cef_value(alert["Protocol"])
    if "Count" in alert:
        extensions["cnt"] = _escape_cef_value(alert["Count"])
    if "Ports Count" in alert:
        extensions["devicePort"] = _escape_cef_value(alert["Ports Count"])
    if "Info" in alert:
        info = str(alert["Info"])[:512]  # Limit message length
        extensions["msg"] = _escape_cef_value(info)

    extension_str = "|".join(f"{k}={v}" for k, v in extensions.items())

    cef_message = (
        f"CEF:0|SecurityLabs|TrafficAnalyser|1.0|{_get_signature_id(alert_type)}|"
        f"{_escape_cef_value(alert_type)}|{severity}|{extension_str}"
    )

    return f"{timestamp} {host_name} {cef_message}"


def alert_to_json(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Convert alert to JSON structure suitable for Wazuh API."""
    try:
        # Sanitize alert before JSON conversion
        alert = sanitize_alert(alert, strict=False)
    except Exception as e:
        logger.warning(f"Failed to sanitize alert for JSON: {e}")
    
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


def send_to_wazuh_api(alerts: List[Dict[str, Any]], wazuh_url: str, auth_token: str, verify_ssl: bool = True) -> bool:
    """
    Send alerts to Wazuh API.
    Requires: wazuh_url (e.g., "https://wazuh-manager:55000") and valid auth token.

    Args:
        alerts: List of alert dictionaries
        wazuh_url: Wazuh Manager API URL
        auth_token: API authentication token
        verify_ssl: Verify SSL certificates (default True for security)
    """
    import requests

    if not alerts:
        return True

    try:
        # Validate URL format
        if not wazuh_url or not isinstance(wazuh_url, str):
            logger.error("Invalid Wazuh URL provided")
            return False
        
        if not wazuh_url.startswith("http"):
            logger.error("Wazuh URL must start with http or https")
            return False
        
        headers = {
            "Authorization": f"Bearer {auth_token}",
            "Content-Type": "application/json",
        }

        for alert in alerts:
            try:
                json_alert = alert_to_json(alert)
                response = requests.post(
                    f"{wazuh_url}/events",
                    json=json_alert,
                    headers=headers,
                    verify=verify_ssl,  # SSL certificate verification enabled
                    timeout=10,
                )

                if response.status_code not in [200, 201]:
                    logger.warning(
                        f"Failed to send alert to Wazuh: {response.status_code} - {response.text[:200]}"
                    )
                else:
                    logger.debug(f"Alert sent to Wazuh successfully")
            
            except Exception as e:
                logger.error(f"Error sending individual alert to Wazuh: {e}")
                continue

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
