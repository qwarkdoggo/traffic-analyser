"""
Input validation and sanitization to prevent injection attacks.
Validates all user inputs, SIEM data, and configuration before use.
"""

import re
import logging
from typing import Any, Dict, List, Union
from urllib.parse import quote, unquote

logger = logging.getLogger(__name__)


class InputValidator:
    """Validates and sanitizes all inputs to prevent injection attacks."""

    # Regex patterns for common validation
    PATTERNS = {
        "ipv4": r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
        "ipv6": r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$",
        "mac": r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$",
        "hostname": r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})*$",
        "port": r"^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$",
        "email": r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
    }

    # Dangerous patterns that may indicate injection attempts
    DANGEROUS_PATTERNS = {
        "sql_injection": [
            r"(\bUNION\b|\bSELECT\b|\bDROP\b|\bINSERT\b|\bDELETE\b|\bUPDATE\b|--|;)",
            r"('\s*OR\s*'|'\s*OR\s*1\s*=\s*1)",
        ],
        "command_injection": [
            r"[`;\|&$(){}[\]<>]",
            r"\$\{.*\}",
            r"^-",
        ],
        "path_traversal": [
            r"\.\./",
            r"\.\.",
            r"%2e%2e",
        ],
        "xss": [
            r"<script.*?>",
            r"javascript:",
            r"onerror\s*=",
            r"onclick\s*=",
        ],
    }

    @staticmethod
    def validate_string(value: Any, max_length: int = 10000, allow_empty: bool = False) -> str:
        """
        Validate and sanitize string input.
        
        Args:
            value: Input value
            max_length: Maximum allowed string length
            allow_empty: Whether empty strings are valid
            
        Returns:
            Sanitized string
            
        Raises:
            ValueError: If validation fails
        """
        if not isinstance(value, str):
            raise ValueError(f"Expected string, got {type(value).__name__}")
        
        value = value.strip()
        
        if not allow_empty and not value:
            raise ValueError("Empty string not allowed")
        
        if len(value) > max_length:
            raise ValueError(f"String exceeds maximum length of {max_length}")
        
        return value

    @staticmethod
    def validate_ip(ip_str: str) -> str:
        """
        Validate IP address (IPv4 or IPv6).
        
        Args:
            ip_str: IP address string
            
        Returns:
            Validated IP
            
        Raises:
            ValueError: If IP is invalid
        """
        ip_str = InputValidator.validate_string(ip_str, max_length=45)
        
        if re.match(InputValidator.PATTERNS["ipv4"], ip_str):
            return ip_str
        if re.match(InputValidator.PATTERNS["ipv6"], ip_str):
            return ip_str
        
        raise ValueError(f"Invalid IP address: {ip_str}")

    @staticmethod
    def validate_mac(mac_str: str) -> str:
        """
        Validate MAC address.
        
        Args:
            mac_str: MAC address string
            
        Returns:
            Validated MAC
            
        Raises:
            ValueError: If MAC is invalid
        """
        mac_str = InputValidator.validate_string(mac_str, max_length=17)
        
        if re.match(InputValidator.PATTERNS["mac"], mac_str):
            return mac_str
        
        raise ValueError(f"Invalid MAC address: {mac_str}")

    @staticmethod
    def validate_port(port: Union[str, int]) -> int:
        """
        Validate port number.
        
        Args:
            port: Port number (string or int)
            
        Returns:
            Validated port as integer
            
        Raises:
            ValueError: If port is invalid
        """
        if isinstance(port, str):
            port = port.strip()
            if not re.match(InputValidator.PATTERNS["port"], port):
                raise ValueError(f"Invalid port: {port}")
            port = int(port)
        elif not isinstance(port, int):
            raise ValueError(f"Port must be string or int, got {type(port).__name__}")
        
        if not (1 <= port <= 65535):
            raise ValueError(f"Port must be between 1-65535, got {port}")
        
        return port

    @staticmethod
    def validate_hostname(hostname: str) -> str:
        """
        Validate hostname.
        
        Args:
            hostname: Hostname string
            
        Returns:
            Validated hostname
            
        Raises:
            ValueError: If hostname is invalid
        """
        hostname = InputValidator.validate_string(hostname, max_length=255)
        
        if re.match(InputValidator.PATTERNS["hostname"], hostname):
            return hostname
        
        raise ValueError(f"Invalid hostname: {hostname}")

    @staticmethod
    def sanitize_alert_message(message: str, max_length: int = 512) -> str:
        """
        Sanitize alert message for safe transmission.
        Remove/escape potentially dangerous characters.
        
        Args:
            message: Alert message
            max_length: Maximum message length
            
        Returns:
            Sanitized message
        """
        try:
            message = InputValidator.validate_string(message, max_length=max_length, allow_empty=True)
        except ValueError as e:
            logger.warning(f"Alert message validation failed: {e}")
            return message[:max_length] if len(message) > max_length else message
        
        # Remove null bytes
        message = message.replace('\x00', '')
        
        # Remove control characters except newlines/tabs
        message = ''.join(c for c in message if ord(c) >= 32 or c in '\n\t')
        
        return message

    @staticmethod
    def check_injection_attempt(value: str, check_type: str = "all") -> bool:
        """
        Check if value contains potential injection patterns.
        
        Args:
            value: Value to check
            check_type: Type of injection to check ('sql', 'command', 'path_traversal', 'xss', 'all')
            
        Returns:
            True if dangerous pattern detected, False otherwise
        """
        value_upper = value.upper()
        
        checks = {
            "sql": InputValidator.DANGEROUS_PATTERNS["sql_injection"],
            "command": InputValidator.DANGEROUS_PATTERNS["command_injection"],
            "path_traversal": InputValidator.DANGEROUS_PATTERNS["path_traversal"],
            "xss": InputValidator.DANGEROUS_PATTERNS["xss"],
        }
        
        if check_type == "all":
            checks_to_run = checks
        else:
            checks_to_run = {check_type: checks.get(check_type, [])}
        
        for check_name, patterns in checks_to_run.items():
            for pattern in patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    logger.warning(f"Potential {check_name} injection detected: {value[:50]}")
                    return True
        
        return False

    @staticmethod
    def validate_alert_dict(alert: Dict[str, Any], strict: bool = True) -> Dict[str, Any]:
        """
        Validate and sanitize alert dictionary before sending to SIEM.
        
        Args:
            alert: Alert dictionary
            strict: If True, reject alerts with injection patterns
            
        Returns:
            Sanitized alert
            
        Raises:
            ValueError: If alert contains dangerous content (strict mode)
        """
        if not isinstance(alert, dict):
            raise ValueError(f"Alert must be a dictionary, got {type(alert).__name__}")
        
        sanitized = {}
        
        for key, value in alert.items():
            # Validate key
            if not isinstance(key, str):
                logger.warning(f"Skipping alert field with non-string key: {key}")
                continue
            
            if InputValidator.check_injection_attempt(key, "all"):
                if strict:
                    raise ValueError(f"Injection pattern detected in alert key: {key}")
                else:
                    logger.warning(f"Suspicious key skipped: {key}")
                    continue
            
            # Sanitize value based on type
            if isinstance(value, str):
                if InputValidator.check_injection_attempt(value, "all"):
                    if strict:
                        raise ValueError(f"Injection pattern detected in alert value: {value[:50]}")
                    else:
                        logger.warning(f"Injection pattern detected, sanitizing value for key: {key}")
                        value = InputValidator._escape_special_chars(value)
                
                sanitized[key] = InputValidator.sanitize_alert_message(value)
            
            elif isinstance(value, (int, float, bool)):
                sanitized[key] = value
            
            elif isinstance(value, list):
                sanitized[key] = [
                    InputValidator.sanitize_alert_message(str(v)) if isinstance(v, str) else v
                    for v in value
                ]
            
            else:
                # Convert complex types to string and sanitize
                sanitized[key] = InputValidator.sanitize_alert_message(str(value))
        
        return sanitized

    @staticmethod
    def _escape_special_chars(value: str) -> str:
        """Escape special characters for safe transmission."""
        escape_map = {
            '\\': '\\\\',
            '"': '\\"',
            "'": "\\'",
            '\n': '\\n',
            '\r': '\\r',
            '\t': '\\t',
            '\x00': '',
        }
        
        for char, escaped in escape_map.items():
            value = value.replace(char, escaped)
        
        return value


# Global validator instance
_validator = InputValidator()


def validate_ip(ip_str: str) -> str:
    """Convenience function to validate IP."""
    return _validator.validate_ip(ip_str)


def validate_mac(mac_str: str) -> str:
    """Convenience function to validate MAC."""
    return _validator.validate_mac(mac_str)


def validate_port(port: Union[str, int]) -> int:
    """Convenience function to validate port."""
    return _validator.validate_port(port)


def sanitize_alert(alert: Dict[str, Any], strict: bool = True) -> Dict[str, Any]:
    """Convenience function to sanitize alert."""
    return _validator.validate_alert_dict(alert, strict)
