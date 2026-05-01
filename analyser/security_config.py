"""
Centralized security configuration management.
Loads settings from environment variables and local config files.
Supports validation of all configuration parameters.
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class SecurityConfig:
    """Centralized configuration for security settings."""

    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize security configuration.
        
        Args:
            config_file: Path to JSON config file (optional, env vars take precedence)
        """
        self.config: Dict[str, Any] = {}
        self._load_defaults()
        
        if config_file and os.path.exists(config_file):
            self._load_from_file(config_file)
        
        self._load_from_env()

    def _load_defaults(self):
        """Set default security values."""
        self.config = {
            # DDoS Detection
            "ddos_enabled": True,
            "ddos_request_threshold": 100,  # Requests per time window
            "ddos_time_window_seconds": 60,  # Time window in seconds
            "ddos_alert_threshold": 50,  # Alert when threshold exceeded
            
            # Rate Limiting
            "rate_limit_enabled": True,
            "rate_limit_requests_per_minute": 60,
            
            # Threat Intelligence
            "threat_intel_enabled": True,
            "threat_feeds_dir": "data/threat_feeds",
            "threat_cache_enabled": True,
            "threat_cache_ttl_hours": 24,
            
            # Input Validation
            "validate_inputs": True,
            "max_input_length": 10000,
            "max_alert_message_length": 512,
            
            # Wazuh Integration
            "wazuh_enabled": True,
            "wazuh_connection_timeout": 10,
            "wazuh_retry_attempts": 3,
            "wazuh_retry_delay_seconds": 2,
            "wazuh_batch_size": 50,  # Send alerts in batches
            "wazuh_verify_ssl": True,
            
            # Syslog
            "syslog_enabled": False,
            "syslog_host": "localhost",
            "syslog_port": 514,
            
            # CEF Logging
            "cef_enabled": True,
            "cef_log_file": "data/alerts.cef",
            
            # Audit Logging
            "audit_logging_enabled": True,
            "audit_log_file": "data/analyser_audit.log",
        }

    def _load_from_file(self, config_file: str):
        """Load configuration from JSON file."""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                file_config = json.load(f)
                self.config.update(file_config)
                logger.info(f"Loaded configuration from {config_file}")
        except Exception as e:
            logger.error(f"Failed to load config file {config_file}: {e}")

    def _load_from_env(self):
        """Load configuration from environment variables (override file config)."""
        env_mapping = {
            "DDOS_ENABLED": ("ddos_enabled", self._parse_bool),
            "DDOS_REQUEST_THRESHOLD": ("ddos_request_threshold", int),
            "DDOS_TIME_WINDOW": ("ddos_time_window_seconds", int),
            "DDOS_ALERT_THRESHOLD": ("ddos_alert_threshold", int),
            "RATE_LIMIT_ENABLED": ("rate_limit_enabled", self._parse_bool),
            "RATE_LIMIT_RPM": ("rate_limit_requests_per_minute", int),
            "THREAT_INTEL_ENABLED": ("threat_intel_enabled", self._parse_bool),
            "THREAT_FEEDS_DIR": ("threat_feeds_dir", str),
            "WAZUH_ENABLED": ("wazuh_enabled", self._parse_bool),
            "WAZUH_URL": ("wazuh_url", str),
            "WAZUH_TOKEN": ("wazuh_token", str),
            "WAZUH_TIMEOUT": ("wazuh_connection_timeout", int),
            "WAZUH_VERIFY_SSL": ("wazuh_verify_ssl", self._parse_bool),
            "SYSLOG_ENABLED": ("syslog_enabled", self._parse_bool),
            "SYSLOG_HOST": ("syslog_host", str),
            "SYSLOG_PORT": ("syslog_port", int),
            "CEF_ENABLED": ("cef_enabled", self._parse_bool),
            "AUDIT_LOGGING_ENABLED": ("audit_logging_enabled", self._parse_bool),
        }

        for env_var, (config_key, parser) in env_mapping.items():
            if env_var in os.environ:
                try:
                    self.config[config_key] = parser(os.environ[env_var])
                except Exception as e:
                    logger.warning(f"Failed to parse {env_var}: {e}")

    @staticmethod
    def _parse_bool(value: str) -> bool:
        """Parse string to boolean."""
        return value.lower() in ('true', '1', 'yes', 'on')

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value."""
        return self.config.get(key, default)

    def set(self, key: str, value: Any):
        """Set configuration value."""
        self.config[key] = value
        logger.debug(f"Configuration {key} set to {value}")

    def validate(self) -> bool:
        """Validate all configuration values."""
        errors = []

        # Validate numeric ranges
        if self.config["ddos_request_threshold"] < 0:
            errors.append("ddos_request_threshold must be non-negative")
        
        if self.config["ddos_time_window_seconds"] <= 0:
            errors.append("ddos_time_window_seconds must be positive")
        
        if self.config["rate_limit_requests_per_minute"] <= 0:
            errors.append("rate_limit_requests_per_minute must be positive")
        
        if self.config["max_input_length"] <= 0:
            errors.append("max_input_length must be positive")

        if errors:
            for error in errors:
                logger.error(f"Configuration error: {error}")
            return False

        logger.info("Configuration validation passed")
        return True

    def to_dict(self) -> Dict[str, Any]:
        """Export configuration as dictionary (excludes sensitive data)."""
        safe_config = self.config.copy()
        # Redact sensitive values
        sensitive_keys = ['wazuh_token', 'api_key']
        for key in sensitive_keys:
            if key in safe_config:
                safe_config[key] = "***REDACTED***"
        return safe_config


# Global config instance
_config_instance: Optional[SecurityConfig] = None


def get_config(config_file: Optional[str] = None) -> SecurityConfig:
    """Get or create global config instance."""
    global _config_instance
    if _config_instance is None:
        _config_instance = SecurityConfig(config_file)
    return _config_instance


def reset_config():
    """Reset global config instance (for testing)."""
    global _config_instance
    _config_instance = None
