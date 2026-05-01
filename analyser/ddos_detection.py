"""
DDoS detection and rate limiting engine.
Tracks request frequency per source IP/MAC and generates alerts on suspicious patterns.
"""

import logging
import time
from collections import defaultdict
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Rate limiter for detecting DDoS and high-volume traffic.
    Uses sliding window algorithm to track requests per source.
    """

    def __init__(self, time_window_seconds: float = 60.0, threshold: int = 100):
        """
        Initialize rate limiter.
        
        Args:
            time_window_seconds: Time window for rate limiting
            threshold: Request count threshold per window
        """
        self.time_window_seconds = time_window_seconds
        self.threshold = threshold
        
        # Track requests: {source: [(timestamp, count), ...]}
        self.request_history: Dict[str, List[Tuple[float, int]]] = defaultdict(list)
        self.last_cleanup = time.time()
        self.cleanup_interval = 300  # Clean up old entries every 5 minutes

    def record_request(self, source: str, count: int = 1) -> bool:
        """
        Record a request from a source.
        
        Args:
            source: Source IP/MAC
            count: Number of requests (batch)
            
        Returns:
            True if rate limit exceeded, False otherwise
        """
        current_time = time.time()
        
        # Perform cleanup periodically
        if current_time - self.last_cleanup > self.cleanup_interval:
            self._cleanup_old_entries(current_time)
            self.last_cleanup = current_time
        
        # Add current request
        self.request_history[source].append((current_time, count))
        
        # Check if threshold exceeded
        return self._is_threshold_exceeded(source, current_time)

    def _cleanup_old_entries(self, current_time: float):
        """Remove entries older than time_window."""
        cutoff_time = current_time - self.time_window_seconds
        
        for source in list(self.request_history.keys()):
            # Keep only recent entries
            self.request_history[source] = [
                (ts, cnt) for ts, cnt in self.request_history[source]
                if ts > cutoff_time
            ]
            
            # Remove source if no recent entries
            if not self.request_history[source]:
                del self.request_history[source]

    def _is_threshold_exceeded(self, source: str, current_time: float) -> bool:
        """
        Check if source has exceeded rate limit threshold.
        
        Args:
            source: Source IP/MAC
            current_time: Current timestamp
            
        Returns:
            True if threshold exceeded within time window
        """
        cutoff_time = current_time - self.time_window_seconds
        
        # Sum requests within time window
        total_requests = sum(
            cnt for ts, cnt in self.request_history[source]
            if ts > cutoff_time
        )
        
        return total_requests > self.threshold

    def get_request_count(self, source: str, current_time: Optional[float] = None) -> int:
        """
        Get current request count for a source within time window.
        
        Args:
            source: Source IP/MAC
            current_time: Current timestamp (uses current time if None)
            
        Returns:
            Request count within time window
        """
        if current_time is None:
            current_time = time.time()
        
        cutoff_time = current_time - self.time_window_seconds
        
        return sum(
            cnt for ts, cnt in self.request_history[source]
            if ts > cutoff_time
        )

    def reset(self, source: Optional[str] = None):
        """
        Reset rate limiter.
        
        Args:
            source: Specific source to reset (None resets all)
        """
        if source:
            self.request_history[source] = []
        else:
            self.request_history.clear()


class DDosDetector:
    """
    Detects potential DDoS attacks based on multiple metrics.
    - High request volume from single source
    - High number of unique sources in short time
    - Protocol anomalies
    """

    def __init__(self, request_threshold: int = 100, time_window: float = 60.0,
                 alert_threshold: int = 50):
        """
        Initialize DDoS detector.
        
        Args:
            request_threshold: Requests per source per window to trigger rate limiter
            time_window: Time window in seconds
            alert_threshold: Minimum requests to generate alert
        """
        self.rate_limiter = RateLimiter(time_window, request_threshold)
        self.alert_threshold = alert_threshold
        self.time_window = time_window
        
        # Track unique sources per time window for distributed attack detection
        self.source_timeline: Dict[str, List[Tuple[float, str]]] = {}  # {window_id: [(ts, source), ...]}

    def check_single_source_attack(self, source: str, packets_count: int) -> Optional[Dict]:
        """
        Check if source shows single-source DDoS characteristics.
        
        Args:
            source: Source IP/MAC
            packets_count: Number of packets from this source
            
        Returns:
            Alert dict if threshold exceeded, None otherwise
        """
        if self.rate_limiter.record_request(source, packets_count):
            current_count = self.rate_limiter.get_request_count(source)
            
            if current_count >= self.alert_threshold:
                return {
                    "Type": "DDoS - Single Source Attack",
                    "Severity": "CRITICAL",
                    "Source": source,
                    "Request Count": current_count,
                    "Time Window": f"{self.time_window}s",
                    "Timestamp": datetime.utcnow().isoformat() + "Z",
                }
        
        return None

    def check_distributed_sources(self, packets: List[Dict], threshold: int = 50) -> Optional[Dict]:
        """
        Check if multiple sources are attacking target (distributed DDoS).
        
        Args:
            packets: List of packet dictionaries
            threshold: Minimum unique sources to trigger alert
            
        Returns:
            Alert dict if threshold exceeded, None otherwise
        """
        if not packets:
            return None
        
        current_time = time.time()
        window_id = int(current_time / self.time_window)
        
        unique_sources = set()
        target_ports = defaultdict(int)
        
        for packet in packets:
            source = packet.get("Source", "")
            dest_port = packet.get("Destination Port", "")
            
            if source:
                unique_sources.add(source)
            if dest_port:
                target_ports[dest_port] += 1
        
        if len(unique_sources) >= threshold:
            # Identify most common target port
            top_port = max(target_ports.items(), key=lambda x: x[1])[0] if target_ports else "unknown"
            
            return {
                "Type": "DDoS - Distributed Attack",
                "Severity": "CRITICAL",
                "Unique Sources": len(unique_sources),
                "Target Port": top_port,
                "Time Window": f"{self.time_window}s",
                "Threshold Exceeded": f"{threshold} sources",
                "Timestamp": datetime.utcnow().isoformat() + "Z",
            }
        
        return None

    def check_port_flood(self, packets: List[Dict], port_variation_threshold: int = 100) -> Optional[Dict]:
        """
        Check for port flood attacks (many different ports targeted).
        
        Args:
            packets: List of packet dictionaries
            port_variation_threshold: Unique port threshold
            
        Returns:
            Alert dict if threshold exceeded, None otherwise
        """
        if not packets:
            return None
        
        unique_ports = set()
        source_ports_map = defaultdict(set)
        
        for packet in packets:
            source = packet.get("Source", "")
            dest_port = packet.get("Destination Port", "")
            
            if dest_port and dest_port.isdigit():
                try:
                    port = int(dest_port)
                    if 0 < port <= 65535:
                        unique_ports.add(port)
                        if source:
                            source_ports_map[source].add(port)
                except ValueError:
                    pass
        
        if len(unique_ports) >= port_variation_threshold:
            # Find source targeting most ports
            top_source = max(source_ports_map.items(), key=lambda x: len(x[1]))
            
            return {
                "Type": "DDoS - Port Flood Attack",
                "Severity": "CRITICAL",
                "Unique Ports": len(unique_ports),
                "Top Attacker": top_source[0],
                "Ports From Top Attacker": len(top_source[1]),
                "Threshold Exceeded": f"{port_variation_threshold} ports",
                "Timestamp": datetime.utcnow().isoformat() + "Z",
            }
        
        return None

    def reset(self):
        """Reset detector state."""
        self.rate_limiter.reset()
        self.source_timeline.clear()


def detect_ddos_attacks(packets: List[Dict], rate_limiter: Optional[RateLimiter] = None,
                       request_threshold: int = 100, time_window: float = 60.0) -> List[Dict]:
    """
    Convenience function to detect DDoS attacks from packets.
    
    Args:
        packets: List of packet dictionaries
        rate_limiter: Optional RateLimiter instance
        request_threshold: Requests per source per window
        time_window: Time window in seconds
        
    Returns:
        List of DDoS alert dictionaries
    """
    if rate_limiter is None:
        rate_limiter = RateLimiter(time_window, request_threshold)
    
    alerts = []
    
    # Count packets per source
    source_counts = defaultdict(int)
    for packet in packets:
        source = packet.get("Source", "")
        if source:
            source_counts[source] += 1
    
    # Check each source for single-source attacks
    for source, count in source_counts.items():
        alert = DDosDetector().check_single_source_attack(source, count)
        if alert:
            alerts.append(alert)
    
    return alerts
