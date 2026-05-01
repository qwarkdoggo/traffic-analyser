"""
Local threat intelligence engine.
Supports multiple local threat feed formats without external API calls.
"""

import os
import json
import csv
import logging
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime, timedelta
import hashlib

logger = logging.getLogger(__name__)


class ThreatIntelligenceDB:
    """
    SQLite-backed threat intelligence database.
    Stores IP reputation scores from local threat feeds.
    """

    def __init__(self, db_path: str = "data/threat_intelligence.db"):
        """
        Initialize threat intelligence database.
        
        Args:
            db_path: Path to SQLite database
        """
        self.db_path = db_path
        self.conn = None
        self._init_db()

    def _init_db(self):
        """Initialize database schema."""
        try:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cursor = self.conn.cursor()
            
            # IP Reputation table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ip_reputation (
                    ip TEXT PRIMARY KEY,
                    reputation_score INTEGER,
                    threat_level TEXT,
                    threat_types TEXT,
                    last_seen TIMESTAMP,
                    source TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Threat feed metadata
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_feeds (
                    feed_id TEXT PRIMARY KEY,
                    feed_name TEXT,
                    feed_path TEXT,
                    last_updated TIMESTAMP,
                    entry_count INTEGER
                )
            """)
            
            # Create index for faster lookups
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_ip_reputation ON ip_reputation(ip)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_threat_level ON ip_reputation(threat_level)
            """)
            
            self.conn.commit()
            logger.info(f"Threat intelligence database initialized: {self.db_path}")
        
        except Exception as e:
            logger.error(f"Failed to initialize threat database: {e}")
            raise

    def add_ip(self, ip: str, reputation_score: int, threat_level: str,
               threat_types: str, source: str = "unknown"):
        """
        Add IP to threat database.
        
        Args:
            ip: IP address
            reputation_score: Score 0-100 (higher = more malicious)
            threat_level: LOW, MEDIUM, HIGH, CRITICAL
            threat_types: Comma-separated threat types
            source: Feed source name
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO ip_reputation 
                (ip, reputation_score, threat_level, threat_types, source, last_seen)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (ip, reputation_score, threat_level, threat_types, source))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to add IP to threat database: {e}")

    def lookup_ip(self, ip: str) -> Optional[Dict]:
        """
        Look up IP in threat database.
        
        Args:
            ip: IP address to lookup
            
        Returns:
            Reputation dict if found, None otherwise
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT ip, reputation_score, threat_level, threat_types, source, last_seen
                FROM ip_reputation
                WHERE ip = ?
            """, (ip,))
            
            row = cursor.fetchone()
            if row:
                return {
                    "ip": row[0],
                    "reputation_score": row[1],
                    "threat_level": row[2],
                    "threat_types": row[3].split(",") if row[3] else [],
                    "source": row[4],
                    "last_seen": row[5],
                }
        except Exception as e:
            logger.error(f"Failed to lookup IP: {e}")
        
        return None

    def get_all_malicious_ips(self, threat_level: Optional[str] = None) -> List[str]:
        """
        Get all malicious IPs, optionally filtered by threat level.
        
        Args:
            threat_level: Optional threat level filter (HIGH, CRITICAL)
            
        Returns:
            List of IP addresses
        """
        try:
            cursor = self.conn.cursor()
            if threat_level:
                cursor.execute("""
                    SELECT DISTINCT ip FROM ip_reputation WHERE threat_level = ?
                """, (threat_level,))
            else:
                cursor.execute("""
                    SELECT DISTINCT ip FROM ip_reputation
                """)
            
            return [row[0] for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get malicious IPs: {e}")
            return []

    def get_stats(self) -> Dict:
        """Get database statistics."""
        try:
            cursor = self.conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM ip_reputation")
            total_ips = cursor.fetchone()[0]
            
            cursor.execute("""
                SELECT threat_level, COUNT(*) FROM ip_reputation 
                GROUP BY threat_level
            """)
            threat_breakdown = dict(cursor.fetchall())
            
            return {
                "total_ips": total_ips,
                "threat_breakdown": threat_breakdown,
            }
        except Exception as e:
            logger.error(f"Failed to get database stats: {e}")
            return {}

    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()


class ThreatFeedLoader:
    """Loads threat feeds from multiple local formats."""

    def __init__(self, db: ThreatIntelligenceDB):
        """
        Initialize feed loader.
        
        Args:
            db: ThreatIntelligenceDB instance
        """
        self.db = db

    def load_text_blocklist(self, file_path: str, threat_level: str = "HIGH",
                           threat_type: str = "malware", source: str = "unknown") -> int:
        """
        Load simple text blocklist (one IP per line).
        
        Args:
            file_path: Path to text file
            threat_level: Threat level to assign
            threat_type: Threat type description
            source: Feed source name
            
        Returns:
            Number of IPs loaded
        """
        count = 0
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    ip = line.strip()
                    
                    # Skip comments and empty lines
                    if not ip or ip.startswith('#'):
                        continue
                    
                    # Validate IP
                    if self._is_valid_ip(ip):
                        score = 75 if threat_level == "HIGH" else 90 if threat_level == "CRITICAL" else 50
                        self.db.add_ip(ip, score, threat_level, threat_type, source)
                        count += 1
                    else:
                        logger.debug(f"Invalid IP at line {line_num}: {ip}")
            
            logger.info(f"Loaded {count} IPs from {file_path}")
        except Exception as e:
            logger.error(f"Failed to load text blocklist {file_path}: {e}")
        
        return count

    def load_json_feed(self, file_path: str, source: str = "unknown") -> int:
        """
        Load JSON threat feed.
        Expected format: [{"ip": "...", "threat_level": "...", "threat_types": "...", ...}, ...]
        
        Args:
            file_path: Path to JSON file
            source: Feed source name
            
        Returns:
            Number of IPs loaded
        """
        count = 0
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if not isinstance(data, list):
                data = [data]
            
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                
                ip = entry.get("ip") or entry.get("address") or entry.get("host")
                if not ip or not self._is_valid_ip(ip):
                    continue
                
                threat_level = entry.get("threat_level", "MEDIUM").upper()
                threat_types = entry.get("threat_types") or entry.get("type", "unknown")
                reputation_score = entry.get("reputation_score", 50)
                
                self.db.add_ip(ip, reputation_score, threat_level, 
                              str(threat_types), source)
                count += 1
            
            logger.info(f"Loaded {count} IPs from JSON feed {file_path}")
        except Exception as e:
            logger.error(f"Failed to load JSON feed {file_path}: {e}")
        
        return count

    def load_csv_feed(self, file_path: str, ip_column: int = 0,
                     threat_level_column: Optional[int] = None,
                     source: str = "unknown") -> int:
        """
        Load CSV threat feed.
        
        Args:
            file_path: Path to CSV file
            ip_column: Column index containing IP addresses
            threat_level_column: Optional column index containing threat level
            source: Feed source name
            
        Returns:
            Number of IPs loaded
        """
        count = 0
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                next(reader, None)  # Skip header
                
                for row in reader:
                    if len(row) <= ip_column:
                        continue
                    
                    ip = row[ip_column].strip()
                    if not self._is_valid_ip(ip):
                        continue
                    
                    threat_level = "MEDIUM"
                    if threat_level_column is not None and len(row) > threat_level_column:
                        threat_level = row[threat_level_column].strip().upper()
                    
                    self.db.add_ip(ip, 70, threat_level, "csv_entry", source)
                    count += 1
            
            logger.info(f"Loaded {count} IPs from CSV feed {file_path}")
        except Exception as e:
            logger.error(f"Failed to load CSV feed {file_path}: {e}")
        
        return count

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Quick IP validation."""
        # IPv4 check
        parts = ip.split(".")
        if len(parts) == 4:
            try:
                return all(0 <= int(p) <= 255 for p in parts)
            except ValueError:
                pass
        
        # IPv6 check (simple)
        if ":" in ip:
            return True
        
        return False


class ThreatIntelligence:
    """High-level threat intelligence API."""

    def __init__(self, db_path: str = "data/threat_intelligence.db",
                 feeds_dir: str = "data/threat_feeds"):
        """
        Initialize threat intelligence engine.
        
        Args:
            db_path: Path to SQLite database
            feeds_dir: Directory containing threat feed files
        """
        self.db = ThreatIntelligenceDB(db_path)
        self.loader = ThreatFeedLoader(self.db)
        self.feeds_dir = feeds_dir
        self.loaded_feeds: Set[str] = set()

    def load_feeds(self):
        """Load all threat feeds from feeds directory."""
        if not os.path.exists(self.feeds_dir):
            logger.warning(f"Threat feeds directory does not exist: {self.feeds_dir}")
            return
        
        try:
            for file_path in Path(self.feeds_dir).iterdir():
                if not file_path.is_file():
                    continue
                
                file_name = file_path.name.lower()
                
                try:
                    if file_name.endswith(".txt"):
                        self.loader.load_text_blocklist(str(file_path), source=file_name)
                        self.loaded_feeds.add(file_name)
                    
                    elif file_name.endswith(".json"):
                        self.loader.load_json_feed(str(file_path), source=file_name)
                        self.loaded_feeds.add(file_name)
                    
                    elif file_name.endswith(".csv"):
                        self.loader.load_csv_feed(str(file_path), source=file_name)
                        self.loaded_feeds.add(file_name)
                
                except Exception as e:
                    logger.error(f"Failed to load feed {file_path}: {e}")
            
            logger.info(f"Loaded {len(self.loaded_feeds)} threat feeds")
        except Exception as e:
            logger.error(f"Error loading threat feeds: {e}")

    def is_malicious(self, ip: str) -> Tuple[bool, Optional[Dict]]:
        """
        Check if IP is in threat database.
        
        Args:
            ip: IP address to check
            
        Returns:
            Tuple of (is_malicious, reputation_dict)
        """
        reputation = self.db.lookup_ip(ip)
        if reputation:
            is_malicious = reputation["threat_level"] in ("HIGH", "CRITICAL")
            return is_malicious, reputation
        return False, None

    def get_reputation_score(self, ip: str) -> int:
        """
        Get IP reputation score (0-100, higher = more malicious).
        
        Args:
            ip: IP address
            
        Returns:
            Reputation score or 0 if not found
        """
        reputation = self.db.lookup_ip(ip)
        return reputation["reputation_score"] if reputation else 0

    def get_stats(self) -> Dict:
        """Get threat database statistics."""
        return self.db.get_stats()

    def close(self):
        """Close database connection."""
        self.db.close()
