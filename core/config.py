"""
Configuration manager for ReconPro with advanced features and validation.
"""
import os
import json
import logging
import aiohttp
import ssl
import certifi
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
from pathlib import Path

# Directory Configuration
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
PAYLOADS_DIR = DATA_DIR / "payloads"
NUCLEI_TEMPLATES_DIR = DATA_DIR / "nuclei-templates"
GF_PATTERNS_DIR = DATA_DIR / "gf-patterns"

# Create directories if they don't exist
for directory in [DATA_DIR, PAYLOADS_DIR, NUCLEI_TEMPLATES_DIR, GF_PATTERNS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

@dataclass
class ScanConfig:
    """Scan configuration settings"""
    max_concurrent_requests: int = 50
    request_timeout: int = 30
    max_retries: int = 3
    retry_delay: int = 1
    similarity_threshold: float = 0.8
    follow_redirects: bool = True
    verify_ssl: bool = True
    user_agent: str = "ReconPro Scanner/1.0"
    max_redirects: int = 10
    connection_timeout: int = 10
    total_timeout: int = 300
    dns_cache_ttl: int = 10
    max_connections_per_host: int = 0  # 0 means no limit

@dataclass
class ProxyConfig:
    """Proxy configuration settings"""
    enabled: bool = False
    http: Optional[str] = None
    https: Optional[str] = None
    socks5: Optional[str] = None
    no_proxy: List[str] = None
    auth: Optional[Dict[str, str]] = None

    def __post_init__(self):
        if self.no_proxy is None:
            self.no_proxy = []
        if self.auth is None:
            self.auth = {}

@dataclass
class OutputConfig:
    """Output configuration settings"""
    log_level: str = "INFO"
    output_dir: str = "reports"
    save_raw_responses: bool = False
    report_format: str = "html"
    notify_on_finding: bool = True

@dataclass
class ToolConfig:
    """External tool configuration"""
    nuclei_templates: List[str] = None
    nuclei_severity: List[str] = None
    gf_patterns: List[str] = None
    custom_wordlists: List[str] = None

    def __post_init__(self):
        if self.nuclei_templates is None:
            self.nuclei_templates = ["cves", "vulnerabilities"]
        if self.nuclei_severity is None:
            self.nuclei_severity = ["critical", "high", "medium"]
        if self.gf_patterns is None:
            self.gf_patterns = ["debug-pages", "takeovers", "php-errors"]
        if self.custom_wordlists is None:
            self.custom_wordlists = []

class Config:
    """Main configuration class with validation and persistence"""
    def __init__(self, config_file: str = None):
        self.config_file = config_file or os.path.join(os.path.dirname(__file__), "config.json")
        self.scan = ScanConfig()
        self.proxy = ProxyConfig()
        self.output = OutputConfig()
        self.tools = ToolConfig()
        self._load_config()

    def _load_config(self):
        """Load configuration from file with validation"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                
                # Update configurations with validation
                if 'scan' in data:
                    self.scan = ScanConfig(**data['scan'])
                if 'proxy' in data:
                    self.proxy = ProxyConfig(**data['proxy'])
                if 'output' in data:
                    self.output = OutputConfig(**data['output'])
                if 'tools' in data:
                    self.tools = ToolConfig(**data['tools'])
                
                self._validate_config()
                logging.info("Configuration loaded successfully from %s", self.config_file)
            except Exception as e:
                logging.error("Error loading configuration: %s", e)
                logging.warning("Using default configuration")

    def _validate_config(self):
        """Validate configuration values"""
        # Validate scan config
        if self.scan.max_concurrent_requests < 1:
            raise ValueError("max_concurrent_requests must be greater than 0")
        if self.scan.similarity_threshold < 0 or self.scan.similarity_threshold > 1:
            raise ValueError("similarity_threshold must be between 0 and 1")

        # Validate proxy config
        if self.proxy.enabled:
            if not any([self.proxy.http, self.proxy.https, self.proxy.socks5]):
                raise ValueError("At least one proxy must be configured when proxy is enabled")

        # Validate output config
        if self.output.log_level not in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            raise ValueError("Invalid log level")
        if not os.path.exists(self.output.output_dir):
            os.makedirs(self.output.output_dir)

        # Validate tool config
        for template in self.tools.nuclei_templates:
            if not isinstance(template, str):
                raise ValueError("Nuclei templates must be strings")
        for pattern in self.tools.gf_patterns:
            if not isinstance(pattern, str):
                raise ValueError("GF patterns must be strings")

    def save(self):
        """Save current configuration to file"""
        config_data = {
            'scan': asdict(self.scan),
            'proxy': asdict(self.proxy),
            'output': asdict(self.output),
            'tools': asdict(self.tools)
        }
        
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config_data, f, indent=4)
            logging.info("Configuration saved successfully to %s", self.config_file)
        except Exception as e:
            logging.error("Error saving configuration: %s", e)

    def get_aiohttp_settings(self) -> Dict[str, Any]:
        """Get settings formatted for aiohttp client"""
        # Create SSL context
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        if not self.scan.verify_ssl:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        # Configure TCP connector
        connector = aiohttp.TCPConnector(
            ssl=ssl_context,
            limit=self.scan.max_concurrent_requests,
            ttl_dns_cache=self.scan.dns_cache_ttl,
            limit_per_host=self.scan.max_connections_per_host,
            force_close=True
        )

        # Configure timeout
        timeout = aiohttp.ClientTimeout(
            total=self.scan.total_timeout,
            connect=self.scan.connection_timeout,
            sock_connect=self.scan.connection_timeout,
            sock_read=self.scan.request_timeout
        )

        # Configure proxy settings
        proxy = None
        proxy_auth = None
        if self.proxy.enabled:
            proxy = self.proxy.http or self.proxy.https
            if self.proxy.auth:
                proxy_auth = aiohttp.BasicAuth(
                    login=self.proxy.auth.get('username', ''),
                    password=self.proxy.auth.get('password', '')
                )

        return {
            'timeout': timeout,
            'connector': connector,
            'headers': {
                'User-Agent': self.scan.user_agent
            },
            'proxy': proxy,
            'proxy_auth': proxy_auth,
            'raise_for_status': True,
            'trust_env': True  # Allow environment variables to configure proxy
        }

    def get_nuclei_command(self, target: str) -> List[str]:
        """Get formatted nuclei command with current configuration"""
        cmd = ["nuclei", "-target", target]
        for template in self.tools.nuclei_templates:
            cmd.extend(["-t", template])
        for severity in self.tools.nuclei_severity:
            cmd.extend(["-severity", severity])
        if self.proxy.enabled and self.proxy.http:
            cmd.extend(["-proxy", self.proxy.http])
        return cmd

    def get_logging_config(self) -> Dict[str, Any]:
        """Get logging configuration dictionary"""
        return {
            'level': getattr(logging, self.output.log_level),
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            'handlers': [
                logging.FileHandler(os.path.join(self.output.output_dir, 'reconpro.log')),
                logging.StreamHandler()
            ]
        }

# Global configuration instance
config = Config() 