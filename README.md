# ReconPro

**ReconPro** is a comprehensive web security scanning and reconnaissance platform written in Python. It combines advanced scanning techniques with robust external tool integrations to provide a powerful, automated security assessment solution.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Core Components](#core-components)
- [External Tool Integration](#external-tool-integration)
- [Web Interface](#web-interface)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## Overview

ReconPro is designed to automate and streamline the web security assessment process by:
- Coordinating multiple security tools and techniques
- Providing real-time scan monitoring and control
- Offering comprehensive vulnerability detection
- Generating detailed reports and analytics
- Supporting customizable scanning workflows

## Features

### Scanning Capabilities
- **Subdomain Enumeration:**
  - Multiple tools integration (subfinder, assetfinder, amass, chaos, sublist3r)
  - Passive and active enumeration techniques
  - Automatic validation of discovered subdomains
  - DNS resolution and HTTP(S) probing

- **URL Discovery:**
  - Wayback machine integration
  - Multiple source aggregation (gau, waybackurls, gospider)
  - Pattern-based filtering
  - Duplicate removal and validation

- **Parameter Analysis:**
  - Automated parameter extraction
  - Smart payload selection
  - Context-aware fuzzing
  - Response analysis and anomaly detection

- **Vulnerability Detection:**
  - Integration with nuclei templates
  - Custom vulnerability patterns
  - Multiple security tools (sqlmap, nikto, dalfox, etc.)
  - Advanced JWT token analysis

- **Technology Detection:**
  - Web technology fingerprinting
  - Service version detection
  - Framework identification
  - Security header analysis

### Advanced Features
- **Real-time Monitoring:**
  - WebSocket-based updates
  - Progress tracking
  - Live vulnerability notifications
  - Interactive data visualization

- **Scan Management:**
  - Priority-based queue system
  - Concurrent scan execution
  - Resource management
  - Pause/Resume functionality

- **Error Handling:**
  - Circuit breaker pattern
  - Automatic retries
  - Rate limiting
  - Comprehensive logging

- **Reporting:**
  - Multiple export formats (PDF, CSV, JSON)
  - Customizable report templates
  - Detailed analytics
  - Historical data tracking

## Architecture

### Core Components

#### Scanner Module (`core/scanner.py`)
The central scanning engine that coordinates all security assessment activities:
- **ScanPhase Class:** Defines distinct scanning phases:
  - Initialization
  - Wayback Collection
  - Parameter Discovery
  - Subdomain Enumeration
  - Content Discovery
  - Parameter Fuzzing
  - Vulnerability Scanning
  - Technology Detection
  - Port Scanning
  - API Discovery
  - Report Generation

- **Scanner Class:**
  - Manages the scanning lifecycle
  - Coordinates tool execution
  - Handles results aggregation
  - Implements phase transitions
  - Provides progress updates

#### Fuzzing Engine (`core/fuzz.py`)
Advanced fuzzing capabilities with:
- **Smart Payload Selection:**
  - Context-aware payload choice
  - Parameter name analysis
  - Response-based adaptation
  - Custom payload support

- **Analysis Features:**
  - Response similarity comparison
  - Error pattern detection
  - Reflection analysis
  - Time-based detection

#### Database Management (`core/db.py`)
Efficient data storage and retrieval:
- **Async SQLite Interface:**
  - Connection pooling
  - Transaction management
  - Result caching
  - Migration support

- **Data Models:**
  - Scan results
  - Vulnerability findings
  - Historical data
  - Analytics metrics

#### External Tool Integration (`core/external.py`)
Robust external tool management:
- **Tool Executor:**
  - Process management
  - Output parsing
  - Error handling
  - Resource cleanup

- **Circuit Breaker:**
  - Failure detection
  - Automatic recovery
  - State management
  - Threshold configuration

#### Retry Handler (`core/retry.py`)
Sophisticated retry mechanisms:
- **Multiple Backoff Strategies:**
  - Exponential
  - Linear
  - Fibonacci

- **Advanced Features:**
  - Jitter implementation
  - Timeout handling
  - Status code based retries
  - Exception filtering

### Web Interface

#### Dashboard (`templates/base.html`, `static/js/app.js`)
Modern web interface with:
- **Real-time Updates:**
  - WebSocket communication
  - Live progress indicators
  - Dynamic content updates
  - Status notifications

- **Interactive Controls:**
  - Scan configuration
  - Tool selection
  - Priority management
  - Result filtering

#### Analytics (`templates/charts.html`, `static/js/charts.js`)
Comprehensive data visualization:
- **Multiple Chart Types:**
  - Vulnerability trends
  - Severity distribution
  - Technology breakdown
  - Response time analysis

- **Interactive Features:**
  - Date range selection
  - Data filtering
  - Export capabilities
  - Custom views

#### Activity Monitoring (`static/js/activity-log.js`)
Detailed activity tracking:
- **Event Logging:**
  - Scan events
  - Tool execution
  - Error reporting
  - Status changes

- **Filtering Capabilities:**
  - Severity-based
  - Time-based
  - Type-based
  - Custom filters

## Installation

1. **System Requirements:**
   ```sh
   # For Debian/Ubuntu
   sudo apt-get update
   sudo apt-get install -y python3 python3-pip golang git nmap

   # For macOS
   brew install python go nmap
   ```

2. **Clone and Install:**
   ```sh
   git clone https://github.com/yourusername/reconpro.git
   cd reconpro
   pip install -r requirements.txt
   pip install -e .
   ```

3. **External Tools:**
   The installation process automatically installs required Go tools:
   - nuclei
   - subfinder
   - httpx
   - katana
   - gf
   - assetfinder
   - waybackurls
   - hakrawler
   - and more...

## Configuration

### Main Configuration (`config.json`)
```json
{
    "scan": {
        "max_concurrent_requests": 50,
        "request_timeout": 30,
        "max_retries": 3,
        "similarity_threshold": 0.8
    },
    "proxy": {
        "enabled": false,
        "http": null,
        "https": null
    },
    "output": {
        "log_level": "INFO",
        "output_dir": "reports"
    }
}
```

### Tool Configuration
Each external tool can be configured in the `tools` section:
```json
{
    "tools": {
        "nuclei_templates": ["cves", "vulnerabilities"],
        "nuclei_severity": ["critical", "high", "medium"],
        "gf_patterns": ["debug-pages", "takeovers", "php-errors"]
    }
}
```

## Development

### Project Structure
```
reconpro/
├── core/               # Core functionality
│   ├── scanner.py     # Main scanning engine
│   ├── fuzz.py        # Fuzzing engine
│   ├── db.py          # Database operations
│   ├── external.py    # External tool integration
│   └── retry.py       # Retry handling
├── static/            # Web assets
│   ├── js/           # JavaScript files
│   └── css/          # CSS styles
├── templates/         # HTML templates
├── data/             # Resource files
└── tests/            # Test suite
```

### Adding New Features
1. **New Scanning Capability:**
   - Add phase to `ScanPhase` class
   - Implement scanning logic
   - Update progress tracking
   - Add result handling

2. **New Tool Integration:**
   - Add tool to `setup.py`
   - Implement wrapper in `external.py`
   - Add configuration options
   - Update documentation

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement changes with tests
4. Submit pull request with:
   - Clear description
   - Test results
   - Documentation updates

## License

This project is licensed under the MIT License. See LICENSE file for details.
