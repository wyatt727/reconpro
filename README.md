# ReconPro

**ReconPro** is a comprehensive web security scanning and reconnaissance platform written in Python. Designed for ethical hacking and authorized penetration testing, ReconPro combines advanced scanning techniques with robust external integrations—including GF, nuclei, subfinder, gau, and waybackurls—to thoroughly assess web targets. With a modular architecture and an advanced web interface, it provides real-time control and monitoring of security assessments.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture and Design](#architecture-and-design)
- [Directory Structure](#directory-structure)
- [Module Breakdown](#module-breakdown)
  - [Core Modules](#core-modules)
  - [Utility Modules](#utility-modules)
  - [Web Interface](#web-interface)
  - [Configuration](#configuration)
- [Installation](#installation)
- [Usage](#usage)
- [Future Enhancements](#future-enhancements)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

ReconPro provides a comprehensive web security assessment platform with:
- Advanced scan management with prioritization and queuing capabilities
- Real-time web interface for controlling and monitoring scans
- Automatic resource updates (payloads, nuclei templates, GF patterns) from GitHub
- Intelligent subdomain enumeration and URL discovery
- Advanced fuzzing with smart payload selection
- Robust error handling and retry mechanisms
- Comprehensive reporting and real-time monitoring
- Integration with popular security tools

---

## Features

- **Advanced Scan Management:**  
  - Priority-based scan queue system
  - Concurrent scan execution with resource management
  - Pause/Resume/Stop functionality for active scans
  - Real-time progress monitoring
  
- **Modern Web Interface:**  
  - Real-time scan control and monitoring
  - Live vulnerability detection updates
  - Advanced configuration options
  - Dark mode support
  - Interactive data visualization
  - Export functionality for findings
  
- **Efficient Asynchronous Processing:**  
  - Shared aiohttp ClientSession for optimized HTTP requests
  - Advanced rate limiting and concurrency control
  - Circuit breaker pattern for failure handling
  - Smart retry mechanisms with exponential backoff
  
- **Intelligent Scanning:**  
  - Smart payload selection based on context
  - Adaptive scanning based on response analysis
  - Advanced parameter extraction and analysis
  - Comprehensive vulnerability detection
  
- **Robust Error Handling:**  
  - Circuit breaker pattern for external services
  - Advanced retry strategies with backoff
  - Comprehensive error logging and monitoring
  - Graceful failure handling
  
- **Advanced Reporting:**  
  - Real-time vulnerability tracking
  - Multiple export formats (HTML, CSV, JSON)
  - Detailed scan statistics and metrics
  - Advanced filtering and search capabilities

---

## Architecture and Design

ReconPro's architecture emphasizes:
- **Modularity:** Clear separation of concerns with independent modules
- **Scalability:** Efficient resource management and concurrent processing
- **Reliability:** Comprehensive error handling and recovery mechanisms
- **Usability:** Intuitive web interface with real-time control and monitoring
- **Performance:** Optimized async operations and smart resource utilization

Key components:
- **Scan Manager:** Coordinates scan execution with priority queue
- **Web Interface:** FastAPI-based dashboard for control and monitoring
- **Core Modules:** Handle scanning, fuzzing, and vulnerability detection
- **External Integration:** Seamless integration with security tools
- **Database:** Efficient storage and retrieval of findings

---

## Directory Structure
```
reconpro/  
├── __init__.py  
├── main.py  
├── config.py  
├── core/  
│   ├── __init__.py  
│   ├── scanner.py  
│   ├── scraper.py  
│   ├── detector.py  
│   ├── fuzz.py  
│   ├── external.py  
│   ├── retry.py  
│   ├── updater.py  
│   └── db.py  
├── utils/  
│   ├── __init__.py  
│   └── file_helpers.py  
├── static/  
│   ├── css/  
│   ├── js/  
│   └── img/  
├── templates/  
├── data/  
├── tests/  
├── webui.py  
├── requirements.txt  
└── setup.py
```

---

## Module Breakdown

### Core Modules
- **scanner.py:**  
  Advanced scanning with improved async handling and rate limiting

- **fuzz.py:**  
  Smart fuzzing with context-aware payload selection and response analysis

- **retry.py:**  
  Robust retry handling with circuit breaker pattern

- **db.py:**  
  Async database operations with improved organization

- **external.py:**  
  Enhanced external tool execution and output management

### Web Interface
- **webui.py:**  
  FastAPI-based dashboard with real-time updates and scan control

- **static/js/scan-manager.js:**  
  Advanced frontend scan management and monitoring

### Configuration
- **config.py:**  
  Centralized configuration with enhanced customization options

---

## Installation

1. **Clone the repository:**
   ```sh
   git clone https://github.com/wyatt727/reconpro.git
   cd reconpro
   ```

2. **Install dependencies:**
   ```sh
   pip install -r requirements.txt
   ```

3. **Optional: Install in editable mode:**
   ```sh
   pip install -e .
   ```

---

## Usage

Start the ReconPro web interface:
```sh
python reconpro/main.py
```

Access the dashboard at `http://localhost:8000` to:
- Configure and launch new scans
- Monitor active scans in real-time
- View and export findings
- Manage scan queue and priorities

Command-line options:
- **--port:** Web interface port (default: 8000)
- **--host:** Web interface host (default: localhost)
- **--config:** Path to custom configuration file

---

## Future Enhancements

- **Enhanced Scan Management:**
  - Distributed scanning capabilities
  - Advanced scheduling options
  - Custom scan templates
  
- **Improved Reporting:**
  - Custom report templates
  - Advanced data visualization
  - Integration with security platforms
  
- **Extended Functionality:**
  - Additional security tool integrations
  - Custom payload generators
  - Machine learning-based analysis

---

## Contributing

Contributions are welcome! Please follow these guidelines:
1. Fork the repository
2. Create a feature branch
3. Commit your changes with clear messages
4. Open a pull request with details

For major changes, please open an issue first.

---

## License

This project is provided for educational and authorized penetration testing purposes only.  
(Include your license information here)
