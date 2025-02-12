Below is the updated README.md file in its entirety. Note that the new version now highlights the use of a shared aiohttp session for improved asynchronous HTTP requests in the fuzzing process, along with other minor wording updates.

# ReconPro

**ReconPro** is a comprehensive reconnaissance and fuzzing platform written in Python. Designed for ethical hacking and authorized penetration testing, ReconPro combines advanced scanning techniques with robust external integrations—including GF, nuclei, subfinder, gau, and waybackurls—to thoroughly assess web targets. With a modular architecture, it is easy to maintain, update, and extend.

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

ReconPro continuously gathers and analyzes data by:
- Automatically updating necessary resources (payloads, nuclei templates, GF patterns) from GitHub.
- Enumerating subdomains and extracting URLs using tools like subfinder, gau, and waybackurls.
- Scraping both live and archived pages to discover hidden endpoints.
- Dynamically detecting API endpoints and handling "405 Method Not Allowed" responses by switching between GET and POST fuzzing.
- Fuzzing discovered parameters with comprehensive payloads.
- Integrating external scanning tools (GF and nuclei) for enhanced vulnerability analysis.
- Persistently storing vulnerability records in a SQLite database and generating detailed HTML, CSV, and JSON reports.
- Providing real-time scan progress and detailed monitoring via an integrated FastAPI web interface.

---

## Features

- **Modular Design:**  
  Components are partitioned into distinct modules for scanning, scraping, detection, fuzzing, external integration, resource updating, and database management.
  
- **Efficient Asynchronous HTTP Requests:**  
  ReconPro now uses a shared aiohttp ClientSession across modules, significantly reducing HTTP request overhead. Blocking calls (such as those for external tool integrations) are offloaded using asyncio.to_thread to ensure smooth, non-blocking execution.
  
- **Automatic Resource Updates:**  
  The updater module downloads and saves the latest payloads, nuclei templates, and GF patterns from GitHub.

- **Comprehensive Web Scraping:**  
  Extracts additional endpoints by traversing both live and archived pages.

- **Intelligent Fuzzing:**  
  Switches between GET and POST fuzzing based on response analysis (e.g., handling 405 errors and API-specific responses) to maximize vulnerability detection.

- **External Tool Integration:**  
  Seamlessly invokes GF and nuclei to enhance the scanning process with additional insights.

- **Web Interface:**  
  A FastAPI-based dashboard that not only displays vulnerability records but also offers real-time insights into scan progress and detailed reporting.

- **Real-time Detailed Monitoring:**  
  The dashboard provides dynamic updates on discovered subdomains, collected URLs, scanning progress, vulnerabilities identified, and generated reports.

- **Continuous Reporting:**  
  Detailed HTML (or CSV/JSON) reports are generated while findings are stored persistently in a SQLite database.

---

## Architecture and Design

ReconPro's architecture is based on a clear separation of concerns:
- **Core Modules:** Orchestrate scanning, scraping, detection, fuzzing, and external integrations. The main scanning loop in `main.py` coordinates these continuous tasks.
- **Utility Modules:** Provide essential support functions for file handling, report generation, and dependency checks.
- **Web Interface:** A FastAPI-based dashboard (`webui.py`) that not only displays stored vulnerability records but also updates users with real-time scanning progress.
- **Asynchronous Efficiency:** Utilizes a shared aiohttp ClientSession across modules to optimize HTTP requests and offloads blocking operations using asyncio techniques.
- **Configuration:** Centralizes settings in `config.py` for timeouts, directory paths, API endpoints, and scan intervals, making adjustments straightforward.

Notably, the fuzzing module now reuses a shared aiohttp session for all HTTP calls. This design improvement cuts down on session initialization overhead and leverages asynchronous features to improve performance.

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
│   ├── updater.py  
│   └── db.py  
├── utils/  
│   ├── __init__.py  
│   └── file_helpers.py  
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
  Enumerates subdomains, collects URLs using tools like subfinder, gau, and waybackurls, and extracts GET parameterized URLs for fuzzing.

- **scraper.py:**  
  Retrieves web pages asynchronously and uses scraping techniques to discover additional endpoints.

- **detector.py:**  
  Analyzes HTTP responses to identify API endpoints and determine appropriate fuzzing strategies.

- **fuzz.py:**  
  Performs both GET and POST fuzzing—using difflib to compare baseline and fuzzed responses—and calls external scanners for in-depth analysis. This module now accepts a shared aiohttp session for all HTTP requests, offering improved efficiency by offloading blocking operations.

- **external.py:**  
  Wraps calls to external tools (GF and nuclei) to incorporate their scanning results into the vulnerability assessment.

- **updater.py:**  
  Keeps payloads, nuclei templates, and GF patterns up to date by downloading them from GitHub.

- **db.py:**  
  Manages the SQLite database for storing and retrieving vulnerability records.

### Utility Modules
- **file_helpers.py:**  
  Contains helper functions for report generation (HTML, CSV, JSON) and other file operations.

### Web Interface
- **webui.py:**  
  Implements a FastAPI-based dashboard that displays vulnerability records, allows triggering of new scans, and serves generated reports.

### Configuration
- **config.py:**  
  Centralizes settings such as timeouts, scan intervals, concurrency levels, directory paths, and GitHub API endpoints.

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

To run the continuous scanning loop – which now automatically starts the FastAPI dashboard and opens your default browser for real-time monitoring – use:
```sh
   python reconpro/main.py -d http://testphp.vulnweb.com --interval 300
```
- **-d, --domain:** Specifies the target domain (e.g., example.com).  
- **--interval:** Sets the delay (in seconds) between scan cycles (default is defined in config.py).

The system automatically launches the web UI, opens your browser to display the dashboard, and continuously updates scan progress in real time.

---

## Future Enhancements

- **Enhanced Error Handling:**  
  Improved retry mechanisms and error management for network requests and interactions with external tools.

- **Advanced Web Dashboard:**  
  Additional features for real-time monitoring and control via the FastAPI web interface.

- **Extended Testing Suite:**  
  More comprehensive unit and integration tests to boost reliability.

- **Dynamic Configuration:**  
  Support for external configuration files (YAML/JSON) to offer more granular control over scan parameters.

- **Multi-Target Scanning:**  
  Capability to scan multiple domains concurrently.

---

## Contributing

Contributions are welcome! Please follow these guidelines:
- Fork the repository.
- Create a feature branch.
- Commit your changes with clear, descriptive messages.
- Open a pull request detailing your modifications.

For major changes, please open an issue first to discuss your proposed changes.

---

## License

This project is provided for educational and authorized penetration testing purposes only.  
(Include your license information here, e.g., MIT License.)
