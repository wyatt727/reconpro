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
- Updating payloads, nuclei templates, and GF patterns from GitHub.
- Enumerating subdomains and collecting URLs using external tools.
- Scraping live and historical web pages to uncover hidden endpoints.
- Detecting API endpoints and "405 Method Not Allowed" responses to toggle between GET and POST fuzzing.
- Fuzzing discovered parameters with a wide array of payloads.
- Running external scans with GF and nuclei to further analyze potential vulnerabilities.
- Storing vulnerability records in a SQLite database and generating human-readable reports.

---

## Features

- **Modular Design:**  
  Components are partitioned into distinct modules for scanning, scraping, detection, fuzzing, external integration, resource updating, and database management.

- **Automatic Resource Updates:**  
  The updater module downloads and saves the latest payloads, nuclei templates, and GF patterns from GitHub.

- **Comprehensive Web Scraping:**  
  Extracts additional endpoints by traversing both live and archived pages.

- **Intelligent Fuzzing:**  
  Switches between GET and POST fuzzing based on response analysis (e.g., handling 405 errors and API-specific responses) to maximize vulnerability detection.

- **External Tool Integration:**  
  Seamlessly invokes GF and nuclei to enhance the scanning process with additional insights.

- **Web Interface:**  
  A FastAPI-based dashboard allows you to view vulnerability records, trigger scans, and access generated reports.

- **Continuous Reporting:**  
  Detailed HTML (or CSV/JSON) reports are generated while findings are stored persistently in a SQLite database.

---

## Architecture and Design

ReconPro's architecture is based on a clear separation of concerns:
- **Core Modules:** Handle scanning, scraping, detection, fuzzing, and integration with external tools.
- **Utility Modules:** Provide support functions for file handling and report generation.
- **Web Interface:** Offers a built-in dashboard via FastAPI for monitoring and managing scans.
- **Configuration:** Centralizes global settings (timeouts, paths, API endpoints, etc.), ensuring flexibility without modifying core logic.

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
  Performs both GET and POST fuzzing—using difflib to compare baseline and fuzzed responses—and calls external scanners for in-depth analysis.

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

To run the continuous scanning loop:

   python reconpro/main.py -d http://testphp.vulnweb.com --interval 300

- **-d, --domain:** Specifies the target domain (e.g., example.com).  
- **--interval:** Sets the delay (in seconds) between scan cycles (default is defined in config.py).

To launch the web interface:

   python webui.py

The tool will:
- Update necessary resources (payloads, nuclei templates, GF patterns).
- Enumerate subdomains and gather URLs.
- Scrape web content to find additional endpoints.
- Fuzz parameters using both GET and POST methods.
- Execute external scans with GF and nuclei.
- Store findings in a SQLite database.
- Generate a detailed HTML report (saved in the `reports/` directory) at the end of each scan cycle.

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
