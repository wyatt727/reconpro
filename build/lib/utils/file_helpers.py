# reconpro/utils/file_helpers.py
import os
import json
import csv
import logging
from datetime import datetime

REPORT_DIR = "reports"
if not os.path.exists(REPORT_DIR):
    os.makedirs(REPORT_DIR)

def save_scan_result(url, gf_results, nuclei_results):
    result = {
        "url": url,
        "gf_results": gf_results,
        "nuclei_results": nuclei_results,
        "timestamp": datetime.utcnow().isoformat()
    }
    file_path = os.path.join(REPORT_DIR, "scan_results.json")
    try:
        data = []
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        data.append(result)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        logging.info("Saved scan result for %s", url)
    except Exception as e:
        logging.error("Error saving scan result for %s: %s", url, e)

def generate_report(domain):
    file_path = os.path.join(REPORT_DIR, f"{domain}_report.html")
    try:
        json_path = os.path.join(REPORT_DIR, "scan_results.json")
        if not os.path.exists(json_path):
            logging.warning("No scan results found to generate report.")
            return
        with open(json_path, "r", encoding="utf-8") as f:
            results = json.load(f)
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>ReconPro Report for {domain}</title>
    <style>
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <h1>ReconPro Report for {domain}</h1>
    <table>
        <tr>
            <th>URL</th>
            <th>GF Results</th>
            <th>Nuclei Results</th>
            <th>Timestamp</th>
        </tr>
"""
        for item in results:
            html += f"""
        <tr>
            <td>{item.get('url')}</td>
            <td>{item.get('gf_results')}</td>
            <td>{item.get('nuclei_results')}</td>
            <td>{item.get('timestamp')}</td>
        </tr>
"""
        html += """
    </table>
</body>
</html>
"""
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html)
        logging.info("Generated report at %s", file_path)
    except Exception as e:
        logging.error("Error generating report: %s", e)
