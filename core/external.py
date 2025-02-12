# reconpro/core/external.py
import subprocess
import logging

def run_nuclei_scan(url):
    cmd = f"nuclei -u {url} -t data/nuclei_templates -silent"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        output = result.stdout.strip()
        logging.info("Nuclei scan output for %s: %s", url, output[:50])
        return output
    except Exception as e:
        logging.error("Error running nuclei scan on %s: %s", url, e)
        return ""

def run_gf_scan(url):
    cmd = f"curl -s {url} | gf"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        output = result.stdout.strip()
        logging.info("GF scan output for %s: %s", url, output[:50])
        return output
    except Exception as e:
        logging.error("Error running GF scan on %s: %s", url, e)
        return ""
