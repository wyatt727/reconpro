#!/usr/bin/env python3
# reconpro/main.py
import asyncio
import argparse
import logging
from datetime import datetime
import aiohttp
import shutil
import subprocess
import sys
from config import SCAN_INTERVAL, TIMEOUT
from core import scanner, scraper, detector, fuzz, external, updater, db
from utils import file_helpers

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

async def run_payload_tests(session, fuzz_func, url, param, payloads):
    # Create tasks for testing each payload concurrently.
    tasks = [asyncio.create_task(fuzz_func(session, url, param, payload)) for payload in payloads]
    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()  # Cancel remaining tasks once one completes
    for task in done:
        result = task.result()
        if result:
            return result
    return None

def check_install_external_tools():
    tools = ["waybackurls", "gau", "subfinder", "uvicorn"]
    for tool in tools:
        if not shutil.which(tool):
            logging.info(f"{tool} not found; attempting to install {tool}.")
            if sys.platform == "darwin":
                if tool == "waybackurls":
                    # Check if Go is installed
                    if not shutil.which("go"):
                        logging.error("Go is not installed. Please install Go to automatically install waybackurls.")
                        continue
                    install_cmd = ["go", "install", "github.com/tomnomnom/waybackurls@latest"]
                else:
                    install_cmd = ["brew", "install", tool]
            elif sys.platform.startswith("linux"):
                install_cmd = ["sudo", "apt-get", "install", "-y", tool]
            else:
                logging.error(f"Automatic installation for {tool} is not supported on this platform.")
                continue
            
            try:
                subprocess.run(install_cmd, check=True)
                logging.info(f"Successfully installed {tool}.")
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to install {tool}: {e}")
        else:
            logging.info(f"{tool} is already installed.")
            
        # Additional check for uvicorn installation
        if tool == "uvicorn" and not shutil.which("uvicorn"):
            logging.info("uvicorn not found; attempting to install uvicorn.")
            install_cmd = [sys.executable, "-m", "pip", "install", "uvicorn"]
            try:
                subprocess.run(install_cmd, check=True)
                logging.info("Successfully installed uvicorn.")
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to install uvicorn: {e}")
            logging.info(f"{tool} is already installed.")

async def run_scan_cycle(domain):
    logging.info("=== Starting new scan cycle for %s ===", domain)
    updater.update_resources()
    subdomains = await scanner.enumerate_subdomains(domain)
    urls = await scanner.collect_urls(subdomains)
    scraped_urls = await scraper.scrape_urls(list(urls), depth=1)
    all_urls = urls.union(scraped_urls)
    param_urls = scanner.extract_parameterized_urls(all_urls)
    payloads = fuzz.load_payloads()
    vulnerabilities = []
    # Create one shared session for all HTTP requests in this scan cycle.
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=TIMEOUT)) as session:
        for url, params in param_urls:
            for param in params:
                # First try GET fuzzing using the shared session.
                record = await run_payload_tests(session, fuzz.fuzz_get_param, url, param, payloads)
                if record:
                    vulnerabilities.append(record)
                else:
                    # If no GET vulnerability found, check if endpoint returns 405
                    # using the updated send_get_request that accepts a session.
                    get_response = await fuzz.send_get_request(session, url, param)
                    if detector.is_method_not_allowed(get_response):
                        record = await run_payload_tests(session, fuzz.fuzz_post_param, url, param, payloads)
                        if record:
                            vulnerabilities.append(record)
    conn = db.init_db()
    for v in vulnerabilities:
        db.insert_vulnerability(
            conn,
            v["url"],
            v["parameter"],
            v["payload"],
            v["method"],
            v["similarity"],
            v.get("gf_matches", ""),
            v["nuclei_output"],
        )
    db.close_db(conn)
    file_helpers.generate_report(domain)
    logging.info("=== Scan cycle complete at %s ===", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))

async def main_loop(domain, interval):
    while True:
        await run_scan_cycle(domain)
        logging.info("Sleeping for %d seconds before next cycle...", interval)
        await asyncio.sleep(interval)

def main():
    parser = argparse.ArgumentParser(description="ReconPro Full-Fledged Recon & Fuzzing Project")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("--interval", type=int, default=SCAN_INTERVAL, help="Scan interval in seconds")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose debugging output")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose debugging enabled")

    # Check and install external tools if needed
    check_install_external_tools()

    try:
        asyncio.run(main_loop(args.domain, args.interval))
    except KeyboardInterrupt:
        logging.info("Exiting ReconPro...")

if __name__ == "__main__":
    main()
