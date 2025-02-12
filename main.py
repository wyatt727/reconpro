#!/usr/bin/env python3
# reconpro/main.py
import asyncio
import argparse
import logging
from datetime import datetime
from core import scanner, scraper, detector, fuzz, external, updater, db
from utils import file_helpers
from config import SCAN_INTERVAL

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

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
    # For each parameterized URL, try every payload
    for url, params in param_urls:
        for param in params:
            # First try GET fuzzing
            for payload in payloads:
                record = await fuzz.fuzz_get_param(url, param, payload)
                if record:
                    vulnerabilities.append(record)
                    break  # stop once a vulnerability is detected
            else:
                # If no GET vulnerability found, check if endpoint returns 405:
                get_response = await fuzz.send_get_request(url, param)
                if detector.is_method_not_allowed(get_response):
                    for payload in payloads:
                        record = await fuzz.fuzz_post_param(url, param, payload)
                        if record:
                            vulnerabilities.append(record)
                            break
    conn = db.init_db()
    for v in vulnerabilities:
        db.insert_vulnerability(conn, v["url"], v["parameter"], v["payload"], v["method"],
                                  v["similarity"], v["gf_matches"], v["nuclei_output"])
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
    args = parser.parse_args()
    try:
        asyncio.run(main_loop(args.domain, args.interval))
    except KeyboardInterrupt:
        logging.info("Exiting ReconPro...")

if __name__ == "__main__":
    main()
