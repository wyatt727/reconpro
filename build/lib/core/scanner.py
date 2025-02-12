# reconpro/core/scanner.py
import asyncio
import subprocess
import logging
from urllib.parse import urlparse, parse_qs

async def enumerate_subdomains(domain):
    logging.info("Enumerating subdomains for %s", domain)
    cmd = f"subfinder -d {domain} -silent"
    proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE)
    stdout, _ = await proc.communicate()
    subdomains = set(stdout.decode().strip().splitlines())
    subdomains.add(domain)
    logging.info("Found %d subdomains", len(subdomains))
    return subdomains

async def collect_urls(domains):
    urls = set()
    tasks = [collect_urls_for_domain(domain) for domain in domains]
    results = await asyncio.gather(*tasks)
    for res in results:
        urls.update(res)
    logging.info("Collected %d URLs", len(urls))
    return urls

async def collect_urls_for_domain(domain):
    commands = [f"gau {domain}", f"echo {domain} | waybackurls"]
    domain_urls = set()
    for cmd in commands:
        proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE)
        stdout, _ = await proc.communicate()
        domain_urls.update(stdout.decode().strip().splitlines())
    return domain_urls

def extract_parameterized_urls(urls):
    param_urls = []
    for url in urls:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if qs:
            param_urls.append((url, list(qs.keys())))
    return param_urls
