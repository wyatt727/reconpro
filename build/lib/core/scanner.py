# reconpro/core/scanner.py
import asyncio
import aiohttp
import logging
import json
from typing import Set, List, Tuple, Dict, Any
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from .config import config
from .db import save_scan_result
from .retry import RetryHandler

class Scanner:
    """Advanced scanner class with rate limiting and concurrent execution"""
    def __init__(self):
        self.session = None
        self.semaphore = asyncio.Semaphore(config.scan.max_concurrent_requests)
        self.retry_handler = RetryHandler(
            max_retries=config.scan.max_retries,
            delay=config.scan.retry_delay
        )
        self.stats = {
            'start_time': None,
            'end_time': None,
            'subdomains_found': 0,
            'urls_collected': 0,
            'parameters_found': 0,
            'vulnerabilities_found': 0
        }

    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(**config.get_aiohttp_settings())
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()

    async def scan_domain(self, domain: str) -> Dict[str, Any]:
        """Main scanning function that coordinates the entire scan process"""
        self.stats['start_time'] = datetime.now()
        logging.info("Starting scan for domain: %s", domain)

        try:
            # Step 1: Enumerate subdomains
            subdomains = await self.enumerate_subdomains(domain)
            self.stats['subdomains_found'] = len(subdomains)
            logging.info("Found %d subdomains", len(subdomains))

            # Step 2: Collect URLs from all subdomains
            urls = await self.collect_urls(subdomains)
            self.stats['urls_collected'] = len(urls)
            logging.info("Collected %d unique URLs", len(urls))

            # Step 3: Extract and analyze parameters
            param_urls = self.extract_parameterized_urls(urls)
            self.stats['parameters_found'] = sum(len(params) for _, params in param_urls)
            logging.info("Found %d parameters to analyze", self.stats['parameters_found'])

            # Save scan metadata
            await self.save_scan_metadata(domain)

            return {
                'subdomains': list(subdomains),
                'urls': list(urls),
                'parameterized_urls': param_urls,
                'stats': self.stats
            }

        except Exception as e:
            logging.error("Error during scan: %s", e)
            raise
        finally:
            self.stats['end_time'] = datetime.now()

    async def enumerate_subdomains(self, domain: str) -> Set[str]:
        """Enhanced subdomain enumeration with multiple tools and validation"""
        async def run_tool(cmd: str) -> Set[str]:
            try:
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await proc.communicate()
                if stderr:
                    logging.warning("Tool warning: %s", stderr.decode())
                return set(stdout.decode().strip().splitlines())
            except Exception as e:
                logging.error("Tool error: %s", e)
                return set()

        # Run multiple enumeration tools concurrently
        tasks = [
            run_tool(f"subfinder -d {domain} -silent"),
            run_tool(f"amass enum -passive -d {domain}"),
            run_tool(f"assetfinder --subs-only {domain}")
        ]
        
        results = await asyncio.gather(*tasks)
        subdomains = set().union(*results)
        subdomains.add(domain)  # Add the root domain

        # Validate subdomains
        valid_subdomains = set()
        async def validate_subdomain(subdomain: str):
            try:
                async with self.semaphore:
                    async with self.session.head(f"https://{subdomain}", timeout=5) as response:
                        if response.status < 500:
                            valid_subdomains.add(subdomain)
            except Exception:
                try:
                    async with self.session.head(f"http://{subdomain}", timeout=5) as response:
                        if response.status < 500:
                            valid_subdomains.add(subdomain)
                except Exception:
                    pass

        validation_tasks = [validate_subdomain(subdomain) for subdomain in subdomains]
        await asyncio.gather(*validation_tasks)
        return valid_subdomains

    async def collect_urls(self, domains: Set[str]) -> Set[str]:
        """Improved URL collection with multiple sources and filtering"""
        all_urls = set()
        
        async def collect_from_source(domain: str, source: str):
            cmd = {
                'gau': f"gau {domain}",
                'wayback': f"waybackurls {domain}",
                'gospider': f"gospider -s http://{domain} -o /dev/stdout",
            }[source]
            
            try:
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL
                )
                stdout, _ = await proc.communicate()
                urls = set(url.strip() for url in stdout.decode().splitlines() if url.strip())
                
                # Filter and clean URLs
                for url in urls:
                    parsed = urlparse(url)
                    if parsed.scheme in ('http', 'https') and parsed.netloc:
                        all_urls.add(url)
                
            except Exception as e:
                logging.error("Error collecting URLs from %s using %s: %s", domain, source, e)

        # Collect from all sources for each domain concurrently
        tasks = []
        for domain in domains:
            for source in ['gau', 'wayback', 'gospider']:
                tasks.append(collect_from_source(domain, source))
        
        await asyncio.gather(*tasks)
        return all_urls

    def extract_parameterized_urls(self, urls: Set[str]) -> List[Tuple[str, List[str]]]:
        """Extract and analyze URL parameters with improved filtering"""
        param_urls = []
        seen_params = set()

        for url in urls:
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                
                if params:
                    # Filter out common non-vulnerable parameters
                    filtered_params = [
                        param for param in params.keys()
                        if param.lower() not in {'page', 'limit', 'offset', 'lang'}
                    ]
                    
                    if filtered_params:
                        # Create a unique key for this URL's parameter combination
                        param_key = f"{parsed.netloc}{parsed.path}:{','.join(sorted(filtered_params))}"
                        
                        if param_key not in seen_params:
                            seen_params.add(param_key)
                            param_urls.append((url, filtered_params))
            
            except Exception as e:
                logging.error("Error processing URL %s: %s", url, e)

        return param_urls

    async def save_scan_metadata(self, domain: str):
        """Save scan metadata to the database"""
        metadata = {
            'domain': domain,
            'start_time': self.stats['start_time'].isoformat(),
            'end_time': self.stats['end_time'].isoformat(),
            'subdomains_found': self.stats['subdomains_found'],
            'urls_collected': self.stats['urls_collected'],
            'parameters_found': self.stats['parameters_found'],
            'vulnerabilities_found': self.stats['vulnerabilities_found']
        }
        
        await save_scan_result('scan_metadata', json.dumps(metadata))

async def scan_target(domain: str) -> Dict[str, Any]:
    """Convenience function to run a scan"""
    async with Scanner() as scanner:
        return await scanner.scan_domain(domain)
