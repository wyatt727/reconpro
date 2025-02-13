# reconpro/core/scanner.py
import asyncio
import aiohttp
import logging
import json
import ssl
import socket
import os
import re
from typing import Set, List, Tuple, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from .config import config
from .db import save_scan_result
from .retry import RetryHandler, RetryConfig

logger = logging.getLogger(__name__)

class ScanError(Exception):
    """Base exception for scanner errors"""
    pass

class ConnectionError(ScanError):
    """Connection-related errors"""
    pass

class SSLError(ScanError):
    """SSL-related errors"""
    pass

class TimeoutError(ScanError):
    """Timeout-related errors"""
    pass

class ScanPhase:
    """Represents a phase in the scanning process"""
    INIT = "initialization"
    WAYBACK = "wayback_collection"
    PARAM_DISCOVERY = "parameter_discovery"
    SUBDOMAIN_ENUM = "subdomain_enumeration"
    CONTENT_DISCOVERY = "content_discovery"
    FUZZING = "parameter_fuzzing"
    VULNERABILITY_SCAN = "vulnerability_scan"
    TECH_DETECTION = "technology_detection"
    PORT_SCAN = "port_scanning"
    API_DISCOVERY = "api_discovery"
    REPORTING = "report_generation"

class ScanResult:
    """Container for scan results"""
    def __init__(self):
        self.wayback_urls: Set[str] = set()
        self.parameterized_urls: List[Tuple[str, List[str]]] = []
        self.subdomains: Set[str] = set()
        self.interesting_endpoints: List[Dict[str, Any]] = []
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.requests_history: List[Dict[str, Any]] = []
        self.phase_status: Dict[str, str] = {}
        self.technologies: List[Dict[str, Any]] = []
        self.open_ports: List[Dict[str, Any]] = []
        self.api_endpoints: List[Dict[str, Any]] = []
        self.start_time = datetime.utcnow()
        self.end_time: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert results to dictionary"""
        return {
            'wayback_urls': list(self.wayback_urls),
            'parameterized_urls': self.parameterized_urls,
            'subdomains': list(self.subdomains),
            'interesting_endpoints': self.interesting_endpoints,
            'vulnerabilities': self.vulnerabilities,
            'requests_history': self.requests_history,
            'phase_status': self.phase_status,
            'technologies': self.technologies,
            'open_ports': self.open_ports,
            'api_endpoints': self.api_endpoints,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None
        }

class Scanner:
    """Advanced scanner with phase-based scanning and result access"""
    def __init__(self):
        self.config = config
        self.results = ScanResult()
        self.session: Optional[aiohttp.ClientSession] = None
        self.is_running = False
        self.current_phase = ScanPhase.INIT
        self._phase_callbacks = {}

    async def __aenter__(self):
        """Initialize scanner resources"""
        self.session = aiohttp.ClientSession(**self.config.get_aiohttp_settings())
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Cleanup scanner resources"""
        if self.session:
            await self.session.close()

    def register_phase_callback(self, phase: str, callback):
        """Register a callback for phase updates"""
        self._phase_callbacks[phase] = callback

    async def _notify_phase_update(self, phase: str, status: str, data: Any = None):
        """Notify phase status change"""
        self.results.phase_status[phase] = status
        if phase in self._phase_callbacks:
            await self._phase_callbacks[phase](status, data)

    @RetryHandler(RetryConfig(max_retries=3, initial_delay=1.0))
    async def collect_wayback_urls(self, domain: str) -> Set[str]:
        """Collect URLs from Wayback Machine"""
        self.current_phase = ScanPhase.WAYBACK
        await self._notify_phase_update(ScanPhase.WAYBACK, "started")

        try:
            wayback_url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
            async with self.session.get(wayback_url) as response:
                data = await response.json()
                # Skip header row
                urls = {row[0] for row in data[1:]} if len(data) > 1 else set()
                self.results.wayback_urls.update(urls)
                
                await self._notify_phase_update(ScanPhase.WAYBACK, "completed", urls)
                return urls
        except Exception as e:
            await self._notify_phase_update(ScanPhase.WAYBACK, "error", str(e))
            raise

    async def extract_parameterized_urls(self) -> List[Tuple[str, List[str]]]:
        """Extract URLs with parameters from collected URLs"""
        self.current_phase = ScanPhase.PARAM_DISCOVERY
        await self._notify_phase_update(ScanPhase.PARAM_DISCOVERY, "started")

        try:
            param_urls = []
            for url in self.results.wayback_urls:
                parsed = urlparse(url)
                params = list(parse_qs(parsed.query).keys())
                if params:
                    param_urls.append((url, params))

            self.results.parameterized_urls = param_urls
            await self._notify_phase_update(ScanPhase.PARAM_DISCOVERY, "completed", param_urls)
            return param_urls
        except Exception as e:
            await self._notify_phase_update(ScanPhase.PARAM_DISCOVERY, "error", str(e))
            raise

    async def fuzz_parameter(self, url: str, parameter: str, custom_payloads: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Fuzz a parameter with optional custom payloads"""
        from .fuzz import Fuzzer  # Import here to avoid circular imports
        
        vulnerabilities = []
        try:
            async with Fuzzer() as fuzzer:
                # Record the original request for history
                baseline_request = {
                    'url': url,
                    'parameter': parameter,
                    'method': 'GET',
                    'timestamp': datetime.utcnow().isoformat()
                }
                self.results.requests_history.append(baseline_request)

                # Use custom payloads if provided, otherwise use default
                results = await fuzzer.fuzz_parameter(
                    url, 
                    parameter,
                    custom_payloads=custom_payloads
                )
                
                if results:
                    vulnerabilities.extend(results)
                    self.results.vulnerabilities.extend(results)
                    
                    # Record interesting responses
                    for result in results:
                        self.results.requests_history.append({
                            'url': url,
                            'parameter': parameter,
                            'payload': result.get('payload'),
                            'method': 'GET',
                            'response_code': result.get('status_code'),
                            'response_length': result.get('content_length'),
                            'timestamp': datetime.utcnow().isoformat()
                        })

        except Exception as e:
            logger.error(f"Error fuzzing parameter {parameter} in {url}: {e}")
            
        return vulnerabilities

    async def resend_request(self, request_id: int, custom_params: Dict[str, str]) -> Dict[str, Any]:
        """Resend a previous request with custom parameters"""
        try:
            original_request = self.results.requests_history[request_id]
            url = original_request['url']
            
            # Build new request with custom parameters
            parsed = urlparse(url)
            params = {**parse_qs(parsed.query), **custom_params}
            
            async with self.session.get(url, params=params) as response:
                result = {
                    'url': str(response.url),
                    'status_code': response.status,
                    'headers': dict(response.headers),
                    'content_length': int(response.headers.get('content-length', 0)),
                    'response_time': response.elapsed,
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                # Store in history
                self.results.requests_history.append({
                    **original_request,
                    'custom_params': custom_params,
                    'response': result,
                    'timestamp': result['timestamp']
                })
                
                return result
                
        except Exception as e:
            logger.error(f"Error resending request {request_id}: {e}")
            raise

    async def get_interesting_requests(self) -> List[Dict[str, Any]]:
        """Get requests that might be interesting for further testing"""
        return [
            req for req in self.results.requests_history
            if any([
                req.get('response_code', 0) in [200, 301, 302, 307],
                req.get('response_length', 0) > 0,
                'error' in (req.get('response', {}).get('body', '').lower()),
                'exception' in (req.get('response', {}).get('body', '').lower())
            ])
        ]

    def get_current_results(self) -> Dict[str, Any]:
        """Get current scan results"""
        return self.results.to_dict()

    def get_phase_status(self) -> Dict[str, str]:
        """Get status of all scanning phases"""
        return self.results.phase_status

    async def _make_request(self, url: str, method: str = "GET", **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Make HTTP request with comprehensive error handling"""
        try:
            async with self.session.request(method, url, **kwargs) as response:
                await response.read()  # Ensure connection is closed properly
                return response
        except (aiohttp.ClientSSLError, ssl.SSLError) as e:
            raise SSLError(f"SSL error for {url}: {e}")
        except (aiohttp.ClientConnectorError, socket.gaierror) as e:
            raise ConnectionError(f"Connection error for {url}: {e}")
        except asyncio.TimeoutError as e:
            raise TimeoutError(f"Timeout error for {url}: {e}")
        except Exception as e:
            raise ScanError(f"Request error for {url}: {e}")

    @RetryHandler(RetryConfig(max_retries=3, initial_delay=1.0))
    async def validate_domain(self, domain: str) -> bool:
        """Validate domain accessibility with error handling"""
        try:
            # Try HTTPS first
            try:
                response = await self._make_request(f"https://{domain}", method="HEAD", timeout=5)
                return response.status < 500
            except (SSLError, aiohttp.ClientSSLError):
                # Fall back to HTTP if SSL fails
                response = await self._make_request(f"http://{domain}", method="HEAD", timeout=5)
                return response.status < 500
        except Exception as e:
            logger.warning("Domain validation failed for %s: %s", domain, e)
            return False

    async def scan_domain(self, domain: str) -> Dict[str, Any]:
        """Main scanning function that coordinates the entire scan process"""
        self.results.start_time = datetime.now()
        logging.info("Starting scan for domain: %s", domain)

        try:
            # Phase 1: Enumerate subdomains
            self.current_phase = ScanPhase.SUBDOMAIN_ENUM
            await self._notify_phase_update(ScanPhase.SUBDOMAIN_ENUM, "started")
            subdomains = await self.enumerate_subdomains(domain)
            self.results.subdomains.update(subdomains)
            await self._notify_phase_update(ScanPhase.SUBDOMAIN_ENUM, "completed", len(subdomains))
            logging.info("Found %d subdomains", len(subdomains))

            # Phase 2: Port scanning
            self.current_phase = ScanPhase.PORT_SCAN
            await self._notify_phase_update(ScanPhase.PORT_SCAN, "started")
            for subdomain in subdomains:
                ports = await self._run_port_scan(subdomain)
                self.results.open_ports.extend(ports)
            await self._notify_phase_update(ScanPhase.PORT_SCAN, "completed", len(self.results.open_ports))
            
            # Phase 3: Technology detection
            self.current_phase = ScanPhase.TECH_DETECTION
            await self._notify_phase_update(ScanPhase.TECH_DETECTION, "started")
            for subdomain in subdomains:
                techs = await self._detect_technologies(subdomain)
                self.results.technologies.extend(techs)
            await self._notify_phase_update(ScanPhase.TECH_DETECTION, "completed", len(self.results.technologies))

            # Phase 4: Collect URLs
            self.current_phase = ScanPhase.WAYBACK
            await self._notify_phase_update(ScanPhase.WAYBACK, "started")
            urls = await self.collect_urls(subdomains)
            self.results.wayback_urls.update(urls)
            await self._notify_phase_update(ScanPhase.WAYBACK, "completed", len(urls))
            logging.info("Collected %d unique URLs", len(urls))

            # Phase 5: API Discovery
            self.current_phase = ScanPhase.API_DISCOVERY
            await self._notify_phase_update(ScanPhase.API_DISCOVERY, "started")
            api_endpoints = await self._discover_api_endpoints(urls)
            self.results.api_endpoints.extend(api_endpoints)
            await self._notify_phase_update(ScanPhase.API_DISCOVERY, "completed", len(api_endpoints))

            # Phase 6: Parameter Discovery
            self.current_phase = ScanPhase.PARAM_DISCOVERY
            await self._notify_phase_update(ScanPhase.PARAM_DISCOVERY, "started")
            param_urls = await self.extract_parameterized_urls()
            self.results.parameterized_urls = param_urls
            await self._notify_phase_update(ScanPhase.PARAM_DISCOVERY, "completed", len(param_urls))
            logging.info("Found %d parameters to analyze", len(param_urls))

            # Phase 7: Content Discovery
            self.current_phase = ScanPhase.CONTENT_DISCOVERY
            await self._notify_phase_update(ScanPhase.CONTENT_DISCOVERY, "started")
            await self._discover_content(subdomains)
            await self._notify_phase_update(ScanPhase.CONTENT_DISCOVERY, "completed")

            # Phase 8: Parameter Fuzzing
            self.current_phase = ScanPhase.FUZZING
            await self._notify_phase_update(ScanPhase.FUZZING, "started")
            total_params = sum(len(params) for _, params in param_urls)
            processed = 0

            for url, params in param_urls:
                for param in params:
                    try:
                        vulnerabilities = await self.fuzz_parameter(url, param)
                        if vulnerabilities:
                            for vuln in vulnerabilities:
                                await self._handle_vulnerability(vuln)
                        processed += 1
                        progress = (processed / total_params) * 100
                        await self._notify_phase_update(ScanPhase.FUZZING, "in_progress", progress)
                    except Exception as e:
                        logger.error(f"Error fuzzing {url} {param}: {e}")

            await self._notify_phase_update(ScanPhase.FUZZING, "completed")

            # Phase 9: Vulnerability Scanning
            self.current_phase = ScanPhase.VULNERABILITY_SCAN
            await self._notify_phase_update(ScanPhase.VULNERABILITY_SCAN, "started")
            await self._run_vulnerability_scan(subdomains)
            await self._notify_phase_update(ScanPhase.VULNERABILITY_SCAN, "completed")

            # Phase 10: Report Generation
            self.current_phase = ScanPhase.REPORTING
            await self._notify_phase_update(ScanPhase.REPORTING, "started")
            await self.save_scan_metadata(domain)
            await self._notify_phase_update(ScanPhase.REPORTING, "completed")

            return self.get_current_results()

        except Exception as e:
            logging.error("Error during scan: %s", e)
            raise
        finally:
            self.results.end_time = datetime.now()

    async def enumerate_subdomains(self, domain: str) -> Set[str]:
        """Enumerate subdomains using multiple tools"""
        self.current_phase = ScanPhase.SUBDOMAIN_ENUM
        await self._notify_phase_update(ScanPhase.SUBDOMAIN_ENUM, "started")
        
        subdomains = set()
        
        async def run_tool(cmd: str) -> Set[str]:
            try:
                result = await self.executor.run_tool(cmd.split())
                return {line.strip() for line in result['output'].splitlines() if line.strip()}
            except Exception as e:
                self.logger.warning(f"Tool warning: {str(e)}")
                return set()

        # Run tools concurrently
        tasks = [
            run_tool(f"subfinder -d {domain}"),
            run_tool(f"assetfinder --subs-only {domain}"),
            run_tool(f"amass enum -passive -d {domain}"),
            run_tool(f"chaos -d {domain}"),
            run_tool(f"waybackurls {domain} | unfurl -u domains"),
            run_tool(f"gau {domain} | unfurl -u domains"),
            run_tool(f"sublist3r -d {domain} -n")
        ]

        results = await asyncio.gather(*tasks)
        subdomains.update(*results)
        subdomains.add(domain)  # Add the root domain

        # Validate and probe subdomains with httpx
        valid_subdomains = set()
        try:
            subdomains_file = "subdomains_temp.txt"
            with open(subdomains_file, "w") as f:
                f.write("\n".join(subdomains))
            
            cmd = f"httpx -l {subdomains_file} -silent -status-code -title -tech-detect -follow-redirects"
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            
            for line in stdout.decode().splitlines():
                if line:
                    url = line.split()[0]
                    valid_subdomains.add(urlparse(url).netloc)
            
            os.remove(subdomains_file)
        except Exception as e:
            logging.error(f"Error validating subdomains with httpx: {e}")
            # Fallback to basic validation if httpx fails
            async def validate_subdomain(subdomain: str):
                try:
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

    async def save_scan_metadata(self, domain: str):
        """Save scan metadata to the database"""
        metadata = {
            'domain': domain,
            'start_time': self.results.start_time.isoformat(),
            'end_time': self.results.end_time.isoformat(),
            'subdomains_found': len(self.results.subdomains),
            'urls_collected': len(self.results.wayback_urls),
            'parameters_found': len(self.results.parameterized_urls),
            'vulnerabilities_found': len(self.results.vulnerabilities)
        }
        
        await save_scan_result('scan_metadata', json.dumps(metadata))

    async def _run_port_scan(self, domain: str) -> List[Dict[str, Any]]:
        """Run port scan using nmap"""
        try:
            ports = []
            cmd = f"nmap -sS -sV -p- --min-rate 1000 -T4 {domain} -oX -"
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            if proc.returncode == 0:
                # Parse nmap XML output
                import xml.etree.ElementTree as ET
                root = ET.fromstring(stdout.decode())
                for host in root.findall('.//host'):
                    for port in host.findall('.//port'):
                        if port.find('state').get('state') == 'open':
                            service = port.find('service')
                            ports.append({
                                'port': int(port.get('portid')),
                                'protocol': port.get('protocol'),
                                'service': service.get('name') if service is not None else 'unknown',
                                'version': service.get('version') if service is not None else 'unknown'
                            })
            return ports
        except Exception as e:
            logger.error(f"Error during port scan of {domain}: {e}")
            return []

    async def _detect_technologies(self, domain: str) -> List[Dict[str, Any]]:
        """Detect technologies using Wappalyzer"""
        try:
            cmd = f"wappalyzer https://{domain}"
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            if proc.returncode == 0:
                techs = json.loads(stdout.decode())
                return [{
                    'name': tech,
                    'version': version,
                    'confidence': confidence
                } for tech, version, confidence in techs.items()]
            return []
        except Exception as e:
            logger.error(f"Error detecting technologies for {domain}: {e}")
            return []

    async def _discover_api_endpoints(self, urls: Set[str]) -> List[Dict[str, Any]]:
        """Discover API endpoints using various techniques"""
        api_endpoints = []
        
        # Use various tools and techniques to discover API endpoints
        tools = [
            ("ffuf", f"ffuf -w wordlist.txt -u FUZZ -mc 200,201,202,203,204,400,401,403,405,500"),
            ("arjun", f"arjun -u URL -t 10"),
            ("gospider", f"gospider -s URL -t 10 -c 10 -d 3")
        ]
        
        for url in urls:
            if any(api_pattern in url.lower() for api_pattern in ['/api/', '/v1/', '/v2/', '/rest/', '/graphql']):
                api_endpoints.append({
                    'url': url,
                    'method': 'GET',  # Default method
                    'parameters': [],
                    'discovery_source': 'pattern_matching'
                })
        
        return api_endpoints

    async def _discover_content(self, domains: Set[str]) -> None:
        """Enhanced content discovery with multiple tools"""
        tools = [
            ("feroxbuster", "--url URL --threads 10 --depth 3 --filter-status 404"),
            ("gobuster", "dir -u URL -t 10 -w wordlist.txt"),
            ("dirsearch", "-u URL -t 10 -r -R 2"),
            ("katana", "-u URL -jc -silent -d 10"),
            ("hakrawler", "-url URL -depth 3 -plain"),
            ("jaeles", "scan -u URL -s /path/to/signatures -L 50 --silent"),
            ("meg", "-d 1000 -v paths.txt URL")
        ]

        # Create temporary directory for results
        scan_dir = "content_discovery_results"
        os.makedirs(scan_dir, exist_ok=True)

        for domain in domains:
            for tool_name, tool_args in tools:
                try:
                    output_file = os.path.join(scan_dir, f"{domain}_{tool_name}.txt")
                    cmd = f"{tool_name} {tool_args.replace('URL', f'https://{domain}')} > {output_file}"
                    proc = await asyncio.create_subprocess_shell(
                        cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    await proc.communicate()

                    # Process results with httpx for validation
                    if os.path.exists(output_file):
                        validate_cmd = f"httpx -l {output_file} -silent -status-code -content-length -title"
                        proc = await asyncio.create_subprocess_shell(
                            validate_cmd,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE
                        )
                        stdout, _ = await proc.communicate()

                        for line in stdout.decode().splitlines():
                            if line:
                                parts = line.split()
                                url = parts[0]
                                status = int(parts[1])
                                length = int(parts[2])
                                title = " ".join(parts[3:]) if len(parts) > 3 else ""

                                if status in [200, 201, 202, 203, 204]:
                                    self.results.interesting_endpoints.append({
                                        'url': url,
                                        'status_code': status,
                                        'content_length': length,
                                        'title': title,
                                        'discovery_tool': tool_name
                                    })

                except Exception as e:
                    logger.error(f"Error running {tool_name} on {domain}: {e}")

        # Cleanup
        import shutil
        shutil.rmtree(scan_dir, ignore_errors=True)

    async def _run_vulnerability_scan(self, domains: Set[str]) -> None:
        """Enhanced vulnerability scanning with multiple tools"""
        tools = [
            ("nuclei", "-t nuclei-templates -c 50 -bulk-size 50 -rate-limit 150"),
            ("nikto", "-Tuning x123456789a -maxtime 1h"),
            ("sqlmap", "--batch --random-agent --level 1 --risk 1"),
            ("dalfox", "pipe --silence --no-color --no-spinner"),
            ("cariddi", "-intensive"),
            ("crlfuzz", "-s -o crlfuzz_results.txt"),
            ("corstest", "-o corstest_results.txt"),
            ("gxss", "-p parameters.txt"),
            ("jaeles", "scan -s /path/to/signatures -L 50 --silent"),
            ("graphqlmap", "-m detect")
        ]

        # Special handling for GraphQL endpoints
        graphql_endpoints = [url for url in self.results.api_endpoints if 'graphql' in url['url'].lower()]
        if graphql_endpoints:
            tools.append(("graphw00f", "-t -f json"))
            tools.append(("inql", "scan -t"))

        for domain in domains:
            # First, run fast tools concurrently
            fast_tools = ["nuclei", "dalfox", "cariddi", "crlfuzz", "corstest"]
            fast_tasks = []
            for tool_name, tool_args in tools:
                if tool_name in fast_tools:
                    cmd = f"{tool_name} {tool_args} -target https://{domain}"
                    fast_tasks.append(self._run_tool(cmd))
            
            await asyncio.gather(*fast_tasks)

            # Then run slower, more intensive tools sequentially
            slow_tools = ["nikto", "sqlmap", "jaeles", "graphqlmap"]
            for tool_name, tool_args in tools:
                if tool_name in slow_tools:
                    try:
                        cmd = f"{tool_name} {tool_args} -target https://{domain}"
                        await self._run_tool(cmd)
                    except Exception as e:
                        logger.error(f"Error running {tool_name} on {domain}: {e}")

        # Process JWT tokens if found
        jwt_tokens = self._extract_jwt_tokens()
        if jwt_tokens:
            await self._analyze_jwt_tokens(jwt_tokens)

    async def _analyze_jwt_tokens(self, tokens: List[str]) -> None:
        """Analyze JWT tokens for vulnerabilities"""
        for token in tokens:
            try:
                cmd = f"jwt_tool {token} --mode scan"
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await proc.communicate()

                if "Vulnerability" in stdout.decode():
                    self.results.vulnerabilities.append({
                        'type': 'jwt',
                        'name': 'JWT Token Vulnerability',
                        'severity': 'high',
                        'token': token,
                        'description': 'Potential JWT token vulnerability found',
                        'tool': 'jwt_tool'
                    })
            except Exception as e:
                logger.error(f"Error analyzing JWT token: {e}")

    def _extract_jwt_tokens(self) -> List[str]:
        """Extract JWT tokens from collected responses"""
        tokens = []
        jwt_pattern = r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'
        
        for request in self.results.requests_history:
            response = request.get('response', {})
            headers = response.get('headers', {})
            body = response.get('body', '')

            # Check Authorization header
            auth_header = headers.get('Authorization', '')
            if 'Bearer' in auth_header:
                token = auth_header.split('Bearer ')[-1]
                if re.match(jwt_pattern, token):
                    tokens.append(token)

            # Check response body
            if body:
                matches = re.findall(jwt_pattern, body)
                tokens.extend(matches)

        return list(set(tokens))  # Remove duplicates

async def scan_target(domain: str) -> Dict[str, Any]:
    """Convenience function to run a scan"""
    async with Scanner() as scanner:
        return await scanner.scan_domain(domain)
