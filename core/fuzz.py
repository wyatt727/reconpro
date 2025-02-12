# reconpro/core/fuzz.py
import asyncio
import aiohttp
import logging
import difflib
import json
import os
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from dataclasses import dataclass
from .config import config
from .external import run_nuclei_scan, run_gf_scan
from .retry import RetryHandler

@dataclass
class FuzzResult:
    """Data class for fuzzing results"""
    url: str
    parameter: str
    payload: str
    method: str
    similarity: float
    response_time: float
    status_code: int
    content_length: int
    gf_matches: List[str]
    nuclei_output: str
    reflection_count: int
    error_patterns: List[str]

class PayloadManager:
    """Manages fuzzing payloads with categories and smart selection"""
    def __init__(self):
        self.payloads: Dict[str, List[str]] = {
            'xss': [],
            'sqli': [],
            'rce': [],
            'lfi': [],
            'ssrf': [],
            'ssti': [],
            'default': []
        }
        self.load_payloads()

    def load_payloads(self):
        """Load payloads from files with categories"""
        payloads_dir = os.path.join(os.path.dirname(__file__), '..', 'data', 'payloads')
        if not os.path.exists(payloads_dir):
            logging.error("Payloads directory not found")
            return

        for category in self.payloads.keys():
            file_path = os.path.join(payloads_dir, f"{category}.txt")
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        self.payloads[category] = [
                            line.strip() for line in f.readlines()
                            if line.strip() and not line.startswith('#')
                        ]
                except Exception as e:
                    logging.error("Error loading %s payloads: %s", category, e)

    def get_payloads(self, parameter: str, context: Optional[str] = None) -> List[str]:
        """Smart payload selection based on parameter name and context"""
        selected_payloads = set()

        # Select payloads based on parameter name hints
        param_lower = parameter.lower()
        if any(x in param_lower for x in ['id', 'uid', 'user']):
            selected_payloads.update(self.payloads['sqli'])
        elif any(x in param_lower for x in ['file', 'path', 'dir']):
            selected_payloads.update(self.payloads['lfi'])
        elif any(x in param_lower for x in ['cmd', 'exec', 'command']):
            selected_payloads.update(self.payloads['rce'])
        elif any(x in param_lower for x in ['url', 'link', 'redirect']):
            selected_payloads.update(self.payloads['ssrf'])
        elif any(x in param_lower for x in ['template', 'tpl', 'view']):
            selected_payloads.update(self.payloads['ssti'])
        else:
            selected_payloads.update(self.payloads['xss'])

        # Add some default payloads
        selected_payloads.update(self.payloads['default'])

        return list(selected_payloads)

class Fuzzer:
    """Advanced fuzzer with improved detection and analysis"""
    def __init__(self):
        self.payload_manager = PayloadManager()
        self.session = None
        self.retry_handler = RetryHandler(
            max_retries=config.scan.max_retries,
            delay=config.scan.retry_delay
        )
        self.error_patterns = self._load_error_patterns()

    def _load_error_patterns(self) -> Dict[str, List[str]]:
        """Load error patterns for vulnerability detection"""
        patterns_file = os.path.join(os.path.dirname(__file__), '..', 'data', 'patterns.json')
        try:
            with open(patterns_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logging.error("Error loading error patterns: %s", e)
            return {}

    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(**config.get_aiohttp_settings())
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()

    async def fuzz_parameter(self, url: str, parameter: str, method: str = "GET") -> List[FuzzResult]:
        """Fuzz a parameter with smart payload selection and analysis"""
        results = []
        payloads = self.payload_manager.get_payloads(parameter)

        # Get baseline response
        baseline = await self._get_baseline(url, parameter, method)
        if not baseline:
            return results

        for payload in payloads:
            try:
                result = await self._test_payload(url, parameter, payload, method, baseline)
                if result:
                    results.append(result)
            except Exception as e:
                logging.error("Error testing payload %s: %s", payload, e)

        return results

    async def _get_baseline(self, url: str, parameter: str, method: str) -> Optional[Dict[str, Any]]:
        """Get baseline response for comparison"""
        try:
            if method == "GET":
                parsed = urlparse(url)
                query = parse_qs(parsed.query)
                query[parameter] = [""]
                baseline_url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
                
                async with self.session.get(baseline_url) as response:
                    return {
                        'text': await response.text(),
                        'status': response.status,
                        'time': response.raw_response.elapsed.total_seconds(),
                        'length': len(await response.read())
                    }
            else:
                data = {parameter: ""}
                async with self.session.post(url, json=data) as response:
                    return {
                        'text': await response.text(),
                        'status': response.status,
                        'time': response.raw_response.elapsed.total_seconds(),
                        'length': len(await response.read())
                    }
        except Exception as e:
            logging.error("Error getting baseline: %s", e)
            return None

    async def _test_payload(
        self, url: str, parameter: str, payload: str, method: str, baseline: Dict[str, Any]
    ) -> Optional[FuzzResult]:
        """Test a single payload with comprehensive analysis"""
        try:
            if method == "GET":
                parsed = urlparse(url)
                query = parse_qs(parsed.query)
                query[parameter] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
                
                async with self.session.get(test_url) as response:
                    return await self._analyze_response(
                        response, test_url, parameter, payload, method, baseline
                    )
            else:
                data = {parameter: payload}
                async with self.session.post(url, json=data) as response:
                    return await self._analyze_response(
                        response, url, parameter, payload, method, baseline
                    )
        except Exception as e:
            logging.error("Error testing payload: %s", e)
            return None

    async def _analyze_response(
        self, response, url: str, parameter: str, payload: str, method: str, baseline: Dict[str, Any]
    ) -> Optional[FuzzResult]:
        """Comprehensive response analysis"""
        try:
            response_text = await response.text()
            response_time = response.raw_response.elapsed.total_seconds()
            content_length = len(await response.read())

            # Calculate similarity
            similarity = difflib.SequenceMatcher(None, baseline['text'], response_text).ratio()

            # Check for payload reflection
            reflection_count = response_text.count(payload)

            # Check for error patterns
            error_patterns_found = []
            for category, patterns in self.error_patterns.items():
                for pattern in patterns:
                    if pattern in response_text:
                        error_patterns_found.append(f"{category}: {pattern}")

            # Determine if this is likely a vulnerability
            is_vulnerable = (
                similarity < config.scan.similarity_threshold or
                reflection_count > 0 or
                abs(content_length - baseline['length']) > 100 or
                abs(response_time - baseline['time']) > 2 or
                error_patterns_found or
                response.status != baseline['status']
            )

            if is_vulnerable:
                # Run additional security tools
                gf_matches = await asyncio.to_thread(run_gf_scan, url)
                nuclei_output = await asyncio.to_thread(run_nuclei_scan, url)

                return FuzzResult(
                    url=url,
                    parameter=parameter,
                    payload=payload,
                    method=method,
                    similarity=similarity,
                    response_time=response_time,
                    status_code=response.status,
                    content_length=content_length,
                    gf_matches=gf_matches,
                    nuclei_output=nuclei_output,
                    reflection_count=reflection_count,
                    error_patterns=error_patterns_found
                )

        except Exception as e:
            logging.error("Error analyzing response: %s", e)

        return None

async def fuzz_target(url: str, parameters: List[str], method: str = "GET") -> List[FuzzResult]:
    """Convenience function to fuzz a target"""
    async with Fuzzer() as fuzzer:
        all_results = []
        for parameter in parameters:
            results = await fuzzer.fuzz_parameter(url, parameter, method)
            all_results.extend(results)
        return all_results
