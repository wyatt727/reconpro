# reconpro/core/external.py
import asyncio
import logging
import json
import re
import shlex
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
from .config import config
from functools import wraps
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

@dataclass
class ToolResult:
    """Data class for tool execution results"""
    command: str
    output: str
    error: Optional[str]
    return_code: int
    duration: float
    timestamp: str

@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker pattern"""
    failure_threshold: int = 5
    reset_timeout: int = 60
    half_open_timeout: int = 30

class CircuitBreaker:
    """Circuit breaker decorator for handling failures"""
    def __init__(self, config: CircuitBreakerConfig = None):
        self.config = config or CircuitBreakerConfig()
        self.failures = 0
        self.last_failure_time = None
        self.state = "CLOSED"

    def __call__(self, func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            if self.state == "OPEN":
                if datetime.now() - self.last_failure_time > timedelta(seconds=self.config.reset_timeout):
                    self.state = "HALF_OPEN"
                else:
                    raise Exception("Circuit breaker is OPEN")

            try:
                result = await func(*args, **kwargs)
                if self.state == "HALF_OPEN":
                    self.state = "CLOSED"
                    self.failures = 0
                return result
            except Exception as e:
                self.failures += 1
                self.last_failure_time = datetime.now()
                if self.failures >= self.config.failure_threshold:
                    self.state = "OPEN"
                raise e
        return wrapper

class ToolExecutor:
    """Executes external security tools with proper error handling"""
    def __init__(self):
        self.config = config.tools
        self.logger = logging.getLogger(__name__)
        self.retry_handler = RetryHandler()
        self._process_pool = {}

    async def run_tool(self, cmd: List[str], timeout: int = 300, parse_json: bool = False) -> Dict[str, Any]:
        """Run an external tool with timeout"""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # Store process for management
            self._process_pool[process.pid] = process

            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout)
            except asyncio.TimeoutError:
                process.kill()
                raise TimeoutError(f"Tool execution timed out after {timeout} seconds")
            finally:
                self._process_pool.pop(process.pid, None)

            output = stdout.decode().strip()
            error = stderr.decode().strip()

            if process.returncode != 0:
                raise RuntimeError(f"Tool execution failed: {error}")

            if parse_json and output:
                try:
                    output = json.loads(output)
                except json.JSONDecodeError:
                    logger.warning("Failed to parse JSON output")

            return {
                'output': output,
                'error': error,
                'return_code': process.returncode
            }

        except Exception as e:
            logger.error(f"Tool execution error: {str(e)}")
            raise

    async def cleanup(self):
        """Clean up any running processes"""
        for pid, process in self._process_pool.items():
            try:
                process.terminate()
                await process.wait()
            except Exception as e:
                self.logger.error("Error cleaning up process %d: %s", pid, e)

class NucleiRunner:
    """Advanced Nuclei scanner with template management"""
    def __init__(self):
        self.executor = ToolExecutor()
        self.circuit_breaker = CircuitBreaker()

    @CircuitBreaker()
    async def scan(self, target: str, templates: List[str] = None) -> Dict[str, Any]:
        """Run Nuclei scan with specified templates"""
        cmd = config.get_nuclei_command(target)
        if templates:
            for template in templates:
                cmd.extend(["-t", template])

        result = await self.executor.run_tool(cmd, timeout=300, parse_json=True)
        return self._parse_nuclei_output(result['output'])

    def _parse_nuclei_output(self, output: str) -> Dict[str, Any]:
        """Parse Nuclei output into structured format"""
        findings = []
        
        for line in output.splitlines():
            try:
                finding = json.loads(line)
                findings.append({
                    'template': finding.get('template-id'),
                    'severity': finding.get('info', {}).get('severity'),
                    'name': finding.get('info', {}).get('name'),
                    'matched': finding.get('matched-at'),
                    'description': finding.get('info', {}).get('description'),
                    'tags': finding.get('info', {}).get('tags', [])
                })
            except json.JSONDecodeError:
                continue

        return {
            'findings': findings,
            'summary': {
                'total': len(findings),
                'by_severity': {
                    severity: len([f for f in findings if f['severity'] == severity])
                    for severity in ['critical', 'high', 'medium', 'low', 'info']
                }
            }
        }

class GFRunner:
    """Advanced GF pattern matcher"""
    def __init__(self):
        self.executor = ToolExecutor()
        self.pattern_dir = Path.home() / '.gf'
        self._ensure_patterns()

    def _ensure_patterns(self):
        """Ensure GF patterns are installed"""
        if not self.pattern_dir.exists():
            self.pattern_dir.mkdir(parents=True)
            # TODO: Clone default patterns repository

    async def scan(self, target: str, patterns: List[str] = None) -> Dict[str, List[str]]:
        """Run GF scan with specified patterns"""
        if not patterns:
            patterns = config.tools.gf_patterns

        results = {}
        for pattern in patterns:
            cmd = ["gf", pattern]
            if "://" not in target:  # If target is a file
                cmd.append(target)
            else:  # If target is a URL
                cmd = f"echo {shlex.quote(target)} | " + " ".join(cmd)

            try:
                result = await self.executor.run_tool(cmd, timeout=60)
                matches = [line for line in result['output'].splitlines() if line.strip()]
                if matches:
                    results[pattern] = matches
            except Exception as e:
                self.logger.error("Error running GF pattern %s: %s", pattern, e)

        return results

# Global tool instances
nuclei = NucleiRunner()
gf = GFRunner()

# Convenience functions
async def run_nuclei_scan(target: str, templates: List[str] = None) -> Dict[str, Any]:
    """Run Nuclei scan with default configuration"""
    return await nuclei.scan(target, templates)

async def run_gf_scan(target: str, patterns: List[str] = None) -> Dict[str, List[str]]:
    """Run GF scan with default configuration"""
    return await gf.scan(target, patterns)
