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
from .retry import RetryHandler, CircuitBreaker

@dataclass
class ToolResult:
    """Data class for tool execution results"""
    command: str
    output: str
    error: Optional[str]
    return_code: int
    duration: float
    timestamp: str

class ToolExecutor:
    """Advanced tool executor with process management"""
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.retry_handler = RetryHandler()
        self._process_pool = {}

    async def run_tool(
        self,
        command: str,
        timeout: int = 60,
        check: bool = True,
        parse_json: bool = False
    ) -> ToolResult:
        """Run an external tool with timeout and output handling"""
        start_time = asyncio.get_event_loop().time()
        
        try:
            # Split command properly
            if isinstance(command, str):
                command = shlex.split(command)

            # Create subprocess
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # Store process for management
            self._process_pool[process.pid] = process

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError:
                process.terminate()
                await process.wait()
                raise TimeoutError(f"Command timed out after {timeout} seconds: {' '.join(command)}")
            finally:
                self._process_pool.pop(process.pid, None)

            duration = asyncio.get_event_loop().time() - start_time
            output = stdout.decode().strip()
            error = stderr.decode().strip() if stderr else None

            if check and process.returncode != 0:
                raise RuntimeError(
                    f"Command failed with return code {process.returncode}: {error or output}"
                )

            if parse_json and output:
                try:
                    output = json.loads(output)
                except json.JSONDecodeError as e:
                    self.logger.warning("Failed to parse JSON output: %s", e)

            return ToolResult(
                command=' '.join(command),
                output=output,
                error=error,
                return_code=process.returncode,
                duration=duration,
                timestamp=datetime.utcnow().isoformat()
            )

        except Exception as e:
            self.logger.error("Error running command '%s': %s", ' '.join(command), e)
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

    @circuit_breaker
    async def scan(self, target: str, templates: List[str] = None) -> Dict[str, Any]:
        """Run Nuclei scan with specified templates"""
        cmd = config.get_nuclei_command(target)
        if templates:
            for template in templates:
                cmd.extend(["-t", template])

        result = await self.executor.run_tool(cmd, timeout=300, parse_json=True)
        return self._parse_nuclei_output(result.output)

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
                matches = [line for line in result.output.splitlines() if line.strip()]
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
