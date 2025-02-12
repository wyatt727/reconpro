#!/usr/bin/env python3
"""
ReconPro - Advanced Web Security Scanner
Main application entry point with improved error handling and logging.
"""
import asyncio
import argparse
import logging
import logging.handlers
import sys
import signal
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

import aiohttp
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from core.config import config
from core.scanner import Scanner
from core.db import DatabaseManager
from core.external import ToolExecutor
from core import updater

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.handlers.RotatingFileHandler(
            "reconpro.log",
            maxBytes=10_000_000,  # 10MB
            backupCount=5
        )
    ]
)

logger = logging.getLogger(__name__)

# Initialize FastAPI application
app = FastAPI(title="ReconPro", version="1.0.0")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Global state
active_scans: Dict[str, Dict[str, Any]] = {}
websocket_clients = set()

class ScanManager:
    """Manages active scans and their state"""
    def __init__(self):
        self.active_scans = {}
        self.scanner = Scanner()
        self.db = DatabaseManager()
        self.tool_executor = ToolExecutor()

    async def start_scan(self, domain: str, scan_config: Optional[Dict] = None) -> Dict[str, Any]:
        """Start a new scan with the given configuration"""
        if domain in self.active_scans:
            raise ValueError(f"Scan already running for domain: {domain}")

        # Create scan state
        scan_state = {
            'domain': domain,
            'start_time': datetime.utcnow(),
            'status': 'initializing',
            'progress': 0,
            'urls_scanned': 0,
            'subdomains_found': 0,
            'vulnerabilities_found': 0,
            'config': scan_config or {},
            'task': None
        }

        try:
            # Initialize scan task
            scan_state['task'] = asyncio.create_task(
                self._run_scan(domain, scan_state)
            )
            self.active_scans[domain] = scan_state
            
            # Broadcast scan started event
            await broadcast_event('scan_started', {
                'domain': domain,
                'message': f'Started scan for {domain}',
                'config': scan_config
            })

            return scan_state

        except Exception as e:
            logger.error(f"Failed to start scan for {domain}: {e}", exc_info=True)
            raise

    async def stop_scan(self, domain: str) -> None:
        """Stop an active scan"""
        if domain not in self.active_scans:
            raise ValueError(f"No active scan found for domain: {domain}")

        scan_state = self.active_scans[domain]
        if scan_state['task']:
            scan_state['task'].cancel()
            try:
                await scan_state['task']
            except asyncio.CancelledError:
                pass

        scan_state['status'] = 'cancelled'
        del self.active_scans[domain]

        await broadcast_event('scan_completed', {
            'domain': domain,
            'message': f'Scan cancelled for {domain}',
            'status': 'cancelled'
        })

    async def _run_scan(self, domain: str, scan_state: Dict[str, Any]) -> None:
        """Run the actual scan process"""
        try:
            async with self.scanner as scanner:
                # Update scan status
                scan_state['status'] = 'running'
                await self._update_scan_progress(scan_state, 5)

                # Step 1: Enumerate subdomains
                subdomains = await scanner.enumerate_subdomains(domain)
                scan_state['subdomains_found'] = len(subdomains)
                await self._update_scan_progress(scan_state, 20)

                # Step 2: Collect URLs
                urls = await scanner.collect_urls(subdomains)
                scan_state['urls_scanned'] = len(urls)
                await self._update_scan_progress(scan_state, 40)

                # Step 3: Extract and analyze parameters
                param_urls = scanner.extract_parameterized_urls(urls)
                await self._update_scan_progress(scan_state, 60)

                # Step 4: Fuzz parameters
                total_params = sum(len(params) for _, params in param_urls)
                processed_params = 0

                for url, params in param_urls:
                    for param in params:
                        try:
                            vulnerabilities = await scanner.fuzz_parameter(url, param)
                            if vulnerabilities:
                                scan_state['vulnerabilities_found'] += len(vulnerabilities)
                                for vuln in vulnerabilities:
                                    await self._handle_vulnerability(vuln)
                        except Exception as e:
                            logger.error(f"Error fuzzing {url} {param}: {e}", exc_info=True)

                        processed_params += 1
                        progress = 60 + (processed_params / total_params * 30)
                        await self._update_scan_progress(scan_state, progress)

                # Step 5: Run external tools
                await self._run_external_tools(domain, scan_state)

                # Step 6: Generate report
                await self._generate_report(domain, scan_state)

                # Complete scan
                scan_state['status'] = 'completed'
                scan_state['progress'] = 100
                await self._update_scan_progress(scan_state, 100)

                await broadcast_event('scan_completed', {
                    'domain': domain,
                    'message': f'Scan completed for {domain}',
                    'stats': {
                        'duration': (datetime.utcnow() - scan_state['start_time']).total_seconds(),
                        'subdomains_found': scan_state['subdomains_found'],
                        'urls_scanned': scan_state['urls_scanned'],
                        'vulnerabilities_found': scan_state['vulnerabilities_found']
                    }
                })

        except asyncio.CancelledError:
            logger.info(f"Scan cancelled for {domain}")
            raise

        except Exception as e:
            logger.error(f"Scan error for {domain}: {e}", exc_info=True)
            scan_state['status'] = 'error'
            await broadcast_event('error', {
                'domain': domain,
                'message': f'Scan failed: {str(e)}'
            })
            raise

        finally:
            if domain in self.active_scans:
                del self.active_scans[domain]

    async def _update_scan_progress(self, scan_state: Dict[str, Any], progress: float) -> None:
        """Update scan progress and broadcast status"""
        scan_state['progress'] = min(round(progress), 100)
        await broadcast_event('scan_progress', {
            'domain': scan_state['domain'],
            'status': scan_state['status'],
            'progress': scan_state['progress'],
            'urls_scanned': scan_state['urls_scanned'],
            'subdomains_found': scan_state['subdomains_found'],
            'vulnerabilities_found': scan_state['vulnerabilities_found']
        })

    async def _handle_vulnerability(self, vulnerability: Dict[str, Any]) -> None:
        """Handle a discovered vulnerability"""
        # Save to database
        await self.db.save_vulnerability(vulnerability)

        # Broadcast to clients
        await broadcast_event('vulnerability_found', {
            'vulnerability': vulnerability
        })

    async def _run_external_tools(self, domain: str, scan_state: Dict[str, Any]) -> None:
        """Run configured external security tools"""
        try:
            # Run nuclei
            nuclei_result = await self.tool_executor.run_tool(
                config.get_nuclei_command(domain),
                timeout=300
            )
            if nuclei_result.return_code == 0:
                await self._handle_nuclei_results(nuclei_result.output)

            # Run other external tools...

        except Exception as e:
            logger.error(f"Error running external tools for {domain}: {e}", exc_info=True)

    async def _generate_report(self, domain: str, scan_state: Dict[str, Any]) -> None:
        """Generate scan report"""
        try:
            report_path = Path(config.output.output_dir) / f"report_{domain}_{scan_state['start_time'].strftime('%Y%m%d_%H%M%S')}"
            
            # Generate reports in different formats
            await self.db.export_results(str(report_path) + ".json")
            await self.db.export_results(str(report_path) + ".csv")
            
            logger.info(f"Generated reports for {domain}")

        except Exception as e:
            logger.error(f"Error generating report for {domain}: {e}", exc_info=True)

# Initialize scan manager
scan_manager = ScanManager()

async def broadcast_event(event: str, data: Dict[str, Any]) -> None:
    """Broadcast event to all connected WebSocket clients"""
    if not websocket_clients:
        return

    message = {
        'event': event,
        'data': data,
        'timestamp': datetime.utcnow().isoformat()
    }

    dead_clients = set()
    for client in websocket_clients:
        try:
            await client.send_json(message)
        except Exception:
            dead_clients.add(client)

    # Clean up dead clients
    websocket_clients.difference_update(dead_clients)

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates"""
    await websocket.accept()
    websocket_clients.add(websocket)
    
    try:
        while True:
            data = await websocket.receive_json()
            # Handle incoming WebSocket messages if needed
            logger.debug(f"Received WebSocket message: {data}")
    except WebSocketDisconnect:
        websocket_clients.remove(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}", exc_info=True)
        if websocket in websocket_clients:
            websocket_clients.remove(websocket)

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logger.info("Shutdown signal received, cleaning up...")
    # Cancel all active scans
    for domain in list(scan_manager.active_scans.keys()):
        asyncio.create_task(scan_manager.stop_scan(domain))
    sys.exit(0)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="ReconPro - Advanced Web Security Scanner")
    parser.add_argument("-d", "--domain", help="Target domain (e.g., example.com)")
    parser.add_argument("--config", help="Path to configuration file")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Load configuration
    if args.config:
        config.load_config(args.config)

    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Update resources
    asyncio.run(updater.update_resources())

    if args.domain:
        # Run single scan mode
        asyncio.run(scan_manager.start_scan(args.domain))
    else:
        # Run web interface
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=8000,
            log_level="info"
        )

if __name__ == "__main__":
    main()
