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
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse

from core.config import config
from core.scanner import Scanner, ScanPhase
from core.db import DatabaseManager
from core.external import ToolExecutor
from core import updater

# Import the web UI components
from webui import app as webui_app, ScanManager as WebUIScanManager

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

# Mount the web UI app
app.mount("/ui", webui_app)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Set up templates
templates = Jinja2Templates(directory="templates")

# Root route
@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# Charts route
@app.get("/charts", response_class=HTMLResponse)
async def charts(request: Request):
    return templates.TemplateResponse("charts.html", {"request": request})

# Reports route
@app.get("/reports", response_class=HTMLResponse)
async def reports(request: Request):
    return templates.TemplateResponse("reports.html", {"request": request})

# Settings route
@app.get("/settings", response_class=HTMLResponse)
async def settings(request: Request):
    return templates.TemplateResponse("settings.html", {"request": request})

# API endpoints
@app.post("/api/scan/start")
async def start_scan(request: Request):
    data = await request.json()
    domain = data.get('domain')
    if not domain:
        return {"error": "Domain is required"}
    try:
        scan_state = await scan_manager.start_scan(domain, data)
        return {"message": f"Started scan for {domain}", "scan_id": scan_state['domain']}
    except Exception as e:
        logger.error(f"Failed to start scan: {e}", exc_info=True)
        return {"error": str(e)}

@app.get("/api/vulnerabilities")
async def get_vulnerabilities():
    try:
        results = await scan_manager.db.get_results()
        return {"vulnerabilities": results}
    except Exception as e:
        logger.error(f"Failed to get vulnerabilities: {e}", exc_info=True)
        return {"error": str(e)}

@app.post("/api/scans")
async def create_scan(request: Request):
    data = await request.json()
    domain = data.get('domain')
    if not domain:
        return {"error": "Domain is required"}
    try:
        scan_state = await scan_manager.start_scan(domain, data)
        return {"message": f"Started scan for {domain}", "scan_id": scan_state['domain']}
    except Exception as e:
        logger.error(f"Failed to create scan: {e}", exc_info=True)
        return {"error": str(e)}

@app.post("/api/scan/stop")
async def stop_scan(request: Request):
    data = await request.json()
    domain = data.get('domain')
    if not domain:
        return {"error": "Domain is required"}
    try:
        await scan_manager.stop_scan(domain)
        return {"message": f"Stopped scan for {domain}"}
    except ValueError as e:
        return {"error": str(e)}
    except Exception as e:
        logger.error(f"Failed to stop scan: {e}", exc_info=True)
        return {"error": str(e)}

@app.get("/api/scan/{domain}/status")
async def get_scan_status(domain: str):
    try:
        if domain in scan_manager.active_scans:
            scan_state = scan_manager.active_scans[domain]
            return {
                "domain": domain,
                "status": scan_state['status'],
                "progress": scan_state['progress'],
                "stats": {
                    "urls_scanned": scan_state['urls_scanned'],
                    "subdomains_found": scan_state['subdomains_found'],
                    "vulnerabilities_found": scan_state['vulnerabilities_found']
                }
            }
        return {"error": f"No active scan found for domain: {domain}"}
    except Exception as e:
        logger.error(f"Failed to get scan status: {e}", exc_info=True)
        return {"error": str(e)}

@app.get("/api/settings")
async def get_settings():
    try:
        return {
            "general": {
                "maxConcurrentScans": config.get("max_concurrent_scans", 3),
                "scanTimeout": config.get("scan_timeout", 60),
                "autoOpenBrowser": config.get("auto_open_browser", True)
            },
            "scan": {
                "subdomainDepth": config.get("subdomain_depth", 2),
                "followRedirects": config.get("follow_redirects", True),
                "screenshotPages": config.get("screenshot_pages", False)
            },
            "api": {
                "webhookUrl": config.get("webhook_url", "")
            }
        }
    except Exception as e:
        logger.error(f"Failed to get settings: {e}", exc_info=True)
        return {"error": str(e)}

@app.post("/api/settings")
async def update_settings(request: Request):
    try:
        settings = await request.json()
        config.update(settings)
        return {"message": "Settings updated successfully"}
    except Exception as e:
        logger.error(f"Failed to update settings: {e}", exc_info=True)
        return {"error": str(e)}

# Global state
active_scans: Dict[str, Dict[str, Any]] = {}
websocket_clients = set()

class ScanManager:
    """Manages active scans and their state"""
    def __init__(self):
        self.active_scans = {}
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
            'task': None,
            'results': None,
            'current_phase': None
        }

        try:
            # Initialize scan task
            scan_state['task'] = asyncio.create_task(
                self._run_scan(domain, scan_state)
            )
            self.active_scans[domain] = scan_state
            
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
        """Run the scan process"""
        try:
            async with Scanner() as scanner:
                # Register phase callbacks for all phases
                for phase in [
                    ScanPhase.INIT,
                    ScanPhase.WAYBACK,
                    ScanPhase.PARAM_DISCOVERY,
                    ScanPhase.SUBDOMAIN_ENUM,
                    ScanPhase.CONTENT_DISCOVERY,
                    ScanPhase.FUZZING,
                    ScanPhase.VULNERABILITY_SCAN,
                    ScanPhase.TECH_DETECTION,
                    ScanPhase.PORT_SCAN,
                    ScanPhase.API_DISCOVERY,
                    ScanPhase.REPORTING
                ]:
                    scanner.register_phase_callback(phase, self._handle_phase_update)
                
                scan_state['results'] = scanner.results

                # Phase 1: Collect URLs from Wayback Machine
                scan_state['current_phase'] = ScanPhase.WAYBACK
                urls = await scanner.collect_wayback_urls(domain)
                await self._update_scan_progress(scan_state, 20)

                # Phase 2: Extract parameterized URLs
                scan_state['current_phase'] = ScanPhase.PARAM_DISCOVERY
                param_urls = await scanner.extract_parameterized_urls()
                await self._update_scan_progress(scan_state, 40)

                # Phase 3: Enumerate subdomains
                scan_state['current_phase'] = ScanPhase.SUBDOMAIN_ENUM
                subdomains = await scanner.enumerate_subdomains(domain)
                await self._update_scan_progress(scan_state, 60)

                # Phase 4: Fuzz parameters
                scan_state['current_phase'] = ScanPhase.FUZZING
                total_params = sum(len(params) for _, params in param_urls)
                processed = 0

                for url, params in param_urls:
                    for param in params:
                        try:
                            vulnerabilities = await scanner.fuzz_parameter(url, param)
                            if vulnerabilities:
                                for vuln in vulnerabilities:
                                    await self._handle_vulnerability(vuln)
                            processed += 1
                            progress = 60 + (processed / total_params * 30)
                            await self._update_scan_progress(scan_state, progress)
                        except Exception as e:
                            logger.error(f"Error fuzzing {url} {param}: {e}")

                # Phase 5: Generate report
                scan_state['current_phase'] = ScanPhase.REPORTING
                await self._generate_report(domain, scan_state)
                await self._update_scan_progress(scan_state, 100)

                scan_state['status'] = 'completed'
                await broadcast_event('scan_completed', {
                    'domain': domain,
                    'message': f'Scan completed for {domain}',
                    'results': scanner.get_current_results()
                })

        except asyncio.CancelledError:
            logger.info(f"Scan cancelled for {domain}")
            scan_state['status'] = 'cancelled'
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

    async def _handle_phase_update(self, phase: str, status: str, data: Any = None):
        """Handle phase status updates"""
        message = f"Phase {phase}: {status}"
        if isinstance(data, (int, float)):
            message += f" ({data}%)"
        elif isinstance(data, (list, set)) and data:
            message += f" (found {len(data)} items)"
            
        await broadcast_event('phase_update', {
            'phase': phase,
            'status': status,
            'message': message,
            'data': data,
            'timestamp': datetime.utcnow().isoformat()
        })

    async def get_scan_results(self, domain: str, phase: Optional[str] = None) -> Dict[str, Any]:
        """Get current scan results, optionally filtered by phase"""
        if domain not in self.active_scans:
            raise ValueError(f"No scan found for domain: {domain}")

        scan_state = self.active_scans[domain]
        if not scan_state['results']:
            return {}

        results = scan_state['results'].to_dict()
        if phase:
            # Filter results by phase
            phase_results = {
                ScanPhase.WAYBACK: 'wayback_urls',
                ScanPhase.PARAM_DISCOVERY: 'parameterized_urls',
                ScanPhase.SUBDOMAIN_ENUM: 'subdomains',
                ScanPhase.FUZZING: 'vulnerabilities'
            }
            if phase in phase_results:
                return {phase_results[phase]: results[phase_results[phase]]}
        return results

    async def resend_request(self, domain: str, request_id: int, custom_params: Dict[str, str]) -> Dict[str, Any]:
        """Resend a previous request with custom parameters"""
        if domain not in self.active_scans:
            raise ValueError(f"No scan found for domain: {domain}")

        scan_state = self.active_scans[domain]
        if not scan_state['results']:
            raise ValueError("No results available")

        async with Scanner() as scanner:
            scanner.results = scan_state['results']
            return await scanner.resend_request(request_id, custom_params)

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
            if nuclei_result['return_code'] == 0:
                await self._handle_nuclei_results(nuclei_result['output'])

        except Exception as e:
            logger.error(f"Error running external tools for {domain}: {e}", exc_info=True)

    async def _handle_nuclei_results(self, output: str) -> None:
        """Handle nuclei scan results"""
        try:
            results = json.loads(output)
            for finding in results:
                await self._handle_vulnerability({
                    'type': 'nuclei',
                    'severity': finding.get('info', {}).get('severity', 'unknown'),
                    'name': finding.get('info', {}).get('name'),
                    'url': finding.get('matched-at'),
                    'description': finding.get('info', {}).get('description'),
                    'tags': finding.get('info', {}).get('tags', [])
                })
        except json.JSONDecodeError:
            logger.error("Failed to parse nuclei output as JSON")
        except Exception as e:
            logger.error(f"Error handling nuclei results: {e}", exc_info=True)

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
    parser.add_argument("--config", help="Path to custom configuration file")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--no-browser", action="store_true", help="Don't open browser automatically")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind the web interface to")
    parser.add_argument("--port", type=int, default=8000, help="Port to run the web interface on")
    args = parser.parse_args()

    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")

    # Load configuration
    if args.config:
        logger.debug(f"Loading custom configuration from {args.config}")
        config.load_config(args.config)

    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    logger.debug("Signal handlers registered")

    # Verify resources
    try:
        logger.debug("Verifying required resources...")
        asyncio.run(updater.verify_resources())
        logger.debug("Resource verification completed successfully")
    except Exception as e:
        logger.error("Error verifying resources: %s", e)
        sys.exit(1)

    if args.domain:
        # CLI mode - Run single scan mode
        logger.debug("Starting in CLI mode for domain: %s", args.domain)
        async def run_scan():
            manager = ScanManager()
            try:
                scan_state = await manager.start_scan(args.domain)
                # Wait for the scan task to complete
                if scan_state['task']:
                    try:
                        await scan_state['task']
                    except asyncio.CancelledError:
                        logger.error("Scan was cancelled")
                        sys.exit(1)
                    except Exception as e:
                        logger.error(f"Scan failed: {e}")
                        sys.exit(1)
            except Exception as e:
                logger.error(f"Failed to start scan: {e}")
                sys.exit(1)
        asyncio.run(run_scan())
    else:
        # Web interface mode
        import webbrowser
        import threading
        import time

        logger.debug("Starting in Web UI mode")
        logger.debug(f"Host: {args.host}, Port: {args.port}")
        logger.debug(f"Browser auto-launch: {'disabled' if args.no_browser else 'enabled'}")

        def open_browser():
            logger.debug("Browser launch thread started")
            logger.debug("Waiting 2 seconds for web server to initialize...")
            time.sleep(2)  # Wait for server to start
            url = f"http://{args.host}:{args.port}"
            
            if not args.no_browser:
                try:
                    logger.debug(f"Attempting to open browser at {url}")
                    webbrowser.open(url)
                    logger.info(f"Successfully opened browser at {url}")
                except Exception as e:
                    logger.warning(f"Failed to open browser: {e}")
                    logger.debug(f"Browser launch error details:", exc_info=True)
            else:
                logger.debug("Browser auto-launch is disabled")

        # Start browser in a separate thread
        logger.debug("Creating browser launch thread")
        browser_thread = threading.Thread(target=open_browser, daemon=True)
        logger.debug("Starting browser launch thread")
        browser_thread.start()
        logger.debug("Browser launch thread started successfully")

        # Run web interface
        logger.info(f"Starting web interface on http://{args.host}:{args.port}")
        logger.debug("Initializing FastAPI application")
        logger.debug("Static files directory: ./static")
        logger.debug("Templates directory: ./templates")
        logger.debug("Starting Uvicorn server...")
        
        # Check if directories exist
        static_dir = Path("static")
        templates_dir = Path("templates")
        logger.debug(f"Checking static directory exists: {static_dir.exists()}")
        logger.debug(f"Checking templates directory exists: {templates_dir.exists()}")
        
        if not static_dir.exists() or not templates_dir.exists():
            logger.error("Required directories are missing!")
            logger.error(f"Static directory exists: {static_dir.exists()}")
            logger.error(f"Templates directory exists: {templates_dir.exists()}")
            sys.exit(1)

        uvicorn.run(
            "main:app",
            host=args.host,
            port=args.port,
            log_level="debug" if args.verbose else "info",
            reload=False,
            access_log=args.verbose
        )

if __name__ == "__main__":
    main()
