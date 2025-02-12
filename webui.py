from fastapi import FastAPI, Request, BackgroundTasks, WebSocket, WebSocketDisconnect, Query, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import sqlite3
import os
import asyncio
import logging
from datetime import datetime, timedelta
import json
from typing import Dict, List, Optional
from dataclasses import dataclass
from queue import PriorityQueue

# Initialize FastAPI app
app = FastAPI(title="ReconPro Web UI")

# Mount static files (for CSS, JavaScript, Chart.js, etc.)
app.mount("/static", StaticFiles(directory="static"), name="static")

# Set up Jinja2 templates (assume templates/ is at the root of the project)
templates = Jinja2Templates(directory="templates")

# Database and Report paths (same as used in scanning modules)
DATABASE = "reconpro_results.db"
REPORT_DIR = "reports"

@dataclass
class ScanRequest:
    """Represents a scan request with priority"""
    domain: str
    priority: int
    config: dict
    timestamp: datetime
    status: str = "queued"
    progress: float = 0.0
    scan_id: Optional[str] = None

class ScanManager:
    """Manages scan requests and execution"""
    def __init__(self):
        self.scan_queue = PriorityQueue()
        self.active_scans: Dict[str, ScanRequest] = {}
        self.max_concurrent_scans = 3
        self.scan_history: Dict[str, ScanRequest] = {}
        self._worker_task = None

    async def start_worker(self):
        """Start the scan worker"""
        if self._worker_task is None:
            self._worker_task = asyncio.create_task(self._process_scan_queue())

    async def stop_worker(self):
        """Stop the scan worker"""
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
            self._worker_task = None

    def add_scan(self, domain: str, config: dict, priority: int = 1) -> str:
        """Add a new scan to the queue"""
        scan_id = f"{domain}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        scan_request = ScanRequest(
            domain=domain,
            priority=priority,
            config=config,
            timestamp=datetime.utcnow(),
            scan_id=scan_id
        )
        self.scan_queue.put((priority, scan_request))
        self.scan_history[scan_id] = scan_request
        return scan_id

    async def stop_scan(self, scan_id: str):
        """Stop a running scan"""
        if scan_id in self.active_scans:
            scan = self.active_scans[scan_id]
            scan.status = "stopping"
            # Implement actual scan stopping logic here
            await self._stop_scan_process(scan)
            scan.status = "stopped"
            del self.active_scans[scan_id]

    async def pause_scan(self, scan_id: str):
        """Pause a running scan"""
        if scan_id in self.active_scans:
            scan = self.active_scans[scan_id]
            scan.status = "paused"
            # Implement actual scan pausing logic here

    async def resume_scan(self, scan_id: str):
        """Resume a paused scan"""
        if scan_id in self.active_scans:
            scan = self.active_scans[scan_id]
            if scan.status == "paused":
                scan.status = "running"
                # Implement actual scan resuming logic here

    async def get_scan_status(self, scan_id: str) -> Optional[dict]:
        """Get the status of a scan"""
        if scan_id in self.active_scans:
            scan = self.active_scans[scan_id]
            return {
                "scan_id": scan_id,
                "domain": scan.domain,
                "status": scan.status,
                "progress": scan.progress,
                "timestamp": scan.timestamp.isoformat()
            }
        elif scan_id in self.scan_history:
            scan = self.scan_history[scan_id]
            return {
                "scan_id": scan_id,
                "domain": scan.domain,
                "status": scan.status,
                "progress": scan.progress,
                "timestamp": scan.timestamp.isoformat()
            }
        return None

    async def _process_scan_queue(self):
        """Process the scan queue"""
        while True:
            try:
                # Check if we can start a new scan
                if len(self.active_scans) < self.max_concurrent_scans:
                    try:
                        _, scan_request = self.scan_queue.get_nowait()
                        self.active_scans[scan_request.scan_id] = scan_request
                        asyncio.create_task(self._run_scan(scan_request))
                    except asyncio.QueueEmpty:
                        pass

                await asyncio.sleep(1)  # Prevent CPU hogging
            except asyncio.CancelledError:
                break
            except Exception as e:
                logging.error(f"Error in scan queue processing: {e}")
                await asyncio.sleep(5)  # Back off on error

    async def _run_scan(self, scan_request: ScanRequest):
        """Run a single scan"""
        try:
            scan_request.status = "running"
            # Implement actual scan execution logic here
            await self._execute_scan(scan_request)
        except Exception as e:
            logging.error(f"Error running scan {scan_request.scan_id}: {e}")
            scan_request.status = "error"
        finally:
            if scan_request.scan_id in self.active_scans:
                del self.active_scans[scan_request.scan_id]

    async def _execute_scan(self, scan_request: ScanRequest):
        """Execute the actual scan"""
        from core.scanner import Scanner
        
        async with Scanner() as scanner:
            try:
                # Update status
                await self._update_scan_status(scan_request, "Enumerating subdomains", 5)
                
                # Run the scan steps
                subdomains = await scanner.enumerate_subdomains(scan_request.domain)
                await self._update_scan_status(scan_request, "Collecting URLs", 20)
                
                urls = await scanner.collect_urls(subdomains)
                await self._update_scan_status(scan_request, "Analyzing parameters", 40)
                
                param_urls = scanner.extract_parameterized_urls(urls)
                await self._update_scan_status(scan_request, "Fuzzing parameters", 60)
                
                # Process parameters
                total_params = sum(len(params) for _, params in param_urls)
                processed = 0
                
                for url, params in param_urls:
                    for param in params:
                        try:
                            await scanner.fuzz_parameter(url, param)
                            processed += 1
                            progress = 60 + (processed / total_params * 30)
                            await self._update_scan_status(
                                scan_request,
                                f"Fuzzing parameters ({processed}/{total_params})",
                                progress
                            )
                        except Exception as e:
                            logging.error(f"Error fuzzing {url} {param}: {e}")
                
                await self._update_scan_status(scan_request, "Generating report", 90)
                # Generate report logic here
                
                await self._update_scan_status(scan_request, "Completed", 100)
                scan_request.status = "completed"
                
            except Exception as e:
                logging.error(f"Scan execution error: {e}")
                scan_request.status = "error"
                raise

    async def _update_scan_status(self, scan_request: ScanRequest, message: str, progress: float):
        """Update scan status and broadcast to websocket clients"""
        scan_request.progress = progress
        await broadcast_event('scan_progress', {
            'scan_id': scan_request.scan_id,
            'domain': scan_request.domain,
            'status': scan_request.status,
            'message': message,
            'progress': progress
        })

# Initialize scan manager
scan_manager = ScanManager()

# Start scan worker on application startup
@app.on_event("startup")
async def startup_event():
    await scan_manager.start_worker()

# Stop scan worker on application shutdown
@app.on_event("shutdown")
async def shutdown_event():
    await scan_manager.stop_worker()

# API endpoints for scan control
@app.post("/api/scans")
async def start_scan(request: Request):
    data = await request.json()
    domain = data.get("domain")
    config = data.get("config", {})
    priority = data.get("priority", 1)
    
    if not domain:
        raise HTTPException(status_code=400, detail="Domain is required")
    
    scan_id = scan_manager.add_scan(domain, config, priority)
    return {"scan_id": scan_id}

@app.delete("/api/scans/{scan_id}")
async def stop_scan(scan_id: str):
    await scan_manager.stop_scan(scan_id)
    return {"status": "stopped"}

@app.post("/api/scans/{scan_id}/pause")
async def pause_scan(scan_id: str):
    await scan_manager.pause_scan(scan_id)
    return {"status": "paused"}

@app.post("/api/scans/{scan_id}/resume")
async def resume_scan(scan_id: str):
    await scan_manager.resume_scan(scan_id)
    return {"status": "resumed"}

@app.get("/api/scans/{scan_id}")
async def get_scan_status(scan_id: str):
    status = await scan_manager.get_scan_status(scan_id)
    if status is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return status

@app.get("/api/scans")
async def list_scans():
    active = {id: await scan_manager.get_scan_status(id) for id in scan_manager.active_scans}
    history = {id: await scan_manager.get_scan_status(id) for id in scan_manager.scan_history}
    return {
        "active_scans": active,
        "scan_history": history
    }

# ---------------------------------------------------------------------------
# WebSocket Connection Manager
# ---------------------------------------------------------------------------
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logging.info("WebSocket connected: %s", websocket.client)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logging.info("WebSocket disconnected: %s", websocket.client)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                logging.error("Broadcast error: %s", e)

manager = ConnectionManager()

# ---------------------------------------------------------------------------
# Helper Function to Retrieve Vulnerabilities with Filtering
# ---------------------------------------------------------------------------
def get_vulnerabilities(method: str = None, start_date: str = None, end_date: str = None):
    """Retrieve vulnerability records from the SQLite database with optional filtering."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    query = "SELECT id, url, parameter, payload, method, similarity, gf_matches, nuclei_output, timestamp FROM vulnerabilities"
    params = []
    filters = []
    if method:
        filters.append("method = ?")
        params.append(method.upper())
    if start_date:
        filters.append("timestamp >= ?")
        params.append(start_date)
    if end_date:
        filters.append("timestamp <= ?")
        params.append(end_date)
    if filters:
        query += " WHERE " + " AND ".join(filters)
    query += " ORDER BY timestamp DESC"
    cursor.execute(query, tuple(params))
    records = cursor.fetchall()
    conn.close()
    return records

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, method: str = Query(None), start_date: str = Query(None), end_date: str = Query(None)):
    """Dashboard page showing vulnerabilities with filtering controls."""
    vulnerabilities = get_vulnerabilities(method, start_date, end_date)
    return templates.TemplateResponse("index.html", {
        "request": request,
        "vulnerabilities": vulnerabilities,
        "filter": {"method": method or "", "start_date": start_date or "", "end_date": end_date or ""},
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    })

@app.get("/charts", response_class=HTMLResponse)
async def charts_page(request: Request):
    """Page that shows real‑time charts using Chart.js."""
    return templates.TemplateResponse("charts.html", {
        "request": request,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    })

@app.get("/api/vulnerabilities", response_class=JSONResponse)
async def api_vulnerabilities(method: str = Query(None), start_date: str = Query(None), end_date: str = Query(None)):
    """API endpoint to get vulnerabilities with optional filtering."""
    vulnerabilities = get_vulnerabilities(method, start_date, end_date)
    vulnerabilities_list = []
    for vuln in vulnerabilities:
        vulnerabilities_list.append({
            "id": vuln[0],
            "url": vuln[1],
            "parameter": vuln[2],
            "payload": vuln[3],
            "method": vuln[4],
            "similarity": vuln[5],
            "gf_matches": vuln[6],
            "nuclei_output": vuln[7],
            "timestamp": vuln[8]
        })
    return {"vulnerabilities": vulnerabilities_list}

@app.get("/report", response_class=FileResponse)
async def get_report():
    """Return the latest HTML report."""
    if os.path.exists(REPORT_DIR):
        reports = [f for f in os.listdir(REPORT_DIR) if f.endswith(".html")]
        if reports:
            report_path = os.path.join(REPORT_DIR, sorted(reports)[-1])
            return FileResponse(report_path, media_type="text/html")
    return HTMLResponse("No report found", status_code=404)

@app.post("/scan")
async def trigger_scan(background_tasks: BackgroundTasks):
    """
    Trigger a new scan cycle. This schedules the scan as a background task.
    In this advanced version, the domain could be passed via form parameters.
    """
    from core import main as scan_main  # Import the scanning module
    domain = "example.com"  # For demo purposes; in production, read from request data
    background_tasks.add_task(scan_main.run_scan_cycle, domain)
    # Broadcast a scan trigger event
    asyncio.create_task(manager.broadcast(json.dumps({
        "event": "scan_triggered",
        "timestamp": datetime.utcnow().isoformat(),
        "message": f"Scan cycle triggered for {domain}"
    })))
    return {"message": f"Scan cycle triggered for {domain}"}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint to send real‑time updates to connected clients."""
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Optionally, process incoming messages here
            await websocket.send_text(f"Echo: {data}")
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Background task to broadcast periodic status updates
@app.on_event("startup")
async def startup_event():
    async def broadcast_status():
        while True:
            vulnerabilities = get_vulnerabilities()
            status_message = json.dumps({
                "event": "status_update",
                "timestamp": datetime.utcnow().isoformat(),
                "vulnerability_count": len(vulnerabilities),
                # Here you might calculate additional metrics, e.g. counts by method:
                "GET_count": sum(1 for v in vulnerabilities if v[4] == "GET"),
                "POST_count": sum(1 for v in vulnerabilities if v[4] == "POST")
            })
            await manager.broadcast(status_message)
            await asyncio.sleep(10)  # Update every 10 seconds
    asyncio.create_task(broadcast_status())
