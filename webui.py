from fastapi import FastAPI, Request, BackgroundTasks, WebSocket, WebSocketDisconnect, Query
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import sqlite3
import os
import asyncio
import logging
from datetime import datetime, timedelta
import json

# Initialize FastAPI app
app = FastAPI(title="ReconPro Web UI")

# Mount static files (for CSS, JavaScript, Chart.js, etc.)
app.mount("/static", StaticFiles(directory="static"), name="static")

# Set up Jinja2 templates (assume templates/ is at the root of the project)
templates = Jinja2Templates(directory="templates")

# Database and Report paths (same as used in scanning modules)
DATABASE = "reconpro_results.db"
REPORT_DIR = "reports"

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
