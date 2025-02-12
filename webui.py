from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
import sqlite3
import os
from datetime import datetime

# Create FastAPI app instance
app = FastAPI(title="ReconPro Web UI")

# Set up Jinja2 templates (place your HTML templates in a "templates" folder)
templates = Jinja2Templates(directory="templates")

# Define locations (adjust these paths as needed)
DATABASE = "reconpro_results.db"  # Same database as used by your scanning modules
REPORT_DIR = "reports"            # Directory where HTML reports are generated

def get_vulnerabilities():
    """Retrieve vulnerability records from the SQLite database."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, url, parameter, payload, method, similarity, gf_matches, nuclei_output, timestamp FROM vulnerabilities ORDER BY timestamp DESC")
    records = cursor.fetchall()
    conn.close()
    return records

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Main dashboard page displaying vulnerability records."""
    vulnerabilities = get_vulnerabilities()
    return templates.TemplateResponse("index.html", {
        "request": request,
        "vulnerabilities": vulnerabilities,
        "timestamp": datetime.utcnow()
    })

@app.get("/api/vulnerabilities", response_class=JSONResponse)
async def api_vulnerabilities():
    """API endpoint that returns vulnerability records in JSON format."""
    vulnerabilities = get_vulnerabilities()
    return {"vulnerabilities": vulnerabilities}

@app.get("/report", response_class=FileResponse)
async def get_report():
    """
    Return the latest report from the reports folder.
    (For simplicity, this returns the first found HTML file.)
    """
    if os.path.exists(REPORT_DIR):
        reports = [f for f in os.listdir(REPORT_DIR) if f.endswith(".html")]
        if reports:
            # For example, return the most recent report file (this logic can be improved)
            report_path = os.path.join(REPORT_DIR, sorted(reports)[-1])
            return FileResponse(report_path, media_type="text/html")
    return HTMLResponse("No report found", status_code=404)

@app.post("/scan")
async def trigger_scan(background_tasks: BackgroundTasks):
    """
    API endpoint to trigger a new scan cycle.
    This adds a background task that calls your scan cycle.
    
    For demonstration, we trigger a scan on a hard-coded domain.
    In a complete solution, you’d pass parameters via the UI.
    """
    from core import main as scan_main  # Import the main scanning module
    domain = "example.com"              # Replace with a configurable domain as needed
    background_tasks.add_task(scan_main.run_scan_cycle, domain)
    return {"message": f"Scan cycle triggered for {domain}"}
