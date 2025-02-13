// Dashboard functionality
document.addEventListener('DOMContentLoaded', function() {
    const scanStats = {
        totalScans: 0,
        activeScans: 0,
        vulnerabilitiesFound: 0
    };

    function updateDashboard() {
        // Update scan statistics
        document.getElementById('total-scans').textContent = scanStats.totalScans;
        document.getElementById('active-scans').textContent = scanStats.activeScans;
        document.getElementById('vulnerabilities-found').textContent = scanStats.vulnerabilitiesFound;
    }

    // WebSocket connection for real-time updates
    const ws = new WebSocket(`ws://${window.location.host}/ws`);
    
    ws.onmessage = function(event) {
        const data = JSON.parse(event.data);
        
        if (data.event === 'scan_started') {
            scanStats.totalScans++;
            scanStats.activeScans++;
        } else if (data.event === 'scan_completed') {
            scanStats.activeScans--;
        } else if (data.event === 'vulnerability_found') {
            scanStats.vulnerabilitiesFound++;
        }
        
        updateDashboard();
    };

    // Initial dashboard update
    updateDashboard();
}); 