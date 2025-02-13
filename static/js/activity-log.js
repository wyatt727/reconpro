// Activity Log functionality
document.addEventListener('DOMContentLoaded', function() {
    const activityLog = document.getElementById('activity-log');
    const maxLogEntries = 100;

    function addLogEntry(message, type = 'info') {
        const entry = document.createElement('div');
        entry.className = `log-entry log-${type}`;
        
        const timestamp = new Date().toLocaleTimeString();
        entry.innerHTML = `<span class="log-time">[${timestamp}]</span> ${message}`;
        
        activityLog.insertBefore(entry, activityLog.firstChild);
        
        // Limit the number of log entries
        while (activityLog.children.length > maxLogEntries) {
            activityLog.removeChild(activityLog.lastChild);
        }
    }

    // WebSocket connection for real-time updates
    const ws = new WebSocket(`ws://${window.location.host}/ws`);
    
    ws.onmessage = function(event) {
        const data = JSON.parse(event.data);
        
        switch (data.event) {
            case 'scan_started':
                addLogEntry(`Started scan for ${data.data.domain}`, 'info');
                break;
            case 'scan_completed':
                addLogEntry(`Scan completed for ${data.data.domain}`, 'success');
                break;
            case 'scan_progress':
                addLogEntry(`Scan progress for ${data.data.domain}: ${data.data.progress}%`, 'info');
                break;
            case 'vulnerability_found':
                addLogEntry(`Found vulnerability in ${data.data.vulnerability.url}`, 'warning');
                break;
            case 'error':
                addLogEntry(data.data.message, 'error');
                break;
        }
    };

    // Add initial log entry
    addLogEntry('Activity log initialized', 'info');
}); 