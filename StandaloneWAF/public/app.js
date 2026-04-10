const socket = new WebSocket(`ws://${window.location.host}`);
const logContainer = document.getElementById('traffic-log');
const totalCountEl = document.getElementById('total-count');
const topDestEl = document.getElementById('top-dest');

let totalIntercepts = 0;
let destFrequency = {};

socket.onmessage = (event) => {
    const data = JSON.parse(event.data);
    
    document.getElementById('last-update').innerText = `Last Event: ${new Date().toLocaleTimeString()}`;
    
    // Remove empty state if present
    const empty = logContainer.querySelector('.empty-state');
    if (empty) empty.remove();

    // Create log entry
    const entry = document.createElement('div');
    entry.className = 'log-entry';
    entry.innerHTML = `
        <span>${data.timestamp}</span>
        <span class="domain-cell">${data.domain}</span>
        <span style="font-size: 0.75rem; opacity: 0.8">${data.ip}</span>
        <span>${data.port}</span>
        <span style="color: var(--muted); font-size: 0.75rem">${data.proto}</span>
        <span style="font-weight: 600; font-size: 0.75rem">${data.method}</span>
        <span><span class="process-cell">${data.process}</span></span>
    `;

    // Add to top of list
    logContainer.prepend(entry);

    // Limit log entries
    if (logContainer.children.length > 50) {
        logContainer.lastElementChild.remove();
    }

    // Update stats
    totalIntercepts++;
    totalCountEl.innerText = totalIntercepts;

    destFrequency[data.domain] = (destFrequency[data.domain] || 0) + 1;
    const top = Object.entries(destFrequency).sort((a,b) => b[1] - a[1])[0][0];
    topDestEl.innerText = top;
};

socket.onclose = () => {
    console.log('Connection closed. Retrying...');
    setTimeout(() => {
        window.location.reload();
    }, 5000);
};
