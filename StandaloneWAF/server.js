const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const { exec, spawn } = require('child_process');
const dns = require('dns');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = 3005;

app.use(express.static(path.join(__dirname, 'public')));

let lastActiveUrl = "";

function getActiveBrowserUrl() {
    const script = `
        if application "Google Chrome" is running then
            tell application "Google Chrome" to get URL of active tab of first window
        else if application "Safari" is running then
            tell application "Safari" to get URL of current tab of first window
        end if
    `;
    exec(`osascript -e '${script}'`, (err, stdout) => {
        if (err || !stdout) return;
        const url = stdout.trim();
        if (url !== lastActiveUrl && url !== "") {
            lastActiveUrl = url;
            try {
                const domain = new URL(url).hostname;
                broadcastTraffic({
                    timestamp: new Date().toLocaleTimeString(),
                    domain: domain,
                    ip: "BROWSER",
                    port: "80/443",
                    proto: "HTTP",
                    method: "BROWSE",
                    process: "ActiveTab"
                });
            } catch(e) {}
        }
    });
}

function broadcastTraffic(data) {
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify(data));
        }
    });
}

setInterval(getActiveBrowserUrl, 2000);

let seenConnections = new Set();
let ipCache = {};

// Comprehensive hostname map (similar to trafficSniffer.js but standalone)
const knownHosts = [
    // Google / YouTube
    ['142.250.', 'google.com'], ['142.251.', 'google.com'], ['172.217.', 'google.com'],
    ['216.58.', 'google.com'], ['1e100.net', 'google.com'], 
    // Microsoft / LinkedIn / Azure
    ['13.107.', 'linkedin.com/msft'], ['20.42.', 'microsoft.com'], ['52.167.', 'linkedin.com'],
    ['20.45.', 'microsoft.com'], ['40.126.', 'microsoft.com'], ['20.190.', 'microsoft.com'],
    // Amazon / AWS
    ['17.253.', 'apple.com'], ['17.', 'apple.com'], 
    ['52.', 'amazonaws.com'], ['54.', 'amazonaws.com'], ['3.', 'aws.amazon.com'],
    ['157.240.', 'instagram.com'], ['31.13.', 'facebook.com'],
    ['162.159.', 'discord.com'], ['104.16.', 'cloudflare.com'],
    ['104.17.', 'cloudflare.com'], ['104.18.', 'cloudflare.com']
];

async function resolveIp(ip) {
    if (ipCache[ip]) return ipCache[ip];
    for (const [prefix, host] of knownHosts) {
        if (ip.startsWith(prefix)) {
            ipCache[ip] = host;
            return host;
        }
    }
    return new Promise((resolve) => {
        dns.reverse(ip, (err, hostnames) => {
            if (!err && hostnames && hostnames.length > 0) {
                let name = hostnames[0].replace(/\.$/, '');
                // Simplify generic names
                if (name.includes('linkedin')) name = 'linkedin.com';
                if (name.includes('google')) name = 'google.com';
                if (name.includes('1e100.net')) name = 'google.com';
                if (name.includes('apple.com')) name = 'apple.com';
                if (name.includes('microsoft')) name = 'microsoft.com';
                if (name.includes('azure')) name = 'azure.com';
                if (name.includes('cloudfront')) name = 'aws-cdn.com';
                
                ipCache[ip] = name;
                resolve(name);
            } else {
                ipCache[ip] = ip;
                resolve(ip);
            }
        });
    });
}

function pollTraffic() {
    const cmd = `lsof -i tcp -n -P 2>/dev/null | grep -E 'ESTABLISHED|SYN_SENT'`;
    exec(cmd, async (err, stdout) => {
        if (err || !stdout) return;
        const lines = stdout.trim().split('\n');
        for (const line of lines) {
            // Updated regex: Look for "->", and capture the parts around it. 
            // Handles both IPv4 and IPv6 (bracketed) formats from lsof.
            const match = line.match(/\s+TCP\s+(.+)->(.+)\s+\(/);
            if (!match) continue;

            let source = match[1].trim();
            let destination = match[2].trim();

            // Extract IP and Port
            // For IPv6, it's [addr]:port. For IPv4, it's addr:port
            const dstParts = destination.match(/(.+):(\d+)$/);
            if (!dstParts) continue;

            const dstIp = dstParts[1].replace(/[\[\]]/g, ''); // Remove brackets if IPv6
            const dstPort = dstParts[2];

            // Filter out local traffic
            if (dstIp === '127.0.0.1' || dstIp === '::1') continue;

            const key = `${dstIp}:${dstPort}`;
            if (seenConnections.has(key)) continue;
            seenConnections.add(key);

            // Periodically clear seen set (every 30s) to allow new activity from same ports
            if (seenConnections.size > 200) seenConnections.clear();

            const domain = await resolveIp(dstIp);
            
            // Guess protocol and method based on port
            let proto = 'TCP';
            let method = '-';
            if (dstPort === '443') { proto = 'HTTPS'; method = 'TLS'; }
            else if (dstPort === '80') { proto = 'HTTP'; method = 'GET/POST'; }
            else if (dstPort === '53') { proto = 'DNS'; method = 'QUERY'; }
            else if (dstPort === '22') { proto = 'SSH'; method = 'TUNNEL'; }

            const data = {
                timestamp: new Date().toLocaleTimeString(),
                domain: domain,
                ip: dstIp,
                port: dstPort,
                proto: proto,
                method: method,
                process: line.split(/\s+/)[0]
            };

            broadcastTraffic(data);
        }
    });
}

// Extreme Speed: 500ms polling
setInterval(pollTraffic, 500); 

server.listen(PORT, () => {
    console.log(`\n🚀 Standalone WAF Traffic Analyzer running at http://localhost:${PORT}`);
    console.log(`📡 WebSocket server live on same port\n`);
});
