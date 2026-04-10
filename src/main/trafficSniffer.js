const { exec } = require('child_process');
const dns = require('dns');

/**
 * TrafficSniffer - Uses `lsof` to poll active network connections
 * Works without root, sees ALL connections (HTTP, HTTPS, DoH, DoT, etc.)
 */
class TrafficSniffer {
  constructor() {
    this.pollInterval = null;
    this.ipCache = {};
    this.seenConnections = new Set(); // Avoid re-showing same connections
    this.targetIp = null;
  }

  start(targetIp, callback) {
    this.stop();
    this.targetIp = targetIp;
    this.callback = callback;

    console.log('[TrafficSniffer] Starting lsof-based connection monitor...');

    // Poll every 500ms — critical for catching high-velocity DoS bursts
    this.pollInterval = setInterval(() => {
      this._pollConnections();
    }, 500);

    // First poll immediately
    setTimeout(() => this._pollConnections(), 500);
  }

  _pollConnections() {
    // Use netstat for better compatibility and speed on macOS
    const cmd = `netstat -f inet -n | grep -E 'ESTABLISHED|SYN_SENT|UDP'`;
    exec(cmd, { timeout: 5000 }, async (err, stdout) => {
      if (err || !stdout) return;

      const lines = stdout.trim().split('\n');
      const now = new Date().toLocaleTimeString('en-US', { hour12: false });

      for (const line of lines) {
        try {
          // Netstat format: proto  recv-q send-q  local address  foreign address  state
          // tcp4  0  0  127.0.0.1.55234  127.0.0.1.443  ESTABLISHED
          const parts = line.trim().split(/\s+/);
          if (parts.length < 4) continue;

          const local = parts[3];
          const foreign = parts[4];
          
          // Parse IP and Port (Mac netstat uses dot for port)
          const localMatch = local.match(/(.+)\.(\d+)$/);
          const foreignMatch = foreign ? foreign.match(/(.+)\.(\d+)$/) : null;

          if (!localMatch || !foreignMatch) continue;

          const srcIp = localMatch[1] === '*' ? '0.0.0.0' : localMatch[1];
          const dstIp = foreignMatch[1];
          const dstPort = foreignMatch[2];

          // Connection metadata for seen list
          const connKey = `${srcIp}->${dstIp}:${dstPort}`;
          if (this.seenConnections.has(connKey)) continue;
          this.seenConnections.add(connKey);

          if (this.seenConnections.size > 2000) this.seenConnections.clear();

          const domain = await this.resolveIp(dstIp);
          let proto = parts[0].includes('udp') ? 'UDP' : 'TCP';
          let method = `PORT ${dstPort}`;

          if (dstPort === '443') { proto = 'HTTPS'; method = 'TLS'; }
          else if (dstPort === '80') { proto = 'HTTP'; method = 'GET'; }
          
          this.callback({ 
            proto, 
            method, 
            domain, 
            sourceIp: srcIp, 
            ip: srcIp === '127.0.0.1' ? dstIp : srcIp,
            time: now 
          });
        } catch (e) { }
      }
    });
  }

  resolveIp(ip) {
    if (this.ipCache[ip]) return Promise.resolve(this.ipCache[ip]);

    // Comprehensive hostname map — sorted by specificity (longer prefixes first)
    const knownHosts = [
      // YouTube / Google Video
      ['208.117.', 'youtube.com'], ['74.125.', 'youtube.com'],
      ['172.217.', 'youtube.com'], ['216.239.', 'google.com'],
      ['142.250.', 'google.com'], ['64.233.', 'google.com'],
      ['66.102.', 'google.com'], ['34.', 'google-cloud.com'],
      ['35.', 'google-cloud.com'],
      // Apple
      ['17.', 'apple.com'],
      // Discord
      ['162.159.', 'discord.com'], ['104.16.', 'discord.com'],
      ['104.17.', 'discord.com'], ['104.18.', 'cloudflare.com'],
      ['104.19.', 'cloudflare.com'], ['104.20.', 'cloudflare.com'],
      ['104.21.', 'cloudflare.com'],
      // Cloudflare DNS
      ['1.1.1.', 'cloudflare-dns.com'], ['1.0.0.', 'cloudflare-dns.com'],
      // Facebook / Instagram / WhatsApp
      ['157.240.', 'instagram.com'], ['31.13.', 'facebook.com'],
      ['69.171.', 'facebook.com'],
      // Microsoft
      ['13.107.', 'microsoft.com'], ['52.112.', 'teams.microsoft.com'],
      ['20.', 'azure.microsoft.com'],
      // Amazon / AWS
      ['54.', 'amazonaws.com'], ['52.', 'amazonaws.com'],
      ['3.', 'aws.amazon.com'], ['72.21.', 'amazon.com'],
      // GitHub
      ['185.199.', 'github.io'], ['140.82.', 'github.com'],
      // Fastly CDN
      ['151.101.', 'fastly.net'],
      // Akamai
      ['23.', 'akamai.net'], ['2.16.', 'akamai.net'],
      // Google DNS
      ['8.8.', 'dns.google'],
    ];

    for (const [prefix, host] of knownHosts) {
      if (ip.startsWith(prefix)) {
        this.ipCache[ip] = host;
        return Promise.resolve(host);
      }
    }

    // Fallback: Try reverse DNS
    return new Promise((resolve) => {
      dns.reverse(ip, (err, hostnames) => {
        if (!err && hostnames && hostnames.length > 0) {
          let name = hostnames[0].replace(/\.$/, '');
          // Simplify generic names
          if (name.includes('1e100.net')) name = 'google.com';
          if (name.includes('akamaitechnologies')) name = 'akamai.net';
          if (name.includes('googleusercontent')) name = 'googleusercontent.com';
          this.ipCache[ip] = name;
          resolve(name);
        } else {
          this.ipCache[ip] = ip;
          resolve(ip);
        }
      });
    });
  }

  stop() {
    if (this.pollInterval) {
      clearInterval(this.pollInterval);
      this.pollInterval = null;
    }
    this.seenConnections.clear();
  }
}

module.exports = TrafficSniffer;
