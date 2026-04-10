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

    // Poll every 2 seconds using lsof
    this.pollInterval = setInterval(() => {
      this._pollConnections();
    }, 2000);

    // First poll immediately
    setTimeout(() => this._pollConnections(), 500);
  }

  _pollConnections() {
    const cmd = `lsof -i tcp -n -P 2>/dev/null | grep -E 'ESTABLISHED|SYN_SENT'`;
    exec(cmd, { timeout: 5000 }, async (err, stdout) => {
      if (err || !stdout) return;

      const lines = stdout.trim().split('\n');
      const now = new Date().toLocaleTimeString('en-US', { hour12: false });

      for (const line of lines) {
        try {
          // lsof format: COMMAND   PID   USER   FD   TYPE   DEVICE   SIZE   NODE   NAME
          // NAME is like: 192.168.1.5:55234->142.250.68.142:443 (ESTABLISHED)
          const nameMatch = line.match(/(\d+\.\d+\.\d+\.\d+):(\d+)->(\d+\.\d+\.\d+\.\d+):(\d+)/);
          if (!nameMatch) continue;

          const srcIp = nameMatch[1];
          const dstIp = nameMatch[3];
          const dstPort = nameMatch[4];

          // Filter to only outbound connections (not loopback)
          if (dstIp === '127.0.0.1' || dstIp === '::1') continue;
          if (this.targetIp && srcIp !== this.targetIp && dstIp !== this.targetIp) continue;

          const connKey = `${srcIp}:${nameMatch[2]}->${dstIp}:${dstPort}`;
          if (this.seenConnections.has(connKey)) continue;
          this.seenConnections.add(connKey);

          // Cap seen set size
          if (this.seenConnections.size > 500) {
            // Clear oldest entries
            const iter = this.seenConnections.values();
            for (let i = 0; i < 100; i++) this.seenConnections.delete(iter.next().value);
          }

          const domain = await this.resolveIp(dstIp);
          let proto = 'TCP';
          let method = `PORT ${dstPort}`;

          if (dstPort === '443') { proto = 'HTTPS'; method = 'TLS'; }
          else if (dstPort === '80') { proto = 'HTTP'; method = 'GET'; }
          else if (dstPort === '53') { proto = 'DNS'; method = 'Query'; }

          this.callback({ proto, method, domain, sourceIp: srcIp, time: now });
        } catch (e) { /* skip malformed lines */ }
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
