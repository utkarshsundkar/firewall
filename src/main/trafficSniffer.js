const { exec, spawn } = require('child_process');
const fs = require('fs');
const dns = require('dns');

class TrafficSniffer {
  constructor() {
    this.tailProcess = null;
    this.logFile = `/tmp/aegis_sniff_${Date.now()}.log`;
    this.ipCache = {};
  }

  async start(targetIp, callback) {
    this.stop();
    
    // ensure log file exists and is writable
    try { fs.writeFileSync(this.logFile, ''); } catch(e){ console.error("Log init failed", e); }

    if (process.platform === 'darwin') {
      let iface = 'any'; // Listen on all interfaces (including bridge100 for internet sharing)

      // Write a shell script to disk and execute it — avoids all quoting/escaping issues
      const scriptPath = `/tmp/aegis_capture_${Date.now()}.sh`;
      const filter = targetIp ? `host ${targetIp} and \\( port 53 or port 80 or port 443 \\)` : `port 53 or port 80 or port 443`;
      const scriptContent = `#!/bin/bash\ntcpdump -l -i any -n ${filter} > "${this.logFile}" 2>/dev/null &\n`;
      
      try { fs.writeFileSync(scriptPath, scriptContent, { mode: 0o755 }); } catch(e) { console.error('Script write failed', e); }
      
      const osa = `osascript -e 'do shell script "bash ${scriptPath}" with administrator privileges'`;
      
      console.log("[TrafficSniffer] Requesting admin privileges for tcpdump...");
      exec(osa, { timeout: 30000 }, (err) => {
        if (err && err.signal !== 'SIGTERM') {
            console.error("TrafficSniffer: Auth failed", err.message);
            callback({ proto: 'SYS', method: 'ERR', domain: 'Capture auth failed — accept the admin prompt.', time: new Date().toLocaleTimeString('en-US', {hour12:false}) });
        } else {
            console.log("[TrafficSniffer] Capture started successfully.");
        }
        try { fs.unlinkSync(scriptPath); } catch(e) {}
      });
      
      // 2) Start tailing the dump file after a short delay
      setTimeout(() => {
        this.tailProcess = spawn('tail', ['-f', this.logFile]);
        let buffer = '';

        this.tailProcess.stdout.on('data', async (data) => {
          buffer += data.toString();
          let lines = buffer.split('\n');
          buffer = lines.pop(); // keep last incomplete line
          
          for (let line of lines) {
             const parsed = await this.parseLine(line, targetIp);
             if (parsed) callback(parsed);
          }
        });
      }, 2000);

      
    } else {
        // Mock fallback for non-mac environments
        setInterval(() => {
            callback({ proto: 'SYS', method: 'N/A', domain: 'Windows packet capture requires Npcap (not installed).', time: new Date().toLocaleTimeString('en-US', {hour12:false}) });
        }, 5000);
    }
  }

  async parseLine(line, targetIp) {
    line = line.trim();
    if (!line || line.includes('tcpdump: ')) return null;

    // Pattern: 14:03:32.123456 IP 192.168.1.5.54321 > 8.8.8.8.53: 1234+ A? google.com. (28)
    const timeMatch = line.match(/^(\d{2}:\d{2}:\d{2})\.\d+/);
    if (!timeMatch) return null;
    const time = timeMatch[1];

    // Check for DNS query (Port 53)
    if (line.includes('.53: ') || line.includes(' A? ') || line.includes(' AAAA? ')) {
       const match = line.match(/A\??\s+([a-zA-Z0-9.-]+)\./);
       if (match) {
           return { proto: 'DNS', method: 'Query', domain: match[1], time };
       }
    }

    // Check for HTTP/HTTPS outward packets 
    // Generic match: IP [ANY] > [ANY].[PORT]:
    if (line.includes(' > ')) {
        const parts = line.split(' > ');
        if (parts.length < 2) return null;
        
        // Match destination IP and port from the second part
        const dstMatch = parts[1].match(/^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\.(\d+):/);
        if (dstMatch) {
            const dstIp = dstMatch[1];
            const port = dstMatch[2];
            
            if (port === '443') {
                return { proto: 'HTTPS', method: 'TLS', domain: await this.resolveIp(dstIp), time };
            } else if (port === '80') {
                return { proto: 'HTTP', method: 'GET', domain: await this.resolveIp(dstIp), time };
            }
        }
    }

    return null;
  }
  
  resolveIp(ip) {
      if (this.ipCache[ip]) return Promise.resolve(this.ipCache[ip]);
      
      // Known popular IP blocks — broad ranges for major services
      const commonSites = {
          '216.239.': 'google.com',
          '172.217.': 'google.com',
          '142.250.': 'google.com',
          '74.125.': 'google.com',
          '64.233.': 'google.com',
          '66.102.': 'google.com',
          '17.': 'apple.com',
          '23.': 'akamai.net',
          '72.21.': 'amazon-cdn.net',
          '54.': 'amazonaws.com',
          '151.101.': 'fastly.net',
          '104.16.': 'cloudflare.com',
          '104.17.': 'cloudflare.com',
          '104.18.': 'cloudflare.com',
          '104.19.': 'cloudflare.com',
          '185.199.': 'github.io',
          '140.82.': 'github.com',
          '13.107.': 'microsoft.com',
          '52.112.': 'microsoft.com',
          '20.': 'azure.microsoft.com',
          '157.240.': 'facebook.com',
          '31.13.': 'facebook.com',
          '8.8.': 'dns.google',
          '1.1.': 'cloudflare-dns.com',
          '34.': 'google-cloud.com',
          '35.': 'google-cloud.com',
      };

      for (let prefix in commonSites) {
          if (ip.startsWith(prefix)) {
              this.ipCache[ip] = commonSites[prefix];
              return Promise.resolve(commonSites[prefix]);
          }
      }

      return new Promise((resolve) => {
          dns.reverse(ip, (err, hostnames) => {
              if (!err && hostnames && hostnames.length > 0) {
                  let name = hostnames[0].replace(/\.$/, '');
                  // Clean up generic CDN names to be more readable
                  if (name.includes('1e100.net')) name = 'google.services';
                  if (name.includes('deploy.static.akamaitechnologies.com')) name = 'akamai.cdn';
                  
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
    if (this.tailProcess) {
      this.tailProcess.kill();
      this.tailProcess = null;
    }
    if (process.platform === 'darwin') {
      exec(`osascript -e 'do shell script "pkill -f tcpdump" with administrator privileges'`);
    }
  }
}
module.exports = TrafficSniffer;
