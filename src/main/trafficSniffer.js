const { exec, spawn } = require('child_process');
const fs = require('fs');
const dns = require('dns');

class TrafficSniffer {
  constructor() {
    this.tailProcess = null;
    this.logFile = '/tmp/aegis_sniff.log';
    this.ipCache = {};
  }

  async start(targetIp, callback) {
    this.stop();
    
    // reset log file
    if (fs.existsSync(this.logFile)) {
      try { fs.unlinkSync(this.logFile); } catch(e){}
    }
    fs.writeFileSync(this.logFile, '');

    if (process.platform === 'darwin') {
      let iface = 'any'; // Listen on all interfaces (including bridge100 for internet sharing)

      // 1) Run tcpdump as background root process. Native macOS auth dialog will appear!
      // If targetIp is provided, filter for it, otherwise capture all web traffic
      const filter = targetIp ? `host ${targetIp} and (port 53 or port 80 or port 443)` : `(port 53 or port 80 or port 443)`;
      const cmd = `tcpdump -l -i ${iface} -n \\"${filter}\\" > ${this.logFile} 2>&1 &`;
      const osa = `osascript -e 'do shell script "${cmd}" with administrator privileges'`;
      
      exec(osa, (err, stdout, stderr) => {
        if (err) {
            console.error("TrafficSniffer: Auth failed or cancelled", err);
            callback({ proto: 'SYS', method: 'ERR', domain: 'Admin access required to capture packets', time: new Date().toLocaleTimeString('en-US', {hour12:false}) });
        }
      });
      
      // 2) Start tailing the dump file
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

    // Check for DNS query
    if (line.includes(' A? ') || line.includes(' AAAA? ')) {
       const match = line.match(/A\??\s+([a-zA-Z0-9.-]+)\./);
       if (match) {
           return { proto: 'DNS', method: 'Query', domain: match[1], time };
       }
    }

    // Check for HTTP/HTTPS outward packets
    if (line.includes(`IP ${targetIp}.`) && line.includes(' > ')) {
        const parts = line.split(' > ');
        if (parts.length < 2) return null;
        
        // Match destination IP and port
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
      return new Promise((resolve) => {
          dns.reverse(ip, (err, hostnames) => {
              if (!err && hostnames && hostnames.length > 0) {
                  const name = hostnames[0].replace(/\.$/, '');
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
