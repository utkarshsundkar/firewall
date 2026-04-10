const { spawn } = require('child_process');
const EventEmitter = require('events');

/**
 * TcpdumpSniffer - Uses raw packet capture to detect high-velocity floods
 * Requires sudo to run in a real environment.
 */
class TcpdumpSniffer extends EventEmitter {
  constructor() {
    super();
    this.process = null;
    this.packetCount = 0;
    this.lastReset = Date.now();
  }

  start(callback) {
    this.stop();
    
    console.log('[TcpdumpSniffer] Starting deep packet inspection...');

    // tcpdump -i any -l -n 
    // -l: line buffered
    // -n: don't resolve hostnames (fast)
    // -t: don't print timestamp
    this.process = spawn('tcpdump', ['-i', 'any', '-l', '-n', '-t']);

    this.process.stdout.on('data', (data) => {
      const lines = data.toString().split('\n');
      lines.forEach(line => {
        if (!line.trim()) return;
        
        // Example: IP 127.0.0.1.55234 > 127.0.0.1.443: Flags [S]
        const match = line.match(/IP (\d+\.\d+\.\d+\.\d+)\.?\d* > (\d+\.\d+\.\d+\.\d+)\.?\d*/);
        if (match) {
          const srcIp = match[1];
          const dstIp = match[2];
          callback({ ip: srcIp === '127.0.0.1' ? dstIp : srcIp, raw: line });
        }
      });
    });

    this.process.stderr.on('data', (data) => {
      const msg = data.toString();
      if (msg.includes('Permission denied')) {
        console.error('[TcpdumpSniffer] ERROR: Permission denied. Please run with sudo or grant terminal access to BPF.');
        this.emit('error', 'Permission denied');
      }
    });

    this.process.on('close', (code) => {
      console.log(`[TcpdumpSniffer] Process exited with code \${code}`);
    });
  }

  stop() {
    if (this.process) {
      this.process.kill();
      this.process = null;
    }
  }
}

module.exports = TcpdumpSniffer;
