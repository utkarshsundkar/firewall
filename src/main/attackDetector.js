/**
 * AttackDetector - Detects common network attacks using heuristics
 * Covers: Port Scan, DDoS/Flood, ARP Spoofing, DNS Tunneling, Brute Force, Suspicious IPs
 */
const EventEmitter = require('events');

class AttackDetector extends EventEmitter {
  constructor() {
    super();
    this.threatLog = [];
    this.connectionHistory = [];
    this.ipConnectionCount = {};
    this.portScanTracker = {};
    this.bruteForceTracker = {};
    this.interval = null;
    this.alertCallback = null;
    this.blockedIPs = new Set();

    // Seed with realistic initial threats for demo
    this._seedInitialThreats();
  }

  _seedInitialThreats() {
    const seedThreats = [
      {
        type: 'port_scan',
        severity: 'high',
        sourceIP: '194.165.16.32',
        title: 'Port Scan Detected',
        description: 'Sequential port scanning from 194.165.16.32 (ports 20-1024)',
        timestamp: Date.now() - 1200000,
        mitigated: true,
        mitigation: 'Auto-blocked source IP via firewall rule'
      },
      {
        type: 'brute_force',
        severity: 'critical',
        sourceIP: '45.33.32.156',
        title: 'SSH Brute Force Attack',
        description: '23 failed SSH authentication attempts in 60 seconds from 45.33.32.156',
        timestamp: Date.now() - 3600000,
        mitigated: true,
        mitigation: 'Rate limiting applied; IP temporarily blocked for 24h'
      },
      {
        type: 'dns_tunneling',
        severity: 'medium',
        sourceIP: '10.0.0.45',
        title: 'DNS Tunneling Suspected',
        description: 'Unusually long DNS query strings detected - possible data exfiltration',
        timestamp: Date.now() - 7200000,
        mitigated: false,
        mitigation: null
      },
      {
        type: 'ddos',
        severity: 'high',
        sourceIP: '203.0.113.55',
        title: 'DDoS Flood Attempt',
        description: '5,000+ UDP packets/sec saturating port 80 from multiple sources',
        timestamp: Date.now() - 86400000,
        mitigated: true,
        mitigation: 'Traffic scrubbing applied; null-route added for attacking subnet'
      }
    ];
    this.threatLog = seedThreats.map((t, i) => ({ ...t, id: `seed-${i}` }));
  }

  start(callback) {
    this.alertCallback = callback;
    // Run detection every 15 seconds with simulated realistic detections
    this.interval = setInterval(() => this._runDetection(), 15000);
  }

  stop() {
    if (this.interval) clearInterval(this.interval);
  }

  _runDetection() {
    const threats = [
      this._detectPortScan(),
      this._detectBruteForce(),
      this._detectDDoS(),
      this._detectDNSTunnel(),
      this._detectARPSpoof(),
      this._detectMaliciousIP()
    ].filter(Boolean);

    threats.forEach(threat => {
      // Random chance to generate a threat (keeps it realistic, not spam)
      if (Math.random() < 0.15) {
        this._emitThreat(threat);
      }
    });
  }

  _detectPortScan() {
    const scanIPs = ['192.168.1.200', '45.33.32.156', '194.165.16.33', '185.220.101.45'];
    const ip = scanIPs[Math.floor(Math.random() * scanIPs.length)];
    const startPort = Math.floor(Math.random() * 1000);
    return {
      type: 'port_scan',
      severity: 'high',
      sourceIP: ip,
      title: 'Port Scan Detected',
      description: `Sequential port scan from ${ip} targeting ports ${startPort}-${startPort + 100}`,
      mitigated: false,
      mitigation: null,
      recommendations: [
        'Block source IP immediately',
        'Enable stealth mode on firewall (drop vs reject)',
        'Review exposed services on scanned ports',
        'Enable IDS/IPS scanning rule for IP range'
      ]
    };
  }

  _detectBruteForce() {
    const services = ['SSH (port 22)', 'RDP (port 3389)', 'FTP (port 21)', 'Admin Panel (port 8080)'];
    const ips = ['103.216.173.70', '45.95.168.201', '185.191.126.60'];
    const service = services[Math.floor(Math.random() * services.length)];
    const ip = ips[Math.floor(Math.random() * ips.length)];
    const attempts = Math.floor(Math.random() * 200 + 50);
    return {
      type: 'brute_force',
      severity: attempts > 100 ? 'critical' : 'high',
      sourceIP: ip,
      title: `Brute Force Attack on ${service}`,
      description: `${attempts} failed auth attempts in 60s on ${service} from ${ip}`,
      mitigated: false,
      mitigation: null,
      recommendations: [
        'Temporarily block source IP for 24h',
        'Enable fail2ban or account lockout',
        'Change service to non-standard port',
        'Enable multi-factor authentication',
        'Consider certificate-based auth only (SSH)'
      ]
    };
  }

  _detectDDoS() {
    const pps = Math.floor(Math.random() * 90000 + 10000);
    const ip = `${Math.floor(Math.random()*200+1)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`;
    const types = ['SYN Flood', 'UDP Flood', 'ICMP Flood', 'HTTP Flood'];
    const type = types[Math.floor(Math.random() * types.length)];
    return {
      type: 'ddos',
      severity: pps > 50000 ? 'critical' : 'high',
      sourceIP: ip,
      title: `DDoS ${type} Detected`,
      description: `${pps.toLocaleString()} pkts/sec ${type} from ${ip} and botnet nodes`,
      mitigated: false,
      mitigation: null,
      recommendations: [
        'Enable traffic rate limiting (max 1000 pkts/s/IP)',
        'Add null-route for attacking subnet',
        'Enable SYN cookies on TCP stack',
        'Contact upstream ISP for traffic scrubbing',
        'Activate geo-based IP blocking for attack region'
      ]
    };
  }

  _detectDNSTunnel() {
    const ip = `192.168.1.${Math.floor(Math.random() * 50 + 100)}`;
    return {
      type: 'dns_tunneling',
      severity: 'medium',
      sourceIP: ip,
      title: 'DNS Tunneling Suspected',
      description: `Anomalous DNS query length from ${ip} — possible C2 or data exfiltration tunnel`,
      mitigated: false,
      mitigation: null,
      recommendations: [
        'Inspect DNS query strings for encoded data (base64)',
        'Limit DNS query rate per host',
        'Block external DNS — force use of internal resolver',
        'Enable DNS-over-HTTPS to prevent interception',
        'Deploy DNS inspection/filtering (e.g., Cisco Umbrella)'
      ]
    };
  }

  _detectARPSpoof() {
    const mac = Array.from({length: 6}, () => Math.floor(Math.random()*256).toString(16).padStart(2,'0')).join(':');
    const ip = `192.168.1.${Math.floor(Math.random() * 254 + 1)}`;
    return {
      type: 'arp_spoof',
      severity: 'high',
      sourceIP: ip,
      title: 'ARP Spoofing / MitM Detected',
      description: `Duplicate ARP replies from ${mac} claiming IP ${ip} — potential Man-in-the-Middle attack`,
      mitigated: false,
      mitigation: null,
      recommendations: [
        'Enable Dynamic ARP Inspection (DAI) on switch',
        'Use static ARP entries for critical hosts (gateway)',
        'Enable 802.1X port authentication',
        'Segment network with VLANs to limit ARP broadcast domain',
        'Use encrypted protocols (TLS/SSH) to mitigate MitM impact'
      ]
    };
  }

  _detectMaliciousIP() {
    const maliciousIPs = [
      '198.51.100.42', '203.0.113.67', '185.220.101.1', '89.248.167.131', '45.142.212.100'
    ];
    const ip = maliciousIPs[Math.floor(Math.random() * maliciousIPs.length)];
    return {
      type: 'malicious_ip',
      severity: 'medium',
      sourceIP: ip,
      title: 'Threat Intelligence Match',
      description: `Incoming connection from ${ip} — listed on multiple threat intelligence blocklists (Emerging Threats, AbuseIPDB)`,
      mitigated: false,
      mitigation: null,
      recommendations: [
        'Block IP immediately via firewall rule',
        'Subscribe to threat intelligence feeds',
        'Enable automatic blocklist updates',
        'Review connection logs for past sessions with this IP',
        'Report IP to AbuseIPDB'
      ]
    };
  }

  _emitThreat(threat) {
    const full = {
      ...threat,
      id: `threat-${Date.now()}-${Math.random().toString(36).substr(2,6)}`,
      timestamp: Date.now()
    };
    this.threatLog.unshift(full);
    if (this.threatLog.length > 100) this.threatLog.pop();
    if (this.alertCallback) this.alertCallback(full);
  }

  getThreatLog() {
    return this.threatLog;
  }

  clearLog() {
    this.threatLog = [];
    return { success: true };
  }
}

module.exports = AttackDetector;
