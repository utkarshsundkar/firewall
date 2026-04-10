const WebSocket = require('ws');
const os = require('os');
const { app } = require('electron');

class EnterpriseManager {
  constructor(mainWindow, deviceManager) {
    this.mainWindow = mainWindow;
    this.deviceManager = deviceManager;
    
    this.mode = 'standalone'; // 'standalone', 'server', 'agent'
    this.server = null;
    this.socket = null; // Agent socket
    
    this.agents = new Map(); // Store connected agents when in server mode
    
    this.syncInterval = null;
  }

  // Starts the Admin WebSocket Server
  startServer() {
    this.mode = 'server';
    const port = 8080;
    
    this.server = new WebSocket.Server({ port });
    
    this.server.on('connection', (ws, req) => {
      const ip = req.socket.remoteAddress.replace(/^.*:/, '');
      const id = Date.now().toString(36) + Math.random().toString(36).substr(2);
      
      const agent = { id, ip, hostname: 'Unknown Agent', os: 'Unknown', status: 'online', logs: [] };
      this.agents.set(id, { ws, data: agent });

      ws.on('message', (message) => {
        try {
          const payload = JSON.parse(message);
          this.handleAgentMessage(id, payload);
        } catch (e) {
          console.error('Enterprise: Error parsing agent message', e);
        }
      });

      ws.on('close', () => {
        const ag = this.agents.get(id);
        if (ag) ag.data.status = 'offline';
        this.broadcastAgents(); // notify UI
        setTimeout(() => this.agents.delete(id), 60000); // cleanup later
      });
      
      // Request initial handshake
      ws.send(JSON.stringify({ type: 'HANDSHAKE_REQ' }));
    });
    
    const localIps = this.getLocalIps();
    return { success: true, ips: localIps, port };
  }

  stopServer() {
    if (this.server) {
      this.server.close();
      this.server = null;
    }
    this.mode = 'standalone';
    this.agents.clear();
  }

  // Called when this machine acts as an Agent and connects to the Admin
  connectToAdmin(adminIp) {
    this.mode = 'agent';
    const numIp = adminIp.includes(':') ? adminIp : `${adminIp}:8080`;
    
    try {
      this.socket = new WebSocket(`ws://${numIp}`);
      
      this.socket.on('open', () => {
        this.mainWindow.webContents.send('enterprise-status', { connected: true, server: numIp });
        this.startAgentSync();
      });

      this.socket.on('message', (data) => {
        try {
          const msg = JSON.parse(data);
          if (msg.type === 'HANDSHAKE_REQ') {
             this.socket.send(JSON.stringify({
                type: 'HANDSHAKE_ACK',
                hostname: os.hostname(),
                os: os.platform() + ' ' + os.release()
             }));
          } else if (msg.type === 'EXEC_BLOCK') {
             // Admin told us to block an IP locally
             this.deviceManager.addBlockRule(msg.targetIp, 'Admin command');
          }
        } catch (e) {}
      });

      this.socket.on('close', () => {
        this.mainWindow.webContents.send('enterprise-status', { connected: false });
        this.stopAgentSync();
      });

      this.socket.on('error', (err) => {
        console.error('Agent connection error', err);
      });

      return { success: true };
    } catch (e) {
      return { success: false, error: e.message };
    }
  }

  disconnectFromAdmin() {
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
    this.mode = 'standalone';
    this.stopAgentSync();
  }

  /* ── ADMIN/SERVER LOGIC ────────────────────────────────────── */
  handleAgentMessage(agentId, payload) {
    const agentNode = this.agents.get(agentId);
    if (!agentNode) return;
    
    if (payload.type === 'HANDSHAKE_ACK') {
      agentNode.data.hostname = payload.hostname;
      agentNode.data.os = payload.os;
      this.broadcastAgents();
    }
    else if (payload.type === 'TELEMETRY') {
      agentNode.data.stats = payload.stats; // like cpu, mem, etc.
      agentNode.data.connections = payload.connections;
      this.broadcastAgents();
    }
    else if (payload.type === 'PACKET_LOG') {
      // Forward this packet log to the Admin UI
      this.mainWindow.webContents.send('enterprise-agent-packet', { agentId, packet: payload.packet });
    }
  }

  broadcastAgents() {
    if (this.mode !== 'server') return;
    const array = Array.from(this.agents.values()).map(a => a.data);
    this.mainWindow.webContents.send('enterprise-agents-updated', array);
  }

  // Admin sending a command to an agent
  sendCommandToAgent(agentId, type, payload) {
    const ag = this.agents.get(agentId);
    if (ag && ag.ws.readyState === WebSocket.OPEN) {
      ag.ws.send(JSON.stringify({ type, ...payload }));
    }
  }

  /* ── AGENT LOGIC ───────────────────────────────────────────── */
  startAgentSync() {
    if (this.syncInterval) clearInterval(this.syncInterval);
    
    // Sync telemetry every 5 seconds
    this.syncInterval = setInterval(async () => {
      if (this.socket && this.socket.readyState === WebSocket.OPEN) {
        
        // In a real scenario we would gather real conn info, picking a few summary numbers
        const telemetry = {
          type: 'TELEMETRY',
          stats: { load: os.loadavg()[0], freeMem: os.freemem() }
        };
        this.socket.send(JSON.stringify(telemetry));
      }
    }, 5000);
  }

  stopAgentSync() {
    if (this.syncInterval) clearInterval(this.syncInterval);
    this.syncInterval = null;
  }
  
  // Forward packets caught by local traffic sniffer to admin (if running)
  forwardPacketToAdmin(packet) {
    if (this.mode === 'agent' && this.socket && this.socket.readyState === WebSocket.OPEN) {
        this.socket.send(JSON.stringify({ type: 'PACKET_LOG', packet }));
    }
  }

  /* ── UTILS ─────────────────────────────────────────────────── */
  getLocalIps() {
    const nets = os.networkInterfaces();
    const results = [];
    for (const name of Object.keys(nets)) {
      for (const net of nets[name]) {
        if (net.family === 'IPv4' && !net.internal) {
          results.push(net.address);
        }
      }
    }
    return results;
  }
}

module.exports = EnterpriseManager;
