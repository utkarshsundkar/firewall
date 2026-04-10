const WebSocket = require('ws');
const os = require('os');
const { app } = require('electron');

class EnterpriseManager {
  constructor(mainWindow, services) {
    this.mainWindow = mainWindow;
    this.deviceManager = services.deviceManager;
    this.firewallController = services.firewallController;
    this.appController = services.appController;
    this.websiteBlocker = services.websiteBlocker;
    
    this.mode = 'standalone'; // 'standalone', 'server', 'agent'
    this.server = null;
    this.socket = null; // Agent socket
    
    this.agents = new Map(); // Store connected agents when in server mode
    
    this.syncInterval = null;
  }

  // Starts the Admin WebSocket Server
  async startServer() {
    this.mode = 'server';
    const port = 8080;
    
    this.server = new WebSocket.Server({ port });
    
    this.server.on('connection', (ws, req) => {
      const ip = req.socket.remoteAddress.replace(/^.*:/, '');
      const id = Date.now().toString(36) + Math.random().toString(36).substr(2);
      
      console.log(`[FLEET SERVER] New agent connecting from ${ip}. Assigning ID: ${id}`);
      
      const agent = { id, ip, hostname: 'Unknown Agent', os: 'Unknown', status: 'online', logs: [] };
      this.agents.set(id, { ws, data: agent });

      ws.on('message', (message) => {
        try {
          const payload = JSON.parse(message);
          console.log(`[FLEET SERVER] Msg from ${id}: ${payload.type}`);
          this.handleAgentMessage(id, payload);
        } catch (e) {
          console.error('Enterprise: Error parsing agent message', e);
        }
      });

      ws.on('close', () => {
        console.log(`[FLEET SERVER] Agent ${id} disconnected.`);
        const ag = this.agents.get(id);
        if (ag) ag.data.status = 'offline';
        this.broadcastAgents(); // notify UI
        setTimeout(() => this.agents.delete(id), 60000); // cleanup later
      });
      
      // Request initial handshake
      console.log(`[FLEET SERVER] Requesting handshake from ${id}...`);
      ws.send(JSON.stringify({ type: 'HANDSHAKE_REQ' }));
    });
    
    const localIps = this.getLocalIps();
    let globalUrl = null;

    try {
      const localtunnel = require('localtunnel');
      this.tunnel = await localtunnel({ port });
      // Convert https://xyz.loca.lt to wss://xyz.loca.lt
      globalUrl = this.tunnel.url.replace(/^http/, 'ws');
    } catch (e) {
      console.warn('Localtunnel failed to start:', e);
    }

    return { success: true, ips: localIps, port, globalUrl };
  }

  stopServer() {
    if (this.tunnel) {
      this.tunnel.close();
      this.tunnel = null;
    }
    if (this.server) {
      this.server.close();
      this.server = null;
    }
    this.mode = 'standalone';
    this.agents.clear();
  }

  // Called when this machine acts as an Agent and connects to the Admin
  connectToAdmin(connectStr) {
    this.mode = 'agent';
    
    // Normalize URL
    let wsUrl = connectStr.trim();
    if (!wsUrl.includes('://')) {
      wsUrl = `ws://${wsUrl}${wsUrl.includes(':') ? '' : ':8080'}`;
    }
    
    // Force secure protocol if using localtunnel
    if (wsUrl.startsWith('https://')) {
      wsUrl = wsUrl.replace('https://', 'wss://');
    }

    console.log(`[AGENT] Attempting connection to: ${wsUrl}`);

    try {
      // Bypassing Localtunnel Interstitial Page
      const options = {
        headers: {
          'Bypass-Tunnel-Reminder': 'true',
          'User-Agent': 'Aegis-Fleet-Agent'
        },
        timeout: 10000
      };

      this.socket = new WebSocket(wsUrl, options);
      
      this.socket.on('open', () => {
        console.log(`[AGENT] Connected to Admin at ${wsUrl}`);
        this.mainWindow.webContents.send('enterprise-status', { connected: true, server: wsUrl });
        this.startAgentSync();
      });

      this.socket.on('message', async (data) => {
        try {
          const msg = JSON.parse(data);
          if (msg.type === 'HANDSHAKE_REQ') {
             this.socket.send(JSON.stringify({
                type: 'HANDSHAKE_ACK',
                hostname: os.hostname(),
                os: os.platform() + ' ' + os.release()
             }));
          } else if (msg.type === 'REQUEST_FULL_STATE') {
             // Admin wants to see everything
             const runningApps = await this.appController.getRunningApps();
             const appRules    = await this.appController.getAppRules();
             
             // Merge running apps into rules for UI mapping
             const combinedApps = runningApps.map(app => {
                const rule = appRules.find(r => r.appName.toLowerCase() === app.name.toLowerCase());
                return { 
                  appName: app.name, 
                  path: app.path, 
                  action: rule ? rule.action : 'allow',
                  icon: rule ? rule.icon : '📱',
                  category: rule ? rule.category : 'Application'
                };
             });

             const state = {
               type: 'FULL_STATE_UPDATE',
               firewallRules: await this.firewallController.getRules(),
               appRules: combinedApps,
               blockedWebsites: await this.websiteBlocker.getBlockedList(),
               stats: { load: os.loadavg()[0], freeMem: os.freemem(), platform: os.platform() }
             };
             this.socket.send(JSON.stringify(state));
          } else if (msg.type === 'EXEC_BLOCK') {
             this.deviceManager.addBlockRule(msg.targetIp, 'Admin command');
          } else if (msg.type === 'SET_FIREWALL_STATE') {
             await this.firewallController.toggle(msg.enabled);
             // Trigger a refresh
             this.socket.send(JSON.stringify({ type: 'FULL_STATE_UPDATE', firewallRules: await this.firewallController.getRules() }));
          } else if (msg.type === 'SET_APP_RULE') {
             await this.appController.setRule(msg.appName, msg.action);
             await this.websiteBlocker.blockAppDomains(msg.appName, msg.action);
             this.socket.send(JSON.stringify({ type: 'FULL_STATE_UPDATE', appRules: await this.appController.getAppRules() }));
          } else if (msg.type === 'BLOCK_WEBSITE') {
              console.log(`[AGENT] Received Remote Block Request: ${msg.domain}`);
              try {
                const res = await this.websiteBlocker.blockDomain(msg.domain, 'Admin Remote Block');
                console.log(`[AGENT] Block Result for ${msg.domain}:`, res);
                this.socket.send(JSON.stringify({ type: 'FULL_STATE_UPDATE', blockedWebsites: await this.websiteBlocker.getBlockedList() }));
              } catch (err) {
                console.error(`[AGENT] Failed to block ${msg.domain}:`, err);
              }
          }
        } catch (e) {
          console.error('Agent message error:', e);
        }
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
      this.safeSend('enterprise-agent-packet', { agentId, packet: payload.packet });
    }
    else if (payload.type === 'FULL_STATE_UPDATE') {
      this.safeSend('enterprise-agent-state', { agentId, state: payload });
    }
  }

  broadcastAgents() {
    if (this.mode !== 'server') return;
    const array = Array.from(this.agents.values()).map(a => a.data);
    this.safeSend('enterprise-agents-updated', array);
  }

  safeSend(channel, data) {
    try {
      if (this.mainWindow && !this.mainWindow.isDestroyed() && !this.mainWindow.webContents.isDestroyed()) {
        this.mainWindow.webContents.send(channel, data);
      }
    } catch (e) {
      // Ignore disposition errors
    }
  }

  // Admin sending a command to an agent
  sendCommandToAgent(agentId, type, payload) {
    const ag = this.agents.get(agentId);
    if (ag && ag.ws.readyState === WebSocket.OPEN) {
      ag.ws.send(JSON.stringify({ type, ...payload }));
    }
  }

  // Pushes a command to ALL connected agents simultaneously
  broadcastCommand(type, payload) {
    if (this.mode !== 'server') {
      console.warn('Cannot broadcast: Not in server mode');
      return false;
    }
    
    console.log(`[FLEET BROADCAST] Pulsing command ${type} to system...`);
    
    const msg = JSON.stringify({ type, ...payload });
    let count = 0;
    
    this.agents.forEach((ag, id) => {
      if (ag.ws && ag.ws.readyState === WebSocket.OPEN) {
        ag.ws.send(msg);
        count++;
        console.log(` -> Sent to agent ${id} (${ag.data.hostname})`);
      }
    });

    if (count === 0) {
      this.safeSend('threat-alert', { 
        title: 'Fleet Management', 
        message: 'Broadcast failed: No active agents connected.', 
        severity: 'medium' 
      });
    } else {
      this.safeSend('threat-alert', { 
        title: 'Policy Enforced', 
        message: `Successfully pushed policy to ${count} active agents.`, 
        severity: 'low' 
      });
    }

    console.log(`[FLEET BROADCAST] Completed. Reached ${count} active agents.`);
    return true;
  }

  /* ── AGENT LOGIC ───────────────────────────────────────────── */
  // (Inside the message handler around line 130+)
  // I need to find the agent message handler again.


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
