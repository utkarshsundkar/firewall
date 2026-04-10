const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('aegis', {
  // System
  getSystemInfo: () => ipcRenderer.invoke('get-system-info'),
  
  // Firewall
  getFirewallStatus: () => ipcRenderer.invoke('get-firewall-status'),
  toggleFirewall: (enable) => ipcRenderer.invoke('toggle-firewall', enable),
  getFirewallRules: () => ipcRenderer.invoke('get-firewall-rules'),
  addFirewallRule: (rule) => ipcRenderer.invoke('add-firewall-rule', rule),
  removeFirewallRule: (ruleId) => ipcRenderer.invoke('remove-firewall-rule', ruleId),
  
  // IP Blocking
  blockIP: (ip) => ipcRenderer.invoke('block-ip', ip),
  unblockIP: (ip) => ipcRenderer.invoke('unblock-ip', ip),
  
  // App Control
  getRunningApps: () => ipcRenderer.invoke('get-running-apps'),
  getAppRules: () => ipcRenderer.invoke('get-app-rules'),
  setAppRule: (data) => ipcRenderer.invoke('set-app-rule', data),
  getAppDomains: (appName) => ipcRenderer.invoke('get-app-domains', appName),
  getAllAppDomains: () => ipcRenderer.invoke('get-all-app-domains'),

  // Website Blocker
  getBlockedWebsites: () => ipcRenderer.invoke('get-blocked-websites'),
  blockWebsite: (data) => ipcRenderer.invoke('block-website', data),
  unblockWebsite: (domain) => ipcRenderer.invoke('unblock-website', domain),

  // Device Manager
  getDevices: () => ipcRenderer.invoke('get-devices'),
  scanNetwork: () => ipcRenderer.invoke('scan-network'),
  setDeviceRule: (data) => ipcRenderer.invoke('set-device-rule', data),
  getDeviceStats: () => ipcRenderer.invoke('get-device-stats'),
  removeDevice: (ip) => ipcRenderer.invoke('remove-device', ip),
  onScanProgress: (cb) => ipcRenderer.on('scan-progress', (_, data) => cb(data)),
  startDeviceMonitor: (ip) => ipcRenderer.invoke('start-device-monitor', ip),
  stopDeviceMonitor: () => ipcRenderer.invoke('stop-device-monitor'),
  onDevicePacket: (cb) => ipcRenderer.on('device-packet', (_, pkt) => cb(pkt)),

  // Network & Connections
  getNetworkStats: () => ipcRenderer.invoke('get-network-stats'),
  getConnections: () => ipcRenderer.invoke('get-connections'),
  
  // Threats
  getThreatLog: () => ipcRenderer.invoke('get-threat-log'),
  clearThreats: () => ipcRenderer.invoke('clear-threats'),
  
  // WAF
  getWafLog: () => ipcRenderer.invoke('get-waf-log'),
  toggleWaf: (enabled) => ipcRenderer.invoke('toggle-waf', enabled),
  
  // Real-time events
  onNetworkData: (callback) => ipcRenderer.on('network-data', (_, data) => callback(data)),
  onThreatAlert: (callback) => ipcRenderer.on('threat-alert', (_, alert) => callback(alert)),
  onWafThreat: (callback) => ipcRenderer.on('waf-threat', (_, threat) => callback(threat)),
  onDevicePacket: (callback) => ipcRenderer.on('device-packet', (_, packet) => callback(packet)),
  
  // Window controls
  minimize: () => ipcRenderer.send('window-minimize'),
  maximize: () => ipcRenderer.send('window-maximize'),
  close: () => ipcRenderer.send('window-close'),

  // Enterprise Fleet
  entStartServer: () => ipcRenderer.invoke('enterprise:start-server'),
  entStopServer: () => ipcRenderer.invoke('enterprise:stop-server'),
  entConnectAgent: (ip) => ipcRenderer.invoke('enterprise:connect-agent', ip),
  entDisconnectAgent: () => ipcRenderer.invoke('enterprise:disconnect-agent'),
  entBlockAgent: (agentId, targetIp) => ipcRenderer.invoke('enterprise:block-agent', { agentId, targetIp }),
  entToggleFirewall: (agentId, enabled) => ipcRenderer.invoke('enterprise:toggle-firewall', { agentId, enabled }),
  entSetAppRule: (agentId, appName, action) => ipcRenderer.invoke('enterprise:set-app-rule', { agentId, appName, action }),
  entBlockWebsite: (agentId, domain) => ipcRenderer.invoke('enterprise:block-website', { agentId, domain }),
  entRequestFullState: (agentId) => ipcRenderer.invoke('enterprise:request-full-state', agentId),
  entBroadcastWebsiteBlock: (domain) => ipcRenderer.invoke('enterprise:broadcast-website-block', { domain }),
  entBroadcastWebsiteUnblock: (domain) => ipcRenderer.invoke('enterprise:broadcast-website-unblock', { domain }),
  entBroadcastToggleFirewall: (enabled) => ipcRenderer.invoke('enterprise:broadcast-toggle-firewall', { enabled }),
  onEntStatus: (cb) => ipcRenderer.on('enterprise-status', (_, data) => cb(data)),
  onEntAgentsUpdated: (cb) => ipcRenderer.on('enterprise-agents-updated', (_, agents) => cb(agents)),
  onEntAgentPacket: (cb) => ipcRenderer.on('enterprise-agent-packet', (_, data) => cb(data)),
  onEntAgentState: (cb) => ipcRenderer.on('enterprise-agent-state', (_, data) => cb(data)),
  
  platform: process.platform
});
