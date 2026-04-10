const { app, BrowserWindow, ipcMain, Tray, Menu, nativeImage, dialog } = require('electron');
const path = require('path');
const os = require('os');
const { exec, spawn } = require('child_process');
const fs = require('fs');
const NetworkMonitor = require('./networkMonitor');
const FirewallController = require('./firewallController');
const AttackDetector = require('./attackDetector');
const AppController = require('./appController');
const WebsiteBlocker = require('./websiteBlocker');
const DeviceManager = require('./deviceManager');
const TrafficSniffer = require('./trafficSniffer');
const EnterpriseManager = require('./enterprise');

let mainWindow;
let tray;
let networkMonitor;
let firewallController;
let attackDetector;
let appController;
let websiteBlocker;
let deviceManager;
let trafficSniffer;
let enterpriseManager;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1100,
    minHeight: 700,
    frame: false,
    titleBarStyle: 'hidden',
    trafficLightPosition: { x: 16, y: 16 },
    backgroundColor: '#0a0e1a',
    icon: path.join(__dirname, '../../assets/icon.png'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    },
    show: false
  });

  mainWindow.loadFile(path.join(__dirname, '../../renderer/index.html'));

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

function setupTray() {
  try {
    const iconPath = path.join(__dirname, '../../assets/tray-icon.png');
    if (fs.existsSync(iconPath)) {
      const trayIcon = nativeImage.createFromPath(iconPath);
      tray = new Tray(trayIcon.resize({ width: 16, height: 16 }));
    } else {
      tray = new Tray(nativeImage.createEmpty());
    }
    const contextMenu = Menu.buildFromTemplate([
      { label: 'Open Aegis Firewall', click: () => { if (mainWindow) mainWindow.show(); } },
      { type: 'separator' },
      { label: 'Quit', click: () => app.quit() }
    ]);
    tray.setToolTip('Aegis Firewall - Active');
    tray.setContextMenu(contextMenu);
    tray.on('click', () => { if (mainWindow) mainWindow.show(); });
  } catch (e) {
    console.log('Tray setup skipped:', e.message);
  }
}

function initServices() {
  networkMonitor = new NetworkMonitor();
  firewallController = new FirewallController();
  attackDetector = new AttackDetector();
  appController = new AppController();
  websiteBlocker = new WebsiteBlocker();
  deviceManager  = new DeviceManager();
  trafficSniffer = new TrafficSniffer();
  enterpriseManager = new EnterpriseManager(mainWindow, deviceManager);

  // Start network monitoring - push data to renderer
  networkMonitor.start((data) => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('network-data', data);
    }
  });

  attackDetector.start((alert) => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('threat-alert', alert);
    }
  });
}

// IPC Handlers
ipcMain.handle('get-system-info', async () => {
  return {
    platform: process.platform,
    hostname: os.hostname(),
    arch: os.arch(),
    cpus: os.cpus().length,
    totalMem: os.totalmem(),
    freeMem: os.freemem(),
    uptime: os.uptime(),
    networkInterfaces: os.networkInterfaces()
  };
});

ipcMain.handle('get-firewall-status', async () => {
  return firewallController.getStatus();
});

ipcMain.handle('toggle-firewall', async (event, enable) => {
  return firewallController.toggle(enable);
});

ipcMain.handle('get-firewall-rules', async () => {
  return firewallController.getRules();
});

ipcMain.handle('add-firewall-rule', async (event, rule) => {
  return firewallController.addRule(rule);
});

ipcMain.handle('remove-firewall-rule', async (event, ruleId) => {
  return firewallController.removeRule(ruleId);
});

ipcMain.handle('get-running-apps', async () => {
  return appController.getRunningApps();
});

ipcMain.handle('get-app-rules', async () => {
  return appController.getAppRules();
});

ipcMain.handle('set-app-rule', async (event, { appName, action }) => {
  // Block/unblock at OS firewall level
  const result = await appController.setRule(appName, action);
  // Also block/unblock all known domains for this app via hosts
  await websiteBlocker.blockAppDomains(appName, action);
  return result;
});

// Website Blocker IPC
ipcMain.handle('get-blocked-websites', async () => {
  return websiteBlocker.getBlockedList();
});

ipcMain.handle('block-website', async (event, { domain, reason }) => {
  return websiteBlocker.blockDomain(domain, reason);
});

ipcMain.handle('unblock-website', async (event, domain) => {
  return websiteBlocker.unblockDomain(domain);
});

ipcMain.handle('get-app-domains', async (event, appName) => {
  return websiteBlocker.getAppDomains(appName);
});

ipcMain.handle('get-all-app-domains', async () => {
  return websiteBlocker.getAllAppDomains();
});

// Device Manager IPC
ipcMain.handle('get-devices', async () => {
  return deviceManager.getDevices();
});

ipcMain.handle('scan-network', async (event) => {
  return new Promise((resolve) => {
    deviceManager.scanNetwork((progress) => {
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('scan-progress', progress);
      }
    }).then(resolve);
  });
});

ipcMain.handle('set-device-rule', async (event, { ip, action }) => {
  return deviceManager.setDeviceRule(ip, action);
});

ipcMain.handle('get-device-stats', async () => {
  return deviceManager.getDeviceStats();
});

ipcMain.handle('remove-device', async (event, ip) => {
  return deviceManager.removeDevice(ip);
});

// Traffic Sniffer IPC
ipcMain.handle('start-device-monitor', async (event, ip) => {
  trafficSniffer.start(ip, (packet) => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('device-packet', packet);
    }
  });
  return true;
});

ipcMain.handle('stop-device-monitor', async () => {
  trafficSniffer.stop();
  return true;
});

ipcMain.handle('get-threat-log', async () => {
  return attackDetector.getThreatLog();
});

ipcMain.handle('block-ip', async (event, ip) => {
  return firewallController.blockIP(ip);
});

ipcMain.handle('unblock-ip', async (event, ip) => {
  return firewallController.unblockIP(ip);
});

ipcMain.handle('get-network-stats', async () => {
  return networkMonitor.getStats();
});

ipcMain.handle('get-connections', async () => {
  return networkMonitor.getActiveConnections();
});

ipcMain.handle('clear-threats', async () => {
  return attackDetector.clearLog();
});

// Enterprise Fleet IPC
ipcMain.handle('enterprise:start-server', async () => {
  return enterpriseManager.startServer();
});
ipcMain.handle('enterprise:stop-server', async () => {
  return enterpriseManager.stopServer();
});
ipcMain.handle('enterprise:connect-agent', async (event, ip) => {
  return enterpriseManager.connectToAdmin(ip);
});
ipcMain.handle('enterprise:disconnect-agent', async () => {
  return enterpriseManager.disconnectFromAdmin();
});
ipcMain.handle('enterprise:block-agent', async (event, { agentId, targetIp }) => {
  enterpriseManager.sendCommandToAgent(agentId, 'EXEC_BLOCK', { targetIp });
  return true;
});

ipcMain.on('window-minimize', () => { if (mainWindow) mainWindow.minimize(); });
ipcMain.on('window-maximize', () => {
  if (!mainWindow) return;
  if (mainWindow.isMaximized()) mainWindow.unmaximize();
  else mainWindow.maximize();
});
ipcMain.on('window-close', () => { if (mainWindow) mainWindow.hide(); });

app.whenReady().then(() => {
  createWindow();
  setupTray();
  initServices();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  if (networkMonitor) networkMonitor.stop();
  if (attackDetector) attackDetector.stop();
  if (trafficSniffer) trafficSniffer.stop();
});
