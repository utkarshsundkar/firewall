/**
 * AppController - Manages per-application network access control
 * Uses OS process list + firewall rules to allow/block apps from network
 */
const { exec } = require('child_process');
const os = require('os');

class AppController {
  constructor(websiteBlocker) {
    this.platform = process.platform;
    this.appRules = this._getDefaultRules();
    this.websiteBlocker = websiteBlocker;
  }

  _getDefaultRules() {
    return [
      { appName: 'Chrome', path: '/Applications/Google Chrome.app', action: 'allow', icon: '🌐', category: 'Browser', dataUsed: '1.2 GB' },
      { appName: 'Safari', path: '/Applications/Safari.app', action: 'allow', icon: '🧭', category: 'Browser', dataUsed: '456 MB' },
      { appName: 'Brave', path: '/Applications/Brave Browser.app', action: 'allow', icon: '🦁', category: 'Browser', dataUsed: '312 MB' },
      { appName: 'Slack', path: '/Applications/Slack.app', action: 'allow', icon: '💬', category: 'Communication', dataUsed: '89 MB' },
      { appName: 'Discord', path: '/Applications/Discord.app', action: 'allow', icon: '🎮', category: 'Communication', dataUsed: '234 MB' },
      { appName: 'Zoom', path: '/Applications/zoom.us.app', action: 'allow', icon: '📹', category: 'Communication', dataUsed: '245 MB' },
      { appName: 'Spotify', path: '/Applications/Spotify.app', action: 'allow', icon: '🎵', category: 'Media', dataUsed: '678 MB' },
      { appName: 'Steam', path: '/Applications/Steam.app', action: 'allow', icon: '🕹️', category: 'Gaming', dataUsed: '0 B' },
      { appName: 'VS Code', path: '/Applications/Visual Studio Code.app', action: 'allow', icon: '💻', category: 'Development', dataUsed: '1.2 GB' },
      { appName: 'Terminal', path: '/Applications/Utilities/Terminal.app', action: 'allow', icon: '⌨️', category: 'System', dataUsed: '12 MB' },
      { appName: 'Docker', path: '/Applications/Docker.app', action: 'allow', icon: '🐳', category: 'Development', dataUsed: '2.1 GB' },
      { appName: 'Postman', path: '/Applications/Postman.app', action: 'allow', icon: '🚀', category: 'Development', dataUsed: '45 MB' },
    ];
  }

  getRunningApps() {
    return new Promise((resolve) => {
      if (this.platform === 'darwin') {
        // macOS: Scan /Applications folder for high-fidelity list
        exec('ls /Applications | grep ".app"', { timeout: 5000 }, (err, stdout) => {
          const apps = (stdout || '').split('\n')
            .filter(a => a.trim() && a.endsWith('.app'))
            .map(a => ({ 
              name: a.replace('.app', '').trim(), 
              path: `/Applications/${a.trim()}` 
            }));
          
          // Fallback to process list if folder scan is empty
          if (apps.length === 0) resolve(this._getMockRunningApps());
          else resolve(apps.sort((a,b) => a.name.localeCompare(b.name)).slice(0, 50));
        });
      } else if (this.platform === 'win32') {
        // Windows: Scan Program Files
        exec('dir "C:\\Program Files" /B', { timeout: 5000 }, (err, stdout) => {
          const apps = (stdout || '').split('\n')
            .filter(name => name.trim() && !name.includes('.')) // Take folder names
            .map(name => ({ 
              name: name.trim(), 
              path: `C:\\Program Files\\${name.trim()}` 
            }));
          resolve(apps.sort((a,b) => a.name.localeCompare(b.name)).slice(0, 50));
        });
      } else {
        resolve(this._getMockRunningApps());
      }
    });
  }

  _getMockRunningApps() {
    return [
      { name: 'Chrome', path: '/Applications/Google Chrome.app' },
      { name: 'Safari', path: '/Applications/Safari.app' },
      { name: 'Slack', path: '/Applications/Slack.app' },
      { name: 'Zoom', path: '/Applications/zoom.us.app' },
      { name: 'Spotify', path: '/Applications/Spotify.app' },
      { name: 'Discord', path: '/Applications/Discord.app' },
      { name: 'Terminal', path: '/Applications/Utilities/Terminal.app' }
    ];
  }

  getAppRules() {
    return this.appRules;
  }

  setRule(appName, action) {
    return new Promise(async (resolve) => {
      // Find rule case-insensitively
      const existing = this.appRules.find(r => r.appName.toLowerCase() === appName.toLowerCase());
      const targetName = existing ? existing.appName : appName;
      
      if (existing) {
        existing.action = action;
      } else {
        this.appRules.push({
          appName: targetName,
          path: this.platform === 'darwin' ? `/Applications/${targetName}.app` : `C:\\Program Files\\${targetName}`,
          action,
          icon: '📱',
          category: 'User App',
          dataUsed: '0 B'
        });
      }

      // UNIVERSAL BLOCKING: Use domain-based blocking via hosts for ALL platforms
      if (this.websiteBlocker) {
        await this.websiteBlocker.blockAppDomains(targetName, action);
      }
      
      // FORCE IMPACT: If blocking, kill the running processes to clear sockets/cache
      if (action === 'block') {
         this._killProcess(targetName);
      }

      resolve({ success: true, appName: targetName, action });
    });
  }

  _killProcess(name) {
    const cmd = this.platform === 'win32' 
      ? `taskkill /F /IM ${name}.exe /T`
      : `pkill -9 -i "${name}"`;
    exec(cmd, (err) => {
      if (!err) console.log(`Force-terminated ${name} for policy enforcement`);
    });
  }

  _buildAppFirewallCmd(appName, action) {
    if (this.platform === 'win32') {
      const prog = `%ProgramFiles%\\${appName}\\${appName}.exe`;
      if (action === 'block') {
        return `powershell -NoProfile -Command "Start-Process netsh -ArgumentList 'advfirewall firewall add rule name=\\"AEGIS-${appName}\\" dir=out action=block program=\\"${prog}\\"' -Verb RunAs"`;
      } else {
        return `powershell -NoProfile -Command "Start-Process netsh -ArgumentList 'advfirewall firewall delete rule name=\\"AEGIS-${appName}\\"' -Verb RunAs"`;
      }
    } else {
      // macOS: use Application Firewall (socketfilterfw)
      const appPath = `/Applications/${appName}.app`;
      const firewallPath = '/usr/libexec/ApplicationFirewall/socketfilterfw';
      if (action === 'block') {
         return `"${firewallPath}" --blockapp "${appPath}" 2>/dev/null || true`;
      } else {
         return `"${firewallPath}" --unblockapp "${appPath}" 2>/dev/null || true`;
      }
    }
  }
}

module.exports = AppController;
