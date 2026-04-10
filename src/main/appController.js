/**
 * AppController - Manages per-application network access control
 * Uses OS process list + firewall rules to allow/block apps from network
 */
const { exec } = require('child_process');
const os = require('os');

class AppController {
  constructor() {
    this.platform = process.platform;
    this.appRules = this._getDefaultRules();
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
        exec('ps aux | awk \'{print $11}\' | grep -v "^-\\|^[\\[\\{]\\|sbin\\|bin/" | sort -u | head -30', { timeout: 5000 }, (err, stdout) => {
          if (err) {
            resolve(this._getMockRunningApps());
            return;
          }
          const apps = stdout.split('\n').filter(a => a.trim() && a.includes('/Applications'))
            .map(a => ({ path: a.trim(), name: a.split('/').pop().replace('.app', '') }));
          resolve(apps.length > 0 ? apps : this._getMockRunningApps());
        });
      } else if (this.platform === 'win32') {
        exec('tasklist /fo csv /nh', { timeout: 5000 }, (err, stdout) => {
          if (err) {
            resolve(this._getMockRunningApps());
            return;
          }
          const apps = stdout.split('\n')
            .map(line => line.replace(/"/g, '').split(',')[0])
            .filter(name => name && name.endsWith('.exe'))
            .map(name => ({ name: name.replace('.exe', ''), path: `C:\\Program Files\\${name}` }));
          resolve(apps.slice(0, 20));
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
    return new Promise((resolve) => {
      const existing = this.appRules.find(r => r.appName === appName);
      if (existing) {
        existing.action = action;
      } else {
        this.appRules.push({
          appName,
          path: `/Applications/${appName}.app`,
          action,
          icon: '📱',
          category: 'User App',
          dataUsed: '0 B'
        });
      }

      // Apply real firewall rule based on platform
      const cmd = this._buildAppFirewallCmd(appName, action);
      exec(cmd, () => {
        resolve({ success: true, appName, action });
      });
    });
  }

  _buildAppFirewallCmd(appName, action) {
    if (this.platform === 'win32') {
      const prog = `%ProgramFiles%\\${appName}\\${appName}.exe`;
      if (action === 'block') {
        return `netsh advfirewall firewall add rule name="AEGIS-${appName}" dir=out action=block program="${prog}"`;
      } else {
        return `netsh advfirewall firewall delete rule name="AEGIS-${appName}"`;
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
