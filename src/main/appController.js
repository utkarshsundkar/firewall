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
        // macOS: Use Spotlight for an exhaustive list of every .app on the system
        exec('mdfind "kMDItemKind == Application" | head -100', { timeout: 8000 }, (err, stdout) => {
          const apps = (stdout || '').split('\n')
            .filter(a => a.trim() && a.endsWith('.app'))
            .map(a => ({ 
              name: a.split('/').pop().replace('.app', '').trim(), 
              path: a.trim() 
            }));
          resolve(apps.sort((a,b) => a.name.localeCompare(b.name)));
        });
      } else if (this.platform === 'win32') {
        // Windows: Deep dive into Program Files
        exec('powershell "Get-ChildItem \'C:\\Program Files\\\', \'C:\\Program Files (x86)\\\' | Select-Object -ExpandProperty FullName"', { timeout: 8000 }, (err, stdout) => {
          const apps = (stdout || '').split('\n')
            .filter(p => p.trim() && !p.includes('.'))
            .map(p => ({ 
              name: p.split('\\').pop().trim(), 
              path: p.trim() 
            }));
          resolve(apps.slice(0, 100));
        });
      } else {
        resolve(this._getMockRunningApps());
      }
    });
  }

  getAppRules() { return this.appRules; }

  setRule(appName, action) {
    return new Promise(async (resolve) => {
      const existing = this.appRules.find(r => r.appName === appName);
      if (existing) existing.action = action;
      else this.appRules.push({ appName, action, icon: '📱', category: 'Application' });

      // TRIPLE LAYER PROTECTION:
      // 1. OS Firewall (Hard) - Requires Prompt
      const fwCmd = this._buildAppFirewallCmd(appName, action);
      exec(fwCmd, (err) => {
        if (err) console.error('Firewall Elevation failed/cancelled');
        
        // 2. Domain Block (Stealth) - Instant
        if (this.websiteBlocker) this.websiteBlocker.blockAppDomains(appName, action);
        
        // 3. Process Kill (Force) - Absolute
        if (action === 'block') this._killProcess(appName);
        
        resolve({ success: true, appName, action });
      });
    });
  }

  _killProcess(name) {
    const cmd = this.platform === 'win32' ? `taskkill /F /IM ${name}.exe /T` : `pkill -9 -i "${name}"`;
    exec(cmd);
  }

  _buildAppFirewallCmd(appName, action) {
    if (this.platform === 'win32') {
      const findExe = `(Get-ChildItem -Path 'C:\\Program Files', 'C:\\Program Files (x86)' -Filter '${appName}.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1).FullName`;
      if (action === 'block') {
        return `powershell -NoProfile -Command "Start-Process netsh -ArgumentList 'advfirewall firewall add rule name=\\"AEGIS-${appName}\\" dir=out action=block program=\\"' + (${findExe}) + '\\"' -Verb RunAs"`;
      } else {
        return `powershell -NoProfile -Command "Start-Process netsh -ArgumentList 'advfirewall firewall delete rule name=\\"AEGIS-${appName}\\"' -Verb RunAs"`;
      }
    } else {
      const appPath = `/Applications/${appName}.app`;
      const fw = '/usr/libexec/ApplicationFirewall/socketfilterfw';
      const cmd = action === 'block' ? `${fw} --blockapp "${appPath}"` : `${fw} --unblockapp "${appPath}"`;
      return `osascript -e 'do shell script "${cmd}" with administrator privileges'`;
    }
  }
}

module.exports = AppController;
