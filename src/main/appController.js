/**
 * AppController - Manages per-application network access control
 * Uses OS Application Firewall + domain blocking + process kill for triple enforcement
 */
const { exec, execFileSync, spawnSync } = require('child_process');
const os = require('os');

class AppController {
  constructor(websiteBlocker) {
    this.platform = process.platform;
    this.appRules = [];
    this.websiteBlocker = websiteBlocker;
    // Cache of app paths from mdfind: { name -> fullPath }
    this._appPathCache = {};
    // Pre-populate from mdfind on startup
    this._refreshAppCache();
  }

  _refreshAppCache() {
    try {
      const stdout = require('child_process').execSync('mdfind "kMDItemKind == Application"', { timeout: 8000 }).toString();
      const lines = stdout.split('\n').filter(l => l.trim().endsWith('.app'));
      for (const line of lines) {
        const p = line.trim();
        const name = p.split('/').pop().replace('.app', '');
        // Skip internal/noise entries
        if (p.includes('node_modules') || p.includes('/Contents/')) continue;
        this._appPathCache[name.toLowerCase()] = p;
      }
    } catch(e) {
      console.log('mdfind refresh error:', e.message);
    }
  }

  getRunningApps() {
    return new Promise((resolve) => {
      if (this.platform === 'darwin') {
        exec('mdfind "kMDItemKind == Application"', { timeout: 8000 }, (err, stdout) => {
          const seen = new Set();
          const apps = (stdout || '').split('\n')
            .filter(a => {
              const p = a.trim();
              return p.endsWith('.app') && !p.includes('node_modules') && !p.includes('/Contents/');
            })
            .map(a => {
              const p = a.trim();
              const name = p.split('/').pop().replace('.app', '').trim();
              return { name, path: p };
            })
            .filter(a => {
              if (seen.has(a.name.toLowerCase())) return false;
              seen.add(a.name.toLowerCase());
              return true;
            })
            .sort((a, b) => a.name.localeCompare(b.name));

          // Update path cache from fresh results
          for (const app of apps) {
            this._appPathCache[app.name.toLowerCase()] = app.path;
          }

          resolve(apps);
        });
      } else if (this.platform === 'win32') {
        exec('powershell -NoProfile -Command "Get-ChildItem \'C:\\Program Files\', \'C:\\Program Files (x86)\' | Select-Object -ExpandProperty FullName"', { timeout: 8000 }, (err, stdout) => {
          const seen = new Set();
          const apps = (stdout || '').split('\n')
            .filter(p => p.trim() && !p.includes('.'))
            .map(p => ({ name: p.split('\\').pop().trim(), path: p.trim() }))
            .filter(a => {
              if (!a.name || seen.has(a.name.toLowerCase())) return false;
              seen.add(a.name.toLowerCase());
              return true;
            })
            .sort((a, b) => a.name.localeCompare(b.name))
            .slice(0, 100);
          resolve(apps);
        });
      } else {
        resolve([]);
      }
    });
  }

  getAppRules() { return this.appRules; }

  setRule(appName, action) {
    return new Promise((resolve) => {
      const existing = this.appRules.find(r => r.appName.toLowerCase() === appName.toLowerCase());
      if (existing) existing.action = action;
      else this.appRules.push({ appName, action, icon: '📱', category: 'Application' });

      // --- LAYER 1: OS Application Firewall (macOS: socketfilterfw, Windows: netsh) ---
      this._applyFirewallRule(appName, action);

      // --- LAYER 2: Domain-level blackout via hosts file (instant, no prompt) ---
      if (this.websiteBlocker) {
        this.websiteBlocker.blockAppDomains(appName.toLowerCase(), action);
      }

      // --- LAYER 3: Process kill (forces reconnect under new restrictions) ---
      if (action === 'block') {
        this._killProcess(appName);
      }

      resolve({ success: true, appName, action });
    });
  }

  _applyFirewallRule(appName, action) {
    if (this.platform === 'darwin') {
      // Look up the actual path from cache (mdfind gave us real paths)
      const appPath = this._appPathCache[appName.toLowerCase()] || `/Applications/${appName}.app`;
      
      // MAC OUTBOUND KILL-SWITCH: socketfilterfw only blocks incoming connections.
      // To strictly block outgoing internet (and the app itself), we revoke execute permissions
      // physically locking the app out of the OS.
      const chmodArg = action === 'block' ? '000' : '755';
      const cmd = `chmod ${chmodArg} '${appPath.replace(/'/g, "'\\''")}'`;

      // Trigger OS Admin Prompt
      const result = spawnSync('osascript', [
        '-e',
        `do shell script "${cmd}" with administrator privileges`
      ], { timeout: 30000 });

      if (result.error) {
        console.error(`App Lock failed for ${appName}:`, result.error.message);
      } else {
        console.log(`App Lock physically enforced: ${action} ${appName} [${appPath}]`);
      }

    } else if (this.platform === 'win32') {
      // Windows: combine Windows Firewall + ICACLS Execution Deny for double lock
      const ps = `
        $exe = (Get-ChildItem 'C:\\Program Files', 'C:\\Program Files (x86)' -Filter '${appName}.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
        if ($exe) {
          netsh advfirewall firewall ${action === 'block' ? `add rule name="AEGIS-${appName}" dir=out action=block program="$exe"` : `delete rule name="AEGIS-${appName}"`}
          ${action === 'block' ? `icacls "$exe" /deny Everyone:(X)` : `icacls "$exe" /remove:d Everyone`}
        }
      `;
      const result = spawnSync('powershell', ['-NoProfile', '-Command', ps], { timeout: 15000 });
      if (result.error) console.error(`Win App Lock failed for ${appName}:`, result.error.message);
    }
  }

  _killProcess(name) {
    if (this.platform === 'win32') {
      exec(`taskkill /F /IM "${name}.exe" /T`);
    } else {
      // Try exact name first, then fuzzy
      exec(`pkill -9 -i "${name}" || pkill -9 -f "${name}"`);
    }
  }
}

module.exports = AppController;
