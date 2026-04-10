/**
 * WebsiteBlocker — Blocks websites via /etc/hosts file manipulation
 * macOS:   /etc/hosts
 * Windows: C:\Windows\System32\drivers\etc\hosts
 * Requires elevated privileges to write to hosts file.
 * Flushes DNS cache after changes.
 */
const { exec } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const AEGIS_START = '# === AEGIS FIREWALL BLOCK START ===';
const AEGIS_END   = '# === AEGIS FIREWALL BLOCK END ===';

const HOSTS_PATH = process.platform === 'win32'
  ? 'C:\\Windows\\System32\\drivers\\etc\\hosts'
  : '/etc/hosts';

// Known domains per app — used by App Control
const APP_DOMAINS = {
  'Discord':      ['discord.com', 'discordapp.com', 'discord.gg', 'cdn.discordapp.com', 'gateway.discord.gg', 'media.discordapp.net'],
  'Spotify':      ['spotify.com', 'spclient.wg.spotify.com', 'apresolve.spotify.com', 'audio-ec.spotify.com'],
  'Slack':        ['slack.com', 'api.slack.com', 'files.slack.com', 'wss-primary.slack.com'],
  'Zoom':         ['zoom.us', 'zoomgov.com', 'zmtrack.net'],
  'Dropbox':      ['dropbox.com', 'dropboxapi.com', 'dropboxusercontent.com'],
  'TeamViewer':   ['teamviewer.com', 'router.teamviewer.com'],
  'BitTorrent':   ['bittorrent.com', 'tracker.bittorrent.com'],
  'Tor Browser':  ['torproject.org'],
  'Chrome':       [], // Don't block Chrome entirely – use website blocker instead
  'Safari':       [],
  'VLC':          [],
  'Terminal':     [],
};

class WebsiteBlocker {
  constructor() {
    this.blockedEntries = []; // { domain, reason, blockedAt }
    this._syncFromHosts();
  }

  _syncFromHosts() {
    try {
      const content = fs.readFileSync(HOSTS_PATH, 'utf8');
      const inBlock = this._extractAegisBlock(content);
      this.blockedEntries = inBlock
        .filter(line => line.startsWith('127.0.0.1'))
        .map(line => {
          const parts = line.split(/\s+/);
          const domain = parts[1] || '';
          const reason = parts.slice(2).join(' ').replace('#', '').trim();
          return { domain, reason: reason || 'Blocked by Aegis', blockedAt: Date.now() };
        });
    } catch (e) {
      // Hosts file not readable (no sudo) — just use in-memory state
      this.blockedEntries = this._getDefaultBlocked();
    }
  }

  _getDefaultBlocked() {
    return []; // Start clean
  }

  _extractAegisBlock(content) {
    const start = content.indexOf(AEGIS_START);
    const end   = content.indexOf(AEGIS_END);
    if (start === -1 || end === -1) return [];
    return content.slice(start + AEGIS_START.length, end)
      .split('\n')
      .map(l => l.trim())
      .filter(Boolean);
  }

  _buildAegisBlock() {
    const lines = this.blockedEntries.map(e =>
      `127.0.0.1 ${e.domain} www.${e.domain} # ${e.reason}`
    );
    return `\n${AEGIS_START}\n${lines.join('\n')}\n${AEGIS_END}\n`;
  }

  _writeHosts(callback) {
    let base = '';
    try {
      const raw = fs.readFileSync(HOSTS_PATH, 'utf8');
      const start = raw.indexOf(AEGIS_START);
      const end   = raw.indexOf(AEGIS_END);
      if (start !== -1 && end !== -1) {
        base = raw.slice(0, start) + raw.slice(end + AEGIS_END.length);
      } else {
        base = raw;
      }
    } catch (e) {
      base = '127.0.0.1 localhost\n::1 localhost\n';
    }

    const newContent = base.trimEnd() + '\n' + this._buildAegisBlock();
    const tmpPath = path.join(os.tmpdir(), 'aegis_hosts_tmp.txt');

    try {
      fs.writeFileSync(tmpPath, newContent, 'utf8');
    } catch (e) {
      return callback(new Error('Failed to write temp file: ' + e.message));
    }

    // First try a direct write (works if already running as root/admin)
    try {
      fs.writeFileSync(HOSTS_PATH, newContent, 'utf8');
      this._flushDNS(() => callback(null));
      return;
    } catch (directErr) {
      // Need elevation — fall through
    }

    if (process.platform === 'win32') {
      // Windows: PowerShell with UAC elevation via Start-Process -Verb RunAs
      const psScript = `Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -Command "Copy-Item ''${tmpPath.replace(/\\/g, '\\\\')}'' ''${HOSTS_PATH}'' -Force; ipconfig /flushdns"' -Wait`;
      exec(`powershell -NoProfile -Command "${psScript}"`, { timeout: 30000 }, (err) => {
        callback(err);
      });
    } else {
      // macOS/Linux: osascript triggers native macOS password dialog — no Terminal needed
      const escapedTmp  = tmpPath.replace(/"/g, '\\"');
      const escapedDest = HOSTS_PATH.replace(/"/g, '\\"');
      const shellScript = [
        `cp \\"${escapedTmp}\\" \\"${escapedDest}\\"`,
        `dscacheutil -flushcache`,
        `killall -HUP mDNSResponder 2>/dev/null || true`
      ].join(' && ');

      // osascript do shell script with administrator privileges
      // This triggers the system native auth dialog (Touch ID or password)
      const osaCmd = `osascript -e 'do shell script "${shellScript}" with administrator privileges'`;

      exec(osaCmd, { timeout: 30000 }, (err, stdout, stderr) => {
        if (err) {
          // User cancelled the auth dialog or osascript unavailable
          console.log('osascript auth failed (user may have cancelled):', err.message);
          callback(new Error(
            `Admin access required. Run manually: sudo cp ${tmpPath} ${HOSTS_PATH} && sudo dscacheutil -flushcache`
          ));
        } else {
          callback(null);
        }
      });
    }
  }

  _flushDNS(callback) {
    if (process.platform === 'win32') {
      exec('ipconfig /flushdns', callback);
    } else if (process.platform === 'darwin') {
      exec('dscacheutil -flushcache && killall -HUP mDNSResponder 2>/dev/null', callback);
    } else {
      exec('systemctl restart systemd-resolved 2>/dev/null || service dns-clean restart 2>/dev/null', callback);
    }
  }

  blockDomain(domain, reason = 'Blocked by Aegis') {
    return new Promise((resolve) => {
      domain = domain.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').toLowerCase().trim();
      if (!domain) return resolve({ success: false, error: 'Invalid domain' });

      // Remove existing
      this.blockedEntries = this.blockedEntries.filter(e => e.domain !== domain);
      this.blockedEntries.unshift({ domain, reason, blockedAt: Date.now() });

      this._writeHosts((err) => {
        resolve({
          success: true,
          domain,
          sudoRequired: !!err,
          message: err
            ? `Domain tracked. Run app with sudo/admin for hosts-file blocking: sudo cp /tmp/aegis_hosts_tmp.txt /etc/hosts`
            : `${domain} blocked via /etc/hosts`
        });
      });
    });
  }

  unblockDomain(domain) {
    return new Promise((resolve) => {
      this.blockedEntries = this.blockedEntries.filter(e => e.domain !== domain);
      this._writeHosts((err) => {
        resolve({ success: true, domain, sudoRequired: !!err });
      });
    });
  }

  blockAppDomains(appName, action) {
    return new Promise(async (resolve) => {
      const domains = APP_DOMAINS[appName] || [];
      if (domains.length === 0) return resolve({ success: true, domains: [] });

      const results = [];
      for (const domain of domains) {
        if (action === 'block') {
          this.blockedEntries = this.blockedEntries.filter(e => e.domain !== domain);
          this.blockedEntries.push({ domain, reason: `Blocked app: ${appName}`, blockedAt: Date.now() });
        } else {
          this.blockedEntries = this.blockedEntries.filter(e => e.domain !== domain);
        }
        results.push(domain);
      }

      this._writeHosts((err) => {
        resolve({ success: true, domains: results, sudoRequired: !!err });
      });
    });
  }

  getBlockedList() {
    return this.blockedEntries;
  }

  getAppDomains(appName) {
    return APP_DOMAINS[appName] || [];
  }

  getAllAppDomains() {
    return APP_DOMAINS;
  }
}

module.exports = WebsiteBlocker;
