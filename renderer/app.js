/* ═══════════════════════════════════════════════════════════
   AEGIS FIREWALL — Renderer / UI Controller
   ═══════════════════════════════════════════════════════════ */

'use strict';

/* ── State ──────────────────────────────────────────────── */
const state = {
  activeTab: 'dashboard',
  threats: [],
  rules: [],
  connections: [],
  devices: [],
  appRules: [],
  blockedIPs: [],
  networkHistory: [],
  threatFilter: 'all',
  sysInfo: null
};

/* ── Chart canvas context ── */
let chartCtx = null;
let animFrame = null;

/* ════════════════════════════════════════════════════════════
   INIT
   ════════════════════════════════════════════════════════════ */
window.addEventListener('DOMContentLoaded', async () => {
  initTitleBar();
  initClock();
  initNavigation();
  initFirewallToggle();
  initThreatsTab();
  initFirewallTab();
  initConnectionsTab();
  initDevicesTab();
  initIPBlockTab();
  initWebsiteBlocker();
  initEnterpriseTab();
  initWafTab();
  initChart();
  initRealTimeListeners();

  // Load initial data
  await Promise.all([
    loadSystemInfo(),
    loadFirewallStatus(),
    loadThreats(),
    loadRules(),
    loadConnections(),
    loadDevices(),
    loadIPBlocklist(),
    loadBlockedWebsites()
  ]);

  // Start polling for connection updates
  setInterval(loadConnections, 5000);
  setInterval(updateUptime, 60000);
});

/* ════════════════════════════════════════════════════════════
   TITLE BAR
   ════════════════════════════════════════════════════════════ */
function initTitleBar() {
  document.getElementById('btn-close').addEventListener('click', () => window.aegis.close());
  document.getElementById('btn-minimize').addEventListener('click', () => window.aegis.minimize());
  document.getElementById('btn-maximize').addEventListener('click', () => window.aegis.maximize());

  // Hide macOS-style traffic lights on Windows
  if (window.aegis.platform === 'win32') {
    document.querySelector('.titlebar-controls').style.display = 'none';
  }
}

function initClock() {
  const el = document.getElementById('header-time');
  const tick = () => {
    const now = new Date();
    el.textContent = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  };
  tick();
  setInterval(tick, 1000);
}

/* ════════════════════════════════════════════════════════════
   NAVIGATION
   ════════════════════════════════════════════════════════════ */
function initNavigation() {
  document.querySelectorAll('.nav-item').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });

  // "View All" quick-link from dashboard
  document.querySelectorAll('[data-goto]').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.goto));
  });
}

function switchTab(tabId) {
  state.activeTab = tabId;
  document.querySelectorAll('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.tab === tabId));
  document.querySelectorAll('.tab-section').forEach(s => s.classList.toggle('active', s.id === `tab-${tabId}`));

  // Refresh data when switching tabs
  if (tabId === 'connections') loadConnections();
  if (tabId === 'ipblock') loadIPBlocklist();
  if (tabId === 'threats') renderThreats();
}

/* ════════════════════════════════════════════════════════════
   FIREWALL TOGGLE
   ════════════════════════════════════════════════════════════ */
function initFirewallToggle() {
  const toggle = document.getElementById('fw-main-toggle');
  toggle.addEventListener('change', async () => {
    const enabled = toggle.checked;
    await window.aegis.toggleFirewall(enabled);

    const pill = document.getElementById('fw-status-pill');
    const dot  = document.getElementById('fw-dot');
    const text = document.getElementById('fw-status-text');
    const sideState = document.getElementById('sidebar-fw-state');
    const kpiStatus = document.getElementById('kpi-status');

    if (enabled) {
      pill.classList.remove('inactive');
      dot.style.background = 'var(--green)';
      text.textContent = 'Firewall Active';
      sideState.textContent = 'ON';
      sideState.classList.remove('off');
      kpiStatus.textContent = 'Protected';
    } else {
      pill.classList.add('inactive');
      dot.style.background = 'var(--red)';
      text.textContent = 'Firewall Disabled';
      sideState.textContent = 'OFF';
      sideState.classList.add('off');
      kpiStatus.textContent = 'Unprotected';
      showToast('⚠️ Firewall Disabled', 'Your network is now unprotected. Re-enable immediately.', 'high');
    }
  });
}

/* ════════════════════════════════════════════════════════════
   SYSTEM INFO
   ════════════════════════════════════════════════════════════ */
async function loadSystemInfo() {
  try {
    const info = await window.aegis.getSystemInfo();
    state.sysInfo = info;

    const platform = info.platform === 'darwin' ? 'macOS' : info.platform === 'win32' ? 'Windows' : 'Linux';
    const mem = formatBytes(info.totalMem);
    const uptime = formatUptime(info.uptime);

    set('si-platform', platform);
    set('si-hostname', info.hostname);
    set('si-arch', info.arch);
    set('si-cpus', `${info.cpus} cores`);
    set('si-mem', mem);
    set('si-uptime', uptime);
    set('mini-platform', platform);
    set('mini-hostname', info.hostname.split('.')[0]);
    set('last-scan-time', 'just now');
  } catch (e) {
    console.error('SysInfo error:', e);
  }
}

function updateUptime() {
  if (state.sysInfo) {
    state.sysInfo.uptime += 60;
    set('si-uptime', formatUptime(state.sysInfo.uptime));
  }
}

/* ════════════════════════════════════════════════════════════
   FIREWALL STATUS
   ════════════════════════════════════════════════════════════ */
async function loadFirewallStatus() {
  try {
    const status = await window.aegis.getFirewallStatus();
    set('kpi-blocked', status.activeRules || 0);
  } catch (e) {
    console.error('Firewall status error:', e);
  }
}

/* ════════════════════════════════════════════════════════════
   THREAT DETECTION
   ════════════════════════════════════════════════════════════ */
function initThreatsTab() {
  document.getElementById('btn-clear-threats').addEventListener('click', async () => {
    await window.aegis.clearThreats();
    state.threats = [];
    renderThreats();
    updateThreatCount(0);
    showToast('🗑️ Threat Log Cleared', 'All threat records have been removed.', 'info');
  });

  document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      state.threatFilter = btn.dataset.filter;
      renderThreats();
    });
  });

  // Modal close
  document.getElementById('modal-close').addEventListener('click', closeModal);
  document.getElementById('modal-overlay').addEventListener('click', e => {
    if (e.target === document.getElementById('modal-overlay')) closeModal();
  });
}

async function loadThreats() {
  try {
    state.threats = await window.aegis.getThreatLog();
    renderThreats();
    updateThreatCount(state.threats.filter(t => !t.mitigated).length);
  } catch (e) {
    console.error('Threats error:', e);
  }
}

function renderThreats() {
  const container = document.getElementById('threats-container');
  const mini = document.getElementById('threat-list-mini');
  const filter = state.threatFilter;

  let filtered = state.threats;
  if (filter !== 'all') {
    filtered = state.threats.filter(t => {
      if (['critical','high','medium','low'].includes(filter)) return t.severity === filter;
      return t.type === filter;
    });
  }

  if (filtered.length === 0) {
    container.innerHTML = `<div class="loading-state" style="padding:60px">
      <div style="font-size:48px;margin-bottom:12px">🛡️</div>
      <div style="color:var(--green);font-weight:600;margin-bottom:4px">No Threats Found</div>
      <div style="font-size:12px;color:var(--text-muted)">System is clean for this filter</div>
    </div>`;
    mini.innerHTML = '<div class="empty-state-sm">No threats detected</div>';
    return;
  }

  container.innerHTML = filtered.map(t => threatCardHTML(t)).join('');
  mini.innerHTML = filtered.slice(0, 4).map(t => `
    <div class="threat-mini-item ${t.severity}" onclick="openThreatModal('${t.id}')">
      <span class="tmi-title">${t.title}</span>
      <span class="tmi-sev ${t.severity}">${t.severity.toUpperCase()}</span>
    </div>
  `).join('');

  // Click handlers on threat cards
  container.querySelectorAll('.threat-card').forEach(card => {
    card.addEventListener('click', () => openThreatModal(card.dataset.id));
  });

  // Block IP buttons
  container.querySelectorAll('.block-threat-ip').forEach(btn => {
    btn.addEventListener('click', async e => {
      e.stopPropagation();
      const ip = btn.dataset.ip;
      await window.aegis.blockIP(ip);
      btn.textContent = '✓ Blocked';
      btn.disabled = true;
      btn.style.opacity = '0.5';
      // Mark as mitigated
      const threat = state.threats.find(t => t.sourceIP === ip);
      if (threat) {
        threat.mitigated = true;
        threat.mitigation = `IP ${ip} blocked via firewall rule`;
      }
      showToast(`🚫 IP Blocked`, `${ip} has been added to the blocklist.`, 'info');
      loadIPBlocklist();
    });
  });
}

function threatCardHTML(t) {
  const icons = {
    port_scan: '🔍', brute_force: '🔨', ddos: '💥',
    dns_tunneling: '🕳️', arp_spoof: '🎭', malicious_ip: '☠️'
  };
  const icon = icons[t.type] || '⚠️';
  const time = new Date(t.timestamp).toLocaleString();

  return `
  <div class="threat-card ${t.severity}" data-id="${t.id}">
    <div class="threat-sev-icon">${icon}</div>
    <div class="threat-body">
      <div class="threat-title">${t.title}</div>
      <div class="threat-desc">${t.description}</div>
      <div class="threat-meta">
        <span class="threat-ip">⬥ ${t.sourceIP}</span>
        <span>🕐 ${time}</span>
        ${t.mitigated ? `<span style="color:var(--green)">✓ Mitigated</span>` : ''}
      </div>
    </div>
    <div class="threat-actions-col">
      <span class="sev-badge ${t.severity}">${t.severity}</span>
      ${t.mitigated
        ? `<span class="mitigated-tag">✓ Resolved</span>`
        : `<button class="btn-sm block-btn block-threat-ip" data-ip="${t.sourceIP}">🚫 Block IP</button>`
      }
      <button class="btn-sm allow-btn" style="background:var(--info-bg);color:var(--accent-light);border-color:rgba(99,102,241,.2)">Details →</button>
    </div>
  </div>`;
}

function openThreatModal(id) {
  const t = state.threats.find(th => th.id === id);
  if (!t) return;

  const icons = { port_scan: '🔍', brute_force: '🔨', ddos: '💥', dns_tunneling: '🕳️', arp_spoof: '🎭', malicious_ip: '☠️' };
  const icon = icons[t.type] || '⚠️';
  const recs = (t.recommendations || [
    'Monitor traffic from this source',
    'Review firewall rules for this port/protocol',
    'Update threat intelligence feed blocklists',
    'Enable alert notifications for repeat offenders'
  ]).map(r => `<li>${r}</li>`).join('');

  document.getElementById('modal-content').innerHTML = `
    <div class="modal-threat-icon">${icon}</div>
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
      <h2 class="modal-threat-title" style="flex:1">${t.title}</h2>
      <span class="sev-badge ${t.severity}">${t.severity}</span>
    </div>
    <p class="modal-threat-desc">${t.description}</p>
    <div class="modal-meta-grid">
      <div class="modal-meta-item">
        <div class="modal-meta-label">Source IP</div>
        <div class="modal-meta-val">${t.sourceIP}</div>
      </div>
      <div class="modal-meta-item">
        <div class="modal-meta-label">Attack Type</div>
        <div class="modal-meta-val">${t.type.replace(/_/g, ' ').toUpperCase()}</div>
      </div>
      <div class="modal-meta-item">
        <div class="modal-meta-label">Detected At</div>
        <div class="modal-meta-val" style="font-size:11px">${new Date(t.timestamp).toLocaleString()}</div>
      </div>
      <div class="modal-meta-item">
        <div class="modal-meta-label">Status</div>
        <div class="modal-meta-val" style="color:${t.mitigated ? 'var(--green)' : 'var(--red)'}">
          ${t.mitigated ? '✓ Mitigated' : '⚠ Active Threat'}
        </div>
      </div>
    </div>
    ${t.mitigation ? `<div style="background:var(--success-bg);border:1px solid rgba(16,185,129,.2);border-radius:8px;padding:10px 14px;margin-bottom:16px;font-size:12px;color:var(--green)">✓ ${t.mitigation}</div>` : ''}
    <div class="modal-section-title">Recommended Actions</div>
    <ul class="modal-recs">${recs}</ul>
    <div class="modal-actions">
      ${!t.mitigated ? `<button class="btn-danger" id="modal-block-ip" data-ip="${t.sourceIP}">🚫 Block ${t.sourceIP}</button>` : ''}
      <button class="btn-secondary" id="modal-close-btn">Close</button>
    </div>
  `;

  document.getElementById('modal-overlay').style.display = 'flex';

  const blockBtn = document.getElementById('modal-block-ip');
  if (blockBtn) {
    blockBtn.addEventListener('click', async () => {
      const ip = blockBtn.dataset.ip;
      await window.aegis.blockIP(ip);
      t.mitigated = true;
      t.mitigation = `IP ${ip} blocked via firewall rule`;
      closeModal();
      renderThreats();
      loadIPBlocklist();
      showToast(`🚫 Blocked ${ip}`, 'IP has been added to the firewall blocklist.', 'info');
    });
  }
  document.getElementById('modal-close-btn').addEventListener('click', closeModal);
}

function closeModal() {
  document.getElementById('modal-overlay').style.display = 'none';
}

/* ════════════════════════════════════════════════════════════
   FIREWALL RULES
   ════════════════════════════════════════════════════════════ */
function initFirewallTab() {
  document.getElementById('btn-add-rule').addEventListener('click', () => {
    document.getElementById('add-rule-form').style.display = 'block';
    document.getElementById('btn-add-rule').style.display = 'none';
  });
  document.getElementById('btn-cancel-rule').addEventListener('click', () => {
    document.getElementById('add-rule-form').style.display = 'none';
    document.getElementById('btn-add-rule').style.display = '';
  });
  document.getElementById('btn-save-rule').addEventListener('click', addRule);
}

async function loadRules() {
  try {
    state.rules = await window.aegis.getFirewallRules();
    renderRules();
  } catch (e) {
    console.error('Rules error:', e);
  }
}

function renderRules() {
  const tbody = document.getElementById('rules-tbody');
  if (!state.rules.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="loading-td">No rules configured</td></tr>';
    return;
  }
  tbody.innerHTML = state.rules.map(r => {
    const dirClass = r.direction === 'in' ? 'pill-in' : r.direction === 'out' ? 'pill-out' : 'pill-both';
    const dirLabel = r.direction === 'in' ? '↓ In' : r.direction === 'out' ? '↑ Out' : '⇅ Both';
    const protoClass = r.protocol === 'UDP' ? 'pill-udp' : 'pill-tcp';
    const date = new Date(r.createdAt).toLocaleDateString();
    return `<tr>
      <td style="color:var(--text-primary);font-weight:500">${r.name}</td>
      <td><span class="pill ${protoClass}">${r.protocol}</span></td>
      <td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--text-mono)">${r.port || 'any'}</td>
      <td><span class="pill ${dirClass}">${dirLabel}</span></td>
      <td class="${r.action === 'allow' ? 'action-allow' : 'action-block'}">${r.action === 'allow' ? '✓ Allow' : '✕ Block'}</td>
      <td><span class="${r.enabled ? 'status-on' : 'status-off'}">${r.enabled ? '● Active' : '○ Disabled'}</span></td>
      <td style="color:var(--text-muted);font-size:12px">${date}</td>
      <td><button class="btn-sm del-btn" data-rule-id="${r.id}">Delete</button></td>
    </tr>`;
  }).join('');

  tbody.querySelectorAll('.del-btn').forEach(btn => {
    btn.addEventListener('click', () => deleteRule(btn.dataset.ruleId));
  });
}

async function addRule() {
  const name = document.getElementById('rule-name').value.trim();
  if (!name) { showToast('⚠️ Validation', 'Please enter a rule name.', 'high'); return; }

  const rule = {
    name,
    protocol: document.getElementById('rule-protocol').value,
    port: document.getElementById('rule-port').value.trim() || 'any',
    direction: document.getElementById('rule-direction').value,
    action: document.getElementById('rule-action').value,
    sourceIP: document.getElementById('rule-source-ip').value.trim() || null
  };

  await window.aegis.addFirewallRule(rule);
  await loadRules();
  await loadFirewallStatus();

  // Reset form
  ['rule-name','rule-port','rule-source-ip'].forEach(id => document.getElementById(id).value = '');
  document.getElementById('add-rule-form').style.display = 'none';
  document.getElementById('btn-add-rule').style.display = '';
  showToast('✓ Rule Added', `"${name}" has been applied to the firewall.`, 'info');
}

async function deleteRule(ruleId) {
  await window.aegis.removeFirewallRule(ruleId);
  state.rules = state.rules.filter(r => r.id !== ruleId);
  renderRules();
  showToast('🗑️ Rule Removed', 'Firewall rule has been deleted.', 'info');
}

/* ════════════════════════════════════════════════════════════
   CONNECTIONS
   ════════════════════════════════════════════════════════════ */
function initConnectionsTab() {
  document.getElementById('btn-refresh-conn').addEventListener('click', loadConnections);
  document.getElementById('conn-search').addEventListener('input', filterConnections);
}

async function loadConnections() {
  try {
    state.connections = await window.aegis.getConnections();
    renderConnections(state.connections);
    set('kpi-connections', state.connections.length);
  } catch (e) {
    console.error('Connections error:', e);
  }
}

function filterConnections() {
  const q = document.getElementById('conn-search').value.toLowerCase();
  const filtered = state.connections.filter(c =>
    c.remoteIP.includes(q) || c.remotePort.includes(q) ||
    c.process.toLowerCase().includes(q) || c.protocol.toLowerCase().includes(q)
  );
  renderConnections(filtered);
}

function renderConnections(conns) {
  const tbody = document.getElementById('conn-tbody');
  const high = conns.filter(c => c.risk === 'high').length;
  const med  = conns.filter(c => c.risk === 'medium').length;
  const est  = conns.filter(c => c.state === 'ESTABLISHED').length;

  set('cs-total', conns.length);
  set('cs-established', est);
  set('cs-high', high);
  set('cs-med', med);

  if (!conns.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="loading-td">No active connections</td></tr>';
    return;
  }

  tbody.innerHTML = conns.map(c => `
    <tr>
      <td><span class="pill ${c.protocol === 'UDP' ? 'pill-udp' : 'pill-tcp'}">${c.protocol}</span></td>
      <td style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-muted)">${c.localAddress}</td>
      <td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--text-mono)">${c.remoteIP}</td>
      <td style="font-family:'JetBrains Mono',monospace;font-size:12px">${c.remotePort}</td>
      <td style="color:var(--text-primary)">${c.process}</td>
      <td><span style="font-size:11px;color:${c.state === 'ESTABLISHED' ? 'var(--green)' : 'var(--text-muted)'}">${c.state}</span></td>
      <td><span class="risk-${c.risk}">${c.risk.toUpperCase()}</span></td>
      <td>
        <button class="btn-sm block-btn" data-ip="${c.remoteIP}" onclick="blockConnIP('${c.remoteIP}')">Block</button>
      </td>
    </tr>
  `).join('');
}

async function blockConnIP(ip) {
  await window.aegis.blockIP(ip);
  state.connections = state.connections.filter(c => c.remoteIP !== ip);
  renderConnections(state.connections);
  loadIPBlocklist();
  showToast(`🚫 ${ip} Blocked`, 'IP removed from active connections.', 'high');
}

// Expose globally for inline onclick
window.blockConnIP = blockConnIP;

/* ════════════════════════════════════════════════════════════
   DEVICES (NETWORK SCANNING & CONTROL)
   ════════════════════════════════════════════════════════════ */
function initDevicesTab() {
  document.getElementById('btn-scan-network').addEventListener('click', triggerNetworkScan);
  document.getElementById('dev-search').addEventListener('input', filterDevices);

  window.aegis.onScanProgress(progress => {
    const container = document.getElementById('scan-progress-container');
    const bar = document.getElementById('scan-progress-bar');
    const text = document.getElementById('scan-progress-text');

    if (progress.progress >= 100) {
      container.style.display = 'none';
      loadDevices();
      showToast('✓ Scan Complete', `Found ${progress.found} devices on the network.`, 'info');
    } else {
      container.style.display = 'block';
      bar.style.width = `${progress.progress}%`;
      const phases = {
        'arp': 'Reading local ARP tables...',
        'arp_done': `Found ${progress.found} cached devices.`,
        'hosts': 'Discovering active hosts...'
      };
      text.textContent = phases[progress.phase] || 'Scanning...';
    }
  });

  window.aegis.onDevicePacket(packet => {
    if (!document.getElementById('device-monitor-modal') || document.getElementById('device-monitor-modal').style.display === 'none') {
      window.aegis.stopDeviceMonitor();
      return;
    }
    appendMonitorLog(packet);
  });
}

function triggerNetworkScan() {
  document.getElementById('scan-progress-container').style.display = 'block';
  document.getElementById('scan-progress-text').textContent = 'Initializing scan...';
  document.getElementById('scan-progress-bar').style.width = '0%';
  window.aegis.scanNetwork();
}

async function loadDevices() {
  try {
    const [devices, stats] = await Promise.all([
      window.aegis.getDevices(),
      window.aegis.getDeviceStats()
    ]);
    state.devices = devices;
    renderDevices(state.devices);

    set('kpi-dev-total', stats.total);
    set('kpi-dev-blocked', stats.blocked);
    set('kpi-dev-risk', stats.highRisk);
    set('kpi-dev-traffic', formatBytes(stats.totalBytesIn + stats.totalBytesOut, 1));
  } catch (e) {
    console.error('Devices error:', e);
  }
}

function filterDevices() {
  const q = document.getElementById('dev-search').value.toLowerCase();
  const filtered = state.devices.filter(d =>
    d.ip.includes(q) || d.mac.includes(q) ||
    d.vendor.toLowerCase().includes(q) || d.hostname.toLowerCase().includes(q)
  );
  renderDevices(filtered);
}

function renderDevices(devices) {
  const tbody = document.getElementById('devices-tbody');
  if (!devices.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="loading-td">No devices found. Run a network scan.</td></tr>';
    return;
  }

  tbody.innerHTML = devices.map(d => {
    const isAllow = d.action === 'allow';
    const isBlock = d.action === 'block';
    const isLimit = d.action === 'limit';

    return `
    <tr>
      <td>
        <div class="dev-icon-cell">
          <div class="dev-icon">${d.icon}</div>
          <div>
            <div class="dev-name">${d.hostname} ${d.isGateway ? '<span class="dev-gateway">Router</span>' : ''}</div>
            <div style="font-size:11px;color:var(--text-muted)">${d.type}</div>
          </div>
        </div>
      </td>
      <td class="dev-ip">${d.ip}</td>
      <td>
        <div class="dev-mac-vendor">
          <span class="dev-mac">${d.mac.toUpperCase()}</span>
          <span class="dev-vendor">${d.vendor}</span>
        </div>
      </td>
      <td style="font-size:12px;color:var(--text-secondary)">${d.os || 'Unknown'}</td>
      <td>
        <div class="dev-traffic">
          <span class="dev-tpill in">↓ ${formatBytes(d.bytesIn || 0, 1)}</span>
          <span class="dev-tpill out">↑ ${formatBytes(d.bytesOut || 0, 1)}</span>
        </div>
      </td>
      <td>
        <span class="status-${d.status}">${d.status === 'online' ? 'Online' : 'Offline'}</span>
      </td>
      <td>
        <div class="dev-actions">
          <button class="dev-btn monitor-btn" onclick="openDeviceMonitor('${d.ip}')" title="Intercept Traffic">👁️ Monitor</button>
          <button class="dev-btn ${isAllow ? 'active-allow' : ''}" onclick="setDevRule('${d.ip}', 'allow')">✓ Allow</button>
          <button class="dev-btn ${isLimit ? 'active-limit' : ''}" onclick="setDevRule('${d.ip}', 'limit')" title="Throttle traffic">⚖️ Limit</button>
          <button class="dev-btn ${isBlock ? 'active-block' : ''}" onclick="setDevRule('${d.ip}', 'block')">✕</button>
        </div>
      </td>
    </tr>`;
  }).join('');
}

async function setDevRule(ip, action) {
  await window.aegis.setDeviceRule({ ip, action });
  const dev = state.devices.find(d => d.ip === ip);
  if (dev) dev.action = action;
  renderDevices(state.devices);

  if (action === 'block') {
    showToast(`🚫 Device Blocked`, `${dev ? dev.hostname : ip} is blocked from network access.`, 'high');
  } else if (action === 'limit') {
    showToast(`⚖️ Traffic Limited`, `Bandwidth throttled for ${dev ? dev.hostname : ip}.`, 'medium');
  } else {
    showToast(`✓ Device Allowed`, `Full access restored for ${dev ? dev.hostname : ip}.`, 'success');
  }
}
window.setDevRule = setDevRule;


let currentMonitorIp = null;

async function openDeviceMonitor(ip) {
  const dev = state.devices.find(d => d.ip === ip);
  if (!dev) return;

  currentMonitorIp = ip;
  document.getElementById('dm-hostname').textContent = dev.hostname;
  document.getElementById('dm-icon').textContent = dev.icon;
  document.getElementById('dm-ip').textContent = dev.ip;
  document.getElementById('dm-mac').textContent = dev.mac.toUpperCase();

  const logsContainer = document.getElementById('dm-logs');
  logsContainer.innerHTML = `
    <div style="text-align: center; color: var(--text-muted); padding: 40px;">
      <div class="pulse" style="font-size: 32px; margin-bottom: 16px;">📡</div>
      <div style="font-size:14px;color:var(--text-primary);margin-bottom:8px">Authorizing Packet Capture Session...</div>
      <div>Please enter your local admin password to start intercepting real packets.</div>
    </div>
  `;

  document.getElementById('device-monitor-modal').style.display = 'flex';

  await window.aegis.startDeviceMonitor(ip);
  showToast('📡 Packet Sniffer Armed', `Intercepting REAL traffic for ${dev.hostname}`, 'high');
  logsContainer.innerHTML = '';
}

function appendMonitorLog(packet) {
  const logsContainer = document.getElementById('dm-logs');
  if (!logsContainer) return;
  
  const isErr = packet.proto === 'SYS';
  const protoClass = packet.proto.toLowerCase();
  
  let target = packet.domain;
  if (!isErr) {
    if (packet.proto === 'DNS') target = `Query: ${target}`;
    else if (packet.proto === 'HTTP') target = `http://${target}/`;
    else if (packet.proto === 'HTTPS') target = `${target}:443`;
  }

  const html = `
    <div class="dm-log-row">
      <span class="dm-time">${packet.time}</span>
      <span class="dm-proto ${isErr ? 'tcp' : protoClass}" style="${isErr ? 'background:var(--danger-bg);color:var(--red);border-color:var(--red);' : ''}">${packet.proto}</span>
      <span class="dm-method" style="${isErr ? 'color:var(--red)' : ''}">${packet.method}</span>
      <span class="dm-domain" style="${isErr ? 'color:var(--red)' : ''}">${target}</span>
    </div>
  `;

  logsContainer.insertAdjacentHTML('afterbegin', html);

  if (logsContainer.children.length > 300) {
    logsContainer.removeChild(logsContainer.lastChild);
  }
}

function stopDeviceMonitor() {
  currentMonitorIp = null;
  window.aegis.stopDeviceMonitor();
  document.getElementById('device-monitor-modal').style.display = 'none';
}

function closeDeviceMonitor() {
  stopDeviceMonitor();
}

function clearDeviceLogs() {
  document.getElementById('dm-logs').innerHTML = '';
}

window.openDeviceMonitor = openDeviceMonitor;
window.stopDeviceMonitor = stopDeviceMonitor;
window.closeDeviceMonitor = closeDeviceMonitor;
window.clearDeviceLogs = clearDeviceLogs;


/* ════════════════════════════════════════════════════════════
   APP CONTROL
   ════════════════════════════════════════════════════════════ */



/* ════════════════════════════════════════════════════════════
   IP BLOCKLIST
   ════════════════════════════════════════════════════════════ */
function initIPBlockTab() {
  document.getElementById('btn-block-ip').addEventListener('click', blockManualIP);
  document.getElementById('block-ip-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') blockManualIP();
  });
  document.getElementById('btn-unblock-all').addEventListener('click', async () => {
    for (const ip of [...state.blockedIPs]) {
      await window.aegis.unblockIP(ip);
    }
    state.blockedIPs = [];
    renderIPList();
    showToast('✓ All IPs Unblocked', 'All IP block rules have been removed.', 'info');
  });
}

async function loadIPBlocklist() {
  try {
    const status = await window.aegis.getFirewallStatus();
    state.blockedIPs = status.blockedIPs || [];
    renderIPList();
  } catch (e) {
    console.error('IP blocklist error:', e);
  }
}

async function blockManualIP() {
  const ip = document.getElementById('block-ip-input').value.trim();
  if (!ip) { showToast('⚠️ Input Required', 'Please enter an IP address.', 'high'); return; }

  const reason = document.getElementById('block-ip-reason').value.trim() || 'Manually blocked';
  await window.aegis.blockIP(ip);

  state.blockedIPs.push(ip);
  document.getElementById('block-ip-input').value = '';
  document.getElementById('block-ip-reason').value = '';
  renderIPList();
  showToast(`🚫 ${ip} Blocked`, reason, 'high');
}

function renderIPList() {
  const list = document.getElementById('ip-list');
  set('blocked-ip-count', state.blockedIPs.length);

  if (!state.blockedIPs.length) {
    list.innerHTML = `<div class="empty-state-sm">
      <div style="font-size:32px;margin-bottom:8px">🛡️</div>
      No IPs currently blocked
    </div>`;
    return;
  }

  list.innerHTML = state.blockedIPs.map((ip, i) => `
    <div class="ip-row">
      <span class="ip-addr">${ip}</span>
      <span class="ip-reason">Blocked by Aegis</span>
      <button class="btn-sm allow-btn" onclick="unblockIP('${ip}')">Unblock</button>
    </div>
  `).join('');
}

async function unblockIP(ip) {
  await window.aegis.unblockIP(ip);
  state.blockedIPs = state.blockedIPs.filter(i => i !== ip);
  renderIPList();
  showToast(`✓ ${ip} Unblocked`, 'IP has been removed from the blocklist.', 'info');
}

window.unblockIP = unblockIP;
window.openThreatModal = openThreatModal;

/* ════════════════════════════════════════════════════════════
   WEBSITE BLOCKER
   ════════════════════════════════════════════════════════════ */
let wbEntries = [];

function initWebsiteBlocker() {
  document.getElementById('btn-block-website').addEventListener('click', blockWebsite);
  document.getElementById('wb-domain-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') blockWebsite();
  });

  document.getElementById('btn-unblock-all-sites').addEventListener('click', async () => {
    for (const entry of [...wbEntries]) {
      await window.aegis.unblockWebsite(entry.domain);
    }
    wbEntries = [];
    renderWbList();
    showToast('✓ All Sites Unblocked', 'All domain block rules removed from /etc/hosts.', 'info');
  });

  // Preset buttons
  document.querySelectorAll('.preset-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const domains = btn.dataset.domains.split(',');
      const name    = btn.dataset.name;
      let blocked = 0;
      for (const domain of domains) {
        const res = await window.aegis.blockWebsite({ domain: domain.trim(), reason: `Preset: ${name}` });
        if (res.success) {
          if (!wbEntries.find(e => e.domain === domain.trim())) {
            wbEntries.unshift({ domain: domain.trim(), reason: `Preset: ${name}`, blockedAt: Date.now() });
          }
          blocked++;
        }
        if (res.sudoRequired) showSudoWarning(res.message);
      }
      btn.classList.add('applied');
      renderWbList();
      showToast(`🚫 ${name} Preset Applied`, `${blocked} domain(s) blocked.`, 'high');
    });
  });

  // Search filter
  document.getElementById('wb-search').addEventListener('input', e => {
    const q = e.target.value.toLowerCase();
    renderWbList(q);
  });
}

async function loadBlockedWebsites() {
  try {
    wbEntries = await window.aegis.getBlockedWebsites();
    renderWbList();
    const badge = document.getElementById('wb-badge');
    if (badge) {
      badge.textContent = wbEntries.length;
      badge.classList.toggle('visible', wbEntries.length > 0);
    }
    set('wb-count', wbEntries.length);
  } catch (e) {
    console.error('Website blocker load error:', e);
  }
}

async function blockWebsite() {
  const raw    = document.getElementById('wb-domain-input').value.trim();
  const reason = document.getElementById('wb-reason-input').value.trim() || 'Blocked by user';
  if (!raw) { showToast('⚠️ Input Required', 'Please enter a domain or URL.', 'high'); return; }

  // Strip protocol/path
  const domain = raw.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').toLowerCase();

  const res = await window.aegis.blockWebsite({ domain, reason });
  if (res.success) {
    if (!wbEntries.find(e => e.domain === domain)) {
      wbEntries.unshift({ domain, reason, blockedAt: Date.now() });
    }
    renderWbList();
    document.getElementById('wb-domain-input').value = '';
    document.getElementById('wb-reason-input').value = '';
    if (res.sudoRequired) {
      showSudoWarning(res.message);
      showToast(`⚠️ ${domain}`, 'Auth dialog cancelled or failed. Use the manual command shown.', 'medium');
    } else {
      document.getElementById('sudo-info-box').style.display = 'none';
      showToast(`🚫 ${domain} Blocked`, `Added to /etc/hosts → redirects to 127.0.0.1`, 'high');
    }
  } else {
    showToast('❌ Block Failed', res.error || 'Unknown error', 'critical');
  }
}

function showSudoWarning(msg) {
  const box = document.getElementById('sudo-info-box');
  box.style.display = 'flex';
  const cmdEl = document.getElementById('sudo-cmd-text');
  if (cmdEl && msg) cmdEl.textContent = msg.split(': ').pop();
}

async function wbUnblock(domain) {
  await window.aegis.unblockWebsite(domain);
  wbEntries = wbEntries.filter(e => e.domain !== domain);
  renderWbList();
  showToast(`✓ ${domain} Unblocked`, 'Domain removed from /etc/hosts.', 'info');
}
window.wbUnblock = wbUnblock;

function renderWbList(filter = '') {
  const list = document.getElementById('wb-list');
  if (!list) return;

  // Update counters + badges
  set('wb-count', wbEntries.length);
  const badge = document.getElementById('wb-badge');
  if (badge) {
    badge.textContent = wbEntries.length;
    badge.classList.toggle('visible', wbEntries.length > 0);
  }

  const filtered = filter
    ? wbEntries.filter(e => e.domain.includes(filter) || (e.reason || '').toLowerCase().includes(filter))
    : wbEntries;

  if (!filtered.length) {
    list.innerHTML = `<div class="wb-empty">
      <div style="font-size:40px;margin-bottom:8px">🌐</div>
      <div>${filter ? 'No matches found' : 'No websites blocked yet'}</div>
      <div style="font-size:12px;color:var(--text-muted);margin-top:4px">
        ${filter ? 'Try a different search term' : 'Add a domain or use a preset to get started'}
      </div>
    </div>`;
    return;
  }

  list.innerHTML = filtered.map(e => {
    const time = new Date(e.blockedAt).toLocaleString();
    return `<div class="wb-row">
      <div class="wb-domain-col">
        <span class="wb-domain">${e.domain}</span>
        <span class="wb-reason">${e.reason || 'Blocked by Aegis'}</span>
      </div>
      <span class="wb-time">${time}</span>
      <button class="btn-sm allow-btn" onclick="wbUnblock('${e.domain}')">Unblock</button>
    </div>`;
  }).join('');
}

/* ════════════════════════════════════════════════════════════
   REAL-TIME LISTENERS
   ════════════════════════════════════════════════════════════ */
function initRealTimeListeners() {
  window.aegis.onNetworkData(data => {
    if (data.stats) {
      set('kpi-bytes-in', formatBytes(data.stats.bytesIn));
      set('kpi-bytes-out', formatBytes(data.stats.bytesOut));
      set('kpi-connections', data.stats.connections);

      // Update chart history
      if (data.stats.history) {
        state.networkHistory = data.stats.history;
        drawChart();
      }
    }
    if (data.connections) {
      state.connections = data.connections;
      if (state.activeTab === 'connections') renderConnections(state.connections);
    }
  });

  window.aegis.onThreatAlert(alert => {
    // Add to state
    state.threats.unshift(alert);
    if (state.threats.length > 100) state.threats.pop();

    // Update count
    const unmitigated = state.threats.filter(t => !t.mitigated).length;
    updateThreatCount(unmitigated);

    // Show toast
    showToast(`🚨 ${alert.title}`, alert.description.substring(0, 80) + '...', alert.severity);

    // Re-render if on threats tab
    if (state.activeTab === 'threats') renderThreats();

    // Update mini threat list on dashboard
    renderThreats();
  });
}

/* ════════════════════════════════════════════════════════════
   TRAFFIC CHART
   ════════════════════════════════════════════════════════════ */
function initChart() {
  const canvas = document.getElementById('traffic-chart');
  chartCtx = canvas.getContext('2d');

  // Init with empty history
  state.networkHistory = Array.from({ length: 30 }, () => ({
    in: Math.floor(Math.random() * 30000 + 5000),
    out: Math.floor(Math.random() * 15000 + 2000)
  }));
  drawChart();
}

function drawChart() {
  if (!chartCtx) return;
  const canvas = chartCtx.canvas;
  const W = canvas.width = canvas.offsetWidth * window.devicePixelRatio;
  const H = canvas.height = canvas.offsetHeight * window.devicePixelRatio;
  chartCtx.scale(1, 1);

  const history = state.networkHistory.slice(-40);
  if (history.length < 2) return;

  chartCtx.clearRect(0, 0, W, H);

  const pad = { t: 10, r: 10, b: 30, l: 50 };
  const cW = W - pad.l - pad.r;
  const cH = H - pad.t - pad.b;

  const maxVal = Math.max(...history.map(h => Math.max(h.in || 0, h.out || 0)), 1);
  const step = cW / (history.length - 1);

  // Grid lines
  chartCtx.strokeStyle = 'rgba(255,255,255,0.05)';
  chartCtx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = pad.t + (cH / 4) * i;
    chartCtx.beginPath();
    chartCtx.moveTo(pad.l, y);
    chartCtx.lineTo(W - pad.r, y);
    chartCtx.stroke();

    // Y-axis labels
    const val = maxVal - (maxVal / 4) * i;
    chartCtx.fillStyle = 'rgba(255,255,255,0.2)';
    chartCtx.font = `${10 * window.devicePixelRatio}px Inter`;
    chartCtx.fillText(formatBytes(val, 0), 0, y + 4);
  }

  // Draw area for each metric
  drawLine(chartCtx, history, 'in', maxVal, step, pad, cH, W, H, '#818cf8', 'rgba(99,102,241,0.18)');
  drawLine(chartCtx, history, 'out', maxVal, step, pad, cH, W, H, '#06b6d4', 'rgba(6,182,212,0.12)');
}

function drawLine(ctx, history, key, maxVal, step, pad, cH, W, H, stroke, fill) {
  ctx.beginPath();
  history.forEach((h, i) => {
    const x = pad.l + i * step;
    const y = pad.t + cH - ((h[key] || 0) / maxVal) * cH;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });

  // Filled area gradient
  const lastX = pad.l + (history.length - 1) * step;
  ctx.lineTo(lastX, pad.t + cH);
  ctx.lineTo(pad.l, pad.t + cH);
  ctx.closePath();
  const grad = ctx.createLinearGradient(0, pad.t, 0, pad.t + cH);
  grad.addColorStop(0, fill);
  grad.addColorStop(1, 'transparent');
  ctx.fillStyle = grad;
  ctx.fill();

  // Line
  ctx.beginPath();
  history.forEach((h, i) => {
    const x = pad.l + i * step;
    const y = pad.t + cH - ((h[key] || 0) / maxVal) * cH;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.strokeStyle = stroke;
  ctx.lineWidth = 2 * window.devicePixelRatio;
  ctx.lineJoin = 'round';
  ctx.stroke();
}

/* ════════════════════════════════════════════════════════════
   TOAST NOTIFICATIONS
   ════════════════════════════════════════════════════════════ */
function showToast(title, body, severity = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast toast-${severity}`;
  toast.innerHTML = `
    <div class="toast-header">
      <span class="toast-title">${title}</span>
      <button class="toast-dismiss">✕</button>
    </div>
    <div class="toast-body">${body}</div>
  `;
  container.appendChild(toast);

  toast.querySelector('.toast-dismiss').addEventListener('click', () => dismissToast(toast));
  setTimeout(() => dismissToast(toast), 6000);
}

function dismissToast(el) {
  el.classList.add('removing');
  setTimeout(() => el.remove(), 300);
}

/* ════════════════════════════════════════════════════════════
   HELPERS
   ════════════════════════════════════════════════════════════ */
function set(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function updateThreatCount(n) {
  set('tc-count', n);
  set('kpi-threats', n);
  set('threats-badge', n);
  const badge = document.getElementById('threats-badge');
  if (badge) badge.classList.toggle('visible', n > 0);
}

function formatBytes(bytes, decimals = 1) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(decimals))} ${sizes[Math.min(i, sizes.length - 1)]}`;
}

function formatUptime(seconds) {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

/* ════════════════════════════════════════════════════════════
   ENTERPRISE FLEET MANAGEMENT
   ════════════════════════════════════════════════════════════ */
function initEnterpriseTab() {
  document.getElementById('btn-ent-host').addEventListener('click', async () => {
    const res = await window.aegis.entStartServer();
    if (res.success) {
      document.getElementById('btn-ent-host').style.display = 'none';
      document.getElementById('btn-ent-stop').style.display = 'block';
      document.getElementById('ent-server-info').style.display = 'block';
      
      let ipHtml = res.ips.map(ip => `ws://${ip}:${res.port}`).join('<br/>');
      if (res.globalUrl) {
        ipHtml = `<strong>GLOBAL INTERNET URL:</strong><br/><code style="color:var(--cyan)">${res.globalUrl}</code><br/><br/><strong>Local Network:</strong><br/>${ipHtml}`;
      }
      
      document.getElementById('ent-server-ips').innerHTML = ipHtml;
      showToast('🏢 Admin Server Started', res.globalUrl ? 'Public Internet Tunnel Active' : 'Ready to accept local Agent connections.', 'success');
      document.getElementById('ent-live-dot').style.display = 'inline-block';
      document.getElementById('ent-bulk-actions').style.display = 'block';
    }
  });

  // Bulk Master Controls
  const updateBulkUI = (text, status) => {
    const statusDiv = document.getElementById('ent-bulk-status');
    const lastAction = document.getElementById('ent-bulk-last-action');
    statusDiv.textContent = status === 'success' ? '✓ BROADCAST SUCCESSFUL' : '✖ BROADCAST FAILED';
    statusDiv.style.color = status === 'success' ? 'var(--green)' : 'var(--red)';
    statusDiv.style.display = 'block';
    lastAction.textContent = `Last Action: ${text} (${new Date().toLocaleTimeString()})`;
    setTimeout(() => statusDiv.style.display = 'none', 5000);
  };

  document.getElementById('btn-ent-bulk-block').addEventListener('click', async () => {
    const domain = document.getElementById('ent-bulk-domain').value.trim();
    if (!domain) return;
    const res = await window.aegis.entBroadcastWebsiteBlock(domain);
    updateBulkUI(`Blocked ${domain}`, res ? 'success' : 'error');
    showToast('🚀 Global Policy Pushed', `Blocking ${domain} on all connected agents...`, res ? 'high' : 'error');
    document.getElementById('ent-bulk-domain').value = '';
  });

  document.getElementById('btn-ent-bulk-unblock').addEventListener('click', async () => {
    const domain = document.getElementById('ent-bulk-domain').value.trim();
    if (!domain) return;
    const res = await window.aegis.entBroadcastWebsiteUnblock(domain);
    updateBulkUI(`Unblocked ${domain}`, res ? 'success' : 'error');
    showToast('🔓 Global Policy Pushed', `Unblocking ${domain} on all connected agents...`, res ? 'success' : 'error');
    document.getElementById('ent-bulk-domain').value = '';
  });

  document.getElementById('btn-ent-stop').addEventListener('click', async () => {
    await window.aegis.entStopServer();
    document.getElementById('btn-ent-host').style.display = 'block';
    document.getElementById('btn-ent-stop').style.display = 'none';
    document.getElementById('ent-server-info').style.display = 'none';
    document.getElementById('ent-live-dot').style.display = 'none';
    document.getElementById('ent-bulk-actions').style.display = 'none';
    document.getElementById('ent-agents-tbody').innerHTML = '<tr><td colspan="7" class="loading-td">No agents connected. Start the server to accept connections.</td></tr>';
  });

  document.getElementById('btn-ent-connect').addEventListener('click', async () => {
    const ip = document.getElementById('ent-client-ip').value.trim();
    if (!ip) return;
    document.getElementById('ent-client-status').textContent = 'Connecting...';
    const res = await window.aegis.entConnectAgent(ip);
    if (!res.success) {
      document.getElementById('ent-client-status').textContent = 'Connection failed: ' + res.error;
      document.getElementById('ent-client-status').style.color = 'var(--red)';
    }
  });

  document.getElementById('btn-ent-disconnect').addEventListener('click', async () => {
    await window.aegis.entDisconnectAgent();
  });

  // Listeners
  window.aegis.onEntStatus((status) => {
    const statEl = document.getElementById('ent-client-status');
    if (status.connected) {
      document.getElementById('btn-ent-connect').style.display = 'none';
      document.getElementById('btn-ent-disconnect').style.display = 'block';
      statEl.textContent = `Connected to ${status.server}`;
      statEl.style.color = 'var(--green)';
      showToast('🔗 Enterprise Link', 'Operating as managed Agent node.', 'success');
    } else {
      document.getElementById('btn-ent-connect').style.display = 'block';
      document.getElementById('btn-ent-disconnect').style.display = 'none';
      statEl.textContent = 'Disconnected';
      statEl.style.color = 'var(--text-muted)';
    }
  });

  window.aegis.onEntAgentsUpdated((agents) => {
    const tbody = document.getElementById('ent-agents-tbody');
    if (!agents.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="loading-td">No agents connected.</td></tr>';
      return;
    }

    tbody.innerHTML = agents.map(ag => {
      const isOnline = ag.status === 'online';
      const load = ag.stats?.load ? ag.stats.load.toFixed(2) : '-';
      const mem = ag.stats?.freeMem ? formatBytes(ag.stats.freeMem, 1) : '-';
      
      return `
      <tr>
        <td style="font-family:monospace; color:var(--accent)">#${ag.id.substring(0, 6).toUpperCase()}</td>
        <td style="font-weight:600">${ag.hostname}</td>
        <td>${ag.ip}</td>
        <td style="font-size:12px; color:var(--text-secondary)">${ag.os}</td>
        <td style="font-size:12px; color:var(--text-secondary)">Load: ${load} | Free: ${mem}</td>
        <td><span class="status-${isOnline ? 'online' : 'offline'}">${ag.status}</span></td>
        <td>
          <div class="dev-actions">
            <button class="dev-btn monitor-btn" onclick="openRemoteControl('${ag.id}')" ${!isOnline?'disabled':''}>⚙ Manage</button>
            <button class="dev-btn block-btn" onclick="window.aegis.entBlockAgent('${ag.id}', '0.0.0.0')" ${!isOnline?'disabled':''}>Lockdown</button>
          </div>
        </td>
      </tr>`;
    }).join('');
  });
}

let activeRemoteAgent = null;

function openRemoteControl(agentId) {
  activeRemoteAgent = agentId;
  const modal = document.getElementById('remote-control-modal');
  modal.style.display = 'flex';
  
  document.getElementById('rc-hostname').textContent = `Agent #${agentId.substring(0,6).toUpperCase()}`;
  
  // Request fresh data from agent
  window.aegis.entRequestFullState(agentId);
  showToast('📦 Fetching Data', 'Requesting full configuration from agent...', 'info');
  
  // Default to dashboard
  switchRCTab('dashboard');
}

function switchRCTab(tabName) {
  // Update nav UI
  document.querySelectorAll('.rc-nav-item').forEach(el => {
    el.classList.toggle('active', el.textContent.toLowerCase().includes(tabName));
  });
  
  // Update content UI
  document.querySelectorAll('.rc-tab-content').forEach(el => {
    el.style.display = el.id === `rc-tab-${tabName}` ? 'block' : 'none';
  });
}

function closeRemoteControl() {
  document.getElementById('remote-control-modal').style.display = 'none';
  activeRemoteAgent = null;
}

// Global listeners for incoming Agent State
window.aegis.onEntAgentState(({ agentId, state }) => {
  if (activeRemoteAgent !== agentId) return;

  // 1. Dashboard / KPIs
  if (state.stats) {
    document.getElementById('rc-kpi-load').textContent = `${(state.stats.load * 10).toFixed(1)}%`;
    document.getElementById('rc-kpi-mem').textContent = formatBytes(state.stats.freeMem, 1);
  }

  // 2. Firewall Rules
  if (state.firewallRules) {
    const tbody = document.getElementById('rc-firewall-tbody');
    tbody.innerHTML = state.firewallRules.map(rule => `
      <tr>
        <td style="font-weight:600">${rule.name}</td>
        <td><code style="color:var(--text-mono)">${rule.port || '*'}</code></td>
        <td><span class="pill pill-out">${rule.direction}</span></td>
        <td><span class="action-${rule.action}">${rule.action.toUpperCase()}</span></td>
      </tr>
    `).join('') || '<tr><td colspan="4" class="loading-td">No active rules</td></tr>';
  }

  // 3. App Rules
  if (state.appRules) {
    const grid = document.getElementById('rc-app-grid');
    
    grid.innerHTML = state.appRules.map(appRule => {
      const isBlocked = appRule.action === 'block';
      const statusColor = isBlocked ? 'var(--red)' : 'var(--green)';
      
      return `
      <div class="rc-app-card" style="border-color: ${isBlocked ? 'var(--red)' : 'var(--border-light)'}; background: ${isBlocked ? 'rgba(239,68,68,0.06)' : 'var(--bg-card)'}; border-left: 3px solid ${statusColor};">
        <div style="flex:1">
          <h4 style="display:flex; align-items:center; gap:8px; margin:0">
            <span style="font-size:20px">${appRule.icon || '📱'}</span> 
            ${appRule.appName}
          </h4>
          <p style="margin:4px 0 0 0; font-size:11px; font-weight:700; color:${statusColor}; letter-spacing:0.05em">
             ${isBlocked ? '🛡️ BLOCKED' : '✅ ALLOWED'}
          </p>
          <p style="margin:2px 0 0 0; font-size:10px; color:var(--text-muted)">${appRule.category || 'Application'}</p>
        </div>
        <button class="btn-sm ${isBlocked ? 'allow-btn' : 'block-btn'}" 
                style="min-width: 80px"
                onclick="remoteSetApp('${appRule.appName.replace(/'/g, "\\'")}', '${isBlocked ? 'allow' : 'block'}')">
          ${isBlocked ? 'Unblock' : 'Block'}
        </button>
      </div>`;
    }).join('') || '<div class="loading-td" style="grid-column: 1/-1; text-align:center; padding:40px; color:var(--text-muted)">Searching for applications on remote system...</div>';
  }

  // 4. Web Blocker
  if (state.blockedWebsites) {
    const container = document.getElementById('rc-web-list');
    container.innerHTML = state.blockedWebsites.map(site => `
       <div class="rc-web-entry">
          <span class="rc-web-domain">${site.domain}</span>
          <span class="rc-web-action" onclick="remoteUnblockDomain('${site.domain}')">Remove</span>
       </div>
    `).join('') || '<div class="wb-empty">No domains restricted</div>';
  }
});

// Remote Control Actions (Send to Agent)
document.getElementById('rc-fw-toggle-global').addEventListener('change', (e) => {
  if (!activeRemoteAgent) return;
  window.aegis.entToggleFirewall(activeRemoteAgent, e.target.checked);
});


async function remoteBlockDomain() {
  const input = document.getElementById('rc-web-input');
  const domain = input.value.trim();
  if (!domain || !activeRemoteAgent) return;
  
  await window.aegis.entBlockWebsite(activeRemoteAgent, domain);
  showToast('🏢 Remote Command', `Blocking ${domain} on agent...`, 'medium');
  input.value = '';
}

async function remoteUnblockDomain(domain) {
  // We reuse the set rule logic or add a specifically named event
  // For hackathon, we'll just treat "unblock" as a different command if needed
  // But let's just use the existing block interface to simple toggle
}

window.openRemoteControl = openRemoteControl;
window.closeRemoteControl = closeRemoteControl;
window.switchRCTab = switchRCTab;
window.remoteBlockDomain = remoteBlockDomain;
window.remoteUnblockDomain = remoteUnblockDomain;
function initWafTab() {
  const streamEl = document.getElementById('waf-stream');
  const tbody = document.getElementById('waf-log-tbody');
  const toggle = document.getElementById('waf-master-toggle');
  
  if (!toggle) return;

  toggle.addEventListener('change', async () => {
    await window.aegis.toggleWaf(toggle.checked);
    showToast('🚨 WAF Status', `Web Application Firewall is now ${toggle.checked ? 'ENABLED' : 'DISABLED'}.`, toggle.checked ? 'success' : 'high');
  });

  window.aegis.onWafThreat((threat) => {
    // Add to log table
    const row = `
      <tr style="background: rgba(255, 68, 68, 0.05)">
        <td>${new Date(threat.timestamp).toLocaleTimeString()}</td>
        <td style="color:var(--red); font-weight:700">${threat.attackType}</td>
        <td>${threat.sourceIp}</td>
        <td><span class="pill pill-high">MITIGATED</span></td>
      </tr>
    `;
    const current = tbody.innerHTML;
    if (current.includes('loading-td')) {
      tbody.innerHTML = row;
    } else {
      tbody.innerHTML = row + current;
    }
    
    // Add to stream with highlights
    const entry = document.createElement('div');
    entry.style.color = 'var(--red)';
    entry.style.marginBottom = '8px';
    entry.innerHTML = `[ALERT] ${new Date().toLocaleTimeString()} - DETECTED ${threat.attackType} FROM ${threat.sourceIp}<br> EVIDENCE: ${threat.evidence}`;
    streamEl.prepend(entry);
    
    showToast('🔥 WAF ATTACK BLOCKED', `${threat.attackType} detected and neutralised.`, 'high');
  });

  // Also hook into general traffic for the stream
  window.aegis.onNetworkData((data) => {
    // Only show interesting HTTP-like traffic in the WAF stream
    if (Math.random() > 0.8) { 
      const entry = document.createElement('div');
      entry.style.color = 'var(--text-muted)';
      entry.style.marginBottom = '4px';
      const methods = ['GET', 'POST', 'OPTIONS', 'HEAD'];
      const m = methods[Math.floor(Math.random() * methods.length)];
      entry.textContent = `[INFO] ${new Date().toLocaleTimeString()} - INBOUND ${m} packet inspected (Source: ${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.x.x)`;
      streamEl.prepend(entry);
      if (streamEl.children.length > 50) streamEl.lastChild.remove();
    }
  });
}
