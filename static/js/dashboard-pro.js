(() => {
  'use strict';

  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';
  const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info'];
  const SEVERITY_LABELS = {Critical: 'Critical', High: 'High', Medium: 'Medium', Low: 'Low', Info: 'Info'};
  const STATUS_LABELS = {
    queued: 'Queued', running: 'Running', cancelling: 'Cancelling', cancelled: 'Cancelled', done: 'Completed', completed: 'Completed', complete: 'Completed',
    failed: 'Failed', interrupted: 'Interrupted', budget_exhausted: 'Budget exhausted', error: 'Error', potential: 'Potential', confirmed: 'Confirmed', not_vulnerable: 'Not vulnerable', inconclusive: 'Inconclusive'
  };
  const QUICK_SCAN_IDS = ['info_scan', 'cors_scanner', 'clickjacking_scanner', 'host_header_scanner', 'csrf_scan'];
  const MODERN_SCAN_IDS = ['modern_spa_scanner', 'openapi_scanner', 'graphql_scanner', 'websocket_scanner', 'grpc_scanner', 'authorization_matrix_scanner', 'oidc_scanner'];
  const STANDARD_EXCLUDED = new Set(['weak_password_scanner', 'auth_scanner', ...MODERN_SCAN_IDS]);

  const state = {
    scans: [],
    stats: {},
    scanners: [],
    scopes: [],
    audit: [],
    selectedScanId: null,
    findingFilter: 'all',
    search: '',
    polling: false
  };

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const clamp = (n, min, max) => Math.max(min, Math.min(max, n));
  const asNumber = (value, fallback = 0) => Number.isFinite(Number(value)) ? Number(value) : fallback;

  function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>'"]/g, (char) => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'}[char]));
  }

  function displayScannerName(value) {
    const raw = String(value || 'unknown scanner');
    return raw.replace(/_/g, ' ').replace(/\b\w/g, letter => letter.toUpperCase());
  }

  function normalizeSeverity(value) {
    const text = String(value || 'Info').toLowerCase();
    return SEVERITIES.find(sev => sev.toLowerCase() === text) || 'Info';
  }

  function normalizeStatus(value) {
    const text = String(value || 'unknown').toLowerCase();
    if (['done', 'complete', 'completed'].includes(text)) return 'completed';
    return text;
  }

  function translateStatus(value) {
    const normalized = normalizeStatus(value);
    return STATUS_LABELS[normalized] || STATUS_LABELS[String(value || '').toLowerCase()] || value || 'Unknown';
  }

  function statusClass(value) {
    return normalizeStatus(value).replace(/[^a-z0-9_-]/g, '');
  }

  function isActiveStatus(status) {
    return ['queued', 'running', 'cancelling'].includes(normalizeStatus(status));
  }

  function isExportableScan(scan) {
    return scan && Number.isInteger(Number(scan.id)) && normalizeStatus(scan.status) === 'completed';
  }

  function selectedScan() {
    if (!state.scans.length) return null;
    return state.scans.find(scan => String(scan.id) === String(state.selectedScanId)) || state.scans[0];
  }

  function resultIsFinding(item) {
    if (!item || typeof item !== 'object') return false;
    const status = String(item.status || '').toLowerCase();
    return Boolean(item.vulnerable) || ['confirmed', 'potential', 'error'].includes(status);
  }

  function normalizeFinding(item, scan) {
    const evidence = item.evidence && typeof item.evidence === 'object' ? JSON.stringify(item.evidence, null, 2) : String(item.evidence || '');
    return {
      scanner: displayScannerName(item.name || item.scanner || 'Unknown Scanner'),
      scannerKey: String(item.name || item.scanner || '').toLowerCase().replace(/\s+/g, '_'),
      severity: normalizeSeverity(item.severity),
      status: String(item.status || (item.vulnerable ? 'confirmed' : 'potential')),
      confidence: String(item.confidence || 'Low'),
      description: String(item.result || item.description || 'No details available.'),
      endpoint: String(item.endpoint || scan?.target || ''),
      parameter: String(item.parameter || ''),
      recommendation: String(item.recommendation || 'Review the finding manually and validate the evidence before relying on it.'),
      cwe: String(item.cwe || ''),
      cvss: asNumber(item.cvss, 0).toFixed(1),
      evidence: evidence || 'N/A'
    };
  }

  function findingsForScan(scan) {
    const results = Array.isArray(scan?.results) ? scan.results : [];
    return results.filter(resultIsFinding).map(item => normalizeFinding(item, scan));
  }

  function severityDistribution(findings) {
    const dist = Object.fromEntries(SEVERITIES.map(sev => [sev, 0]));
    findings.forEach(item => { dist[item.severity] = (dist[item.severity] || 0) + 1; });
    return dist;
  }

  function highestSeverity(findings) {
    return SEVERITIES.find(sev => findings.some(item => item.severity === sev)) || 'Info';
  }

  function formatDate(value) {
    if (!value) return '—';
    const safe = String(value).replace(' ', 'T');
    const date = new Date(safe);
    if (Number.isNaN(date.getTime())) return String(value);
    return new Intl.DateTimeFormat('en-US', {dateStyle: 'medium', timeStyle: 'short'}).format(date);
  }

  function hostnameOf(url) {
    try { return new URL(url).hostname; } catch (_) { return String(url || '—'); }
  }

  function toast(message, type = 'info') {
    const region = $('#toastRegion');
    const item = document.createElement('div');
    item.className = `toast ${type}`;
    item.textContent = message;
    region.appendChild(item);
    setTimeout(() => item.remove(), 4200);
  }

  async function fetchJson(url, options = {}) {
    const response = await fetch(url, options);
    const data = await response.json().catch(() => ({}));
    if (response.status === 401) {
      window.location.href = '/login';
      return data;
    }
    if (!response.ok) throw new Error(data.error || data.message || `HTTP ${response.status}`);
    return data;
  }

  async function loadScanners() {
    const data = await fetchJson('/api/scanners');
    state.scanners = Array.isArray(data.scanners) ? data.scanners : [];
    renderScannerGrid();
    renderScannerInputs();
  }

  async function loadScopes() {
    const data = await fetchJson('/api/scopes');
    state.scopes = Array.isArray(data.scopes) ? data.scopes : [];
    $('#queueMode').textContent = data.required ? 'Scopes Required' : 'Safe Local';
  }

  async function loadAudit() {
    const data = await fetchJson('/api/audit');
    state.audit = Array.isArray(data.events) ? data.events : [];
  }

  async function refreshDashboard({silent = false} = {}) {
    try {
      const [historyData, statsData, scopesResult, auditResult] = await Promise.allSettled([
        fetchJson('/api/history'),
        fetchJson('/api/dashboard-stats'),
        loadScopes(),
        loadAudit()
      ]);
      if (historyData.status === 'fulfilled') state.scans = Array.isArray(historyData.value.scans) ? historyData.value.scans : [];
      if (statsData.status === 'fulfilled') state.stats = statsData.value.stats || {};
      if (scopesResult.status === 'rejected' && !silent) toast(scopesResult.reason.message || 'Unable to load scopes', 'warning');
      if (auditResult.status === 'rejected' && !silent) toast(auditResult.reason.message || 'Unable to load audit events', 'warning');
      if (!state.selectedScanId && state.scans.length) state.selectedScanId = state.scans[0].id;
      if (state.selectedScanId && !state.scans.some(scan => String(scan.id) === String(state.selectedScanId)) && state.scans.length) state.selectedScanId = state.scans[0].id;
      renderAll();
      schedulePolling();
      if (!silent) toast('Dashboard refreshed', 'success');
    } catch (error) {
      toast(error.message || 'Unable to load data', 'error');
      renderAll();
    }
  }

  function renderAll() {
    renderExecutive();
    renderMetrics();
    renderSelectedScan();
    renderSeverity();
    renderFindings();
    renderScanList();
    renderModules();
    renderScopes();
    renderAudit();
    renderTimeline();
  }

  function renderExecutive() {
    const scan = selectedScan();
    const findings = findingsForScan(scan);
    const risk = clamp(asNumber(scan?.risk_score ?? averageRisk(), 0), 0, 100);
    $('#riskValue').textContent = Math.round(risk);
    $('#riskRing').style.strokeDashoffset = String(352 - (352 * risk / 100));
    $('#executiveTitle').textContent = scan ? `Latest analysis: ${hostnameOf(scan.target)}` : 'Ready to monitor the attack surface';
    $('#executiveText').textContent = scan
      ? `${translateStatus(scan.status)} — ${findings.length} security findings, highest severity: ${SEVERITY_LABELS[highestSeverity(findings)]}.`
      : 'Start a new scan or review the latest history. Confirmed and potential findings are shown with confidence and evidence.';
    const live = state.scans.find(item => isActiveStatus(item.status));
    const liveStatus = $('#liveStatus');
    liveStatus.className = `status-pill ${statusClass(live?.status || '')}`;
    liveStatus.textContent = live ? `${translateStatus(live.status)} · ${hostnameOf(live.target)}` : 'No active scan';
  }

  function averageRisk() {
    if (!state.scans.length) return 0;
    const values = state.scans.map(scan => asNumber(scan.risk_score, 0));
    return values.reduce((sum, value) => sum + value, 0) / values.length;
  }

  function renderMetrics() {
    const stats = state.stats || {};
    const totalFindings = asNumber(stats.total_findings, state.scans.reduce((sum, scan) => sum + findingsForScan(scan).length, 0));
    const running = asNumber(stats.running_scans, state.scans.filter(scan => isActiveStatus(scan.status)).length);
    const completed = asNumber(stats.completed_scans, state.scans.filter(scan => normalizeStatus(scan.status) === 'completed').length);
    const failed = asNumber(stats.failed_scans, state.scans.filter(scan => ['failed', 'interrupted', 'budget_exhausted'].includes(normalizeStatus(scan.status))).length);
    const high = state.scans.flatMap(findingsForScan).filter(item => ['Critical', 'High'].includes(item.severity)).length;
    const cards = [
      ['Total Scans', state.scans.length, `${completed} completed`],
      ['Running Now', running, 'Queued / Running'],
      ['Total Findings', totalFindings, `${high} critical or high`],
      ['Failed Scans', failed, 'Needs review'],
      ['Average Risk', Math.round(averageRisk()), 'Risk score']
    ];
    $('#metricsGrid').innerHTML = cards.map(([label, value, hint]) => `
      <article class="metric-card"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong><small>${escapeHtml(hint)}</small></article>
    `).join('');
  }

  function renderSelectedScan() {
    const scan = selectedScan();
    const target = $('#selectedTarget');
    const box = $('#scanSummary');
    if (!scan) {
      target.textContent = 'No target selected';
      box.innerHTML = '<div class="empty" style="grid-column:1/-1">No scans yet. Start a new scan from the button above.</div>';
      return;
    }
    const findings = findingsForScan(scan);
    target.textContent = scan.target || `Scan #${scan.id}`;
    const progress = clamp(asNumber(scan.progress, normalizeStatus(scan.status) === 'completed' ? 100 : 0), 0, 100);
    const activeScanner = scan.current_scanner || '—';
    box.innerHTML = `
      <div class="summary-tile"><span>Status</span><strong><span class="status-pill ${statusClass(scan.status)}">${escapeHtml(translateStatus(scan.status))}</span></strong></div>
      <div class="summary-tile"><span>Findings</span><strong>${findings.length}</strong></div>
      <div class="summary-tile"><span>Risk</span><strong>${escapeHtml(asNumber(scan.risk_score, 0).toFixed(1))}/100</strong></div>
      <div class="summary-tile"><span>Requests</span><strong>${escapeHtml(scan.request_count ?? 0)} / ${escapeHtml(scan.request_budget ?? '—')}</strong></div>
      <div class="summary-tile"><span>Scan Mode</span><strong>${escapeHtml(scan.scan_mode || 'standard')}</strong></div>
      <div class="summary-tile"><span>Highest Severity</span><strong class="sev-${highestSeverity(findings).toLowerCase()}">${escapeHtml(SEVERITY_LABELS[highestSeverity(findings)])}</strong></div>
      <div class="summary-tile"><span>Current Module</span><strong>${escapeHtml(activeScanner)}</strong></div>
      <div class="summary-tile"><span>Date</span><strong>${escapeHtml(formatDate(scan.created_at))}</strong></div>
      <div class="progress-wrap">
        <div class="progress-top"><span>Progress</span><span>${progress}%</span></div>
        <div class="progress"><i style="width:${progress}%"></i></div>
      </div>
    `;
  }

  function renderSeverity() {
    const scan = selectedScan();
    const findings = findingsForScan(scan);
    const dist = severityDistribution(findings);
    const total = findings.length;
    $('#severityTotal').textContent = `${total} findings`;
    $('#severityDonut').innerHTML = `<span>${total}</span>`;
    const angles = {};
    let start = 0;
    SEVERITIES.forEach(sev => {
      start += total ? (dist[sev] / total) * 360 : 0;
      angles[sev] = start;
    });
    const donut = $('#severityDonut');
    donut.style.setProperty('--crit', `${angles.Critical || 0}deg`);
    donut.style.setProperty('--high', `${angles.High || 0}deg`);
    donut.style.setProperty('--med', `${angles.Medium || 0}deg`);
    donut.style.setProperty('--low', `${angles.Low || 0}deg`);
    donut.style.setProperty('--info', `${angles.Info || 0}deg`);
    const max = Math.max(1, ...Object.values(dist));
    $('#severityBars').innerHTML = SEVERITIES.map(sev => {
      const percent = Math.round((dist[sev] / max) * 100);
      return `<div class="bar-row"><strong class="sev-${sev.toLowerCase()}">${SEVERITY_LABELS[sev]}</strong><div class="bar-track"><i class="bar-fill bg-${sev.toLowerCase()}" style="width:${percent}%"></i></div><span>${dist[sev]}</span></div>`;
    }).join('');
  }

  function renderFilters() {
    const labels = {all: 'All', Critical: 'Critical', High: 'High', Medium: 'Medium', Low: 'Low', Info: 'Info'};
    $('#findingFilters').innerHTML = ['all', ...SEVERITIES].map(key => `
      <button type="button" class="${state.findingFilter === key ? 'active' : ''}" data-filter="${key}">${labels[key]}</button>
    `).join('');
  }

  function renderFindings() {
    renderFilters();
    const scan = selectedScan();
    const query = state.search.trim().toLowerCase();
    let findings = findingsForScan(scan);
    if (state.findingFilter !== 'all') findings = findings.filter(item => item.severity === state.findingFilter);
    if (query) {
      findings = findings.filter(item => [item.scanner, item.description, item.endpoint, item.status].join(' ').toLowerCase().includes(query));
    }
    const body = $('#findingsBody');
    if (!scan) {
      body.innerHTML = '<tr><td colspan="5"><div class="empty">Select or start a scan to view findings.</div></td></tr>';
      return;
    }
    if (!findings.length) {
      body.innerHTML = '<tr><td colspan="5"><div class="empty">No findings match the current filters.</div></td></tr>';
      return;
    }
    body.innerHTML = findings.map((finding, index) => `
      <tr>
        <td><strong>${escapeHtml(finding.scanner)}</strong><br><span class="muted">${escapeHtml(finding.endpoint || scan.target || '')}</span></td>
        <td><span class="badge sev-${finding.severity.toLowerCase()}">${escapeHtml(SEVERITY_LABELS[finding.severity])}</span></td>
        <td><span class="status-pill ${statusClass(finding.status)}">${escapeHtml(translateStatus(finding.status))}</span><br><span class="muted">Confidence: ${escapeHtml(finding.confidence)}</span></td>
        <td><div class="finding-desc">${escapeHtml(finding.description).slice(0, 280)}${finding.description.length > 280 ? '…' : ''}</div></td>
        <td><button class="mini-btn" type="button" data-finding="${index}">View</button></td>
      </tr>
    `).join('');
  }

  function filteredScans() {
    const query = state.search.trim().toLowerCase();
    if (!query) return state.scans;
    return state.scans.filter(scan => {
      const text = [scan.target, scan.status, scan.current_scanner, scan.scan_mode, ...(scan.results || []).map(item => item.result || item.name || '')].join(' ').toLowerCase();
      return text.includes(query);
    });
  }

  function renderScanList() {
    const scans = filteredScans();
    const list = $('#scanList');
    if (!scans.length) {
      list.innerHTML = '<div class="empty">No matching scans.</div>';
      return;
    }
    list.innerHTML = scans.slice(0, 12).map(scan => {
      const findings = findingsForScan(scan);
      const progress = clamp(asNumber(scan.progress, normalizeStatus(scan.status) === 'completed' ? 100 : 0), 0, 100);
      return `<button type="button" class="scan-item ${String(scan.id) === String(state.selectedScanId) ? 'active' : ''}" data-scan-id="${escapeHtml(scan.id)}">
        <span class="scan-item-head"><span class="scan-target">${escapeHtml(scan.target || `Scan #${scan.id}`)}</span><span class="status-pill ${statusClass(scan.status)}">${escapeHtml(translateStatus(scan.status))}</span></span>
        <span class="scan-meta"><span>${escapeHtml(formatDate(scan.created_at))}</span><span>${findings.length} findings</span><span>Risk ${escapeHtml(asNumber(scan.risk_score, 0).toFixed(1))}</span></span>
        <span class="progress"><i style="width:${progress}%"></i></span>
      </button>`;
    }).join('');
  }

  function renderModules() {
    $('#scannerCount').textContent = `${state.scanners.length} modules`;
    const groups = new Map();
    state.scanners.forEach(scanner => {
      const category = scanner.category || 'General';
      groups.set(category, (groups.get(category) || 0) + 1);
    });
    const entries = [...groups.entries()].slice(0, 8);
    $('#moduleCloud').innerHTML = entries.length ? entries.map(([category, count]) => `
      <div class="module-chip"><strong>${escapeHtml(category)}</strong><span>${count} modules</span></div>
    `).join('') : '<div class="empty">Unable to load modules.</div>';
  }

  function renderScopes() {
    const box = $('#scopeBox');
    if (!state.scopes.length) {
      box.innerHTML = '<div class="empty">No scopes added. Add scopes to restrict production scanning.</div>';
      return;
    }
    box.innerHTML = state.scopes.slice(0, 6).map(scope => `
      <div class="scope-row">
        <strong>${escapeHtml(scope.hostname_pattern)}</strong>
        <span>${scope.include_subdomains ? 'Includes subdomains' : 'Host only'} · ${escapeHtml(scope.description || 'No description')}</span>
      </div>
    `).join('');
  }

  function renderAudit() {
    const box = $('#auditList');
    if (!state.audit.length) {
      box.innerHTML = '<div class="empty">No recent events.</div>';
      return;
    }
    box.innerHTML = state.audit.slice(0, 7).map(event => `
      <div class="audit-row"><strong>${escapeHtml(event.action)}</strong><span>${escapeHtml(event.target_type || 'event')} #${escapeHtml(event.target_id || '—')} · ${escapeHtml(formatDate(event.created_at))}</span></div>
    `).join('');
  }

  function renderTimeline() {
    const active = state.scans.filter(scan => isActiveStatus(scan.status));
    const recent = active.length ? active : state.scans.slice(0, 4);
    const box = $('#liveTimeline');
    if (!recent.length) {
      box.innerHTML = '<div class="empty">Start a new scan to show runtime events here.</div>';
      return;
    }
    box.innerHTML = recent.map(scan => `
      <div class="timeline-row"><strong>${escapeHtml(hostnameOf(scan.target))}</strong><span>${escapeHtml(translateStatus(scan.status))} · ${escapeHtml(scan.current_scanner || '—')} · ${escapeHtml(scan.progress ?? 0)}%</span></div>
    `).join('');
  }

  function renderScannerGrid(selectedIds) {
    const selected = new Set(selectedIds || selectedForMode($('#scanMode')?.value || 'standard'));
    const grid = $('#scannerGrid');
    if (!grid) return;
    if (!state.scanners.length) {
      grid.innerHTML = '<div class="empty" style="grid-column:1/-1">Loading scanner modules...</div>';
      return;
    }
    grid.innerHTML = state.scanners.map(scanner => {
      const checked = selected.has(scanner.id);
      return `<article class="scanner-card ${checked ? 'checked' : ''}">
        <label>
          <input type="checkbox" value="${escapeHtml(scanner.id)}" ${checked ? 'checked' : ''} />
          <span><strong>${escapeHtml(scanner.name || displayScannerName(scanner.id))}</strong><p>${escapeHtml(scanner.description || scanner.category || '')}</p></span>
        </label>
      </article>`;
    }).join('');
  }

  function selectedForMode(mode) {
    if (mode === 'quick') return new Set(QUICK_SCAN_IDS.filter(id => state.scanners.some(scanner => scanner.id === id)));
    if (mode === 'modern') return new Set(MODERN_SCAN_IDS.filter(id => state.scanners.some(scanner => scanner.id === id)));
    if (mode === 'deep') return new Set(state.scanners.map(scanner => scanner.id));
    return new Set(state.scanners.filter(scanner => !STANDARD_EXCLUDED.has(scanner.id)).map(scanner => scanner.id));
  }

  function currentScannerSelection() {
    return $$('#scannerGrid input[type="checkbox"]:checked').map(input => input.value);
  }

  function setScannerSelection(ids) {
    const selected = new Set(ids);
    $$('#scannerGrid input[type="checkbox"]').forEach(input => {
      input.checked = selected.has(input.value);
      input.closest('.scanner-card')?.classList.toggle('checked', input.checked);
    });
    renderScannerInputs();
  }

  function renderScannerInputs() {
    const selected = new Set(currentScannerSelection());
    const box = $('#scannerInputs');
    if (!box) return;
    const panels = state.scanners.filter(scanner => selected.has(scanner.id) && Array.isArray(scanner.inputs) && scanner.inputs.length).map(scanner => {
      const fields = scanner.inputs.map(input => {
        const id = `scan-option-${scanner.id}-${input.name}`;
        const required = input.required ? 'required' : '';
        const label = `${input.label || input.name}${input.required ? ' *' : ''}`;
        const common = `data-scanner="${escapeHtml(scanner.id)}" data-name="${escapeHtml(input.name)}" data-required="${input.required ? 'true' : 'false'}"`;
        let control = '';
        if (input.type === 'boolean') {
          control = `<label class="checkbox-line"><input class="scanner-option" id="${escapeHtml(id)}" type="checkbox" ${common} /> Enabled</label>`;
        } else if (input.type === 'textarea') {
          control = `<textarea class="scanner-option" id="${escapeHtml(id)}" rows="3" placeholder="${escapeHtml(input.placeholder || '')}" ${common} ${required}></textarea>`;
        } else {
          control = `<input class="scanner-option" id="${escapeHtml(id)}" type="${escapeHtml(input.type || 'text')}" placeholder="${escapeHtml(input.placeholder || '')}" ${common} ${required} />`;
        }
        return `<label class="field"><span>${escapeHtml(label)}</span>${control}${input.help ? `<small class="muted">${escapeHtml(input.help)}</small>` : ''}</label>`;
      }).join('');
      return `<section class="scanner-panel"><h4>${escapeHtml(scanner.name || scanner.id)}</h4><div class="form-grid">${fields}</div></section>`;
    }).join('');
    box.innerHTML = panels;
  }

  function parseJsonField(id, label, fallback, expected) {
    const raw = $(`#${id}`).value.trim();
    if (!raw) return fallback;
    let value;
    try { value = JSON.parse(raw); } catch (_) { throw new Error(`${label} must be valid JSON`); }
    if (expected === 'object' && (!value || Array.isArray(value) || typeof value !== 'object')) throw new Error(`${label} must be a JSON Object`);
    if (expected === 'array' && !Array.isArray(value)) throw new Error(`${label} must be a JSON Array`);
    return value;
  }

  function collectScannerInputs() {
    const values = {};
    $$('.scanner-option').forEach(field => {
      const value = field.type === 'checkbox' ? field.checked : field.value.trim();
      if (field.dataset.required === 'true' && (value === '' || value === false)) throw new Error(`Missing required field: ${field.dataset.name}`);
      if (!values[field.dataset.scanner]) values[field.dataset.scanner] = {};
      values[field.dataset.scanner][field.dataset.name] = value;
    });
    return values;
  }

  async function startScan(event) {
    event.preventDefault();
    const url = $('#scanUrl').value.trim();
    if (!url) return toast('Enter the target URL first', 'error');
    if (!$('#authorizedTarget').checked) return toast('Authorization confirmation is required before starting the scan', 'error');
    const selected = currentScannerSelection();
    if (!selected.length) return toast('Select at least one scanner module', 'error');
    const requestBudget = Number($('#requestBudget').value || 120);
    if (!Number.isInteger(requestBudget) || requestBudget < 10 || requestBudget > 500) return toast('Request Budget must be between 10 and 500', 'error');
    let payload;
    try {
      payload = {
        url,
        vulns: selected,
        authorized: true,
        scan_mode: $('#scanMode').value,
        request_budget: requestBudget,
        verify_tls: $('#verifyTls').checked,
        scanner_inputs: collectScannerInputs(),
        http_headers: parseJsonField('scanHeaders', 'HTTP Headers', {}, 'object'),
        cookies: parseJsonField('scanCookies', 'Cookies', {}, 'object'),
        auth_profiles: parseJsonField('scanAuthProfiles', 'Auth Profiles', [], 'array'),
        browser_storage_state: parseJsonField('scanBrowserState', 'Browser Storage State', {}, 'object')
      };
    } catch (error) {
      return toast(error.message, 'error');
    }
    try {
      $('#scanModal').close();
      toast('Scan submitted to the queue', 'success');
      const data = await fetchJson('/scan-live', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken},
        body: JSON.stringify(payload)
      });
      state.selectedScanId = data.scan_id;
      await refreshDashboard({silent: true});
      toast(`Started scan #${data.scan_id}`, 'success');
      schedulePolling();
    } catch (error) {
      toast(error.message || 'Unable to start scan', 'error');
    }
  }

  async function cancelSelectedScan() {
    const scan = selectedScan();
    if (!scan) return toast('No scan selected', 'warning');
    if (!isActiveStatus(scan.status)) return toast('Cannot cancel an inactive scan', 'warning');
    try {
      const data = await fetchJson(`/scan/${scan.id}/cancel`, {method: 'POST', headers: {'X-CSRF-Token': csrfToken}});
      toast(data.message || 'Cancellation requested', 'warning');
      await pollScan(scan.id);
    } catch (error) {
      toast(error.message || 'Unable to request cancellation', 'error');
    }
  }

  async function pollScan(scanId) {
    const data = await fetchJson(`/scan-status/${scanId}`);
    const scan = data.scan;
    const index = state.scans.findIndex(item => String(item.id) === String(scan.id));
    if (index >= 0) state.scans[index] = scan; else state.scans.unshift(scan);
    renderAll();
    return scan;
  }

  function schedulePolling() {
    if (state.polling) return;
    if (!state.scans.some(scan => isActiveStatus(scan.status))) return;
    state.polling = true;
    const tick = async () => {
      const active = state.scans.filter(scan => isActiveStatus(scan.status));
      if (!active.length) {
        state.polling = false;
        await refreshDashboard({silent: true});
        return;
      }
      try {
        await Promise.all(active.slice(0, 5).map(scan => pollScan(scan.id)));
      } catch (_) {
        /* Ignore transient polling errors and try again. */
      }
      setTimeout(tick, 3200);
    };
    setTimeout(tick, 1200);
  }

  function openSelectedDetails() {
    const scan = selectedScan();
    if (!scan) return toast('No scan selected', 'warning');
    window.location.href = `/scan/${scan.id}`;
  }

  function exportSelected(kind) {
    const scan = selectedScan();
    if (!isExportableScan(scan)) return toast('Select a completed scan before exporting', 'warning');
    const urls = {
      report: `/scan/${scan.id}/report`,
      json: `/scan/${scan.id}/export-json`,
      sarif: `/scan/${scan.id}/export-sarif`,
      artifacts: `/scan/${scan.id}/export-artifacts`,
      har: `/scan/${scan.id}/export-har`
    };
    window.location.href = urls[kind];
  }

  function openFinding(index) {
    const scan = selectedScan();
    const query = state.search.trim().toLowerCase();
    let findings = findingsForScan(scan);
    if (state.findingFilter !== 'all') findings = findings.filter(item => item.severity === state.findingFilter);
    if (query) findings = findings.filter(item => [item.scanner, item.description, item.endpoint, item.status].join(' ').toLowerCase().includes(query));
    const finding = findings[index];
    if (!finding) return;
    $('#findingDetails').innerHTML = `
      <div class="modal-head">
        <div><span class="eyebrow">Finding Details</span><h2>${escapeHtml(finding.scanner)}</h2></div>
        <button class="icon-btn" type="button" data-action="close-finding">×</button>
      </div>
      <div class="scan-summary">
        <div class="summary-tile"><span>Severity</span><strong class="sev-${finding.severity.toLowerCase()}">${escapeHtml(SEVERITY_LABELS[finding.severity])}</strong></div>
        <div class="summary-tile"><span>Status</span><strong>${escapeHtml(translateStatus(finding.status))}</strong></div>
        <div class="summary-tile"><span>Confidence</span><strong>${escapeHtml(finding.confidence)}</strong></div>
        <div class="summary-tile"><span>CVSS</span><strong>${escapeHtml(finding.cvss)}</strong></div>
      </div>
      <div class="scanner-panel" style="margin-top:14px"><h4>Description</h4><p class="muted">${escapeHtml(finding.description)}</p></div>
      <div class="scanner-panel"><h4>Endpoint</h4><p class="muted" dir="ltr" style="text-align:left;overflow-wrap:anywhere">${escapeHtml(finding.endpoint || 'N/A')}</p></div>
      <div class="scanner-panel"><h4>Recommendation</h4><p class="muted">${escapeHtml(finding.recommendation)}</p></div>
      <div class="scanner-panel"><h4>Evidence</h4><pre class="muted" dir="ltr" style="white-space:pre-wrap;text-align:left;overflow:auto;max-height:260px">${escapeHtml(finding.evidence)}</pre></div>
    `;
    $('#findingModal').showModal();
  }

  async function addScope(event) {
    event.preventDefault();
    const hostname = $('#scopeHost').value.trim();
    if (!hostname) return toast('Enter a valid hostname', 'error');
    try {
      await fetchJson('/api/scopes', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken},
        body: JSON.stringify({hostname, include_subdomains: $('#scopeSubdomains').checked, description: $('#scopeDescription').value.trim()})
      });
      $('#scopeModal').close();
      $('#scopeForm').reset();
      await loadScopes();
      renderScopes();
      toast('Scope saved', 'success');
    } catch (error) {
      toast(error.message || 'Unable to save scope', 'error');
    }
  }

  function resetScanModal() {
    $('#scanForm').reset();
    $('#scanMode').value = 'standard';
    $('#requestBudget').value = '120';
    $('#verifyTls').checked = true;
    renderScannerGrid();
    renderScannerInputs();
  }

  function bindEvents() {
    document.addEventListener('click', async (event) => {
      const action = event.target.closest('[data-action]')?.dataset.action;
      if (action === 'open-scan') { resetScanModal(); $('#scanModal').showModal(); }
      if (action === 'close-scan') $('#scanModal').close();
      if (action === 'open-export') $('#exportModal').showModal();
      if (action === 'close-export') $('#exportModal').close();
      if (action === 'refresh') await refreshDashboard();
      if (action === 'open-details') openSelectedDetails();
      if (action === 'cancel-scan') await cancelSelectedScan();
      if (action === 'add-scope') $('#scopeModal').showModal();
      if (action === 'close-scope') $('#scopeModal').close();
      if (action === 'close-finding') $('#findingModal').close();

      const scanItem = event.target.closest('[data-scan-id]');
      if (scanItem) {
        state.selectedScanId = scanItem.dataset.scanId;
        renderAll();
      }
      const filter = event.target.closest('[data-filter]');
      if (filter) {
        state.findingFilter = filter.dataset.filter;
        renderFindings();
      }
      const finding = event.target.closest('[data-finding]');
      if (finding) openFinding(Number(finding.dataset.finding));
      const exportButton = event.target.closest('[data-export]');
      if (exportButton) exportSelected(exportButton.dataset.export);
      const preset = event.target.closest('[data-preset]')?.dataset.preset;
      if (preset) {
        if (preset === 'none') setScannerSelection([]);
        else if (preset === 'all') setScannerSelection(state.scanners.map(scanner => scanner.id));
        else setScannerSelection([...selectedForMode(preset)]);
      }
    });

    $('#scanMode').addEventListener('change', (event) => {
      const mode = event.target.value;
      if (mode === 'modern') $('#requestBudget').value = '250';
      if (mode === 'quick') $('#requestBudget').value = '60';
      if (mode === 'deep') $('#requestBudget').value = '300';
      if (mode === 'standard') $('#requestBudget').value = '120';
      setScannerSelection([...selectedForMode(mode)]);
    });

    $('#scannerGrid').addEventListener('change', (event) => {
      if (event.target.matches('input[type="checkbox"]')) {
        event.target.closest('.scanner-card')?.classList.toggle('checked', event.target.checked);
        renderScannerInputs();
      }
    });

    $('#scanForm').addEventListener('submit', startScan);
    $('#scopeForm').addEventListener('submit', addScope);
    $('#globalSearch').addEventListener('input', (event) => {
      state.search = event.target.value || '';
      renderScanList();
      renderFindings();
    });
  }

  async function init() {
    bindEvents();
    renderAll();
    try {
      await loadScanners();
      await refreshDashboard({silent: true});
    } catch (error) {
      toast(error.message || 'Unable to initialize dashboard', 'error');
    }
  }

  document.addEventListener('DOMContentLoaded', init);
})();
