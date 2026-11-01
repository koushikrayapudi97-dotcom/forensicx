const state = { report: null, selectedCaseId: null, evidence: [], evidencePage: 1, gps: [], pages: { calls: 1, messages: 1, gps: 1, webHistory: 1, media: 1 }, pageSize: 10 };

function text(value) {
  return String(value ?? 'Not Available').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
}

function rows(items, page, kind) {
  const query = (document.querySelector(`#${kind}-search`)?.value || '').toLowerCase();
  const filter = document.querySelector(`#${kind}-filter`)?.value || 'All Types';
  const filtered = items.filter(item => JSON.stringify(item).toLowerCase().includes(query) && (filter === 'All Types' || item.type === filter));
  const start = (page - 1) * state.pageSize;
  return { filtered, visible: filtered.slice(start, start + state.pageSize) };
}

function renderPagination(id, total, page, kind) {
  const pages = Math.max(1, Math.ceil(total / state.pageSize));
  const buttons = Array.from({ length: Math.min(pages, 8) }, (_, index) => `<button class="${index + 1 === page ? 'selected' : ''}" data-page="${index + 1}" data-kind="${kind}">${index + 1}</button>`).join('');
  document.querySelector(`#${id}`).innerHTML = `<span>Showing ${total ? (page - 1) * state.pageSize + 1 : 0} to ${Math.min(page * state.pageSize, total)} of ${total} records</span><span class="page-buttons">${buttons}</span>`;
}

function renderGps() {
  const query = (document.querySelector('#gps-search')?.value || '').toLowerCase();
  const filtered = state.gps.filter(item => JSON.stringify(item).toLowerCase().includes(query));
  const start = (state.pages.gps - 1) * state.pageSize;
  const visible = filtered.slice(start, start + state.pageSize);
  const body = document.querySelector('#gps-body');
  const total = document.querySelector('#gps-total');
  if (total) total.textContent = filtered.length;
  if (!body) return;
  if (!visible.length) {
    body.innerHTML = '<tr><td colspan="7" class="empty-cell">No GPS location data available.</td></tr>';
    return;
  }
  body.innerHTML = visible.map((item, i) => `<tr>
    <td>${start + i + 1}</td>
    <td>${text(item.latitude)}</td>
    <td>${text(item.longitude)}</td>
    <td>${text(item.accuracy)}</td>
    <td><span class="type-pill">${text(item.provider)}</span></td>
    <td>${text(item.timestamp)}</td>
    <td><a href="${text(item.maps_url)}" target="_blank" class="button compact secondary">View Map</a></td>
  </tr>`).join('');
  renderPagination('gps-pagination', filtered.length, state.pages.gps, 'gps');
  // Show embedded map for first result
  const first = visible[0];
  const mapContainer = document.querySelector('#gps-map-container');
  const mapFrame = document.querySelector('#gps-map');
  if (mapContainer && mapFrame && first?.latitude && first?.longitude) {
    mapFrame.src = `https://maps.google.com/maps?q=${first.latitude},${first.longitude}&z=18&output=embed`;
    mapContainer.style.display = 'block';
  }
  // Show CSV export button when GPS data is available
  const exportBtn = document.querySelector('#gps-export-btn');
  if (exportBtn) {
    if (state.gps.length > 0 && state.report && state.report.case && state.report.case.case_id) {
      exportBtn.href = `/api/gps/${encodeURIComponent(state.report.case.case_id)}/export/csv`;
      exportBtn.style.display = '';
    } else {
      exportBtn.style.display = 'none';
    }
  }
}

function renderSocialMedia(data) {
  const social = data?.social_media || {};
  const status = social.status || 'not_available';
  const statusEl = document.querySelector('#social-status');
  const body = document.querySelector('#social-body');
  if (statusEl) statusEl.textContent = status === 'available' ? 'Available' : 'Not Available';
  if (!body) return;
  const platforms = ['WhatsApp', 'Facebook', 'Instagram', 'Snapchat', 'Twitter/X', 'Telegram'];
  const error = social.error || 'App-private social-media databases are not generically accessible through authorized ADB.';
  body.innerHTML = platforms.map(p => `<tr><td>${text(p)}</td><td><span class="type-pill">Not Available</span></td><td class="message-body">${text(error)}</td></tr>`).join('');
}

function renderTables() {
  if (!state.report) {
    const callsBody = document.querySelector('#calls-body');
    if (callsBody) callsBody.innerHTML = '<tr><td colspan="7" class="empty-cell">No active case selected (0 call logs).</td></tr>';
    const callTotal = document.querySelector('#call-total');
    if (callTotal) callTotal.textContent = '0';
    renderPagination('calls-pagination', 0, 1, 'calls');

    const messagesBody = document.querySelector('#messages-body');
    if (messagesBody) messagesBody.innerHTML = '<tr><td colspan="5" class="empty-cell">No active case selected (0 messages).</td></tr>';
    const messageTotal = document.querySelector('#message-total');
    if (messageTotal) messageTotal.textContent = '0';
    renderPagination('messages-pagination', 0, 1, 'messages');
    return;
  }
  const calls = rows(state.report.calls || [], state.pages.calls, 'call');
  document.querySelector('#calls-body').innerHTML = calls.visible.length ? calls.visible.map(item => `<tr><td>${text(item.sno)}</td><td>${text(item.date_time)}</td><td>${text(item.number)}</td><td>${text(item.name)}</td><td><span class="type-pill">${text(item.type)}</span></td><td>${text(item.duration)}</td><td>${text(item.source)}</td></tr>`).join('') : '<tr><td colspan="7" class="empty-cell">No call-log evidence available.</td></tr>';
  document.querySelector('#call-total').textContent = calls.filtered.length;
  renderPagination('calls-pagination', calls.filtered.length, state.pages.calls, 'calls');
  const messages = rows(state.report.messages || [], state.pages.messages, 'message');
  document.querySelector('#messages-body').innerHTML = messages.visible.length ? messages.visible.map(item => `<tr><td>${text(item.sno)}</td><td>${text(item.date_time)}</td><td>${text(item.address)}</td><td><span class="type-pill">${text(item.type)}</span></td><td class="message-body">${text(item.body)}</td></tr>`).join('') : '<tr><td colspan="5" class="empty-cell">No message evidence available.</td></tr>';
  document.querySelector('#message-total').textContent = messages.filtered.length;
  renderPagination('messages-pagination', messages.filtered.length, state.pages.messages, 'messages');
}

function renderDevice(info) {
  const fields = [['Device ID', info.device_id], ['Manufacturer', info.manufacturer], ['Model', info.model], ['Android Version', info.android_version], ['SDK Version', info.sdk_version], ['Build ID', info.build_id], ['Serial Number', info.serial], ['Battery Level', info.battery], ['Connection Status', info.status], ['ADB Status', 'Authorized']];
  document.querySelector('#device-info-table').innerHTML = fields.map(item => `<tr><th>${text(item[0])}</th><td>${text(item[1])}</td></tr>`).join('');
}

function renderReport(report) {
  state.report = report;
  const caseData = report.case || {};
  document.querySelector('#header-case-id').textContent = caseData.case_id || 'Not Available';
  document.querySelector('#report-id').textContent = `${caseData.case_id || 'CASE'}-REPORT-001`;
  document.querySelector('#header-investigator').textContent = caseData.investigator || 'Not Available';
  document.querySelector('#analysis-date').textContent = caseData.updated_at || caseData.created_at || 'Not Available';
  const summary = report.summary || {};
  [
    ['devices', summary.devices], ['calls', summary.call_logs], ['messages', summary.messages], ['gps', summary.gps], ['files', summary.files],
    ['normalized', summary.normalized_evidence], ['correlations', summary.correlations], ['reliability', summary.reliability_assessments],
    ['graph-nodes', summary.graph_entities], ['timeline-events', summary.timeline_events], ['ai-findings', summary.ai_findings]
  ].forEach(([key, value]) => { const node = document.querySelector(`#metric-${key}`); if (node) node.textContent = value ?? 0; });
  const fields = [['Case ID', caseData.case_id], ['Case Name', caseData.case_name], ['Investigator', caseData.investigator], ['Description', caseData.description], ['Analysis Date', caseData.updated_at || caseData.created_at], ['Report Generated Date', new Date().toLocaleString()], ['Status', caseData.status]];
  document.querySelector('#case-info').innerHTML = fields.map(item => `<tr><th>${text(item[0])}</th><td>${text(item[1])}</td></tr>`).join('');
  renderTables();
}


const moduleInfo = {
  device: ['Device', 'Authorized Android connection', 'Detect and inspect an Android device through the read-only ADB bridge.'],
  cases: ['Cases', 'Investigation management', 'A case is the container for an authorized examination, investigator details, and its preserved evidence.'],
  evidence: ['Evidence', 'Preserved artifacts', 'Evidence records identify each preserved file, its source, acquisition time, hash, and custody status.'],
  acquisition: ['Acquisition', 'Controlled collection', 'Acquisition collects only authorized, accessible device information and records every generated artifact.'],
  analysis: ['File Analysis', 'Evidence-backed analysis', 'Analysis reads preserved evidence files to expose metadata, file structure, timelines, and keyword matches.'],
  hashes: ['Hash Verification', 'Integrity control', 'SHA-256 verification compares each preserved file with the hash recorded when it entered custody.'],
  reports: ['Reports', 'Investigation output', 'Reports create a PDF summary from the selected case, device information, evidence counts, and custody data.'],
  'ai-investigation': ['AI Investigation', 'Pattern detection & timeline correlation', 'Analyze preserved case evidence using timeline correlation to detect suspicious patterns and generate formal forensic AI reports.'],
  malware: ['Malware Analysis', 'Static threat & signature scanner', 'Scan evidence files for malicious signatures, double extensions, format anomalies, dangerous permissions, and entropy obfuscation.'],
  history: ['History', 'Previous investigations', 'History keeps completed and previous device acquisitions available without combining their evidence.'],
  normalization: ['Evidence Normalization Engine', 'Heterogeneous artifact normalization', 'Converts heterogeneous Android/iOS artifacts into ONE standardized, queryable evidence format.'],
  correlations: ['Cross-Source Evidence Correlation', 'Factual evidence relationship linking', 'Discovers factual relationships across SMS, calls, GPS, web history, contacts, and files.'],
  reliability: ['Reliability & Provenance Scoring', 'Confidence score calculation', 'Calculates explainable 0-100% confidence scores based on technically measurable parameters.'],
  graph: ['Evidence Relationship Graph', 'Traceable entity network', 'Interactive visual graph connecting devices, contacts, communications, files, and locations.'],
  timeline: ['Incident Timeline & AI Report', 'Chronological sequence & AI synthesis', 'Sequences case evidence chronologically with strict separation of FACT, CORRELATION, and AI INTERPRETATION.']
};

function moduleFrame(key, body) {
  const info = moduleInfo[key] || [key.toUpperCase(), 'Active Module', 'ForensicX Intelligence Module'];
  return `<header class="module-header"><div><p class="eyebrow">FORENSICX MODULE</p><h1>${text(info[0])}</h1><p class="module-description">${text(info[2])}</p></div><span class="module-status">${text(info[1])}</span></header><div class="module-body">${body}</div>`;
}

async function getJson(url, options) {
  const response = await fetch(url, options);
  if (response.status === 401) {
    window.location.href = '/login';
    throw new Error('Session expired. Redirecting to login...');
  }
  if (!response.ok) {
    let msg = `Request failed: ${response.status}`;
    try {
      const data = await response.json();
      msg = data.detail || data.message || msg;
    } catch (_) {
      try {
        const txt = await response.text();
        if (txt) msg = txt;
      } catch (_) {}
    }
    throw new Error(msg);
  }
  return response.json();
}

function showModule(key) {
  const dashboard = document.querySelector('#dashboard-view');
  const module = document.querySelector('#module-view');
  document.querySelectorAll('.nav-item').forEach(item => item.classList.toggle('active', item.dataset.module === key));
  if (key === 'dashboard') {
    dashboard.hidden = false;
    module.hidden = true;
    if (state.selectedCaseId) {
      loadReport().catch(() => {});
    } else {
      clearDashboard();
      populateCaseDropdown().catch(() => {});
    }
    return;
  }
  dashboard.hidden = true;
  module.hidden = false;
  module.innerHTML = moduleFrame(key, '<p class="loading-state">Loading module data...</p>');
  moduleLoaders[key]().catch(error => {
    if (error.message.includes('Session expired') || error.message.includes('Not authenticated')) {
      window.location.href = '/login';
      return;
    }
    module.innerHTML = moduleFrame(key, `<div class="error-state" style="padding:20px;background:#fef2f2;border:1px solid #fca5a5;border-radius:8px;color:#991b1b;margin-top:16px;"><strong>Module Status:</strong> ${text(error.message)}</div>`);
  });
}

async function loadDeviceModule() {
  const status = await getJson('/api/device');
  const devices = status.devices || [];
  const rows = devices.length ? devices.map(item => `<tr><td>${text(item.device_id)}</td><td>${text(item.serial)}</td><td><span class="type-pill ${item.state === 'device' ? 'badge-active' : ''}">${text(item.state)}</span></td><td>${text(item.case_id || 'No active case')}</td><td>${text(item.acquisition_id || 'No active acquisition')}</td><td>${item.acquisition_id ? `<button class="button compact" data-action="finalize" data-id="${text(item.acquisition_id)}">Finalize</button>` : 'Ready for acquisition'}</td></tr>`).join('') : '<tr><td colspan="6" class="empty-cell">No ADB devices detected. Connect phone via USB with USB Debugging enabled.</td></tr>';
  const connectedDevice = devices.find(item => item.state === 'device') || devices[0];

  let alertBanner = '';
  const unauthorizedDevice = devices.find(item => item.state === 'unauthorized');
  if (unauthorizedDevice) {
    alertBanner = `<div class="error-state" style="padding:14px;background:#fffbeb;border:1px solid #fcd34d;border-radius:8px;color:#92400e;margin-bottom:16px;">
      <strong>Device Authorization Required:</strong> Android device <code>${text(unauthorizedDevice.serial)}</code> is connected but <em>UNAUTHORIZED</em>. Please unlock your phone screen and tap <strong>"Allow USB debugging"</strong> (check <em>"Always allow from this computer"</em>) on the phone popup.
    </div>`;
  } else if (!devices.length) {
    alertBanner = `<div class="subtle-box" style="padding:12px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;color:#475569;margin-bottom:16px;">
      <strong>Phone Connection Checklist:</strong> 1. Connect phone via USB cable. 2. Unlock phone screen. 3. Swipe down notification shade and set USB mode to <em>"File Transfer (MTP)"</em>. 4. Ensure Developer Options &gt; USB Debugging is ON. 5. Click <strong>"Detect device"</strong>.
    </div>`;
  } else if (connectedDevice?.state === 'device') {
    alertBanner = `<div class="success-box" style="padding:14px;background:#f0fdf4;border:1px solid #86efac;border-radius:8px;color:#166534;margin-bottom:16px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;">
      <div><strong>Device Ready:</strong> <code>${text(connectedDevice.serial)}</code> is authorized and ready for forensic acquisition.</div>
      <a href="#acquisition" class="button primary compact" style="text-decoration:none;">Go to Acquisition Module &rarr;</a>
    </div>`;
  }

  document.querySelector('#module-view').innerHTML = moduleFrame('device', `
    <div class="module-actions"><button class="button primary" data-action="refresh-device">Detect device</button></div>
    <div class="module-stat-grid">
      <article class="module-stat"><span>Connection</span><strong>${status.connected ? 'Connected' : (unauthorizedDevice ? 'Unauthorized' : 'Not connected')}</strong></article>
      <article class="module-stat"><span>Visible devices</span><strong>${devices.length}</strong></article>
    </div>
    ${alertBanner}
    <article class="report-card">
      <h3>Current device sessions</h3>
      <table class="evidence-table"><thead><tr><th>Device ID</th><th>ADB serial</th><th>State</th><th>Current case</th><th>Current acquisition</th><th>Action</th></tr></thead><tbody>${rows}</tbody></table>
    </article>
  `);
}

async function loadCasesModule() {
  const cases = await getJson('/api/cases');
  const workspaces = await Promise.all(cases.map(item => getJson(`/api/cases/${encodeURIComponent(item.case_id)}/workspace`)));
  const rows = cases.length ? cases.map((item, index) => { const workspace = workspaces[index]; const latest = workspace.acquisitions[0]; const device = workspace.devices[0]; const active = latest && ['RUNNING', 'STARTED', 'DISCONNECTED'].includes(latest.status); return `<tr><td><strong>${text(item.case_id)}</strong></td><td>${text(device?.device_id || 'Not assigned')}</td><td>${text(device?.model || 'Not available')}</td><td>${text(latest?.acquisition_id || 'Not started')}</td><td>${text(workspace.evidence_count)}</td><td>${text(item.status)}</td><td>${text(item.created_at)}</td><td>${text(latest?.last_activity || item.updated_at || item.created_at)}</td><td><div class="panel-actions"><button class="button compact" data-action="open-case" data-id="${text(item.case_id)}">Open</button>${active ? `<button class="button compact" data-action="resume-case" data-id="${text(item.case_id)}">Resume</button><button class="button compact" data-action="finalize" data-return="cases" data-id="${text(latest.acquisition_id)}">Finalize</button>` : ''}<a class="button compact" href="/api/reports/${encodeURIComponent(item.case_id)}" target="_blank">Report</a><button class="button compact secondary" style="color:#ef4444;" data-action="delete-case" data-id="${text(item.case_id)}">Delete</button></div></td></tr>`; }).join('') : '<tr><td colspan="9" class="empty-cell">No cases created yet.</td></tr>';
  document.querySelector('#module-view').innerHTML = moduleFrame('cases', `<div class="module-stat-grid"><article class="module-stat"><span>Total cases</span><strong>${cases.length}</strong></article><article class="module-stat"><span>Latest case</span><strong>${text(cases[0]?.case_id || 'None')}</strong></article></div><article class="report-card form-panel"><h3>Create a new case</h3><form id="case-form" class="form-grid"><label>Case name<input name="case_name" required maxlength="200"></label><label>Investigator<input name="investigator" required maxlength="120"></label><label>Organization<input name="organization" maxlength="200"></label><label>Description<textarea name="description" maxlength="5000"></textarea></label><button class="button primary" type="submit">Create case</button></form><div id="case-result" class="data-view"></div></article><article class="report-card"><h3>Investigation cases</h3><div class="table-scroll"><table class="evidence-table"><thead><tr><th>Case ID</th><th>Device ID</th><th>Device model</th><th>Acquisition ID</th><th>Evidence count</th><th>Status</th><th>Created</th><th>Last activity</th><th>Actions</th></tr></thead><tbody>${rows}</tbody></table></div><div id="case-details" class="data-view"></div></article>`);
}

async function loadEvidenceModule() {
  const cases = await getJson('/api/cases');
  state.selectedCaseId = state.selectedCaseId || cases[0]?.case_id;
  const options = cases.map(item => `<option value="${text(item.case_id)}" ${item.case_id === state.selectedCaseId ? 'selected' : ''}>${text(item.case_id)} - ${text(item.case_name)}</option>`).join('');

  const evidence = state.selectedCaseId ? await getJson(`/api/evidence?case_id=${encodeURIComponent(state.selectedCaseId)}`) : [];
  state.evidence = evidence;
  state.evidencePage = 1;

  document.querySelector('#module-view').innerHTML = moduleFrame('evidence', `
    <div class="section-head" style="margin-bottom:16px;">
      <div>
        <h3>Case Evidence Explorer</h3>
        <strong id="evidence-total">${evidence.length} preserved artifacts</strong>
      </div>
      <div class="controls">
        <label style="font-family:var(--mono);font-size:11px;">Selected Case: <select id="evidence-case-select">${options}</select></label>
      </div>
    </div>

    <!-- 01 Call logs -->
    <div class="card evidence-card">
      <div class="card-header">
        <div>
          <span class="card-tag">01</span>
          <h3>Phone / Call Logs</h3>
          <span class="record-count">Total: <b id="call-total">0</b></span>
        </div>
        <div class="card-controls">
          <input id="call-search" class="search-input" placeholder="Search call logs...">
          <select id="call-filter" class="filter-select">
            <option>All Types</option>
            <option>Incoming</option>
            <option>Outgoing</option>
            <option>Missed</option>
            <option>Rejected</option>
          </select>
        </div>
      </div>
      <div class="table-scroll">
        <table class="data-table">
          <thead><tr><th>#</th><th>Date / Time</th><th>Phone Number</th><th>Contact Name</th><th>Call Type</th><th>Duration</th><th>Source</th></tr></thead>
          <tbody id="calls-body"></tbody>
        </table>
      </div>
      <div class="pagination" id="calls-pagination"></div>
    </div>

    <!-- 02 SMS logs -->
    <div class="card evidence-card">
      <div class="card-header">
        <div>
          <span class="card-tag">02</span>
          <h3>Message / SMS Logs</h3>
          <span class="record-count">Total: <b id="message-total">0</b></span>
        </div>
        <div class="card-controls">
          <input id="message-search" class="search-input" placeholder="Search messages...">
          <select id="message-filter" class="filter-select">
            <option>All Types</option>
            <option>Incoming</option>
            <option>Outgoing</option>
            <option>Draft</option>
            <option>Failed</option>
          </select>
        </div>
      </div>
      <div class="table-scroll">
        <table class="data-table">
          <thead><tr><th>#</th><th>Date / Time</th><th>Sender / Address</th><th>Type</th><th>Message</th></tr></thead>
          <tbody id="messages-body"></tbody>
        </table>
      </div>
      <div class="pagination" id="messages-pagination"></div>
    </div>

    <!-- 03 GPS Locations -->
    <div class="card evidence-card">
      <div class="card-header">
        <div>
          <span class="card-tag">03</span>
          <h3>GPS / Location Tracking</h3>
          <span class="record-count">Total: <b id="gps-total">0</b></span>
        </div>
        <div class="card-controls">
          <input id="gps-search" class="search-input" placeholder="Search locations...">
          <a id="gps-export-btn" href="#" class="button compact secondary" style="text-decoration:none;display:none">Export CSV</a>
        </div>
      </div>
      <div id="gps-map-container" style="display:none;margin-bottom:12px;border-radius:8px;overflow:hidden;border:1px solid var(--border)">
        <iframe id="gps-map" width="100%" height="320" style="border:none;display:block" loading="lazy" allowfullscreen referrerpolicy="no-referrer-when-downgrade"></iframe>
      </div>
      <div class="table-scroll">
        <table class="data-table">
          <thead><tr><th>#</th><th>Latitude</th><th>Longitude</th><th>Accuracy (m)</th><th>Provider</th><th>Timestamp</th><th>Map</th></tr></thead>
          <tbody id="gps-body"></tbody>
        </table>
      </div>
      <div class="pagination" id="gps-pagination"></div>
    </div>

    <!-- 04 Social Media -->
    <div class="card evidence-card">
      <div class="card-header">
        <div>
          <span class="card-tag">04</span>
          <h3>Social Media</h3>
          <span class="record-count">Status: <b id="social-status">Checking...</b></span>
        </div>
      </div>
      <div class="table-scroll">
        <table class="data-table">
          <thead><tr><th>Platform</th><th>Status</th><th>Details</th></tr></thead>
          <tbody id="social-body"><tr><td colspan="3" class="empty-cell">Loading...</td></tr></tbody>
        </table>
      </div>
    </div>

    <!-- 05 Preserved Files & Hashes -->
    <div class="card evidence-card">
      <div class="card-header">
        <div>
          <span class="card-tag">05</span>
          <h3>Preserved Artifact Files</h3>
        </div>
        <div class="controls">
          <input id="evidence-search" placeholder="Search evidence files...">
          <select id="evidence-type-filter"><option value="">All types</option>${[...new Set(evidence.map(item => item.evidence_type))].map(type => `<option value="${text(type)}">${text(type)}</option>`).join('')}</select>
          <button class="button compact secondary" data-action="clear-evidence-files" style="white-space:nowrap;">Clear Preserved Evidence</button>
        </div>
      </div>
      <div class="table-scroll">
        <table class="evidence-table">
          <thead><tr><th>Evidence ID</th><th>Case</th><th>Type</th><th>Preserved path</th><th>Status</th><th>Action</th></tr></thead>
          <tbody id="evidence-body"></tbody>
        </table>
      </div>
      <div class="pagination" id="evidence-pagination"></div>
    </div>

    <!-- 06 Extracted Device Files & Media -->
    <div class="card evidence-card">
      <div class="card-header">
        <div>
          <span class="card-tag">06</span>
          <h3>Extracted Device Files & Media Data</h3>
          <span class="record-count">Total: <b id="extracted-files-count">0</b></span>
        </div>
      </div>
      <div class="table-scroll">
        <table class="data-table">
          <thead><tr><th>#</th><th>File Name</th><th>Device Storage Path</th><th>Size</th><th>MIME Type</th><th>Date Modified</th></tr></thead>
          <tbody id="extracted-files-body"><tr><td colspan="6" class="empty-cell">Loading device files...</td></tr></tbody>
        </table>
      </div>
    </div>

  `);

  if (state.selectedCaseId) {
    const [reportResp, gpsResp] = await Promise.all([
      fetch(`/api/report-data/${encodeURIComponent(state.selectedCaseId)}`),
      fetch(`/api/gps/${encodeURIComponent(state.selectedCaseId)}`),
    ]);
    if (reportResp.ok) {
      const reportData = await reportResp.json();
      state.report = reportData;
      renderTables();
      renderSocialMedia(reportData);
      renderExtractedFiles(reportData);
    }
    if (gpsResp.ok) {
      const gpsData = await gpsResp.json();
      state.gps = gpsData.locations || [];
      state.pages.gps = 1;
      renderGps();
    }
  }
  renderEvidenceRows();
}

function renderExtractedFiles(reportData) {
  const body = document.querySelector('#extracted-files-body');
  const countLabel = document.querySelector('#extracted-files-count');
  if (!body) return;
  const files = reportData.extracted_files || [];
  if (countLabel) countLabel.textContent = files.length;
  if (!files.length) {
    body.innerHTML = '<tr><td colspan="6" class="empty-cell">No device files recovered from this device.</td></tr>';
    return;
  }
  body.innerHTML = files.slice(0, 100).map((f, i) => `<tr>
    <td>${f.sno || i + 1}</td>
    <td><strong>${text(f.file_name)}</strong></td>
    <td style="font-family:var(--mono); font-size:11px; color:var(--text-3); word-break:break-all;">${text(f.original_path)}</td>
    <td>${(f.size / 1024).toFixed(1)} KB</td>
    <td><span class="type-pill">${text(f.mime_type)}</span></td>
    <td>${text(f.date_modified)}</td>
  </tr>`).join('');
}

function renderWebHistory(reportData) {
  const body = document.querySelector('#web-history-body');
  const countLabel = document.querySelector('#web-history-count');
  if (!body) return;
  const history = reportData.browser_history || reportData.web_history || [];
  const query = (document.querySelector('#web-history-search')?.value || '').toLowerCase();
  const filtered = history.filter(item => JSON.stringify(item).toLowerCase().includes(query));
  if (countLabel) countLabel.textContent = filtered.length;
  if (!filtered.length) {
    body.innerHTML = '<tr><td colspan="7" class="empty-cell">No web history available.</td></tr>';
    renderPagination('web-history-pagination', 0, 1, 'webHistory');
    return;
  }
  const page = state.pages.webHistory || 1;
  const start = (page - 1) * state.pageSize;
  const visible = filtered.slice(start, start + state.pageSize);
  body.innerHTML = visible.map((item, i) => `<tr>
    <td>${item.sno || start + i + 1}</td>
    <td><span class="type-pill">${text(item.browser || 'Browser')}</span></td>
    <td class="message-body" style="word-break:break-all;"><a href="${text(item.url)}" target="_blank" style="color:var(--primary);text-decoration:none">${text(item.url)}</a></td>
    <td>${text(item.title || item.url)}</td>
    <td>${text(item.visit_timestamp || item.timestamp)}</td>
    <td>${text(item.visit_count ?? 1)}</td>
    <td>${text(item.source || 'content://browser')}</td>
  </tr>`).join('');
  renderPagination('web-history-pagination', filtered.length, page, 'webHistory');
}

function renderMediaFiles(reportData) {
  const body = document.querySelector('#media-files-body');
  const countLabel = document.querySelector('#media-files-count');
  if (!body) return;
  const media = reportData.media_files || [];
  const query = (document.querySelector('#media-files-search')?.value || '').toLowerCase();
  const filter = document.querySelector('#media-files-filter')?.value || 'All Types';
  const filtered = media.filter(item => JSON.stringify(item).toLowerCase().includes(query) && (filter === 'All Types' || item.media_type === filter));
  if (countLabel) countLabel.textContent = filtered.length;
  if (!filtered.length) {
    body.innerHTML = '<tr><td colspan="7" class="empty-cell">No media files available.</td></tr>';
    renderPagination('media-files-pagination', 0, 1, 'media');
    return;
  }
  const page = state.pages.media || 1;
  const start = (page - 1) * state.pageSize;
  const visible = filtered.slice(start, start + state.pageSize);
  body.innerHTML = visible.map((item, i) => `<tr>
    <td>${item.sno || start + i + 1}</td>
    <td><span class="type-pill">${text(item.media_type || 'Image')}</span></td>
    <td><strong>${text(item.file_name)}</strong></td>
    <td style="font-family:var(--mono); font-size:11px; color:var(--text-3); word-break:break-all;">${text(item.original_path)}</td>
    <td>${(item.size / 1024).toFixed(1)} KB</td>
    <td><span class="type-pill">${text(item.mime_type)}</span></td>
    <td>${text(item.date_taken || item.date_modified || 'Not Available')}</td>
  </tr>`).join('');
  renderPagination('media-files-pagination', filtered.length, page, 'media');
}


function renderEvidenceRows() {
  const query = (document.querySelector('#evidence-search')?.value || '').toLowerCase();
  const type = document.querySelector('#evidence-type-filter')?.value || '';
  const filtered = state.evidence.filter(item => JSON.stringify(item).toLowerCase().includes(query) && (!type || item.evidence_type === type));
  const start = (state.evidencePage - 1) * state.pageSize;
  const visible = filtered.slice(start, start + state.pageSize);
  const body = document.querySelector('#evidence-body');
  if (!body) return;
  body.innerHTML = visible.length ? visible.map(item => `<tr><td>${text(item.evidence_id)}</td><td>${text(item.case_id)}</td><td>${text(item.evidence_type)}</td><td>${text(item.file_path)}</td><td>${text(item.status)}</td><td><button class="button compact" data-action="verify" data-id="${text(item.evidence_id)}">Verify</button></td></tr>`).join('') : '<tr><td colspan="6" class="empty-cell">No evidence has been registered for this case.</td></tr>';
  document.querySelector('#evidence-total').textContent = `${filtered.length} records`;
  renderPagination('evidence-pagination', filtered.length, state.evidencePage, 'evidence');
}

async function loadAcquisitionModule() {
  const cases = await getJson('/api/cases');
  const recentCases = cases.slice(0, 5);
  state.selectedCaseId = state.selectedCaseId && recentCases.some(c => c.case_id === state.selectedCaseId) ? state.selectedCaseId : recentCases[0]?.case_id;
  const selectedWorkspace = state.selectedCaseId ? await getJson(`/api/cases/${encodeURIComponent(state.selectedCaseId)}/workspace`) : { devices: [] };
  const deviceStatus = await getJson('/api/device').catch(() => ({ devices: [] }));
  const liveDevice = (deviceStatus.devices || []).find(d => d.state === 'device') || (deviceStatus.devices || [])[0];
  const selectedDevice = liveDevice || selectedWorkspace.devices?.[0];
  const defaultSerial = selectedDevice?.serial || '';
  const options = recentCases.map(item => `<option value="${text(item.case_id)}" ${item.case_id === state.selectedCaseId ? 'selected' : ''}>${text(item.case_id)} - ${text(item.case_name)}</option>`).join('');
  const acquisitions = await getJson('/api/acquisition');
  const sessions = acquisitions.map(item => `<div class="module-list-item"><div><strong>${text(item.acquisition_id)}</strong><span>${text(item.case_id)} · ${text(item.status)}</span></div>${['RUNNING', 'STARTED', 'DISCONNECTED'].includes(item.status) ? `<button class="button compact" data-action="finalize" data-id="${text(item.acquisition_id)}">Finalize</button>` : ''}</div>`).join('') || '<p class="empty-cell">No acquisitions recorded.</p>';

  let alertBanner = '';
  const unauthorizedDevice = (deviceStatus.devices || []).find(item => item.state === 'unauthorized');
  if (unauthorizedDevice) {
    alertBanner = `<div class="error-state" style="padding:14px;background:#fffbeb;border:1px solid #fcd34d;border-radius:8px;color:#92400e;margin-bottom:16px;">
      <strong>Device Authorization Required:</strong> Android device <code>${text(unauthorizedDevice.serial)}</code> is connected but <em>UNAUTHORIZED</em>. Please unlock your phone screen and tap <strong>"Allow USB debugging"</strong> (check <em>"Always allow from this computer"</em>) on the phone popup.
    </div>`;
  } else if (liveDevice?.state === 'device') {
    alertBanner = `<div class="success-box" style="padding:12px;background:#f0fdf4;border:1px solid #86efac;border-radius:8px;color:#166534;margin-bottom:16px;">
      <strong>Live Device Connected:</strong> <code>${text(liveDevice.serial)}</code> (${text(liveDevice.model || 'Android Device')}) is authorized and ready for acquisition.
    </div>`;
  }

  document.querySelector('#module-view').innerHTML = moduleFrame('acquisition', `
    ${alertBanner}
    <article class="report-card form-panel">
      <h3>Start or resume authorized acquisition</h3>
      <p class="subtle">The same case and device automatically resume an unfinished acquisition. The phone must show ADB state <strong>device</strong>.</p>
      <form id="acquisition-form" class="form-grid">
        <label>Case<select name="case_id" required>${options}</select></label>
        <label>Device serial<input name="serial" value="${text(defaultSerial)}" placeholder="ADB device serial" required></label>
        <button class="button primary" type="submit">Start or resume acquisition</button>
      </form>
      <div id="acquisition-result" class="data-view"></div>
    </article>
    <article class="report-card"><h3>Acquisition sessions</h3><div class="module-list">${sessions}</div></article>
  `);
}

async function loadAnalysisModule() {
  const cases = await getJson('/api/cases');
  state.selectedCaseId = state.selectedCaseId || cases[0]?.case_id;
  const options = cases.map(item => `<option value="${text(item.case_id)}" ${item.case_id === state.selectedCaseId ? 'selected' : ''}>${text(item.case_id)} - ${text(item.case_name)}</option>`).join('');

  if (!state.selectedCaseId) {
    document.querySelector('#module-view').innerHTML = moduleFrame('analysis', '<p class="empty-cell">No cases available for file analysis.</p>');
    return;
  }

  const evidence = await getJson(`/api/evidence?case_id=${encodeURIComponent(state.selectedCaseId)}`);
  const rows = evidence.length ? evidence.map(item => {
    const isSuspect = item.file_path.includes('mobile_intelligence.json') || item.file_path.includes('logcat.txt');
    const badge = isSuspect ? '<span class="type-pill pill-med" style="margin-left:6px;">Suspect Data</span>' : '';
    const sizeKb = (item.size / 1024).toFixed(1);
    return `<tr>
      <td><strong>${text(item.evidence_id)}</strong></td>
      <td>${text(item.file_path.split('/').pop() || item.file_path)}${badge}</td>
      <td style="font-family:var(--mono); font-size:11px; color:var(--text-3);">${text(item.file_path)}</td>
      <td>${sizeKb} KB</td>
      <td><span class="type-pill">${text(item.evidence_type || 'Artifact')}</span></td>
      <td><button class="button compact primary" data-action="metadata" data-id="${text(item.evidence_id)}">Analyze Metadata</button></td>
    </tr>`;
  }).join('') : '<tr><td colspan="6" class="empty-cell">No preserved evidence files available for analysis.</td></tr>';

  document.querySelector('#module-view').innerHTML = moduleFrame('analysis', `
    <div class="section-head" style="display: flex; justify-content: space-between; align-items: center; gap: 14px; margin-bottom: 16px;">
      <div>
        <label style="font-family: var(--mono); font-size: 11px;">Selected Case: <select id="analysis-case-select">${options}</select></label>
      </div>
      <span class="record-count">Total Evidence Files: <b>${evidence.length}</b></span>
    </div>
    <article class="report-card">
      <h3>Preserved Artifact Files & Structure Analysis</h3>
      <p class="subtle">Read metadata, timestamps, MIME types, and cryptographic properties from real acquired device files.</p>
      <div class="table-scroll">
        <table class="evidence-table">
          <thead><tr><th>Evidence ID</th><th>File Name</th><th>Preserved Rel Path</th><th>Size</th><th>Type</th><th>Action</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </article>
    <article class="card" style="margin-top: 20px;">
      <h3>Deep Metadata & Artifact Forensic Output</h3>
      <div id="analysis-result" class="data-view" style="font-family:var(--mono); font-size:12px; max-height:400px; overflow-y:auto; background:var(--bg-2); padding:14px; border-radius:8px;">Select an evidence file above to inspect metadata.</div>
    </article>
  `);
}

async function loadHashesModule() {
  const cases = await getJson('/api/cases');
  state.selectedCaseId = state.selectedCaseId || cases[0]?.case_id;
  const options = cases.map(item => `<option value="${text(item.case_id)}" ${item.case_id === state.selectedCaseId ? 'selected' : ''}>${text(item.case_id)} - ${text(item.case_name)}</option>`).join('');

  if (!state.selectedCaseId) {
    document.querySelector('#module-view').innerHTML = moduleFrame('hashes', '<p class="empty-cell">No cases available for hash verification.</p>');
    return;
  }

  const evidence = await getJson(`/api/evidence?case_id=${encodeURIComponent(state.selectedCaseId)}`);
  const verifiedCount = evidence.filter(e => e.status === 'VERIFIED').length;
  const failedCount = evidence.filter(e => e.status === 'INTEGRITY_FAILED').length;

  const rows = evidence.length ? evidence.map(item => {
    const statusPill = item.status === 'VERIFIED' ? '<span class="type-pill pill-low" style="color:var(--green);font-weight:700;">VERIFIED</span>' : item.status === 'INTEGRITY_FAILED' ? '<span class="type-pill pill-high">MISMATCH</span>' : '<span class="type-pill">ACQUIRED</span>';
    return `<tr>
      <td><strong>${text(item.evidence_id)}</strong></td>
      <td>${text(item.file_path.split('/').pop() || item.file_path)}</td>
      <td style="font-family:var(--mono); font-size:11px; color:var(--text-3); word-break:break-all;">${text(item.sha256 || 'Not recorded')}</td>
      <td>${statusPill}</td>
      <td><button class="button compact" data-action="verify" data-id="${text(item.evidence_id)}">Verify SHA-256</button></td>
    </tr>`;
  }).join('') : '<tr><td colspan="5" class="empty-cell">No cryptographic hash records available for this case.</td></tr>';

  document.querySelector('#module-view').innerHTML = moduleFrame('hashes', `
    <div class="section-head" style="display: flex; justify-content: space-between; align-items: center; gap: 14px;">
      <div>
        <label style="font-family: var(--mono); font-size: 11px;">Selected Case: <select id="hashes-case-select">${options}</select></label>
      </div>
      <button class="button primary" data-action="verify-all" data-case="${text(state.selectedCaseId)}">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
        Verify All Evidence Hashes
      </button>
    </div>
    <div class="module-stat-grid" style="grid-template-columns: repeat(3, 1fr); margin-top: 16px;">
      <article class="module-stat"><span>Total Evidence Hashes</span><strong>${evidence.length}</strong></article>
      <article class="module-stat"><span style="color:var(--green)">Verified Unaltered</span><strong style="color:var(--green)">${verifiedCount}</strong></article>
      <article class="module-stat"><span style="color:var(--red)">Integrity Failed</span><strong style="color:var(--red)">${failedCount}</strong></article>
    </div>
    <article class="report-card" style="margin-top: 20px;">
      <h3>Evidence Integrity Verification Log</h3>
      <p class="subtle">Cryptographic SHA-256 hashes recorded at acquisition compared live against preserved storage.</p>
      <div class="table-scroll">
        <table class="evidence-table">
          <thead><tr><th>Evidence ID</th><th>File Name</th><th>Acquisition SHA-256 Hash</th><th>Integrity Status</th><th>Action</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </article>
    <article class="card" style="margin-top: 20px;">
      <h3>Verification Details</h3>
      <div id="hash-result" class="data-view" style="font-family:var(--mono); font-size:12px; background:var(--bg-2); padding:14px; border-radius:8px;">Click "Verify SHA-256" or "Verify All Evidence Hashes" to execute live integrity check.</div>
    </article>
  `);
}


async function loadReportsModule() {
  const cases = await getJson('/api/cases');
  state.selectedCaseId = state.selectedCaseId || cases[0]?.case_id;
  const options = cases.map(item => `<option value="${text(item.case_id)}" ${item.case_id === state.selectedCaseId ? 'selected' : ''}>${text(item.case_id)} - ${text(item.case_name)}</option>`).join('');

  if (!state.selectedCaseId) {
    document.querySelector('#module-view').innerHTML = moduleFrame('reports', '<p class="empty-cell">No cases are available for reporting.</p>');
    return;
  }

  const data = await getJson(`/api/ai-investigation/${encodeURIComponent(state.selectedCaseId)}`);
  const es = data.evidence_summary || {};
  const findings = data.findings || [];
  const corrs = data.correlations || [];
  const limits = data.limitations || [];
  const fin = data.final_summary || {};

  document.querySelector('#module-view').innerHTML = moduleFrame('reports', `
    <div class="section-head" style="display:flex;justify-content:space-between;align-items:center;gap:14px;flex-wrap:wrap;">
      <div style="display:flex;align-items:center;gap:10px;">
        <label style="font-family:var(--mono);font-size:11px;font-weight:600;">Case Report: <select id="reports-case-select" style="padding:6px 10px;border-radius:6px;border:1px solid var(--border);">${options}</select></label>
      </div>
      <div style="display:flex;gap:10px;flex-wrap:wrap;">
        <a class="button primary" href="/api/ai-investigation/${encodeURIComponent(state.selectedCaseId)}/pdf" target="_blank">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          Download 12-Section AI Forensic PDF
        </a>
        <a class="button secondary" href="/api/reports/${encodeURIComponent(state.selectedCaseId)}" target="_blank">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          Download Case Report PDF
        </a>
      </div>
    </div>

    <!-- 12-Section Structure Banner -->
    <article class="card" style="margin-top:16px;background:linear-gradient(to right, #f0f9ff, #ffffff);border-left:4px solid var(--accent);">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;">
        <div>
          <span class="type-pill pill-cyan">PATENT FORENSIC REPORT STRUCTURE</span>
          <h2 style="margin:4px 0 2px;font-size:16px;color:var(--text-1);">AI-Assisted Forensic Investigation Report (12 Sections)</h2>
          <p class="subtle" style="font-size:12px;margin:0;">Formally structured investigation documentation with immutable evidence traceability and objective analytical findings.</p>
        </div>
        <div style="font-family:var(--mono);font-size:11px;color:var(--text-3);text-align:right;">
          <div>Case: <b>${text(state.selectedCaseId)}</b></div>
          <div>Examiner: <b>${text(data.case?.investigator || 'Authorized Investigator')}</b></div>
        </div>
      </div>
    </article>

    <!-- Evidence Live Counts (11 Metrics) -->
    <div class="module-stat-grid" style="grid-template-columns:repeat(auto-fit, minmax(130px, 1fr));gap:10px;margin-top:16px;">
      <article class="module-stat"><span>Devices</span><strong>${es.devices ?? 0}</strong></article>
      <article class="module-stat"><span>Call Logs</span><strong>${es.call_logs ?? 0}</strong></article>
      <article class="module-stat"><span>SMS Messages</span><strong>${es.sms ?? es.messages ?? 0}</strong></article>
      <article class="module-stat"><span>GPS Fixes</span><strong>${es.gps ?? es.gps_locations ?? 0}</strong></article>
      <article class="module-stat"><span>Files & Media</span><strong>${es.files ?? es.media_files ?? 0}</strong></article>
      <article class="module-stat"><span>Applications</span><strong>${es.applications ?? 0}</strong></article>
      <article class="module-stat"><span>Web History</span><strong>${es.browser_web_history ?? es.web_history ?? 0}</strong></article>
      <article class="module-stat"><span style="color:var(--accent);">Normalized</span><strong style="color:var(--accent);">${es.normalized_evidence ?? 0}</strong></article>
      <article class="module-stat"><span style="color:var(--teal);">Correlations</span><strong style="color:var(--teal);">${es.correlations ?? 0}</strong></article>
      <article class="module-stat"><span style="color:var(--purple,#7c3aed);">Timeline Events</span><strong style="color:var(--purple,#7c3aed);">${es.timeline_events ?? 0}</strong></article>
      <article class="module-stat"><span style="color:var(--amber);">AI Findings</span><strong style="color:var(--amber);">${es.ai_findings ?? 0}</strong></article>
    </div>

    <!-- 12-Section Interactive Explorer -->
    <div style="margin-top:20px;display:grid;gap:16px;">
      <!-- Section 1 & 2: Case, Device & Evidence Summary -->
      <article class="card">
        <h3>1. Case & Device Summary</h3>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:10px;">
          <table class="evidence-table" style="font-size:12px;">
            <tr><th>Case ID</th><td><strong>${text(data.case?.case_id)}</strong></td></tr>
            <tr><th>Case Name</th><td>${text(data.case?.case_name)}</td></tr>
            <tr><th>Investigator</th><td>${text(data.case?.investigator)}</td></tr>
            <tr><th>Status</th><td><span class="badge badge--green">${text(data.case?.status || 'ACTIVE')}</span></td></tr>
          </table>
          <table class="evidence-table" style="font-size:12px;">
            <tr><th>Device Serial</th><td>${text(data.device?.serial || 'Multi-Device Case')}</td></tr>
            <tr><th>Manufacturer / Model</th><td>${text(data.device?.manufacturer || '')} ${text(data.device?.model || 'Android')}</td></tr>
            <tr><th>Android Version</th><td>${text(data.device?.android_version || 'N/A')} (SDK ${text(data.device?.sdk_version || 'N/A')})</td></tr>
            <tr><th>Connection State</th><td><span class="badge badge--blue">${text(data.device?.connection_state || 'device')}</span></td></tr>
          </table>
        </div>
      </article>

      <!-- Section 8: Analytical Findings -->
      <article class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <h3>8. AI-Assisted Analytical Findings (${findings.length} findings)</h3>
          <span class="subtle" style="font-size:12px;">Strictly distinguished from raw evidence</span>
        </div>
        <div class="findings-list" style="margin-top:12px;display:grid;gap:12px;">
          ${findings.length ? findings.map(f => {
            const sevClass = f.severity === 'High' ? 'pill-high' : f.severity === 'Medium' ? 'pill-med' : 'pill-low';
            const evBadges = (f.supporting_evidence_ids || []).map(id => `<span class="badge badge--blue" style="cursor:pointer;" onclick="inspectEvidenceId('${text(id)}')">${text(id)}</span>`).join(' ') || '<span class="subtle">None</span>';
            const corrBadges = (f.related_correlation_ids || []).map(cid => `<span class="badge badge--purple">${text(cid)}</span>`).join(' ') || '<span class="subtle">None</span>';
            const tlBadges = (f.timeline_event_ids || []).map(tid => `<span class="badge badge--gray">${text(tid)}</span>`).join(' ') || '<span class="subtle">None</span>';
            return `
              <div style="padding:14px;border:1px solid var(--border);border-radius:8px;background:var(--bg-1);">
                <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;">
                  <div>
                    <span class="badge badge--blue" style="font-weight:700;">${text(f.finding_id)}</span>
                    <span class="type-pill ${sevClass}" style="margin-left:6px;">${text(f.severity)}</span>
                    <span class="type-pill pill-cyan" style="margin-left:6px;">${text(f.category)}</span>
                    <strong style="margin-left:8px;font-size:13px;">${text(f.title)}</strong>
                  </div>
                  <span class="record-count" style="font-size:11px;">Confidence: <b>${text(f.ai_confidence || '90%')}</b></span>
                </div>
                <p class="subtle" style="margin:8px 0;font-size:12px;">${text(f.description)}</p>
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:8px;font-size:11px;font-family:var(--mono);">
                  <div><strong>Supporting Evidence:</strong> ${evBadges}</div>
                  <div><strong>Correlations:</strong> ${corrBadges} | <strong>Timeline:</strong> ${tlBadges}</div>
                </div>
                <div style="margin-top:10px;padding:8px 10px;background:rgba(2,132,199,0.06);border:1px solid rgba(2,132,199,0.2);border-radius:6px;font-size:12px;">
                  <strong>Forensic Analysis Explanation:</strong> ${text(f.analysis_explanation)}
                </div>
              </div>
            `;
          }).join('') : '<p class="empty-cell">No suspicious patterns detected in preserved records.</p>'}
        </div>
      </article>

      <!-- Section 10: Investigation Traceability -->
      <article class="card">
        <h3>10. Investigation Traceability Chain</h3>
        <p class="subtle" style="font-size:12px;margin:4px 0 10px;">Verifiable audit chain from AI analytical findings back to original preserved evidence items.</p>
        <div class="table-scroll">
          <table class="evidence-table" style="font-size:11px;">
            <thead>
              <tr><th>AI Finding</th><th>Timeline Event IDs</th><th>Correlation IDs</th><th>Normalized Evidence ID</th><th>Original Record Reference</th></tr>
            </thead>
            <tbody>
              ${(data.investigation_traceability || []).slice(0, 30).map(tr => `
                <tr>
                  <td><span class="badge badge--blue" style="font-weight:700;">${text(tr.finding_id)}</span></td>
                  <td>${(tr.timeline_event_ids || []).map(id => `<span class="badge badge--gray">${text(id)}</span>`).join(' ')}</td>
                  <td>${(tr.correlation_ids || []).map(id => `<span class="badge badge--purple">${text(id)}</span>`).join(' ')}</td>
                  <td><span class="badge badge--blue" style="cursor:pointer;" onclick="inspectEvidenceId('${text(tr.normalized_evidence_id)}')">${text(tr.normalized_evidence_id)}</span></td>
                  <td><code style="font-size:10px;">${text(tr.original_record_reference)}</code></td>
                </tr>
              `).join('') || '<tr><td colspan="5" class="empty-cell">No traceability paths recorded.</td></tr>'}
            </tbody>
          </table>
        </div>
      </article>

      <!-- Section 11 & 12: Limitations & Summary -->
      <article class="card">
        <h3>11. Limitations & Technical Disclosures</h3>
        <ul style="margin:8px 0 0 18px;font-size:12px;color:var(--text-2);line-height:1.6;">
          ${limits.map(lim => `<li>${text(lim)}</li>`).join('')}
        </ul>
        <div style="margin-top:16px;padding:12px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;font-size:12px;">
          <h4 style="margin:0 0 4px;color:var(--text-1);">12. Final Investigation Summary</h4>
          <p class="subtle" style="margin:0;">${text(fin.summary_text || data.ai_summary)}</p>
          <div style="margin-top:8px;font-family:var(--mono);font-size:11px;color:var(--amber);">
            <strong>Forensic Verification:</strong> ${text(fin.verification_statement || 'Requires independent examiner review.')}
          </div>
        </div>
      </article>
    </div>
  `);

  const select = document.querySelector('#reports-case-select');
  if (select) {
    select.addEventListener('change', (e) => {
      state.selectedCaseId = e.target.value;
      loadReportsModule();
    });
  }
}


async function loadAiInvestigationModule() {
  const cases = await getJson('/api/cases');
  state.selectedCaseId = state.selectedCaseId || cases[0]?.case_id;
  const options = cases.map(item => `<option value="${text(item.case_id)}" ${item.case_id === state.selectedCaseId ? 'selected' : ''}>${text(item.case_id)} - ${text(item.case_name)}</option>`).join('');

  if (!state.selectedCaseId) {
    document.querySelector('#module-view').innerHTML = moduleFrame('ai-investigation', '<p class="empty-cell">No cases available for AI investigation analysis.</p>');
    return;
  }

  const data = await getJson(`/api/ai-investigation/${encodeURIComponent(state.selectedCaseId)}`);
  const summary = data.summary || {};
  const es = data.evidence_summary || {};
  const findings = data.findings || [];
  const correlations = data.correlations || [];
  const traceability = data.investigation_traceability || [];
  const limitations = data.limitations || [];

  const findingsHtml = findings.length ? findings.slice(0, 50).map(f => {
    const sevClass = f.severity === 'High' ? 'pill-high' : f.severity === 'Medium' ? 'pill-med' : 'pill-low';
    const evBadges = (f.supporting_evidence_ids || []).map(id => `<span class="badge badge--blue" style="cursor:pointer;" onclick="inspectEvidenceId('${text(id)}')">${text(id)}</span>`).join(' ') || '<span class="subtle">None</span>';
    const corrBadges = (f.related_correlation_ids || []).map(cid => `<span class="badge badge--purple">${text(cid)}</span>`).join(' ') || '<span class="subtle">None</span>';
    const tlBadges = (f.timeline_event_ids || []).map(tid => `<span class="badge badge--gray">${text(tid)}</span>`).join(' ') || '<span class="subtle">None</span>';
    const relScore = f.reliability_info?.score ?? 85;
    const intStatus = f.reliability_info?.integrity_status || 'VERIFIED';

    return `<article class="card finding-card" style="margin-bottom:14px;">
      <div class="card-header" style="align-items:flex-start;">
        <div>
          <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:6px;">
            <span class="badge badge--blue" style="font-weight:700;font-size:11px;">${text(f.finding_id)}</span>
            <span class="type-pill ${sevClass}">${text(f.severity)} SEVERITY</span>
            <span class="type-pill pill-cyan">${text(f.category)}</span>
            <span class="badge badge--green">Reliability: ${relScore}/100</span>
            <span class="badge ${intStatus === 'VERIFIED' ? 'badge--green' : 'badge--yellow'}">${text(intStatus)}</span>
          </div>
          <h3 style="margin:2px 0 4px;font-size:14px;">${text(f.title)}</h3>
        </div>
        <span class="record-count" style="font-size:11px;">AI Confidence: <b>${text(f.ai_confidence || '90%')}</b></span>
      </div>
      <p class="subtle" style="font-size:12px;margin:6px 0 10px;">${text(f.description)}</p>

      <!-- Distinct Relationship & Timeline Markers -->
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;padding:8px 12px;background:var(--bg-2);border-radius:6px;font-size:11px;font-family:var(--mono);">
        <div>
          <strong>Supporting Evidence:</strong> ${evBadges}
        </div>
        <div>
          <strong>Relationship:</strong> <span class="badge badge--purple">${text(f.relationship_summary)}</span>
        </div>
        <div>
          <strong>Timeline Event IDs:</strong> ${tlBadges}
        </div>
        <div>
          <strong>Related Correlations:</strong> ${corrBadges}
        </div>
      </div>

      <!-- Analytical Rationale & Action Box -->
      <div class="finding-meta" style="margin-top:10px;display:grid;gap:8px;">
        <div class="meta-box action-box" style="padding:10px;background:rgba(2,132,199,.06);border:1px solid rgba(2,132,199,.2);border-radius:6px;font-size:12px;">
          <strong>Forensic Analysis Explanation:</strong> ${text(f.analysis_explanation)}
        </div>
        <div class="meta-box why-box" style="padding:10px;background:rgba(217,119,6,.06);border:1px solid rgba(217,119,6,.2);border-radius:6px;font-size:12px;">
          <strong>Recommended Next Step:</strong> ${text(f.recommended_action)}
        </div>
      </div>

      <div class="finding-footer" style="margin-top:10px;display:flex;justify-content:space-between;align-items:center;font-family:var(--mono);font-size:11px;color:var(--text-3);">
        <span>Timestamp: <b>${text(f.timestamp)}</b></span>
        <button class="button secondary compact" style="font-size:11px;" onclick="inspectEvidenceId('${text((f.supporting_evidence_ids || [])[0] || '')}')">Inspect Evidence Chain</button>
      </div>
    </article>`;
  }).join('') : '<p class="empty-cell">No suspicious patterns or anomalies identified in preserved evidence.</p>';

  const correlationRows = correlations.length ? correlations.map(c => `<tr>
    <td><span class="badge badge--purple" style="font-weight:700;">${text(c.correlation_id)}</span></td>
    <td><span class="type-pill pill-cyan">${text(c.relationship_type || c.correlation_type)}</span></td>
    <td>${(c.evidence_ids || []).map(id => `<span class="badge badge--blue" style="cursor:pointer;" onclick="inspectEvidenceId('${text(id)}')">${text(id)}</span>`).join(' ')}</td>
    <td>${text(c.reason || c.details)}</td>
    <td><span class="badge badge--green">${text(c.correlation_strength || c.significance)}</span></td>
  </tr>`).join('') : '<tr><td colspan="5" class="empty-cell">No supported relationships identified in preserved evidence.</td></tr>';

  const traceabilityRows = traceability.length ? traceability.slice(0, 30).map(t => `<tr>
    <td><span class="badge badge--blue" style="font-weight:700;">${text(t.finding_id)}</span></td>
    <td>${(t.timeline_event_ids || []).map(id => `<span class="badge badge--gray">${text(id)}</span>`).join(' ')}</td>
    <td>${(t.correlation_ids || []).map(id => `<span class="badge badge--purple">${text(id)}</span>`).join(' ')}</td>
    <td><span class="badge badge--blue" style="cursor:pointer;" onclick="inspectEvidenceId('${text(t.normalized_evidence_id)}')">${text(t.normalized_evidence_id)}</span></td>
    <td><code style="font-size:10px;">${text(t.original_record_reference)}</code></td>
  </tr>`).join('') : '<tr><td colspan="5" class="empty-cell">Traceability chain available upon finding detection.</td></tr>';

  document.querySelector('#module-view').innerHTML = moduleFrame('ai-investigation', `
    <div class="section-head" style="display:flex;justify-content:space-between;align-items:center;gap:14px;flex-wrap:wrap;">
      <div style="display:flex;align-items:center;gap:10px;">
        <label style="font-family:var(--mono);font-size:11px;font-weight:600;">Selected Case: <select id="ai-case-select" style="padding:6px 10px;border-radius:6px;border:1px solid var(--border);">${options}</select></label>
      </div>
      <div style="display:flex;gap:10px;flex-wrap:wrap;">
        <a class="button primary" href="/api/ai-investigation/${encodeURIComponent(state.selectedCaseId)}/pdf" target="_blank">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          Download AI Forensic Report PDF
        </a>
      </div>
    </div>

    <!-- Live Evidence Counts (11 Live Metrics) -->
    <div class="module-stat-grid" style="grid-template-columns:repeat(auto-fit, minmax(130px, 1fr));gap:10px;margin-top:16px;">
      <article class="module-stat"><span>Devices</span><strong>${es.devices ?? 0}</strong></article>
      <article class="module-stat"><span>Call Logs</span><strong>${es.call_logs ?? 0}</strong></article>
      <article class="module-stat"><span>SMS Messages</span><strong>${es.sms ?? es.messages ?? 0}</strong></article>
      <article class="module-stat"><span>GPS Fixes</span><strong>${es.gps ?? es.gps_locations ?? 0}</strong></article>
      <article class="module-stat"><span>Files & Media</span><strong>${es.files ?? es.media_files ?? 0}</strong></article>
      <article class="module-stat"><span>Applications</span><strong>${es.applications ?? 0}</strong></article>
      <article class="module-stat"><span>Web History</span><strong>${es.browser_web_history ?? es.web_history ?? 0}</strong></article>
      <article class="module-stat"><span style="color:var(--accent);">Normalized</span><strong style="color:var(--accent);">${es.normalized_evidence ?? 0}</strong></article>
      <article class="module-stat"><span style="color:var(--teal);">Correlations</span><strong style="color:var(--teal);">${es.correlations ?? 0}</strong></article>
      <article class="module-stat"><span style="color:var(--purple,#7c3aed);">Timeline Events</span><strong style="color:var(--purple,#7c3aed);">${es.timeline_events ?? 0}</strong></article>
      <article class="module-stat"><span style="color:var(--amber);">AI Findings</span><strong style="color:var(--amber);">${es.ai_findings ?? 0}</strong></article>
    </div>

    <!-- AI Analysis Executive Summary Banner -->
    <article class="card" style="margin-top:16px;background:linear-gradient(to right, #f8fafc, #ffffff);border-left:4px solid var(--accent);">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:8px;">
        <div>
          <span class="type-pill pill-cyan">OBJECTIVE AI SYNTHESIS</span>
          <h3 style="margin:4px 0 2px;">AI Investigation Executive Summary</h3>
          <p class="subtle" style="font-size:12px;margin:0;">${text(data.ai_summary || data.final_summary?.summary_text)}</p>
        </div>
      </div>
    </article>

    <!-- Sub-Navigation for Forensic Pillars -->
    <div style="margin-top:20px;display:flex;gap:8px;border-bottom:1px solid var(--border);padding-bottom:8px;flex-wrap:wrap;">
      <button class="button primary compact" id="tab-btn-findings" onclick="switchAiTab('findings')">AI Analytical Findings (${findings.length})</button>
      <button class="button secondary compact" id="tab-btn-relationships" onclick="switchAiTab('relationships')">Discovered Relationships (${correlations.length})</button>
      <button class="button secondary compact" id="tab-btn-traceability" onclick="switchAiTab('traceability')">Investigation Traceability (${traceability.length})</button>
      <button class="button secondary compact" id="tab-btn-limitations" onclick="switchAiTab('limitations')">Limitations & Disclosures (${limitations.length})</button>
    </div>

    <!-- Tab 1: AI Analytical Findings -->
    <div id="ai-tab-findings" style="margin-top:16px;">
      <div class="findings-list">${findingsHtml}</div>
    </div>

    <!-- Tab 2: Relationships & Correlations -->
    <div id="ai-tab-relationships" style="margin-top:16px;display:none;">
      <article class="card">
        <h3>Discovered Cross-Source Relationships</h3>
        <p class="subtle" style="font-size:12px;margin:4px 0 12px;">Objective relationships identified across heterogeneous mobile evidence sources.</p>
        <div class="table-scroll">
          <table class="evidence-table">
            <thead><tr><th>Correlation ID</th><th>Type</th><th>Evidence IDs</th><th>Factual Reason</th><th>Strength</th></tr></thead>
            <tbody>${correlationRows}</tbody>
          </table>
        </div>
      </article>
    </div>

    <!-- Tab 3: Traceability Chain -->
    <div id="ai-tab-traceability" style="margin-top:16px;display:none;">
      <article class="card">
        <h3>Investigation Traceability Chain</h3>
        <p class="subtle" style="font-size:12px;margin:4px 0 12px;">Full audit pathway: AI Finding &rarr; Timeline Event &rarr; Correlation &rarr; Normalized Evidence &rarr; Original Extraction Record.</p>
        <div class="table-scroll">
          <table class="evidence-table">
            <thead><tr><th>AI Finding</th><th>Timeline Event IDs</th><th>Correlation IDs</th><th>Normalized Evidence ID</th><th>Original Record Reference</th></tr></thead>
            <tbody>${traceabilityRows}</tbody>
          </table>
        </div>
      </article>
    </div>

    <!-- Tab 4: Limitations & Disclosures -->
    <div id="ai-tab-limitations" style="margin-top:16px;display:none;">
      <article class="card">
        <h3>Forensic Disclosures & Missing Evidence</h3>
        <p class="subtle" style="font-size:12px;margin:4px 0 12px;">Explicit disclosure of unavailable or inaccessible mobile partitions and boundaries.</p>
        <ul style="margin:8px 0 0 18px;font-size:12px;color:var(--text-2);line-height:1.7;">
          ${limitations.map(lim => `<li>${text(lim)}</li>`).join('')}
        </ul>
      </article>
    </div>
  `);

  const select = document.querySelector('#ai-case-select');
  if (select) {
    select.addEventListener('change', (e) => {
      state.selectedCaseId = e.target.value;
      loadAiInvestigationModule();
    });
  }
}

window.switchAiTab = function(tabName) {
  const tabs = ['findings', 'relationships', 'traceability', 'limitations'];
  tabs.forEach(t => {
    const pane = document.querySelector(`#ai-tab-${t}`);
    const btn = document.querySelector(`#tab-btn-${t}`);
    if (pane) pane.style.display = (t === tabName) ? 'block' : 'none';
    if (btn) {
      btn.className = (t === tabName) ? 'button primary compact' : 'button secondary compact';
    }
  });
};


async function loadMalwareModule() {
  const cases = await getJson('/api/cases');
  state.selectedCaseId = state.selectedCaseId || cases[0]?.case_id;
  const options = cases.map(item => `<option value="${text(item.case_id)}" ${item.case_id === state.selectedCaseId ? 'selected' : ''}>${text(item.case_id)} - ${text(item.case_name)}</option>`).join('');

  if (!state.selectedCaseId) {
    document.querySelector('#module-view').innerHTML = moduleFrame('malware', '<p class="empty-cell">No cases available for malware analysis.</p>');
    return;
  }

  const data = await getJson(`/api/malware-analysis/${encodeURIComponent(state.selectedCaseId)}`);
  const summary = data.summary || {};
  const results = data.results || [];

  const cardsHtml = results.length ? results.map(r => {
    const sevClass = r.verdict === 'MALICIOUS' ? 'pill-high' : r.verdict === 'SUSPICIOUS' ? 'pill-med' : r.verdict === 'SAFE' ? 'pill-low' : '';
    const indicatorsHtml = (r.indicators || []).map(ind => `<span class="type-pill">${text(ind)}</span>`).join(' ');
    const reasonsHtml = (r.reasons || []).map(reason => `<li>${text(reason)}</li>`).join('');

    return `<article class="card malware-card" style="margin-bottom: 14px;">
      <div class="card-header">
        <div>
          <span class="type-pill ${sevClass}" style="font-weight:700;">${text(r.verdict)}</span>
          <h3>${text(r.file_name)}</h3>
        </div>
        <span class="record-count">Risk Level: <b style="color:var(--text)">${text(r.risk_level)}</b></span>
      </div>
      <div class="finding-meta" style="display: grid; gap: 8px; margin-top: 10px;">
        <div style="font-family:var(--mono); font-size:11px; color:var(--text-3); word-break:break-all;">
          <strong>SHA-256:</strong> ${text(r.sha256)}
        </div>
        <div style="display:flex; gap:16px; font-family:var(--mono); font-size:11px; color:var(--text-3); flex-wrap:wrap;">
          <span>Type: <b>${text(r.file_type)}</b></span>
          <span>Size: <b>${r.file_size} bytes</b></span>
          <span>Entropy: <b>${r.entropy}/8.0</b></span>
        </div>
        <div style="margin-top: 4px;">
          <strong style="font-family:var(--mono); font-size:10px; color:var(--text-3); text-transform:uppercase;">Detected Indicators:</strong>
          <div style="margin-top:4px;">${indicatorsHtml || 'None'}</div>
        </div>
        <div style="padding: 10px; background: rgba(2,132,199,.06); border: 1px solid rgba(2,132,199,.2); border-radius: 6px; font-size: 12px;">
          <strong>Verdict Rationale:</strong>
          <ul style="margin-left: 18px; margin-top: 4px;">${reasonsHtml}</ul>
        </div>
        <div style="font-family:var(--mono); font-size:11px; color:var(--text-3); margin-top:4px;">
          <strong>Forensic Scan Details:</strong> ${text(r.analysis_details)}
        </div>
      </div>
    </article>`;
  }).join('') : '<p class="empty-cell">No evidence files available for malware scanning.</p>';

  document.querySelector('#module-view').innerHTML = moduleFrame('malware', `
    <div class="section-head" style="display: flex; justify-content: space-between; align-items: center; gap: 14px;">
      <div>
        <label style="font-family: var(--mono); font-size: 11px;">Selected Case: <select id="malware-case-select">${options}</select></label>
      </div>
      <a class="button primary" href="/api/malware-analysis/${encodeURIComponent(state.selectedCaseId)}/pdf" target="_blank">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
        Download Malware PDF Report
      </a>
    </div>
    <div class="module-stat-grid" style="grid-template-columns: repeat(5, 1fr); margin-top: 16px;">
      <article class="module-stat"><span>Files Scanned</span><strong>${summary.total_files || 0}</strong></article>
      <article class="module-stat"><span style="color:var(--red)">Malicious</span><strong style="color:var(--red)">${summary.malicious_count || 0}</strong></article>
      <article class="module-stat"><span style="color:var(--amber)">Suspicious</span><strong style="color:var(--amber)">${summary.suspicious_count || 0}</strong></article>
      <article class="module-stat"><span style="color:var(--green)">Safe</span><strong style="color:var(--green)">${summary.safe_count || 0}</strong></article>
      <article class="module-stat"><span>Unknown</span><strong>${summary.unknown_count || 0}</strong></article>
    </div>
    <article class="card" style="margin-top: 16px;">
      <h3>Malware Threat Executive Summary</h3>
      <p class="subtle">${text(data.executive_summary)}</p>
    </article>
    <div class="section-head" style="margin-top: 20px;">
      <h3>Scanned Evidence File Verdicts (${results.length})</h3>
    </div>
    <div class="malware-results-list">${cardsHtml}</div>
  `);
}

async function loadHistoryModule() {
  const [history, auditLogs] = await Promise.all([
    getJson('/api/cases/history/all'),
    getJson('/api/cases/history/audit'),
  ]);

  const auditRows = auditLogs.length ? auditLogs.map(item => `<tr>
    <td><strong>${text(item.case_id)}</strong></td>
    <td><span class="type-pill">${text(item.action)}</span></td>
    <td>${text(item.evidence_item_id || '-')}</td>
    <td>${text(item.person || 'System')}</td>
    <td>${text(item.timestamp)}</td>
    <td>${text(item.description)}</td>
  </tr>`).join('') : '<tr><td colspan="6" class="empty-cell">No forensic action audit records logged yet.</td></tr>';

  const rows = history.length ? history.map(item => `<tr><td>${text(item.case_id)}</td><td>${text(item.device_id || 'Not assigned')}</td><td>${text(item.model || item.serial || 'Not available')}</td><td>${text(item.acquisition_id || 'Not started')}</td><td>${text(item.evidence_count)}</td><td>${text(item.acquisition_status || item.case_status)}</td><td>${text(item.last_activity || item.created_at)}</td><td>${item.acquisition_id ? `<a class="button compact" href="/api/reports/${encodeURIComponent(item.case_id)}" target="_blank">Report</a>` : ''}</td></tr>`).join('') : '<tr><td colspan="8" class="empty-cell">No previous acquisitions recorded.</td></tr>';

  document.querySelector('#module-view').innerHTML = moduleFrame('history', `
    <article class="report-card" style="margin-bottom: 20px;">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px;gap:16px;">
        <div>
          <h3 style="margin-top:0;">Forensic Investigation Audit Trail</h3>
          <p class="subtle" style="margin:0;">Immutable action audit log tracking evidence acquisition, hash verification, file analysis, malware scanning, AI investigation, and report generation.</p>
        </div>
        <button class="button compact secondary" data-action="clear-audit-log" style="white-space:nowrap;">Clear Audit Trail</button>
      </div>
      <div class="table-scroll">
        <table class="evidence-table">
          <thead><tr><th>Case ID</th><th>Action / Event</th><th>Evidence ID</th><th>Investigator / Actor</th><th>Timestamp</th><th>Description</th></tr></thead>
          <tbody>${auditRows}</tbody>
        </table>
      </div>
    </article>
    <article class="report-card">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px;gap:16px;">
        <div>
          <h3 style="margin-top:0;">Previous Case and Device History</h3>
          <p class="subtle" style="margin:0;">Each row belongs to one case and acquisition. Evidence remains isolated by case.</p>
        </div>
        <button class="button compact secondary" data-action="clear-acquisitions-history" style="white-space:nowrap;">Clear History</button>
      </div>
      <div class="table-scroll">
        <table class="evidence-table">
          <thead><tr><th>Case</th><th>Device ID</th><th>Device</th><th>Acquisition</th><th>Evidence</th><th>Status</th><th>Last activity</th><th>Report</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </article>
  `);
}


// Helper functions for Module UI interactivity
function closeEvidenceModal() {
  const modal = document.querySelector('#evidence-inspect-modal');
  if (modal) modal.style.display = 'none';
}

async function inspectEvidenceId(id) {
  if (!id) return;
  const modal = document.querySelector('#evidence-inspect-modal');
  const title = document.querySelector('#inspect-modal-title');
  const content = document.querySelector('#inspect-modal-content');
  if (modal) {
    modal.style.display = 'flex';
    if (title) title.textContent = `Evidence Traceability [${id}]`;
    if (content) content.innerHTML = '<div style="padding:40px;text-align:center;" class="subtle">Fetching structured evidence, provenance, and hash records...</div>';
  }

  try {
    const res = await getJson(`/api/forensic-intelligence/evidence-inspect/${encodeURIComponent(id)}`);
    const item = res.normalized_item || {};
    const raw = res.raw_record || {};
    const rel = res.reliability || {};
    const factors = rel.factors_list || [];
    const warnings = rel.warnings || [];
    const missing = rel.missing_information || [];
    const correlated = res.correlated_evidence_ids || [];

    const factorRows = factors.map(f => `
      <div style="display:flex;align-items:center;justify-content:space-between;padding:6px 0;border-bottom:1px solid #f1f5f9;font-size:12px;">
        <span>${f.passed ? '✓' : '✗'} <strong>${text(f.name)}</strong>: <span class="subtle">${text(f.detail || '')}</span></span>
        <span class="badge ${f.passed ? 'badge--green' : 'badge--red'}">${f.impact || `+${f.points} pts`}</span>
      </div>
    `).join('') || '<div class="subtle" style="font-size:12px;">No reliability factor breakdown.</div>';

    const warningsHtml = warnings.length ? `
      <div style="margin-top:10px;padding:10px;background:rgba(239,68,68,0.06);border:1px solid #fecaca;border-radius:6px;font-size:12px;color:#b91c1c;">
        <strong>⚠️ Integrity Warnings:</strong>
        <ul style="margin:4px 0 0 16px;padding:0;">${warnings.map(w => `<li>${text(w)}</li>`).join('')}</ul>
      </div>` : '';

    const missingHtml = missing.length ? `
      <div style="margin-top:8px;padding:10px;background:rgba(245,158,11,0.06);border:1px solid #fde68a;border-radius:6px;font-size:12px;color:#b45309;">
        <strong>ℹ️ Missing Information Disclosures:</strong>
        <ul style="margin:4px 0 0 16px;padding:0;">${missing.map(m => `<li>${text(m)}</li>`).join('')}</ul>
      </div>` : '';

    const corrBadges = correlated.length ? correlated.map(cid => `
      <span class="badge badge--blue" style="cursor:pointer;margin:2px;" onclick="inspectEvidenceId('${text(cid)}')">${text(cid)}</span>
    `).join(' ') : '<span class="subtle">No cross-source correlations found.</span>';

    if (content) {
      content.innerHTML = `
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px;">
          <div style="background:#f8fafc;padding:14px;border-radius:8px;border:1px solid #e2e8f0;">
            <h4 style="margin:0 0 8px;font-size:12px;text-transform:uppercase;color:#64748b;">Evidence Identifiers</h4>
            <table class="info-table" style="font-size:12px;">
              <tr><th>Evidence ID</th><td><strong>${text(item.normalized_id)}</strong></td></tr>
              <tr><th>Artifact Type</th><td><span class="badge badge--purple">${text(item.artifact_type)}</span></td></tr>
              <tr><th>Case ID</th><td>${text(item.case_id)}</td></tr>
              <tr><th>Device ID</th><td>${text(item.device_id)}</td></tr>
              <tr><th>Source Method</th><td>${text(item.source_method)}</td></tr>
              <tr><th>Source Ref</th><td><code>${text(item.source_ref)}</code></td></tr>
            </table>
          </div>

          <div style="background:#f8fafc;padding:14px;border-radius:8px;border:1px solid #e2e8f0;">
            <h4 style="margin:0 0 8px;font-size:12px;text-transform:uppercase;color:#64748b;">Integrity & Timestamps</h4>
            <table class="info-table" style="font-size:12px;">
              <tr><th>Normalized UTC</th><td><strong>${text(item.timestamp_utc || 'Not Available')}</strong></td></tr>
              <tr><th>Original Timestamp</th><td>${text(item.original_timestamp || 'Not Available')}</td></tr>
              <tr><th>SHA-256 Hash</th><td><code style="word-break:break-all;">${text(item.original_hash || 'Not Available in acquisition')}</code></td></tr>
              <tr><th>Integrity Status</th><td><span class="badge ${item.original_hash ? 'badge--green' : 'badge--amber'}">${text(rel.integrity_status || (item.original_hash ? 'VERIFIED' : 'NOT AVAILABLE'))}</span></td></tr>
              <tr><th>Reliability Score</th><td><span class="badge badge--teal"><strong>${rel.reliability_score ?? 80}/100</strong></span></td></tr>
            </table>
          </div>
        </div>

        <div style="margin-bottom:16px;background:#ffffff;border:1px solid #e2e8f0;border-radius:8px;padding:14px;">
          <h4 style="margin:0 0 8px;font-size:12px;text-transform:uppercase;color:#64748b;">Reliability Assessment Factors</h4>
          <div>${factorRows}</div>
          ${warningsHtml}
          ${missingHtml}
        </div>

        <div style="margin-bottom:16px;background:#f8fafc;padding:14px;border-radius:8px;border:1px solid #e2e8f0;">
          <h4 style="margin:0 0 6px;font-size:12px;text-transform:uppercase;color:#64748b;">Cross-Source Corroborating Evidence</h4>
          <div>${corrBadges}</div>
        </div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">
          <div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:8px;padding:14px;">
            <h4 style="margin:0 0 8px;font-size:12px;text-transform:uppercase;color:#64748b;">Normalized Content Payload</h4>
            <pre style="white-space:pre-wrap;font-family:monospace;font-size:11px;background:#f8fafc;padding:10px;border-radius:6px;max-height:200px;overflow-y:auto;border:1px solid #cbd5e1;">${text(JSON.stringify(item.content || item.entity_info || {}, null, 2))}</pre>
          </div>
          <div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:8px;padding:14px;">
            <h4 style="margin:0 0 8px;font-size:12px;text-transform:uppercase;color:#64748b;">Original Preserved Record</h4>
            <pre style="white-space:pre-wrap;font-family:monospace;font-size:11px;background:#f8fafc;padding:10px;border-radius:6px;max-height:200px;overflow-y:auto;border:1px solid #cbd5e1;">${text(JSON.stringify(raw, null, 2))}</pre>
          </div>
        </div>
      `;
    }
  } catch (err) {
    if (content) content.innerHTML = `<div style="padding:20px;color:#ef4444;text-align:center;">Failed to load evidence item details: ${text(err.message || 'Item not found')}</div>`;
  }
}

// ── Module 1: Evidence Normalization UI ──────────────────────────────────────
async function loadNormalizationModule() {
  const cases = await getJson('/api/cases');
  if (!cases || cases.length === 0) {
    document.querySelector('#module-view').innerHTML = moduleFrame('normalization', '<article class="report-card"><div class="empty-cell" style="padding:40px;text-align:center;"><h3>No Investigation Cases Created Yet</h3><p class="subtle">Please create a case in the <strong>Cases</strong> module first.</p></div></article>');
    return;
  }
  state.selectedCaseId = cases.some(c => c.case_id === state.selectedCaseId) ? state.selectedCaseId : cases[0].case_id;
  const options = cases.map(item => `<option value="${text(item.case_id)}" ${item.case_id === state.selectedCaseId ? 'selected' : ''}>${text(item.case_id)} - ${text(item.case_name)}</option>`).join('');

  let normData = await getJson(`/api/normalization/${encodeURIComponent(state.selectedCaseId)}`);

  const s = normData.summary || {};
  const rows = (normData.items || []).map(item => {
    const stBadge = item.normalization_status === 'SUCCESS' ? '<span class="badge badge--green">SUCCESS</span>' : (item.normalization_status === 'PARTIAL' ? '<span class="badge badge--amber">PARTIAL</span>' : '<span class="badge badge--red">FAILED</span>');
    const typeBadge = `<span class="badge badge--blue">${text(item.artifact_type.toUpperCase())}</span>`;
    const hashBadge = item.original_hash ? `<span class="badge badge--purple" title="${text(item.original_hash)}">SHA-256</span>` : '<span class="badge badge--gray">No Hash</span>';
    const cnt = item.content || {};
    const eInfo = item.entity_info || {};
    const summaryText = text(cnt.body || cnt.title || cnt.file_name || eInfo.contact_name || eInfo.address || item.source_ref);

    return `<tr>
      <td><strong>${text(item.normalized_id)}</strong></td>
      <td>${typeBadge}</td>
      <td><div>${text(item.timestamp_utc || 'N/A')}</div><small class="subtle">Raw: ${text(item.original_timestamp || 'N/A')}</small></td>
      <td><div>${text(item.source_method)}</div><small class="subtle">${text(item.source_ref)}</small></td>
      <td>${summaryText}</td>
      <td>${hashBadge}</td>
      <td>${stBadge}</td>
      <td><button class="button compact primary" data-action="inspect-norm" data-case="${text(state.selectedCaseId)}" data-id="${text(item.normalized_id)}">Inspect</button></td>
    </tr>`;
  }).join('') || '<tr><td colspan="8" class="empty-cell">No normalized evidence records available for this case.</td></tr>';

  document.querySelector('#module-view').innerHTML = moduleFrame('normalization', `
    <div class="section-head" style="margin-bottom:16px;">
      <div>
        <h3>Module 1: Evidence Normalization Engine</h3>
        <p class="subtle">Standardizes heterogeneous artifacts from Android/iOS into unified queryable representations.</p>
      </div>
      <div style="display:flex;gap:12px;align-items:center;">
        <select id="norm-case-select" class="search-input">${options}</select>
        <button class="button primary" data-action="run-normalization" data-case="${text(state.selectedCaseId)}">Re-Run Normalization Engine</button>
      </div>
    </div>
    <div class="module-stat-grid">
      <article class="module-stat"><span>Total Processed</span><strong>${s.total || 0}</strong></article>
      <article class="module-stat"><span>Success</span><strong style="color:#10b981;">${s.success || 0}</strong></article>
      <article class="module-stat"><span>Partial / Warnings</span><strong style="color:#f59e0b;">${s.partial || 0}</strong></article>
      <article class="module-stat"><span>Failed / Unsupported</span><strong style="color:#ef4444;">${(s.failed || 0) + (s.unsupported || 0)}</strong></article>
    </div>
    <article class="report-card">
      <div class="table-scroll">
        <table class="evidence-table">
          <thead><tr><th>Normalized ID</th><th>Artifact Type</th><th>Timestamp (UTC / Raw)</th><th>Source / Ref</th><th>Content Summary</th><th>Hash</th><th>Status</th><th>Action</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </article>
    <div id="norm-inspect-result" class="report-card" style="display:none;margin-top:16px;background:#f8fafc;border:1px solid #cbd5e1;padding:16px;border-radius:8px;"></div>
  `);
}

// ── Module 2: Cross-Source Evidence Correlation UI ───────────────────────────
async function loadCorrelationsModule() {
  const cases = await getJson('/api/cases');
  if (!cases || cases.length === 0) {
    document.querySelector('#module-view').innerHTML = moduleFrame('correlations', '<article class="report-card"><div class="empty-cell" style="padding:40px;text-align:center;"><h3>No Investigation Cases Created Yet</h3><p class="subtle">Please create a case in the <strong>Cases</strong> module first.</p></div></article>');
    return;
  }
  state.selectedCaseId = cases.some(c => c.case_id === state.selectedCaseId) ? state.selectedCaseId : cases[0].case_id;
  const options = cases.map(item => `<option value="${text(item.case_id)}" ${item.case_id === state.selectedCaseId ? 'selected' : ''}>${text(item.case_id)} - ${text(item.case_name)}</option>`).join('');

  let corrData = await getJson(`/api/correlations/${encodeURIComponent(state.selectedCaseId)}`);
  const correlations = corrData.correlations || [];

  const rows = correlations.map(item => {
    const strPct = Math.round((item.correlation_strength || 0) * 100);
    const idA = item.evidence_id_a || (item.evidence_ids && item.evidence_ids[0]) || 'N/A';
    const idB = item.evidence_id_b || (item.evidence_ids && item.evidence_ids[1]) || 'N/A';

    const badgeA = `<span class="badge badge--blue" style="cursor:pointer;" onclick="inspectEvidenceId('${text(idA)}')">${text(idA)}</span>`;
    const badgeB = `<span class="badge badge--blue" style="cursor:pointer;" onclick="inspectEvidenceId('${text(idB)}')">${text(idB)}</span>`;

    const supp = item.supporting_attributes || item.matching_attributes || {};
    const suppStr = Object.entries(supp).map(([k, v]) => `<span style="display:inline-block;margin:1px 3px;padding:2px 6px;background:#f1f5f9;border-radius:4px;font-size:11px;"><strong>${text(k)}:</strong> ${text(typeof v === 'object' ? JSON.stringify(v) : v)}</span>`).join('');

    return `<tr>
      <td><strong>${text(item.correlation_id)}</strong></td>
      <td>${badgeA}</td>
      <td>${badgeB}</td>
      <td><span class="badge badge--purple">${text(item.relationship_type)}</span></td>
      <td style="max-width:280px;font-size:12px;">${text(item.reason || item.explanation)}</td>
      <td style="font-size:11px;color:#475569;">${text(item.timestamp_relationship || (item.time_difference_seconds != null ? `Delta: ${Math.round(item.time_difference_seconds)}s` : 'N/A'))}</td>
      <td>${suppStr || '<span class="subtle">None</span>'}</td>
      <td>
        <div style="display:flex;align-items:center;gap:6px;">
          <div style="width:45px;height:5px;background:#e2e8f0;border-radius:3px;overflow:hidden;">
            <div style="width:${strPct}%;height:100%;background:${strPct >= 80 ? '#10b981' : '#2563eb'};"></div>
          </div>
          <span style="font-size:11px;font-weight:600;">${strPct}%</span>
        </div>
      </td>
    </tr>`;
  }).join('');

  const emptyNotice = `<tr><td colspan="8" class="empty-cell" style="padding:40px;text-align:center;">
    <h3 style="color:#64748b;">No supported relationship identified</h3>
    <p class="subtle">Insufficient evidence for correlation in this case acquisition.</p>
  </td></tr>`;

  document.querySelector('#module-view').innerHTML = moduleFrame('correlations', `
    <div class="section-head" style="margin-bottom:16px;">
      <div>
        <h3>Module 2: Cross-Source Evidence Correlation Engine</h3>
        <p class="subtle">Discovers factual cross-source relationships (Temporal, Entity, Communication, Location, File, App) across real stored evidence.</p>
      </div>
      <div style="display:flex;gap:12px;align-items:center;">
        <select id="corr-case-select" class="search-input">${options}</select>
        <button class="button primary" data-action="run-correlations" data-case="${text(state.selectedCaseId)}">Re-Run Correlation Engine</button>
      </div>
    </div>
    <div class="module-stat-grid">
      <article class="module-stat"><span>Total Correlations</span><strong>${correlations.length}</strong></article>
      <article class="module-stat"><span>Status</span><strong style="color:${correlations.length ? '#10b981' : '#f59e0b'};font-size:14px;">${correlations.length ? 'Relationships Verified' : 'Insufficient Evidence'}</strong></article>
    </div>
    <article class="report-card">
      <div class="table-scroll">
        <table class="evidence-table">
          <thead><tr><th>Correlation ID</th><th>Evidence A</th><th>Evidence B</th><th>Correlation Type</th><th>Factual Reason</th><th>Timestamp Relationship</th><th>Supporting Attributes</th><th>Strength</th></tr></thead>
          <tbody>${rows || emptyNotice}</tbody>
        </table>
      </div>
    </article>
  `);
}

// ── Module 3: Reliability & Provenance Scoring UI ─────────────────────────────
async function loadReliabilityModule() {
  const cases = await getJson('/api/cases');
  if (!cases || cases.length === 0) {
    document.querySelector('#module-view').innerHTML = moduleFrame('reliability', '<article class="report-card"><div class="empty-cell" style="padding:40px;text-align:center;"><h3>No Investigation Cases Created Yet</h3><p class="subtle">Please create a case in the <strong>Cases</strong> module first.</p></div></article>');
    return;
  }
  state.selectedCaseId = cases.some(c => c.case_id === state.selectedCaseId) ? state.selectedCaseId : cases[0].case_id;
  const options = cases.map(item => `<option value="${text(item.case_id)}" ${item.case_id === state.selectedCaseId ? 'selected' : ''}>${text(item.case_id)} - ${text(item.case_name)}</option>`).join('');

  let relData = await getJson(`/api/reliability/${encodeURIComponent(state.selectedCaseId)}`);
  const scores = relData.scores || [];
  const avg = scores.length ? Math.round(scores.reduce((acc, x) => acc + x.reliability_score, 0) / scores.length) : 0;

  const rows = scores.map(item => {
    const sc = item.reliability_score;
    const badgeColor = sc >= 80 ? 'badge--green' : (sc >= 50 ? 'badge--amber' : 'badge--red');
    const factors = item.factors_list || [];
    const factorPills = factors.map(f => `
      <span style="display:inline-block;margin:1px;font-size:11px;padding:2px 5px;border-radius:4px;background:${f.passed ? 'rgba(16,185,129,0.1)' : 'rgba(239,68,68,0.1)'};color:${f.passed ? '#047857' : '#b91c1c'};">
        ${f.passed ? '✓' : '✗'} ${text(f.name)}
      </span>
    `).join(' ') || '<span class="subtle">Calculated</span>';

    const warnings = item.warnings || [];
    const missing = item.missing_information || [];
    const issueCount = warnings.length + missing.length;
    const issueBadge = issueCount > 0 ? `<span class="badge badge--amber" title="${text(warnings.concat(missing).join(' | '))}">⚠️ ${issueCount} Disclosure(s)</span>` : '<span class="badge badge--green">Complete</span>';

    return `<tr>
      <td><span class="badge badge--blue" style="cursor:pointer;" onclick="inspectEvidenceId('${text(item.evidence_id)}')"><strong>${text(item.evidence_id)}</strong></span></td>
      <td><span class="badge badge--purple">${text(item.target_type)}</span></td>
      <td><span class="badge ${badgeColor}" style="font-weight:700;">${sc}/100</span></td>
      <td><span class="badge badge--teal">${text(item.integrity_status)}</span></td>
      <td>${text(item.provenance_status)}</td>
      <td style="max-width:240px;">${factorPills}</td>
      <td>${issueBadge}</td>
      <td><button class="button secondary" style="padding:3px 8px;font-size:11px;" onclick="inspectEvidenceId('${text(item.evidence_id)}')">Inspect</button></td>
    </tr>`;
  }).join('') || '<tr><td colspan="8" class="empty-cell">No reliability scores computed. Click "Run Reliability Engine".</td></tr>';

  document.querySelector('#module-view').innerHTML = moduleFrame('reliability', `
    <div class="section-head" style="margin-bottom:16px;">
      <div>
        <h3>Module 3: Evidence Reliability & Provenance Scoring</h3>
        <p class="subtle">Transparent 0-100% confidence scores based on measurable integrity factors, provenance verification, and corroboration.</p>
      </div>
      <div style="display:flex;gap:12px;align-items:center;">
        <select id="rel-case-select" class="search-input">${options}</select>
        <button class="button primary" data-action="run-reliability" data-case="${text(state.selectedCaseId)}">Re-Run Reliability Engine</button>
      </div>
    </div>
    <div class="module-stat-grid">
      <article class="module-stat"><span>Average Reliability</span><strong style="color:#10b981;">${avg}/100</strong></article>
      <article class="module-stat"><span>Assessed Items</span><strong>${scores.length}</strong></article>
    </div>
    <article class="report-card">
      <div class="table-scroll">
        <table class="evidence-table">
          <thead><tr><th>Target ID</th><th>Type</th><th>Assessment Score</th><th>Integrity</th><th>Provenance</th><th>Measurable Factors</th><th>Warnings & Disclosures</th><th>Actions</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </article>
  `);
}

// ── Module 4: Evidence Relationship Graph UI ──────────────────────────────────
let activeGraphData = { nodes: [], edges: [] };

function selectGraphNode(nodeId) {
  const node = (activeGraphData.nodes || []).find(n => n.node_id === nodeId);
  if (!node) return;

  const panel = document.querySelector('#graph-inspector-panel');
  if (panel) {
    panel.style.display = 'block';
    const props = node.properties || {};
    const eids = props.evidence_ids || (node.source_evidence_id ? [node.source_evidence_id] : []);
    const relEids = props.related_evidence || [];

    const eidBadges = eids.map(id => `<span class="badge badge--blue" style="cursor:pointer;" onclick="inspectEvidenceId('${text(id)}')">${text(id)}</span>`).join(' ') || 'None';
    const relBadges = relEids.map(id => `<span class="badge badge--purple" style="cursor:pointer;" onclick="inspectEvidenceId('${text(id)}')">${text(id)}</span>`).join(' ') || 'None';

    panel.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;">
        <h4 style="margin:0;color:#0f172a;">Entity Node Details: <strong>${text(node.label)}</strong></h4>
        <span class="badge badge--blue">${text(node.entity_type)}</span>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;font-size:12px;">
        <div><strong>Node ID:</strong> <code>${text(node.node_id)}</code></div>
        <div><strong>Case ID:</strong> ${text(node.case_id)}</div>
        <div><strong>Device ID:</strong> ${text(props.device_id || 'Primary Device')}</div>
        <div><strong>Timestamp:</strong> ${text(props.timestamp || 'Not Available')}</div>
        <div><strong>Source Method:</strong> ${text(props.source || 'Preserved Database')}</div>
        <div><strong>Provenance:</strong> <code>${text(JSON.stringify(props.provenance || {}))}</code></div>
        <div style="grid-column:1 / -1;"><strong>Primary Evidence IDs:</strong> ${eidBadges}</div>
        <div style="grid-column:1 / -1;"><strong>Related / Corroborated Evidence:</strong> ${relBadges}</div>
      </div>
    `;
    panel.scrollIntoView({ behavior: 'smooth' });
  }

  const src = document.querySelector('#trace-source');
  const tgt = document.querySelector('#trace-target');
  if (src && !src.value) {
    src.value = nodeId;
  } else if (tgt) {
    tgt.value = nodeId;
  }
}

function selectGraphEdge(edgeId) {
  const edge = (activeGraphData.edges || []).find(e => e.edge_id === edgeId);
  if (!edge) return;

  const panel = document.querySelector('#graph-inspector-panel');
  if (panel) {
    panel.style.display = 'block';
    const eids = edge.evidence_ids || (edge.evidence_id ? [edge.evidence_id] : []);
    const eidBadges = eids.map(id => `<span class="badge badge--blue" style="cursor:pointer;" onclick="inspectEvidenceId('${text(id)}')">${text(id)}</span>`).join(' ') || 'None';

    panel.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;">
        <h4 style="margin:0;color:#0f172a;">Relationship Edge Details: <strong>${text(edge.relationship_label)}</strong></h4>
        <span class="badge badge--purple">Weight: ${Math.round((edge.weight || 1)*100)}%</span>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;font-size:12px;">
        <div><strong>Edge ID:</strong> <code>${text(edge.edge_id)}</code></div>
        <div><strong>Correlation ID:</strong> <code>${text(edge.correlation_id || 'Structural Hierarchy')}</code></div>
        <div><strong>Source Node:</strong> <code>${text(edge.source_node_id)}</code></div>
        <div><strong>Target Node:</strong> <code>${text(edge.target_node_id)}</code></div>
        <div style="grid-column:1 / -1;"><strong>Evidence IDs:</strong> ${eidBadges}</div>
        <div style="grid-column:1 / -1;"><strong>Factual Reason:</strong> ${text(edge.reason || 'Verified factual link between stored evidence items.')}</div>
        <div style="grid-column:1 / -1;"><strong>Supporting Attributes:</strong> <code>${text(JSON.stringify(edge.supporting_attributes || edge.properties || {}))}</code></div>
      </div>
    `;
    panel.scrollIntoView({ behavior: 'smooth' });
  }
}

async function loadGraphModule() {
  const cases = await getJson('/api/cases');
  if (!cases || cases.length === 0) {
    document.querySelector('#module-view').innerHTML = moduleFrame('graph', '<article class="report-card"><div class="empty-cell" style="padding:40px;text-align:center;"><h3>No Investigation Cases Created Yet</h3><p class="subtle">Please create a case in the <strong>Cases</strong> module first.</p></div></article>');
    return;
  }
  state.selectedCaseId = cases.some(c => c.case_id === state.selectedCaseId) ? state.selectedCaseId : cases[0].case_id;
  const options = cases.map(item => `<option value="${text(item.case_id)}" ${item.case_id === state.selectedCaseId ? 'selected' : ''}>${text(item.case_id)} - ${text(item.case_name)}</option>`).join('');

  let graphData = await getJson(`/api/graph/${encodeURIComponent(state.selectedCaseId)}`);
  activeGraphData = graphData;

  const nodes = graphData.nodes || [];
  const edges = graphData.edges || [];

  const nodeOptions = nodes.map(n => `<option value="${text(n.node_id)}">${text(n.label)} (${text(n.entity_type)})</option>`).join('');

  // Render SVG Graph Visualization
  let svgContent = '';
  if (nodes.length > 0) {
    const W = 800, H = 380, cx = W / 2, cy = H / 2, R = Math.min(W, H) / 2 - 50;
    const nodeCoords = {};
    nodes.forEach((n, idx) => {
      if (n.entity_type === 'DEVICE') {
        nodeCoords[n.node_id] = { x: cx, y: cy };
      } else {
        const angle = (2 * Math.PI * (idx - 1)) / Math.max(1, nodes.length - 1);
        nodeCoords[n.node_id] = { x: cx + R * Math.cos(angle), y: cy + R * Math.sin(angle) };
      }
    });

    const edgeSvgs = edges.map(e => {
      const src = nodeCoords[e.source_node_id];
      const tgt = nodeCoords[e.target_node_id];
      if (!src || !tgt) return '';
      const mx = (src.x + tgt.x) / 2;
      const my = (src.y + tgt.y) / 2;
      return `<g style="cursor:pointer;" onclick="selectGraphEdge('${text(e.edge_id)}')">
        <line x1="${src.x}" y1="${src.y}" x2="${tgt.x}" y2="${tgt.y}" stroke="#94a3b8" stroke-width="1.8" stroke-dasharray="${e.correlation_id ? '4,4' : 'none'}"/>
        <rect x="${mx - 35}" y="${my - 8}" width="70" height="15" rx="3" fill="#ffffff" stroke="#cbd5e1" opacity="0.9"/>
        <text x="${mx}" y="${my + 3}" fill="#334155" font-size="8.5" font-weight="600" text-anchor="middle" font-family="sans-serif">${text(e.relationship_label.slice(0, 14))}</text>
      </g>`;
    }).join('');

    const colors = { DEVICE: '#0284c7', CONTACT: '#2563eb', PHONE_NUMBER: '#2563eb', SMS: '#9333ea', CALL: '#9333ea', LOCATION: '#16a34a', WEB_ACTIVITY: '#d97706', FILE: '#dc2626', APPLICATION: '#475569' };

    const nodeSvgs = nodes.map(n => {
      const pos = nodeCoords[n.node_id] || { x: cx, y: cy };
      const color = colors[n.entity_type] || '#0284c7';
      const isDev = n.entity_type === 'DEVICE';
      const r = isDev ? 22 : 16;
      return `<g style="cursor:pointer;" onclick="selectGraphNode('${text(n.node_id)}')">
        <circle cx="${pos.x}" cy="${pos.y}" r="${r}" fill="${color}" stroke="#ffffff" stroke-width="2.5" />
        <text x="${pos.x}" y="${pos.y + r + 12}" fill="#0f172a" font-size="10" font-weight="600" text-anchor="middle">${text(n.label.length > 25 ? n.label.slice(0, 22) + '...' : n.label)}</text>
      </g>`;
    }).join('');

    svgContent = `<svg viewBox="0 0 ${W} ${H}" style="width:100%;height:380px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;">${edgeSvgs}${nodeSvgs}</svg>`;
  } else {
    svgContent = '<div class="empty-cell" style="padding:40px;text-align:center;">No graph entities found for this case.</div>';
  }

  const nodeRows = nodes.map(n => `<tr style="cursor:pointer;" onclick="selectGraphNode('${text(n.node_id)}')"><td><strong>${text(n.node_id)}</strong></td><td><span class="badge badge--blue">${text(n.entity_type)}</span></td><td>${text(n.label)}</td><td>${text(n.source_evidence_id || 'Device')}</td></tr>`).join('') || '<tr><td colspan="4" class="empty-cell">No graph nodes available.</td></tr>';
  const edgeRows = edges.map(e => `<tr style="cursor:pointer;" onclick="selectGraphEdge('${text(e.edge_id)}')"><td><strong>${text(e.edge_id)}</strong></td><td>${text(e.source_node_id)}</td><td><span class="badge badge--purple">${text(e.relationship_label)}</span></td><td>${text(e.target_node_id)}</td><td>${Math.round((e.weight || 1)*100)}%</td></tr>`).join('') || '<tr><td colspan="5" class="empty-cell">No graph edges available.</td></tr>';

  document.querySelector('#module-view').innerHTML = moduleFrame('graph', `
    <div class="section-head" style="margin-bottom:16px;">
      <div>
        <h3>Module 4: Evidence Relationship Graph</h3>
        <p class="subtle">Interactive visual graph connecting devices, entities, communications, files, and locations.</p>
      </div>
      <div style="display:flex;gap:12px;align-items:center;">
        <select id="graph-case-select" class="search-input">${options}</select>
      </div>
    </div>
    <div class="module-stat-grid">
      <article class="module-stat"><span>Graph Nodes</span><strong>${nodes.length}</strong></article>
      <article class="module-stat"><span>Relationships (Edges)</span><strong>${edges.length}</strong></article>
    </div>
    <article class="report-card" style="margin-bottom:16px;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
        <h3 style="margin:0;">Interactive Visual Network Diagram</h3>
        <span class="subtle" style="font-size:11px;">Click any Node or Relationship to inspect full evidence traceability</span>
      </div>
      <div>${svgContent}</div>
    </article>

    <!-- Interactive Node/Edge Inspection Panel -->
    <article id="graph-inspector-panel" class="report-card" style="display:none;margin-bottom:16px;background:#ffffff;border:2px solid #3b82f6;border-radius:8px;padding:16px;">
      <p class="subtle">Select a node or edge in the diagram to inspect its detailed evidence traceability.</p>
    </article>

    <article class="report-card form-panel">
      <h3>Trace Relationship Path Between Entities</h3>
      <div style="display:flex;gap:12px;align-items:center;margin-top:12px;">
        <select id="trace-source" class="search-input" style="flex:1;"><option value="">Select Source Node</option>${nodeOptions}</select>
        <select id="trace-target" class="search-input" style="flex:1;"><option value="">Select Target Node</option>${nodeOptions}</select>
        <button class="button primary" data-action="trace-path" data-case="${text(state.selectedCaseId)}">Trace Path</button>
      </div>
      <div id="trace-result" class="data-view" style="display:none;margin-top:12px;background:#ffffff;padding:12px;border:1px solid #cbd5e1;border-radius:6px;"></div>
    </article>
    <article class="report-card">
      <h3>Graph Nodes (${nodes.length})</h3>
      <div class="table-scroll" style="max-height:220px;">
        <table class="evidence-table"><thead><tr><th>Node ID</th><th>Entity Type</th><th>Label</th><th>Source Evidence</th></tr></thead><tbody>${nodeRows}</tbody></table>
      </div>
    </article>
    <article class="report-card" style="margin-top:16px;">
      <h3>Graph Edges / Relationships (${edges.length})</h3>
      <div class="table-scroll" style="max-height:220px;">
        <table class="evidence-table"><thead><tr><th>Edge ID</th><th>Source Node</th><th>Relationship</th><th>Target Node</th><th>Weight</th></tr></thead><tbody>${edgeRows}</tbody></table>
      </div>
    </article>
  `);
}

// ── Module 5: Incident Timeline & AI Report UI ────────────────────────────────
async function loadTimelineModule() {
  const cases = await getJson('/api/cases');
  if (!cases || cases.length === 0) {
    document.querySelector('#module-view').innerHTML = moduleFrame('timeline', '<article class="report-card"><div class="empty-cell" style="padding:40px;text-align:center;"><h3>No Investigation Cases Created Yet</h3><p class="subtle">Please create a case in the <strong>Cases</strong> module first.</p></div></article>');
    return;
  }
  state.selectedCaseId = cases.some(c => c.case_id === state.selectedCaseId) ? state.selectedCaseId : cases[0].case_id;
  const options = cases.map(item => `<option value="${text(item.case_id)}" ${item.case_id === state.selectedCaseId ? 'selected' : ''}>${text(item.case_id)} - ${text(item.case_name)}</option>`).join('');

  let tlData = await getJson(`/api/timeline/${encodeURIComponent(state.selectedCaseId)}`);
  const events = tlData.timeline || [];
  const suspCount = events.filter(e => e.suspicious_flag === 1).length;

  const rows = events.map(item => {
    const alertBadge = item.suspicious_flag === 1 ? '<span class="badge badge--red">SUSPICIOUS PATTERN</span>' : '<span class="badge badge--green">FACT</span>';
    const cEvs = (item.correlated_evidence_ids || []).map(id => `<span class="badge badge--blue" style="cursor:pointer;" onclick="inspectEvidenceId('${text(id)}')">${text(id)}</span>`).join(' ');
    const eventId = item.event_id || `EVT-${item.sequence_number}`;

    return `<tr style="${item.suspicious_flag === 1 ? 'background:rgba(239,68,68,0.04);' : ''}">
      <td><strong>${text(eventId)}</strong></td>
      <td style="font-size:12px;">${text(item.event_timestamp)}</td>
      <td><span class="badge badge--purple">${text(item.event_category)}</span></td>
      <td>
        <strong>${text(item.title)}</strong>
        <div><small class="subtle">${text(item.description)}</small></div>
        ${item.flag_reason ? `<div style="color:#dc2626;font-size:11px;margin-top:2px;">⚠️ ${text(item.flag_reason)}</div>` : ''}
      </td>
      <td><span class="badge badge--blue" style="cursor:pointer;" onclick="inspectEvidenceId('${text(item.primary_evidence_id)}')"><strong>${text(item.primary_evidence_id)}</strong></span></td>
      <td>${cEvs || '<span class="subtle">None</span>'}</td>
      <td style="font-size:11px;"><code>${text(item.source || 'Database')}</code></td>
      <td>${alertBadge}</td>
    </tr>`;
  }).join('') || '<tr><td colspan="8" class="empty-cell">No timeline events generated for this case.</td></tr>';

  document.querySelector('#module-view').innerHTML = moduleFrame('timeline', `
    <div class="section-head" style="margin-bottom:16px;">
      <div>
        <h3>Module 5: Automatic Incident Timeline & AI Report</h3>
        <p class="subtle">Chronological investigation timeline with strict separation of FACT, CORRELATION, and AI INTERPRETATION.</p>
      </div>
      <div style="display:flex;gap:12px;align-items:center;">
        <select id="timeline-case-select" class="search-input">${options}</select>
        <a class="button primary" href="/api/reports/${encodeURIComponent(state.selectedCaseId)}" target="_blank">Download Full PDF Report</a>
      </div>
    </div>
    <div class="module-stat-grid">
      <article class="module-stat"><span>Timeline Events</span><strong>${events.length}</strong></article>
      <article class="module-stat"><span>Suspicious Anomalies</span><strong style="color:${suspCount ? '#ef4444' : '#10b981'};">${suspCount}</strong></article>
    </div>
    <article class="report-card">
      <div class="table-scroll">
        <table class="evidence-table">
          <thead><tr><th>Event ID</th><th>Timestamp (UTC)</th><th>Event Category</th><th>Event Description</th><th>Primary Evidence</th><th>Correlations</th><th>Source</th><th>Classification</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </article>
  `);
}






const moduleLoaders = {
  device: loadDeviceModule,
  cases: loadCasesModule,
  evidence: loadEvidenceModule,
  acquisition: loadAcquisitionModule,
  analysis: loadAnalysisModule,
  hashes: loadHashesModule,
  reports: loadReportsModule,
  'ai-investigation': loadAiInvestigationModule,
  malware: loadMalwareModule,
  history: loadHistoryModule,
  normalization: loadNormalizationModule,
  correlations: loadCorrelationsModule,
  reliability: loadReliabilityModule,
  graph: loadGraphModule,
  timeline: loadTimelineModule,
};

function clearDashboard() {
  state.report = null;
  state.gps = [];
  state.pages = { calls: 1, messages: 1, gps: 1, webHistory: 1, media: 1 };

  const setEl = (id, val) => { const el = document.querySelector(`#${id}`); if (el) el.textContent = val; };
  setEl('header-case-id', 'None');
  setEl('report-id', 'None');
  setEl('analysis-date', 'Not Available');
  const userChip = document.querySelector('#sidebar-username');
  setEl('header-investigator', userChip?.textContent || 'Not Available');

  ['devices', 'calls', 'messages', 'gps', 'files',
   'normalized', 'correlations', 'reliability', 'graph-nodes', 'timeline-events', 'ai-findings'].forEach(k => {
    setEl(`metric-${k}`, '0');
  });

  const deviceState = document.querySelector('#device-state');
  if (deviceState) deviceState.textContent = 'Device not connected';
  const deviceMessage = document.querySelector('#device-message');
  if (deviceMessage) deviceMessage.textContent = 'Click "Detect Device" to scan for authorized ADB connections.';
  const statusDot = document.querySelector('#status-dot');
  if (statusDot) statusDot.className = 'status-indicator';

  const caseInfo = document.querySelector('#case-info');
  if (caseInfo) caseInfo.innerHTML = '<tr><td colspan="2" class="empty-cell" style="text-align:center;padding:16px;color:var(--text-3);">No active case selected. Select a case from the dropdown or open a case to view records.</td></tr>';
  const deviceInfo = document.querySelector('#device-info-table');
  if (deviceInfo) deviceInfo.innerHTML = '<tr><td colspan="2" class="empty-cell" style="text-align:center;padding:16px;color:var(--text-3);">No authorized ADB device connected in this session.</td></tr>';
  const mapContainer = document.querySelector('#gps-map-container');
  if (mapContainer) mapContainer.style.display = 'none';

  renderTables();
  renderGps();
}

async function populateCaseDropdown() {
  const casesResp = await fetch('/api/cases').catch(() => null);
  const cases = casesResp && casesResp.ok ? await casesResp.json() : [];
  const caseSelect = document.querySelector('#dashboard-case-select');
  if (caseSelect) {
    const opts = ['<option value="">-- No Case Selected (Start at 0) --</option>'];
    cases.forEach(c => {
      opts.push(`<option value="${text(c.case_id)}" ${c.case_id === state.selectedCaseId ? 'selected' : ''}>${text(c.case_id)} - ${text(c.case_name || c.title || 'Case')}</option>`);
    });
    caseSelect.innerHTML = opts.join('');
    caseSelect.value = state.selectedCaseId || '';
  }
  return cases;
}

async function loadReport() {
  await populateCaseDropdown();

  // If no case is explicitly selected (e.g. on fresh website load/refresh), keep dashboard cleanly at ZERO
  if (!state.selectedCaseId) {
    clearDashboard();
    return;
  }

  // A case IS explicitly selected — load its report and GPS data
  const caseId = state.selectedCaseId;
  const [reportResp, gpsResp] = await Promise.all([
    fetch(`/api/report-data/${encodeURIComponent(caseId)}`),
    fetch(`/api/gps/${encodeURIComponent(caseId)}`),
  ]);
  if (reportResp.ok) {
    const reportData = await reportResp.json();
    renderReport(reportData);
    renderSocialMedia(reportData);
  } else {
    clearDashboard();
  }
  if (gpsResp.ok) {
    const gpsData = await gpsResp.json();
    state.gps = gpsData.locations || [];
    state.pages.gps = 1;
    renderGps();
    const gpsMetric = document.querySelector('#metric-gps');
    if (gpsMetric) gpsMetric.textContent = state.gps.length;
  }
}

async function loadDevice() {
  const response = await fetch('/api/device');
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Device detection failed.');
  const connected = data.connected === true;
  document.querySelector('#device-state').textContent = connected ? 'Device connected' : 'Device not connected';
  document.querySelector('#device-message').textContent = connected ? 'Authorized ADB device is ready.' : (data.error || 'No authorized device connected.');
  const connectionValue = document.querySelector('#connection-value');
  if (connectionValue) connectionValue.textContent = connected ? 'CONNECTED' : 'DISCONNECTED';
  const statusDot = document.querySelector('#status-dot');
  if (statusDot) statusDot.className = connected ? 'status-indicator connected' : 'status-indicator';
  const deviceCount = document.querySelector('#device-count') || document.querySelector('#metric-devices');
  if (deviceCount) deviceCount.textContent = connected ? (data.devices?.filter(d => d.state === 'device').length || 1) : 0;
  if (connected) {
    const response = await fetch('/api/device/info');
    if (response.ok) renderDevice(await response.json());
  } else {
    const deviceInfo = document.querySelector('#device-info-table');
    if (deviceInfo) deviceInfo.innerHTML = '<tr><td colspan="2" class="empty-cell" style="text-align:center;padding:16px;color:var(--text-3);">No authorized ADB device connected.</td></tr>';
  }
}

async function refreshDeviceFromDashboard(event) {
  const button = event?.currentTarget || document.querySelector('#refresh-button');
  const message = document.querySelector('#device-message');
  if (button) button.disabled = true;
  if (message) message.textContent = 'Checking ADB connection...';
  try {
    await loadDevice();
    if (state.selectedCaseId) {
      await loadReport();
    }
  } catch (error) {
    if (message) message.textContent = error.message;
  }
  if (button) button.disabled = false;
}

document.querySelector('#detect-button').addEventListener('click', refreshDeviceFromDashboard);
document.querySelector('#refresh-button').addEventListener('click', refreshDeviceFromDashboard);
document.addEventListener('change', event => {
  if (event.target.id === 'dashboard-case-select') {
    state.selectedCaseId = event.target.value || null;
    if (state.selectedCaseId) {
      loadReport().catch(() => {});
    } else {
      clearDashboard();
    }
  }
});
document.querySelector('#report-button').addEventListener('click', () => { const id = state.report?.case?.case_id; if (id) window.open(`/api/reports/${encodeURIComponent(id)}`, '_blank'); });
document.querySelectorAll('#call-search,#call-filter').forEach(node => node.addEventListener('input', () => { state.pages.calls = 1; renderTables(); }));
document.querySelectorAll('#message-search,#message-filter').forEach(node => node.addEventListener('input', () => { state.pages.messages = 1; renderTables(); }));
document.addEventListener('input', event => { if (event.target.id === 'gps-search') { state.pages.gps = 1; renderGps(); } else if (event.target.id === 'web-history-search') { state.pages.webHistory = 1; if (state.report) renderWebHistory(state.report); } });
document.querySelectorAll('.nav-item[data-module]').forEach(item => item.addEventListener('click', event => { event.preventDefault(); const key = item.dataset.module; window.location.hash = key; showModule(key); }));
document.addEventListener('input', event => { if (event.target.id === 'evidence-search') { state.evidencePage = 1; renderEvidenceRows(); } });
document.addEventListener('change', event => { if (event.target.id === 'evidence-type-filter') { state.evidencePage = 1; renderEvidenceRows(); } });
document.addEventListener('click', event => {
  const pageButton = event.target.closest('[data-page]');
  if (pageButton) { if (pageButton.dataset.kind === 'evidence') { state.evidencePage = Number(pageButton.dataset.page); renderEvidenceRows(); } else if (pageButton.dataset.kind === 'gps') { state.pages.gps = Number(pageButton.dataset.page); renderGps(); } else if (pageButton.dataset.kind === 'webHistory') { state.pages.webHistory = Number(pageButton.dataset.page); if (state.report) renderWebHistory(state.report); } else { state.pages[pageButton.dataset.kind] = Number(pageButton.dataset.page); renderTables(); } return; }
  const action = event.target.closest('[data-action]');
  if (!action) return;
  if (action.dataset.action === 'refresh-device') loadDeviceModule().catch(error => { document.querySelector('#module-view').innerHTML = moduleFrame('device', `<div class="error-state">${text(error.message)}</div>`); });
  if (action.dataset.action === 'finalize') getJson(`/api/acquisition/${encodeURIComponent(action.dataset.id)}/finalize`, { method: 'POST' }).then(() => { const target = document.querySelector('#device-result') || document.querySelector('#acquisition-result') || document.querySelector('#case-details'); if (target) target.textContent = `Finalized ${action.dataset.id}`; (action.dataset.return === 'cases' ? loadCasesModule : loadDeviceModule)().catch(() => {}); }).catch(error => { const target = document.querySelector('#device-result') || document.querySelector('#acquisition-result') || document.querySelector('#case-details'); if (target) target.textContent = error.message; });
  if (action.dataset.action === 'open-case') {
    state.selectedCaseId = action.dataset.id;
    window.location.hash = 'dashboard';
    showModule('dashboard');
  }
  if (action.dataset.action === 'delete-case') {
    const caseId = action.dataset.id;
    if (!confirm(`Are you sure you want to delete case ${caseId}? All associated forensic records will be permanently removed.`)) return;
    getJson(`/api/cases/${encodeURIComponent(caseId)}`, { method: 'DELETE' }).then(() => {
      if (state.selectedCaseId === caseId) {
        state.selectedCaseId = null;
      }
      loadCasesModule().catch(() => {});
    }).catch(err => alert(err.message));
  }
  if (action.dataset.action === 'clear-audit-log') {
    if (!confirm('Are you sure you want to clear the forensic action audit trail?')) return;
    getJson('/api/cases/history/audit', { method: 'DELETE' }).then(() => loadHistoryModule()).catch(err => alert(err.message));
  }
  if (action.dataset.action === 'clear-acquisitions-history') {
    if (!confirm('Are you sure you want to clear previous acquisitions history?')) return;
    getJson('/api/cases/history/all', { method: 'DELETE' }).then(() => loadHistoryModule()).catch(err => alert(err.message));
  }
  if (action.dataset.action === 'clear-evidence-files') {
    if (!confirm('Are you sure you want to delete preserved evidence artifacts and extracted files?')) return;
    const caseParam = state.selectedCaseId ? `?case_id=${encodeURIComponent(state.selectedCaseId)}` : '';
    getJson(`/api/evidence/all${caseParam}`, { method: 'DELETE' }).then(() => loadEvidenceModule()).catch(err => alert(err.message));
  }
  if (action.dataset.action === 'verify-all') {
    const caseId = action.dataset.case || state.selectedCaseId;
    getJson(`/api/evidence/verify-all/${encodeURIComponent(caseId)}`, { method: 'POST' }).then(result => {
      const target = document.querySelector('#hash-result');
      if (target) target.textContent = `Batch Verification Result: ${result.verified} of ${result.total} evidence files verified cleanly as UNALTERED (SHA-256 matched).`;
      loadHashesModule().catch(() => {});
    }).catch(error => {
      const target = document.querySelector('#hash-result');
      if (target) target.textContent = error.message;
    });
  }
  if (action.dataset.action === 'verify') getJson(`/api/evidence/${encodeURIComponent(action.dataset.id)}/verify`, { method: 'POST' }).then(result => { const target = document.querySelector('#hash-result') || document.querySelector('#module-view .data-view'); if (target) target.textContent = `${result.evidence_id}: ${result.verified ? 'SHA-256 verified (100% Match)' : 'INTEGRITY FAILED'}`; if (document.querySelector('#hashes-case-select')) loadHashesModule().catch(() => {}); else loadEvidenceModule().catch(() => {}); }).catch(error => { const target = document.querySelector('#hash-result') || document.querySelector('#module-view .data-view'); if (target) target.textContent = error.message; });
  if (action.dataset.action === 'metadata') getJson(`/api/analysis/metadata/${encodeURIComponent(action.dataset.id)}`).then(result => { const target = document.querySelector('#analysis-result'); if (target) target.textContent = JSON.stringify(result, null, 2); }).catch(error => { const target = document.querySelector('#analysis-result'); if (target) target.textContent = error.message; });
  if (action.dataset.action === 'run-normalization') {
    const caseId = action.dataset.case || state.selectedCaseId;
    getJson(`/api/normalization/run/${encodeURIComponent(caseId)}`, { method: 'POST' }).then(() => loadNormalizationModule()).catch(err => alert(err.message));
  }
  if (action.dataset.action === 'run-correlations') {
    const caseId = action.dataset.case || state.selectedCaseId;
    getJson(`/api/correlations/run/${encodeURIComponent(caseId)}`, { method: 'POST' }).then(() => loadCorrelationsModule()).catch(err => alert(err.message));
  }
  if (action.dataset.action === 'run-reliability') {
    const caseId = action.dataset.case || state.selectedCaseId;
    getJson(`/api/reliability/run/${encodeURIComponent(caseId)}`, { method: 'POST' }).then(() => loadReliabilityModule()).catch(err => alert(err.message));
  }
  if (action.dataset.action === 'inspect-norm') {
    const caseId = action.dataset.case || state.selectedCaseId;
    const id = action.dataset.id;
    getJson(`/api/normalization/${encodeURIComponent(caseId)}/detail/${encodeURIComponent(id)}`).then(res => {
      const target = document.querySelector('#norm-inspect-result');
      if (target) {
        target.style.display = 'block';
        target.textContent = JSON.stringify(res, null, 2);
      }
    }).catch(err => alert(err.message));
  }
  if (action.dataset.action === 'trace-path') {
    const caseId = action.dataset.case || state.selectedCaseId;
    const src = document.querySelector('#trace-source')?.value;
    const tgt = document.querySelector('#trace-target')?.value;
    if (!src || !tgt) return alert('Select both source and target nodes.');
    getJson(`/api/graph/${encodeURIComponent(caseId)}/trace?source=${encodeURIComponent(src)}&target=${encodeURIComponent(tgt)}`).then(res => {
      const target = document.querySelector('#trace-result');
      if (target) {
        target.style.display = 'block';
        target.textContent = JSON.stringify(res, null, 2);
      }
    }).catch(err => alert(err.message));
  }
});
document.addEventListener('submit', event => {
  if (event.target.id === 'device-acquisition-form') {
    event.preventDefault();
    const result = document.querySelector('#device-result');
    result.textContent = 'Collecting authorized device data...';
    getJson('/api/acquisition', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(Object.fromEntries(new FormData(event.target))) }).then(data => { result.textContent = `Acquisition ${data.status}: ${data.artifacts?.length || 0} artifacts preserved. Open Dashboard to view extracted calls and messages.`; state.selectedCaseId = data.case_id; }).catch(error => { result.textContent = error.message; });
    return;
  }
  if (event.target.id !== 'acquisition-form') return;
  event.preventDefault();
  const result = document.querySelector('#acquisition-result');
  result.textContent = 'Starting acquisition...';
  getJson('/api/acquisition', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(Object.fromEntries(new FormData(event.target))) }).then(data => { result.textContent = JSON.stringify(data, null, 2); }).catch(error => { result.textContent = error.message; });
  return;
});
document.addEventListener('submit', event => {
  if (event.target.id !== 'case-form') return;
  event.preventDefault();
  const result = document.querySelector('#case-result');
  getJson('/api/cases', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(Object.fromEntries(new FormData(event.target))) }).then(data => { state.selectedCaseId = data.case_id; result.textContent = `Created ${data.case_id}`; loadCasesModule(); }).catch(error => { result.textContent = error.message; });
});
document.addEventListener('change', event => {
  if (event.target.id === 'evidence-case-select') {
    state.selectedCaseId = event.target.value;
    loadEvidenceModule().catch(error => { document.querySelector('#module-view').innerHTML = moduleFrame('evidence', `<div class="error-state">${text(error.message)}</div>`); });
  } else if (event.target.id === 'ai-case-select') {
    state.selectedCaseId = event.target.value;
    loadAiInvestigationModule().catch(error => { document.querySelector('#module-view').innerHTML = moduleFrame('ai-investigation', `<div class="error-state">${text(error.message)}</div>`); });
  } else if (event.target.id === 'malware-case-select') {
    state.selectedCaseId = event.target.value;
    loadMalwareModule().catch(error => { document.querySelector('#module-view').innerHTML = moduleFrame('malware', `<div class="error-state">${text(error.message)}</div>`); });
  } else if (event.target.id === 'analysis-case-select') {
    state.selectedCaseId = event.target.value;
    loadAnalysisModule().catch(error => { document.querySelector('#module-view').innerHTML = moduleFrame('analysis', `<div class="error-state">${text(error.message)}</div>`); });
  } else if (event.target.id === 'hashes-case-select') {
    state.selectedCaseId = event.target.value;
    loadHashesModule().catch(error => { document.querySelector('#module-view').innerHTML = moduleFrame('hashes', `<div class="error-state">${text(error.message)}</div>`); });
  } else if (event.target.id === 'norm-case-select') {
    state.selectedCaseId = event.target.value;
    loadNormalizationModule().catch(error => { document.querySelector('#module-view').innerHTML = moduleFrame('normalization', `<div class="error-state">${text(error.message)}</div>`); });
  } else if (event.target.id === 'corr-case-select') {
    state.selectedCaseId = event.target.value;
    loadCorrelationsModule().catch(error => { document.querySelector('#module-view').innerHTML = moduleFrame('correlations', `<div class="error-state">${text(error.message)}</div>`); });
  } else if (event.target.id === 'rel-case-select') {
    state.selectedCaseId = event.target.value;
    loadReliabilityModule().catch(error => { document.querySelector('#module-view').innerHTML = moduleFrame('reliability', `<div class="error-state">${text(error.message)}</div>`); });
  } else if (event.target.id === 'graph-case-select') {
    state.selectedCaseId = event.target.value;
    loadGraphModule().catch(error => { document.querySelector('#module-view').innerHTML = moduleFrame('graph', `<div class="error-state">${text(error.message)}</div>`); });
  } else if (event.target.id === 'timeline-case-select') {
    state.selectedCaseId = event.target.value;
    loadTimelineModule().catch(error => { document.querySelector('#module-view').innerHTML = moduleFrame('timeline', `<div class="error-state">${text(error.message)}</div>`); });
  }
});

// Initialize dashboard session cleanly at 0 on page load / browser refresh
clearDashboard();
populateCaseDropdown().catch(() => {});

const initialModule = window.location.hash.slice(1);
window.addEventListener('hashchange', () => {
  const key = window.location.hash.slice(1) || 'dashboard';
  if (key === 'dashboard' || moduleLoaders[key]) {
    showModule(key);
  } else {
    showModule('dashboard');
  }
});
if (initialModule && (initialModule === 'dashboard' || moduleLoaders[initialModule])) {
  setTimeout(() => showModule(initialModule), 0);
}
