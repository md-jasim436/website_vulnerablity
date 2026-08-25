import { fetchReportData } from './api.js';
import { showToast, formatDateTime } from './app.js';

document.addEventListener('DOMContentLoaded', async () => {
  const urlParams = new URLSearchParams(window.location.search);
  const scanId = urlParams.get('id');

  if (!scanId) {
    showToast('No scan ID provided in URL.', 'error');
    document.getElementById('report-loading').innerHTML = `
      <div class="card text-center">
        <h3 class="card-title text-danger">Invalid Request</h3>
        <p class="card-subtitle">Please select a valid scan from the <a href="/history.html">Scan History</a> page.</p>
      </div>
    `;
    return;
  }

  const pdfDownloadBtn = document.getElementById('download-pdf-btn');
  if (pdfDownloadBtn) {
    pdfDownloadBtn.href = `/api/reports/${scanId}/pdf`;
  }

  try {
    const res = await fetchReportData(scanId);
    const scan = res.data;
    renderReport(scan);
  } catch (err) {
    showToast(err.message || 'Failed to load report data', 'error');
    document.getElementById('report-loading').innerHTML = `
      <div class="card text-center">
        <h3 class="card-title text-danger">Failed to Load Scan Report</h3>
        <p class="card-subtitle">${err.message}</p>
        <a href="/history.html" class="btn btn-secondary mt-4">Return to History</a>
      </div>
    `;
  }
});

function renderReport(scan) {
  document.getElementById('report-loading').style.display = 'none';
  document.getElementById('report-content').style.display = 'block';

  // Target Details & Risk Badge
  document.getElementById('report-target-url').textContent = scan.url;
  document.getElementById('report-created-at').textContent = formatDateTime(scan.created_at);
  document.getElementById('report-title').textContent = scan.title || 'Untitled Web Application';
  document.getElementById('report-depth').textContent = (scan.depth || 'Quick').toUpperCase();
  document.getElementById('report-final-url').textContent = scan.final_url || scan.url;

  const riskLevel = (scan.risk_level || 'LOW').toUpperCase();
  const riskBadge = document.getElementById('report-risk-badge');
  riskBadge.textContent = `${riskLevel} RISK`;
  if (riskLevel === 'HIGH') {
    riskBadge.className = 'badge badge-high';
  } else if (riskLevel === 'MEDIUM') {
    riskBadge.className = 'badge badge-medium';
  } else {
    riskBadge.className = 'badge badge-low';
  }

  const crawlRes = scan.crawl_results || {};
  const findings = scan.findings || {};

  // Metrics
  const pagesCrawled = crawlRes.pages_crawled || (crawlRes.discovered_links ? crawlRes.discovered_links.length : 0);
  document.getElementById('stat-pages').textContent = pagesCrawled;
  document.getElementById('stat-forms').textContent = (crawlRes.forms || []).length;
  document.getElementById('stat-params').textContent = (crawlRes.query_params || []).length;

  const sqlCount = (findings.sql || []).length;
  const xssCount = (findings.xss || []).length;
  const headerMissingCount = (findings.headers?.missing || []).length;
  const cookieInsecureCount = (findings.cookies?.insecure || []).length;
  const totalFindings = sqlCount + xssCount + headerMissingCount + cookieInsecureCount;
  document.getElementById('stat-findings').textContent = totalFindings;

  // Render SQL Findings
  renderSqlFindings(findings.sql || []);

  // Render XSS Findings
  renderXssFindings(findings.xss || []);

  // Render HTTPS Security
  renderHttpsSecurity(findings.https || {});

  // Render Security Headers
  renderSecurityHeaders(findings.headers || {});

  // Render Cookie Security
  renderCookieSecurity(findings.cookies || {});

  // Render Discovered Attack Surface Links & Forms
  renderAttackSurface(crawlRes);

  // Render Scan Logs
  renderScanLogs(scan.logs || []);
}

function renderSqlFindings(sqlFindings) {
  const container = document.getElementById('sql-findings-container');
  const countBadge = document.getElementById('sql-count-badge');
  countBadge.textContent = sqlFindings.length;

  if (sqlFindings.length === 0) {
    container.innerHTML = `
      <div class="finding-item safe">
        <div class="finding-header">
          <span class="badge badge-low">SAFE</span>
          <span class="finding-title">No SQL injection indicators detected</span>
        </div>
        <p class="finding-desc">Input forms and query parameters tested returned no recognizable database error signatures.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = sqlFindings.map(item => `
    <div class="finding-item danger">
      <div class="finding-header">
        <span class="badge badge-high">HIGH RISK</span>
        <span class="finding-title">SQL Injection in <code>${escapeHtml(item.parameter || 'input')}</code></span>
      </div>
      <p class="finding-desc">${escapeHtml(item.description || 'Database error reflection observed.')}</p>
      <div class="finding-details">
        <div><strong>URL:</strong> <code>${escapeHtml(item.url)}</code></div>
        <div><strong>Database Engine:</strong> <span class="badge badge-info">${escapeHtml(item.database_type || 'Generic SQL')}</span></div>
        <div><strong>Test Payload:</strong> <code>${escapeHtml(item.payload || '')}</code></div>
        ${item.evidence ? `<div><strong>Error Evidence:</strong> <pre class="evidence-block">${escapeHtml(item.evidence)}</pre></div>` : ''}
      </div>
    </div>
  `).join('');
}

function renderXssFindings(xssFindings) {
  const container = document.getElementById('xss-findings-container');
  const countBadge = document.getElementById('xss-count-badge');
  countBadge.textContent = xssFindings.length;

  if (xssFindings.length === 0) {
    container.innerHTML = `
      <div class="finding-item safe">
        <div class="finding-header">
          <span class="badge badge-low">SAFE</span>
          <span class="finding-title">No Reflected XSS vulnerabilities detected</span>
        </div>
        <p class="finding-desc">Payload canary markers injected into parameters and forms were properly encoded or not reflected.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = xssFindings.map(item => `
    <div class="finding-item warning">
      <div class="finding-header">
        <span class="badge badge-medium">MEDIUM RISK</span>
        <span class="finding-title">Reflected Cross-Site Scripting (XSS)</span>
      </div>
      <p class="finding-desc">${escapeHtml(item.description || 'Reflected script execution marker found.')}</p>
      <div class="finding-details">
        <div><strong>URL / Action:</strong> <code>${escapeHtml(item.url)}</code></div>
        <div><strong>Vulnerable Parameter:</strong> <code>${escapeHtml(item.parameter || 'input')}</code></div>
        <div><strong>Payload Reflected:</strong> <code>${escapeHtml(item.payload || '')}</code></div>
      </div>
    </div>
  `).join('');
}

function renderHttpsSecurity(httpsData) {
  const container = document.getElementById('https-container');
  const isHttps = httpsData.is_https;
  const certValid = httpsData.certificate_valid;
  const certDetails = httpsData.cert_details || {};

  let statusBadge = isHttps && certValid
    ? '<span class="badge badge-low">SECURE (HTTPS)</span>'
    : '<span class="badge badge-high">INSECURE (HTTP / Invalid SSL)</span>';

  container.innerHTML = `
    <div class="finding-item ${isHttps && certValid ? 'safe' : 'danger'}">
      <div class="finding-header">
        ${statusBadge}
        <span class="finding-title">Transport Layer Security & Certificate Status</span>
      </div>
      <div class="finding-details mt-3">
        <div><strong>Target Protocol:</strong> ${isHttps ? 'HTTPS (Encrypted)' : 'HTTP (Cleartext)'}</div>
        <div><strong>SSL Certificate Valid:</strong> ${certValid ? ' Valid & Trusted' : ' Invalid or Not Provided'}</div>
        <div><strong>Enforces HTTPS Redirect:</strong> ${httpsData.redirects_to_https ? ' Yes' : ' No'}</div>
        ${certDetails.issuer ? `<div><strong>Certificate Issuer:</strong> ${escapeHtml(JSON.stringify(certDetails.issuer))}</div>` : ''}
        ${certDetails.notAfter ? `<div><strong>Expires On:</strong> ${escapeHtml(certDetails.notAfter)}</div>` : ''}
      </div>
    </div>
  `;
}

function renderSecurityHeaders(headersData) {
  const missingContainer = document.getElementById('missing-headers-container');
  const presentContainer = document.getElementById('present-headers-container');

  const missing = headersData.missing || [];
  const present = headersData.present || {};
  const infoLeaks = headersData.info_leaks || [];

  if (missing.length === 0) {
    missingContainer.innerHTML = '<div class="finding-item safe"><p class="finding-desc">All primary recommended security headers are configured.</p></div>';
  } else {
    missingContainer.innerHTML = missing.map(item => `
      <div class="finding-item ${item.risk === 'HIGH' ? 'danger' : 'warning'}">
        <div class="finding-header">
          <span class="badge badge-${item.risk === 'HIGH' ? 'high' : 'medium'}">${item.risk} RISK</span>
          <span class="finding-title">Missing Header: <code>${escapeHtml(item.header)}</code></span>
        </div>
        <p class="finding-desc">${escapeHtml(item.recommendation)}</p>
      </div>
    `).join('');
  }

  const presentKeys = Object.keys(present);
  if (presentKeys.length === 0) {
    presentContainer.innerHTML = '<p class="text-muted">No security headers detected on target response.</p>';
  } else {
    presentContainer.innerHTML = presentKeys.map(k => {
      const h = present[k];
      return `
        <div class="header-tag-item">
          <strong>${escapeHtml(h.header)}:</strong>
          <code>${escapeHtml(h.value)}</code>
        </div>
      `;
    }).join('');
  }

  // Info leaks
  const leakContainer = document.getElementById('info-leaks-container');
  if (leakContainer) {
    if (infoLeaks.length === 0) {
      leakContainer.innerHTML = '<p class="text-muted">No sensitive server identification headers leaked.</p>';
    } else {
      leakContainer.innerHTML = infoLeaks.map(leak => `
        <div class="finding-item warning">
          <div class="finding-header">
            <span class="badge badge-medium">INFO LEAK</span>
            <span class="finding-title">${escapeHtml(leak.header)}: <code>${escapeHtml(leak.value)}</code></span>
          </div>
          <p class="finding-desc">${escapeHtml(leak.recommendation)}</p>
        </div>
      `).join('');
    }
  }
}

function renderCookieSecurity(cookieData) {
  const container = document.getElementById('cookies-container');
  const cookies = cookieData.cookies || [];
  const insecure = cookieData.insecure || [];

  if (cookies.length === 0) {
    container.innerHTML = '<p class="text-muted">No HTTP cookies detected on the scanned target page.</p>';
    return;
  }

  container.innerHTML = `
    <table class="table">
      <thead>
        <tr>
          <th>Cookie Name</th>
          <th>Domain</th>
          <th>HttpOnly</th>
          <th>Secure</th>
          <th>SameSite</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        ${cookies.map(c => {
          const isInsecure = !c.httponly || !c.secure || !['strict', 'lax'].includes(String(c.samesite).toLowerCase());
          return `
            <tr>
              <td><strong>${escapeHtml(c.name)}</strong></td>
              <td>${escapeHtml(c.domain || 'Host')}</td>
              <td>${c.httponly ? '<span class="text-success">Yes</span>' : '<span class="text-danger">No</span>'}</td>
              <td>${c.secure ? '<span class="text-success">Yes</span>' : '<span class="text-danger">No</span>'}</td>
              <td><code>${escapeHtml(c.samesite || 'None')}</code></td>
              <td>${isInsecure ? '<span class="badge badge-medium">INSECURE</span>' : '<span class="badge badge-low">SECURE</span>'}</td>
            </tr>
          `;
        }).join('')}
      </tbody>
    </table>
  `;
}

function renderAttackSurface(crawlRes) {
  const linksContainer = document.getElementById('discovered-links-list');
  const formsContainer = document.getElementById('discovered-forms-list');

  const links = crawlRes.discovered_links || [];
  const forms = crawlRes.forms || [];

  if (linksContainer) {
    linksContainer.innerHTML = links.length === 0
      ? '<p class="text-muted">No internal links discovered.</p>'
      : links.map(l => `<li><a href="${escapeHtml(l)}" target="_blank" rel="noopener noreferrer">${escapeHtml(l)}</a></li>`).join('');
  }

  if (formsContainer) {
    formsContainer.innerHTML = forms.length === 0
      ? '<p class="text-muted">No HTML form elements discovered on crawled pages.</p>'
      : forms.map(f => `
        <div class="card mb-3 p-3" style="background: rgba(15, 23, 42, 0.6)">
          <div><strong>Action:</strong> <code>${escapeHtml(f.action)}</code> (${escapeHtml(f.method)})</div>
          <div class="mt-2 text-sm text-secondary">
            <strong>Inputs (${f.inputs?.length || 0}):</strong>
            ${(f.inputs || []).map(i => `<span class="badge badge-info mr-1">${escapeHtml(i.name)} (${escapeHtml(i.type)})</span>`).join(' ')}
          </div>
        </div>
      `).join('');
  }
}

function renderScanLogs(logs) {
  const container = document.getElementById('report-logs');
  if (!container) return;

  if (logs.length === 0) {
    container.innerHTML = '<div class="terminal-line muted">// No log entries available.</div>';
    return;
  }

  container.innerHTML = logs.map(line => {
    let lineClass = 'terminal-line';
    if (line.includes('WARN')) lineClass += ' warning';
    else if (line.includes('ERROR')) lineClass += ' error';
    else if (line.includes('SUCCESS')) lineClass += ' success';
    else if (line.includes('INFO')) lineClass += ' info';
    return `<div class="${lineClass}">${escapeHtml(line)}</div>`;
  }).join('');
}

function escapeHtml(str) {
  if (typeof str !== 'string') return String(str);
  return str.replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
