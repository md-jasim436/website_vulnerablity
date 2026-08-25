import { triggerNewScan, pollScanStatus } from './api.js';
import { showToast } from './app.js';

let activePollInterval = null;
let currentScanId = null;

document.addEventListener('DOMContentLoaded', () => {
  const scanForm = document.getElementById('scan-form');
  const targetUrlInput = document.getElementById('target-url');
  const terminalLogs = document.getElementById('terminal-logs');
  const startScanBtn = document.getElementById('start-scan-btn');
  const scanProgressContainer = document.getElementById('scan-progress-container');
  const scanProgressBar = document.getElementById('scan-progress-bar');
  const statusBadge = document.getElementById('scan-status-badge');
  const viewReportBtn = document.getElementById('view-report-btn');
  const clearTerminalBtn = document.getElementById('clear-terminal-btn');

  if (clearTerminalBtn) {
    clearTerminalBtn.addEventListener('click', () => {
      terminalLogs.innerHTML = '<div class="terminal-line muted">// Ready for target assessment. Logs will stream here in real-time.</div>';
    });
  }

  if (scanForm) {
    scanForm.addEventListener('submit', async (e) => {
      e.preventDefault();

      const url = targetUrlInput.value.trim();
      const depth = document.querySelector('input[name="depth"]:checked')?.value || 'quick';
      const consentChecked = document.getElementById('auth-consent')?.checked;

      if (!url) {
        showToast('Please enter a target URL.', 'warning');
        targetUrlInput.focus();
        return;
      }

      if (!consentChecked) {
        showToast('You must confirm you have authorization to scan this target.', 'warning');
        return;
      }

      const checks = {
        sql: document.getElementById('check-sql')?.checked ?? true,
        xss: document.getElementById('check-xss')?.checked ?? true,
        https: document.getElementById('check-https')?.checked ?? true,
        headers: document.getElementById('check-headers')?.checked ?? true,
        cookies: document.getElementById('check-cookies')?.checked ?? true,
      };

      try {
        startScanBtn.disabled = true;
        startScanBtn.innerHTML = `
          <svg class="animate-spin" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10" stroke-opacity="0.25"></circle>
            <path d="M12 2a10 10 0 0 1 10 10" stroke-linecap="round"></path>
          </svg> Initializing Scanner...
        `;

        if (viewReportBtn) viewReportBtn.style.display = 'none';
        if (scanProgressContainer) scanProgressContainer.style.display = 'block';
        if (scanProgressBar) scanProgressBar.style.width = '10%';
        if (statusBadge) {
          statusBadge.textContent = 'RUNNING';
          statusBadge.className = 'badge badge-medium';
        }

        terminalLogs.innerHTML = `
          <div class="terminal-line info">[INIT] Submitting target ${url} (Scope: ${depth.toUpperCase()})...</div>
        `;

        const response = await triggerNewScan(url, depth, checks);
        currentScanId = response.scan_id;

        terminalLogs.innerHTML += `
          <div class="terminal-line info">[INIT] Scan session allocated: ID ${currentScanId}</div>
          <div class="terminal-line">[EXEC] Background security worker launched...</div>
        `;

        showToast('Scan initiated successfully!', 'success');
        startPollingLogs(currentScanId);

      } catch (err) {
        showToast(err.message || 'Failed to start scan', 'error');
        terminalLogs.innerHTML += `
          <div class="terminal-line error">[FATAL] Error starting scan: ${err.message}</div>
        `;
        startScanBtn.disabled = false;
        startScanBtn.innerHTML = `<span>Start Security Assessment</span>`;
      }
    });
  }

  function startPollingLogs(scanId) {
    if (activePollInterval) clearInterval(activePollInterval);

    let progress = 15;
    activePollInterval = setInterval(async () => {
      try {
        const res = await pollScanStatus(scanId);
        const scan = res.data;

        if (scanProgressBar && progress < 90) {
          progress += 5;
          scanProgressBar.style.width = `${progress}%`;
        }

        // Render logs
        if (scan.logs && Array.isArray(scan.logs)) {
          terminalLogs.innerHTML = scan.logs.map(logLine => {
            let lineClass = 'terminal-line';
            if (logLine.includes('WARN') || logLine.includes('WARNING')) lineClass += ' warning';
            else if (logLine.includes('ERROR') || logLine.includes('FATAL')) lineClass += ' error';
            else if (logLine.includes('SUCCESS') || logLine.includes('COMPLETED')) lineClass += ' success';
            else if (logLine.includes('INFO')) lineClass += ' info';
            return `<div class="${lineClass}">${escapeHtml(logLine)}</div>`;
          }).join('');

          // Auto-scroll terminal to bottom
          terminalLogs.scrollTop = terminalLogs.scrollHeight;
        }

        if (scan.status === 'COMPLETED') {
          clearInterval(activePollInterval);
          if (scanProgressBar) scanProgressBar.style.width = '100%';
          if (statusBadge) {
            statusBadge.textContent = 'COMPLETED';
            statusBadge.className = 'badge badge-low';
          }
          if (viewReportBtn) {
            viewReportBtn.href = `/report.html?id=${scanId}`;
            viewReportBtn.style.display = 'inline-flex';
          }
          startScanBtn.disabled = false;
          startScanBtn.innerHTML = `<span>Run Another Scan</span>`;
          showToast('Scan completed successfully! Click View Report to inspect results.', 'success');
        } else if (scan.status === 'FAILED') {
          clearInterval(activePollInterval);
          if (statusBadge) {
            statusBadge.textContent = 'FAILED';
            statusBadge.className = 'badge badge-high';
          }
          startScanBtn.disabled = false;
          startScanBtn.innerHTML = `<span>Restart Scan</span>`;
          showToast(`Scan failed: ${scan.error_message || 'Unknown error'}`, 'error');
        }
      } catch (e) {
        console.warn('Polling error:', e);
      }
    }, 1500);
  }

  function escapeHtml(str) {
    return str.replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
});
