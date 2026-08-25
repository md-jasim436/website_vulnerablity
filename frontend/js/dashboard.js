import { fetchDashboardMetrics } from './api.js';
import { showToast, formatDateTime } from './app.js';

let riskChartInstance = null;
let vulnChartInstance = null;

document.addEventListener('DOMContentLoaded', async () => {
  try {
    const res = await fetchDashboardMetrics();
    const metrics = res.metrics;
    renderDashboard(metrics);
  } catch (err) {
    showToast(err.message || 'Failed to load dashboard metrics', 'error');
  }
});

function renderDashboard(metrics) {
  const totalScans = metrics.total_scans || 0;
  const riskCounts = metrics.risk_counts || { HIGH: 0, MEDIUM: 0, LOW: 0 };
  const vulnCounts = metrics.vulnerability_counts || { sql: 0, xss: 0, headers: 0, cookies: 0, https: 0 };
  const recentScans = metrics.recent_scans || [];

  // Metric Cards
  document.getElementById('dash-total-scans').textContent = totalScans;
  document.getElementById('dash-high-risk').textContent = riskCounts.HIGH || 0;
  document.getElementById('dash-medium-risk').textContent = riskCounts.MEDIUM || 0;
  document.getElementById('dash-low-risk').textContent = riskCounts.LOW || 0;

  // Render Charts with Chart.js
  renderRiskDistributionChart(riskCounts);
  renderVulnerabilitiesChart(vulnCounts);

  // Render Recent Activity Table
  renderRecentScans(recentScans);
}

function renderRiskDistributionChart(riskCounts) {
  const ctx = document.getElementById('riskDistributionChart')?.getContext('2d');
  if (!ctx) return;

  if (riskChartInstance) riskChartInstance.destroy();

  riskChartInstance = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['High Risk', 'Medium Risk', 'Low Risk'],
      datasets: [{
        data: [riskCounts.HIGH || 0, riskCounts.MEDIUM || 0, riskCounts.LOW || 0],
        backgroundColor: ['#EF4444', '#F59E0B', '#10B981'],
        borderWidth: 2,
        borderColor: '#1E293B'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'bottom',
          labels: {
            color: '#94A3B8',
            font: { family: 'Inter', size: 12 }
          }
        }
      },
      cutout: '65%'
    }
  });
}

function renderVulnerabilitiesChart(vulnCounts) {
  const ctx = document.getElementById('vulnerabilitiesBarChart')?.getContext('2d');
  if (!ctx) return;

  if (vulnChartInstance) vulnChartInstance.destroy();

  vulnChartInstance = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['SQLi Indicators', 'Reflected XSS', 'Missing Headers', 'Insecure Cookies', 'Insecure HTTP'],
      datasets: [{
        label: 'Issues Identified',
        data: [
          vulnCounts.sql || 0,
          vulnCounts.xss || 0,
          vulnCounts.headers || 0,
          vulnCounts.cookies || 0,
          vulnCounts.https || 0
        ],
        backgroundColor: ['#EF4444', '#F59E0B', '#38BDF8', '#818CF8', '#F43F5E'],
        borderRadius: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: {
          beginAtZero: true,
          ticks: { color: '#94A3B8', stepSize: 1 },
          grid: { color: '#334155' }
        },
        x: {
          ticks: { color: '#94A3B8' },
          grid: { display: false }
        }
      },
      plugins: {
        legend: { display: false }
      }
    }
  });
}

function renderRecentScans(scans) {
  const tbody = document.getElementById('recent-scans-tbody');
  if (!tbody) return;

  if (scans.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="5" class="text-center py-4 text-muted">No scan activities recorded yet.</td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = scans.map(s => {
    const risk = (s.risk_level || 'LOW').toUpperCase();
    let badgeClass = 'badge-low';
    if (risk === 'HIGH') badgeClass = 'badge-high';
    else if (risk === 'MEDIUM') badgeClass = 'badge-medium';

    return `
      <tr>
        <td>
          <a href="/report.html?id=${s.id}" class="text-primary font-medium hover:underline">
            ${escapeHtml(s.url)}
          </a>
        </td>
        <td><span class="badge ${badgeClass}">${risk}</span></td>
        <td><span class="badge badge-info">${escapeHtml(s.status || 'COMPLETED')}</span></td>
        <td class="text-xs text-secondary">${formatDateTime(s.created_at)}</td>
        <td>
          <a href="/report.html?id=${s.id}" class="btn btn-outline btn-sm">Report</a>
        </td>
      </tr>
    `;
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
