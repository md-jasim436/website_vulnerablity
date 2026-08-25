import { fetchScanHistory } from './api.js';
import { showToast, formatDateTime } from './app.js';

let currentPage = 1;
const pageSize = 15;
let currentSearch = '';
let currentRisk = '';

document.addEventListener('DOMContentLoaded', () => {
  const searchInput = document.getElementById('history-search');
  const riskFilter = document.getElementById('history-risk-filter');
  const prevBtn = document.getElementById('prev-page-btn');
  const nextBtn = document.getElementById('next-page-btn');

  loadHistory();

  if (searchInput) {
    let debounceTimer;
    searchInput.addEventListener('input', (e) => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        currentSearch = e.target.value.trim();
        currentPage = 1;
        loadHistory();
      }, 400);
    });
  }

  if (riskFilter) {
    riskFilter.addEventListener('change', (e) => {
      currentRisk = e.target.value;
      currentPage = 1;
      loadHistory();
    });
  }

  if (prevBtn) {
    prevBtn.addEventListener('click', () => {
      if (currentPage > 1) {
        currentPage--;
        loadHistory();
      }
    });
  }

  if (nextBtn) {
    nextBtn.addEventListener('click', () => {
      currentPage++;
      loadHistory();
    });
  }
});

async function loadHistory() {
  const tbody = document.getElementById('history-table-body');
  const totalCountSpan = document.getElementById('history-total-count');
  const pageSpan = document.getElementById('history-current-page');
  const prevBtn = document.getElementById('prev-page-btn');
  const nextBtn = document.getElementById('next-page-btn');

  tbody.innerHTML = `
    <tr>
      <td colspan="7" class="text-center py-6 text-muted">
        <div class="inline-flex items-center gap-2">
          <svg class="animate-spin" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10" stroke-opacity="0.25"></circle>
            <path d="M12 2a10 10 0 0 1 10 10" stroke-linecap="round"></path>
          </svg> Loading scan records from Supabase...
        </div>
      </td>
    </tr>
  `;

  try {
    const params = {
      page: currentPage,
      limit: pageSize
    };
    if (currentSearch) params.url = currentSearch;
    if (currentRisk) params.risk = currentRisk;

    const res = await fetchScanHistory(params);
    const scans = res.data || [];
    const total = res.total || 0;

    if (totalCountSpan) totalCountSpan.textContent = total;
    if (pageSpan) pageSpan.textContent = `Page ${currentPage}`;

    if (prevBtn) prevBtn.disabled = currentPage <= 1;
    if (nextBtn) nextBtn.disabled = (currentPage * pageSize) >= total;

    if (scans.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="7" class="text-center py-6 text-muted">
            No scan history found matching your filters.
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = scans.map(s => {
      const risk = (s.risk_level || 'LOW').toUpperCase();
      let riskBadgeClass = 'badge-low';
      if (risk === 'HIGH') riskBadgeClass = 'badge-high';
      else if (risk === 'MEDIUM') riskBadgeClass = 'badge-medium';

      const status = (s.status || 'PENDING').toUpperCase();
      let statusBadgeClass = 'badge-info';
      if (status === 'COMPLETED') statusBadgeClass = 'badge-low';
      else if (status === 'FAILED') statusBadgeClass = 'badge-high';
      else if (status === 'RUNNING') statusBadgeClass = 'badge-medium';

      return `
        <tr>
          <td>
            <a href="/report.html?id=${s.id}" class="font-semibold text-primary hover:underline">
              ${escapeHtml(s.url)}
            </a>
            <div class="text-xs text-muted mt-1">${escapeHtml(s.title || 'Untitled')}</div>
          </td>
          <td><span class="badge ${riskBadgeClass}">${risk}</span></td>
          <td><span class="badge ${statusBadgeClass}">${status}</span></td>
          <td><span class="badge badge-info">${s.depth ? s.depth.toUpperCase() : 'QUICK'}</span></td>
          <td><strong>${s.total_findings || 0}</strong></td>
          <td class="text-xs text-secondary">${formatDateTime(s.created_at)}</td>
          <td>
            <a href="/report.html?id=${s.id}" class="btn btn-outline btn-sm">View Report</a>
          </td>
        </tr>
      `;
    }).join('');

  } catch (err) {
    showToast(err.message || 'Failed to fetch scan history', 'error');
    tbody.innerHTML = `
      <tr>
        <td colspan="7" class="text-center py-6 text-danger">
          Error loading history from database: ${escapeHtml(err.message)}
        </td>
      </tr>
    `;
  }
}

function escapeHtml(str) {
  if (typeof str !== 'string') return String(str);
  return str.replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
