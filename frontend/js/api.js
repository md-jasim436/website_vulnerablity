// Centralized API Client & Supabase SDK Integration

const API_BASE_URL = window.location.origin;

export async function fetchApi(endpoint, options = {}) {
  const url = `${API_BASE_URL}${endpoint}`;
  const defaultHeaders = {
    'Content-Type': 'application/json'
  };

  const config = {
    ...options,
    headers: {
      ...defaultHeaders,
      ...(options.headers || {})
    }
  };

  try {
    const response = await fetch(url, config);
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.message || `HTTP error! status: ${response.status}`);
    }
    return data;
  } catch (error) {
    console.error(`API Request Error [${endpoint}]:`, error);
    throw error;
  }
}

export async function triggerNewScan(url, depth, checks) {
  return await fetchApi('/api/scan', {
    method: 'POST',
    body: JSON.stringify({ url, depth, checks })
  });
}

export async function pollScanStatus(scanId) {
  return await fetchApi(`/api/scan/${scanId}/status`);
}

export async function fetchScanDetails(scanId) {
  return await fetchApi(`/api/scan/${scanId}`);
}

export async function fetchReportData(scanId) {
  return await fetchApi(`/api/reports/${scanId}`);
}

export async function fetchDashboardMetrics() {
  return await fetchApi('/api/dashboard');
}

export async function fetchScanHistory(params = {}) {
  const query = new URLSearchParams(params).toString();
  return await fetchApi(`/api/history?${query}`);
}
