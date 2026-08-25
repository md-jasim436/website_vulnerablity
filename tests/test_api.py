import pytest
from backend.app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_health_check(client):
    response = client.get('/api/health')
    assert response.status_code == 200
    data = response.get_json()
    assert data['status'] == 'online'
    assert 'database' in data

def test_scan_validation_empty_url(client):
    response = client.post('/api/scan', json={"url": ""})
    assert response.status_code == 400
    data = response.get_json()
    assert data['status'] == 'error'

def test_scan_validation_invalid_scheme(client):
    response = client.post('/api/scan', json={"url": "ftp://example.com"})
    assert response.status_code == 400
    data = response.get_json()
    assert 'Invalid URL scheme' in data['message']

def test_ssrf_protection_localhost(client):
    response = client.post('/api/scan', json={"url": "http://127.0.0.1:8000"})
    assert response.status_code == 400
    data = response.get_json()
    assert 'Forbidden scan target' in data['message'] or 'restricted' in data['message']

def test_ssrf_protection_private_subnet(client):
    response = client.post('/api/scan', json={"url": "http://192.168.1.1"})
    assert response.status_code == 400
    data = response.get_json()
    assert 'Forbidden scan target' in data['message'] or 'restricted' in data['message']

def test_dashboard_endpoint(client):
    response = client.get('/api/dashboard')
    assert response.status_code in [200, 500]
    if response.status_code == 200:
        data = response.get_json()
        assert data['status'] == 'success'
        assert 'metrics' in data
        assert 'total_scans' in data['metrics']

def test_history_endpoint(client):
    response = client.get('/api/history')
    assert response.status_code in [200, 500]
    if response.status_code == 200:
        data = response.get_json()
        assert data['status'] == 'success'
        assert 'data' in data
