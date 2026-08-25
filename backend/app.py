import os
import sys

# Ensure root workspace directory is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
from backend.config import Config
from backend.database import get_supabase
from backend.routes.scan_routes import scan_bp
from backend.routes.report_routes import report_bp
from backend.routes.dashboard_routes import dashboard_bp
from backend.routes.history_routes import history_bp

FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend'))
app = Flask(__name__, static_folder=None)
app.config.from_object(Config)

CORS(app, resources={r"/api/*": {"origins": "*"}})

# Register API Blueprints
app.register_blueprint(scan_bp)
app.register_blueprint(report_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(history_bp)

@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        # Verify Supabase connection
        sb = get_supabase()
        res = sb.table("scans").select("id").limit(1).execute()
        db_status = "connected"
    except Exception as e:
        db_status = f"disconnected: {str(e)}"

    return jsonify({
        "status": "online",
        "service": "Website Vulnerability Scanner API",
        "database": db_status,
        "environment": Config.FLASK_ENV
    }), 200

# Static Frontend Route Handlers (for local development execution)
@app.route('/')
def serve_index():
    return send_from_directory(os.path.join(FRONTEND_DIR, 'pages'), 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    # Check direct frontend path (css, js, etc.)
    direct_file = os.path.join(FRONTEND_DIR, path)
    if os.path.isfile(direct_file):
        return send_from_directory(FRONTEND_DIR, path)

    # Check pages subdirectory (e.g. /report.html, /history.html, /dashboard.html, /index.html)
    page_file = os.path.join(FRONTEND_DIR, 'pages', path)
    if os.path.isfile(page_file):
        return send_from_directory(os.path.join(FRONTEND_DIR, 'pages'), path)

    # Fallback to index.html
    return send_from_directory(os.path.join(FRONTEND_DIR, 'pages'), 'index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=Config.PORT, debug=(Config.FLASK_ENV == 'development'))
