import os
from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
from backend.config import Config
from backend.database import get_supabase
from backend.routes.scan_routes import scan_bp
from backend.routes.report_routes import report_bp
from backend.routes.dashboard_routes import dashboard_bp
from backend.routes.history_routes import history_bp

app = Flask(__name__, static_folder="../frontend", static_url_path="")
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
    return send_from_directory(app.static_folder, 'pages/index.html')

@app.route('/<path:path>')
def serve_static(path):
    if os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    elif os.path.exists(os.path.join(app.static_folder, 'pages', path)):
        return send_from_directory(os.path.join(app.static_folder, 'pages'), path)
    return send_from_directory(app.static_folder, 'pages/index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=Config.PORT, debug=(Config.FLASK_ENV == 'development'))
