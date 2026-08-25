from flask import Blueprint, jsonify
from backend.database import get_supabase

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/api/dashboard', methods=['GET'])
def get_dashboard_metrics():
    try:
        sb = get_supabase()
        res = sb.table("scans").select("id, url, title, risk_level, status, findings, created_at").order("created_at", desc=True).limit(50).execute()
        scans = res.data or []

        total_scans = len(scans)
        risk_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        vulnerability_counts = {"sql": 0, "xss": 0, "headers": 0, "cookies": 0, "https": 0}

        for scan in scans:
            risk = scan.get("risk_level", "LOW")
            if risk in risk_counts:
                risk_counts[risk] += 1

            findings = scan.get("findings") or {}
            vulnerability_counts["sql"] += len(findings.get("sql", []))
            vulnerability_counts["xss"] += len(findings.get("xss", []))
            vulnerability_counts["headers"] += len(findings.get("headers", {}).get("missing", []))
            vulnerability_counts["cookies"] += len(findings.get("cookies", {}).get("insecure", []))
            
            https_info = findings.get("https", {})
            if https_info and not https_info.get("is_https", True):
                vulnerability_counts["https"] += 1

        recent_scans = scans[:10]

        return jsonify({
            "status": "success",
            "metrics": {
                "total_scans": total_scans,
                "risk_counts": risk_counts,
                "vulnerability_counts": vulnerability_counts,
                "recent_scans": recent_scans
            }
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
