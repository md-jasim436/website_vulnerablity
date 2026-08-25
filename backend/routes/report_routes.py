from flask import Blueprint, jsonify, send_file, Response
from backend.database import get_supabase
from backend.reports.report_generator import generate_pdf_report
import io

report_bp = Blueprint('report', __name__)

@report_bp.route('/api/reports/<scan_id>', methods=['GET'])
def get_report_data(scan_id):
    try:
        sb = get_supabase()
        res = sb.table("scans").select("*").eq("id", scan_id).single().execute()
        if not res.data:
            return jsonify({"status": "error", "message": "Report not found"}), 404
        return jsonify({"status": "success", "data": res.data}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@report_bp.route('/api/reports/<scan_id>/pdf', methods=['GET'])
def download_report_pdf(scan_id):
    try:
        sb = get_supabase()
        res = sb.table("scans").select("*").eq("id", scan_id).single().execute()
        if not res.data:
            return jsonify({"status": "error", "message": "Report not found"}), 404
            
        pdf_bytes = generate_pdf_report(res.data)
        
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=vulnerability_report_{scan_id[:8]}.pdf"}
        )
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to generate PDF: {str(e)}"}), 500
