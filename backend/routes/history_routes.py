from flask import Blueprint, request, jsonify
from backend.database import get_supabase

history_bp = Blueprint('history', __name__)

@history_bp.route('/api/history', methods=['GET'])
def get_scan_history():
    try:
        url_filter = request.args.get('url', '').strip()
        risk_filter = request.args.get('risk', '').strip().upper()
        limit = int(request.args.get('limit', 20))
        page = int(request.args.get('page', 1))
        offset = (page - 1) * limit

        sb = get_supabase()
        query = sb.table("scans").select("id, url, final_url, title, depth, risk_level, status, crawl_results, findings, created_at, completed_at", count="exact")

        if url_filter:
            query = query.ilike("url", f"%{url_filter}%")
        if risk_filter and risk_filter in ["HIGH", "MEDIUM", "LOW"]:
            query = query.eq("risk_level", risk_filter)

        res = query.order("created_at", desc=True).range(offset, offset + limit - 1).execute()

        scans = res.data or []
        total_count = res.count or len(scans)

        # Process summaries
        formatted_scans = []
        for s in scans:
            crawl_res = s.get("crawl_results") or {}
            findings = s.get("findings") or {}
            sql_count = len(findings.get("sql", []))
            xss_count = len(findings.get("xss", []))
            headers_count = len(findings.get("headers", {}).get("missing", []))
            cookies_count = len(findings.get("cookies", {}).get("insecure", []))
            
            formatted_scans.append({
                "id": s.get("id"),
                "url": s.get("url"),
                "title": s.get("title") or s.get("url"),
                "depth": s.get("depth"),
                "risk_level": s.get("risk_level"),
                "status": s.get("status"),
                "pages_crawled": crawl_res.get("pages_crawled", 0),
                "total_findings": sql_count + xss_count + headers_count + cookies_count,
                "created_at": s.get("created_at"),
                "completed_at": s.get("completed_at")
            })

        return jsonify({
            "status": "success",
            "data": formatted_scans,
            "total": total_count,
            "page": page,
            "limit": limit
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
