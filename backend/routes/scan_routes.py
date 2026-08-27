import socket
import threading
import ipaddress
from datetime import datetime
from urllib.parse import urlparse
from flask import Blueprint, request, jsonify
from backend.config import Config
from backend.database import get_supabase
from backend.scanner.crawler import PlaywrightCrawler
from backend.scanner.sql_scanner import run_sql_scan
from backend.scanner.xss_scanner import run_xss_scan
from backend.scanner.https_checker import run_https_check
from backend.scanner.security_headers import run_security_headers_scan
from backend.scanner.cookies import run_cookies_scan
from backend.risk_engine import calculate_risk

scan_bp = Blueprint('scan', __name__)

def validate_target_url(url: str):
    if not url:
        return False, "Target URL is required."
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        return False, "Invalid URL scheme. Only HTTP and HTTPS targets are allowed."
    hostname = parsed.hostname
    if not hostname:
        return False, "Invalid target hostname."
    
    try:
        ip_str = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(ip_str)
        for net in Config.BLOCKED_NETWORKS:
            if ip in net:
                return False, f"Forbidden scan target ({ip_str}). Localhost and private networks are restricted."
    except Exception as e:
        return False, f"DNS resolution failed for host '{hostname}': {str(e)}"
        
    return True, "URL Validated"

def append_logs_to_supabase(scan_id: str, new_logs: list):
    try:
        sb = get_supabase()
        res = sb.table("scans").select("logs").eq("id", scan_id).single().execute()
        existing_logs = res.data.get("logs", []) if res.data else []
        existing_logs.extend(new_logs)
        sb.table("scans").update({"logs": existing_logs}).eq("id", scan_id).execute()
    except Exception as e:
        print(f"Error persisting logs to Supabase: {str(e)}")

def execute_scan_background(scan_id: str, target_url: str, depth: str, checks: dict):
    all_logs = [f"[{datetime.now().strftime('%H:%M:%S')}] INFO Scan worker initialized for {target_url}"]
    append_logs_to_supabase(scan_id, all_logs)

    try:
        # Step 1: Web Crawler
        crawler = PlaywrightCrawler(target_url, depth=depth)
        crawl_results = crawler.crawl()
        append_logs_to_supabase(scan_id, crawler.logs)

        findings = {"sql": [], "xss": [], "https": {}, "headers": {}, "cookies": {}}

        # Step 2: SQL Injection Scan
        if checks.get("sql", True):
            sql_res = run_sql_scan(crawl_results)
            findings["sql"] = sql_res.get("findings", [])
            append_logs_to_supabase(scan_id, sql_res.get("logs", []))

        # Step 3: Reflected XSS Scan
        if checks.get("xss", True):
            xss_res = run_xss_scan(crawl_results)
            findings["xss"] = xss_res.get("findings", [])
            append_logs_to_supabase(scan_id, xss_res.get("logs", []))

        # Step 4: HTTPS Security Check
        if checks.get("https", True):
            https_res = run_https_check(target_url)
            findings["https"] = https_res.get("result", {})
            append_logs_to_supabase(scan_id, https_res.get("logs", []))

        # Step 5: Security Response Headers Check
        if checks.get("headers", True):
            headers_res = run_security_headers_scan(target_url)
            findings["headers"] = headers_res.get("result", {})
            append_logs_to_supabase(scan_id, headers_res.get("logs", []))

        # Step 6: Cookie Security Flags Check
        if checks.get("cookies", True):
            cookies_res = run_cookies_scan(target_url)
            findings["cookies"] = cookies_res.get("result", {})
            append_logs_to_supabase(scan_id, cookies_res.get("logs", []))

        # Step 7: Risk Engine Calculation
        risk_result = calculate_risk(findings)
        # risk_result is a dict: {level, score, factors}
        risk_level = risk_result.get("level", "LOW") if isinstance(risk_result, dict) else str(risk_result)
        risk_score = risk_result.get("score", 0) if isinstance(risk_result, dict) else 0
        risk_factors = risk_result.get("factors", []) if isinstance(risk_result, dict) else []

        complete_log = f"[{datetime.now().strftime('%H:%M:%S')}] SUCCESS Scan completed successfully! Overall Risk: {risk_level} (Score: {risk_score}/100)"
        append_logs_to_supabase(scan_id, [complete_log])

        # Final Supabase Persistence Update
        get_supabase().table("scans").update({
            "final_url": crawl_results.get("final_url", target_url),
            "title": crawl_results.get("title", ""),
            "crawl_results": crawl_results,
            "findings": findings,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "risk_factors": risk_factors,
            "status": "COMPLETED",
            "completed_at": datetime.now().isoformat()
        }).eq("id", scan_id).execute()

    except Exception as e:
        error_msg = f"Scan failed due to unexpected error: {str(e)}"
        err_log = f"[{datetime.now().strftime('%H:%M:%S')}] ERROR {error_msg}"
        append_logs_to_supabase(scan_id, [err_log])
        get_supabase().table("scans").update({
            "status": "FAILED",
            "error_message": error_msg,
            "completed_at": datetime.now().isoformat()
        }).eq("id", scan_id).execute()

@scan_bp.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.get_json() or {}
    url = data.get('url', '').strip()
    depth = data.get('depth', 'quick')
    checks = data.get('checks', {"sql": True, "xss": True, "https": True, "headers": True, "cookies": True})

    valid, msg = validate_target_url(url)
    if not valid:
        return jsonify({"status": "error", "message": msg}), 400

    try:
        sb = get_supabase()
        res = sb.table("scans").insert({
            "url": url,
            "depth": depth,
            "checks_requested": checks,
            "status": "RUNNING",
            "logs": [f"[{datetime.now().strftime('%H:%M:%S')}] INFO Scan queued for {url}"]
        }).execute()

        scan_id = res.data[0]["id"]
        
        # Trigger async worker thread
        thread = threading.Thread(
            target=execute_scan_background,
            args=(scan_id, url, depth, checks),
            daemon=True
        )
        thread.start()

        return jsonify({
            "status": "success",
            "message": "Scan initiated successfully.",
            "scan_id": scan_id
        }), 202
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to initialize scan: {str(e)}"}), 500

@scan_bp.route('/api/scan/<scan_id>/status', methods=['GET'])
def get_scan_status(scan_id):
    try:
        sb = get_supabase()
        res = sb.table("scans").select("id, status, risk_level, logs, error_message").eq("id", scan_id).single().execute()
        if not res.data:
            return jsonify({"status": "error", "message": "Scan record not found"}), 404
        return jsonify({"status": "success", "data": res.data}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@scan_bp.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan_details(scan_id):
    try:
        sb = get_supabase()
        res = sb.table("scans").select("*").eq("id", scan_id).single().execute()
        if not res.data:
            return jsonify({"status": "error", "message": "Scan record not found"}), 404
        return jsonify({"status": "success", "data": res.data}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
