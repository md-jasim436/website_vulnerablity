import requests
import logging

logger = logging.getLogger(__name__)


def _parse_raw_set_cookie(header_value: str) -> dict:
    """
    Parse a raw Set-Cookie header string into a structured dict.
    Handles: name=value; HttpOnly; Secure; SameSite=Strict; Path=/
    """
    parts = [p.strip() for p in header_value.split(";")]
    if not parts:
        return {}

    # First part is name=value
    name_val = parts[0].split("=", 1)
    name = name_val[0].strip()
    # value = name_val[1].strip() if len(name_val) > 1 else ""

    directives = [p.lower() for p in parts[1:]]

    is_httponly = any(d == "httponly" for d in directives)
    is_secure = any(d == "secure" for d in directives)

    samesite = "None"
    for d in directives:
        if d.startswith("samesite="):
            samesite = d.split("=", 1)[1].strip().capitalize()
            break

    domain = ""
    for d in directives:
        if d.startswith("domain="):
            domain = d.split("=", 1)[1].strip()
            break

    path = "/"
    for d in directives:
        if d.startswith("path="):
            path = d.split("=", 1)[1].strip()
            break

    return {
        "name": name,
        "domain": domain,
        "path": path,
        "httponly": is_httponly,
        "secure": is_secure,
        "samesite": samesite,
    }


def run_cookies_scan(target_url: str) -> dict:
    logs = []
    logs.append(f"[INFO] Inspecting Cookie Security Flags for {target_url}...")

    cookies_inspected = []
    insecure_cookies = []
    seen_names = set()

    try:
        res = requests.get(target_url, timeout=10, verify=False, allow_redirects=True)

        # ── Method 1: requests.cookies (standard) ────────────────────────────
        for cookie in res.cookies:
            if cookie.name in seen_names:
                continue
            seen_names.add(cookie.name)

            is_httponly = cookie.has_nonstandard_attr('httponly') or cookie.has_nonstandard_attr('HttpOnly')
            is_secure = cookie.secure
            samesite = (
                cookie.get_nonstandard_attr('samesite')
                or cookie.get_nonstandard_attr('SameSite')
                or "None"
            )

            cookie_info = {
                "name": cookie.name,
                "domain": cookie.domain or "",
                "path": cookie.path or "/",
                "httponly": is_httponly,
                "secure": is_secure,
                "samesite": samesite,
            }
            cookies_inspected.append(cookie_info)

        # ── Method 2: Raw Set-Cookie headers (catches CDN / Cloudflare cookies) ──
        # requests merges duplicate headers, so we use the raw response
        raw_set_cookies = []
        for header_name, header_val in res.headers.items():
            if header_name.lower() == "set-cookie":
                raw_set_cookies.append(header_val)

        for raw_cookie in raw_set_cookies:
            parsed = _parse_raw_set_cookie(raw_cookie)
            cookie_name = parsed.get("name", "")
            if not cookie_name or cookie_name in seen_names:
                continue
            seen_names.add(cookie_name)
            cookies_inspected.append(parsed)

        # ── Evaluate each cookie for insecure flags ───────────────────────────
        for cookie_info in cookies_inspected:
            missing_flags = []

            if not cookie_info.get("httponly"):
                missing_flags.append("HttpOnly")
            if not cookie_info.get("secure"):
                missing_flags.append("Secure")
            if str(cookie_info.get("samesite", "None")).lower() not in ["strict", "lax"]:
                missing_flags.append("SameSite (Strict/Lax)")

            if missing_flags:
                insecure_cookies.append({
                    "name": cookie_info["name"],
                    "domain": cookie_info.get("domain", ""),
                    "missing_flags": missing_flags,
                    "description": (
                        f"Cookie '{cookie_info['name']}' is missing security flags: "
                        f"{', '.join(missing_flags)}."
                    )
                })
                logs.append(
                    f"[WARN] Insecure Cookie: '{cookie_info['name']}' missing {', '.join(missing_flags)}"
                )
            else:
                logs.append(f"[INFO] Cookie '{cookie_info['name']}' has all required security flags.")

    except Exception as e:
        logs.append(f"[ERROR] Cookie Security inspection failed: {str(e)}")

    result = {
        "inspected_count": len(cookies_inspected),
        "cookies": cookies_inspected,
        "insecure": insecure_cookies,
    }

    logs.append(
        f"[INFO] Cookie Scan complete. "
        f"({len(cookies_inspected)} cookies inspected, {len(insecure_cookies)} insecure)"
    )
    return {"result": result, "logs": logs}
