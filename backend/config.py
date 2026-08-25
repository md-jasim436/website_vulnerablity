import os
import ipaddress
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-key-change-in-production")
    FLASK_ENV = os.getenv("FLASK_ENV", "development")
    PORT = int(os.getenv("PORT", 5000))

    # Supabase Configuration
    SUPABASE_URL = os.getenv("SUPABASE_URL", "https://twwijjhjamnvkmwuegcv.supabase.co")
    SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY", "sb_publishable_Mdu3046xmiHuYYqkJu_n0w_diK_Vleh")
    SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", os.getenv("SUPABASE_ANON_KEY", "sb_publishable_Mdu3046xmiHuYYqkJu_n0w_diK_Vleh"))

    # Scanner Controls & Limits
    PLAYWRIGHT_HEADLESS = os.getenv("PLAYWRIGHT_HEADLESS", "true").lower() == "true"
    CRAWL_TIMEOUT_MS = int(os.getenv("CRAWL_TIMEOUT_MS", 15000))
    MAX_CONCURRENT_SCANS = int(os.getenv("MAX_CONCURRENT_SCANS", 3))

    # Scope depth page count caps
    DEPTH_LIMITS = {
        "quick": 5,
        "normal": 15,
        "deep": 30
    }

    # Blocked Private IP Networks (SSRF Safeguard)
    BLOCKED_NETWORKS = [
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('169.254.0.0/16'),
        ipaddress.ip_network('::1/128')
    ]
