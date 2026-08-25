import os
from supabase import create_client, Client
from backend.config import Config

_supabase_client: Client = None

def get_supabase() -> Client:
    global _supabase_client
    if _supabase_client is None:
        url = Config.SUPABASE_URL
        key = Config.SUPABASE_SERVICE_ROLE_KEY or Config.SUPABASE_ANON_KEY
        _supabase_client = create_client(url, key)
    return _supabase_client
