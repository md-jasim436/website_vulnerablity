# Database Schema — Website Vulnerability Scanner (Supabase PostgreSQL)

## Role of This File

This file defines the complete Supabase PostgreSQL database schema, table definitions, column types, JSONB structures, Row Level Security (RLS) policies, indexes, and sample queries for the Website Vulnerability Scanner. AI agents and developers must strictly follow this schema.

---

## Supabase PostgreSQL Architecture

```
Supabase Project: twwijjhjamnvkmwuegcv
URL: https://twwijjhjamnvkmwuegcv.supabase.co
Database: PostgreSQL
├── Table: public.scans (UUID, JSONB findings, RLS Enabled)
└── Extension: pgcrypto / gen_random_uuid()
```

---

## SQL DDL Schema Migration Script

```sql
-- Create Scans Table
CREATE TABLE IF NOT EXISTS public.scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url TEXT NOT NULL,
    final_url TEXT,
    title TEXT,
    depth TEXT NOT NULL DEFAULT 'quick' CHECK (depth IN ('quick', 'normal', 'deep')),
    checks_requested JSONB NOT NULL DEFAULT '{"sql": true, "xss": true, "https": true, "headers": true, "cookies": true}'::jsonb,
    crawl_results JSONB DEFAULT '{}'::jsonb,
    findings JSONB DEFAULT '{}'::jsonb,
    risk_level TEXT DEFAULT 'LOW' CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH')),
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED')),
    error_message TEXT,
    logs JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

-- Performance Indexes
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON public.scans (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_url ON public.scans (url);
CREATE INDEX IF NOT EXISTS idx_scans_risk_level ON public.scans (risk_level);
CREATE INDEX IF NOT EXISTS idx_scans_status ON public.scans (status);

-- Enable Row Level Security
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;

-- RLS Policies
CREATE POLICY "Allow public select on scans" ON public.scans FOR SELECT USING (true);
CREATE POLICY "Allow public insert on scans" ON public.scans FOR INSERT WITH CHECK (true);
CREATE POLICY "Allow public update on scans" ON public.scans FOR UPDATE USING (true);
```

---

## Column Specifications for `public.scans`

| Column Name | Data Type | Default | Constraint / Purpose |
|---|---|---|---|
| `id` | `uuid` | `gen_random_uuid()` | Primary Key |
| `url` | `text` | *None* | Target URL submitted for scan |
| `final_url` | `text` | `NULL` | Final URL reached after redirects |
| `title` | `text` | `NULL` | HTML page title |
| `depth` | `text` | `'quick'` | Scan scope depth (`quick`, `normal`, `deep`) |
| `checks_requested` | `jsonb` | `{sql, xss, ...}` | Enabled security modules map |
| `crawl_results` | `jsonb` | `{}` | Discovered links, forms, inputs, and parameters |
| `findings` | `jsonb` | `{}` | Detected vulnerabilities (SQLi, XSS, Headers, Cookies) |
| `risk_level` | `text` | `'LOW'` | Calculated risk (`LOW`, `MEDIUM`, `HIGH`) |
| `status` | `text` | `'PENDING'` | Scan status (`PENDING`, `RUNNING`, `COMPLETED`, `FAILED`) |
| `error_message` | `text` | `NULL` | Exception details if failed |
| `logs` | `jsonb` | `[]` | Array of log strings |
| `created_at` | `timestamptz` | `now()` | Creation timestamp |
| `completed_at` | `timestamptz` | `NULL` | Scan completion timestamp |

---

## Sample Supabase Query (JavaScript Frontend)

```javascript
import { createClient } from '@supabase/supabase-js'

const supabaseUrl = 'https://twwijjhjamnvkmwuegcv.supabase.co'
const supabaseKey = 'sb_publishable_Mdu3046xmiHuYYqkJu_n0w_diK_Vleh'
const supabase = createClient(supabaseUrl, supabaseKey)

// Fetch recent scan history
export async function getRecentScans() {
  const { data, error } = await supabase
    .from('scans')
    .select('id, url, title, risk_level, status, created_at')
    .order('created_at', { ascending: false })
    .limit(20)

  if (error) throw error
  return data
}
```

---

## Row Level Security (RLS) Policy Rules

1. **`scans` Table RLS Enabled:** All clients must adhere to RLS policies.
2. **Public Select Policy:** Allows readers to view completed scan reports via public UUID link.
3. **Public Insert / Update Policy:** Allows scan operations to insert scan requests and update scan status/results.
