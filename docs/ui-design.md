# UI/UX Design Guide — Website Vulnerability Scanner

## Role of This File

This file is the single source of truth for all visual design decisions, theme tokens, color palettes, component patterns, and page layouts in the Website Vulnerability Scanner. AI agents and developers must strictly apply these design rules.

> **Design Identity:** Sleek Cyber Security & Developer Aesthetic. Modern dark mode by default (`#0F172A`), high-contrast vulnerability risk badges (High Risk Red, Medium Risk Amber, Low Risk Emerald), live streaming terminal log console, and clean data density inspired by professional security tools like Burp Suite and OWASP ZAP.

---

## Color Palette — FIXED (NEVER CHANGE)

```
Primary Cyber Blue:   #0EA5E9     ← Sky-500: Main brand, active states, scan CTA
Primary Hover:        #0284C7     ← Sky-600: Hover state for primary buttons
Background Body:      #0F172A     ← Slate-900: Dark app background
Card Surface:         #1E293B     ← Slate-800: Card backgrounds, modal containers
Border / Divider:     #334155     ← Slate-700: Card borders, table dividers

Risk High (Danger):   #EF4444     ← Red-500: High risk level, SQLi / Critical alerts
Risk Medium (Warning):#F59E0B     ← Amber-500: Medium risk level, Reflected XSS / Header warnings
Risk Low (Safe):      #10B981     ← Emerald-500: Low risk level, HTTPS OK, Secure flags
Risk Info (Notice):   #3B82F6     ← Blue-500: Discovered links/forms info

Text Primary:         #F8FAFC     ← Slate-50: Main headings, primary content
Text Secondary:       #94A3B8     ← Slate-400: Subtitles, field labels, metadata
Terminal Background:  #020617     ← Slate-950: Dark terminal background
Terminal Text Green:  #22C55E     ← Green-500: Terminal log output text
```

---

## Typography

```
Body Font Family:       'Inter', -apple-system, BlinkMacSystemFont, sans-serif
Code & Terminal Font:  'JetBrains Mono', 'Fira Code', Consolas, monospace
```

### Type Scale

| Style | Class / Rule | Size | Weight |
|---|---|---|---|
| Main Heading | `text-3xl font-bold` | 30px | Bold (700) |
| Section Title | `text-2xl font-bold` | 24px | Bold (700) |
| Card Header | `text-xl font-semibold` | 20px | Semibold (600) |
| Body Text | `text-base font-normal` | 16px | Regular (400) |
| Small Label | `text-sm font-medium` | 14px | Medium (500) |
| Terminal Text | `text-xs font-mono` | 13px | Monospace (400) |

---

## Spacing & Grid System

- **Grid System:** 8px baseline grid (`gap-4`, `p-4`, `p-6`, `mb-6`).
- **Page Container Padding (Mobile):** `px-4 py-4`
- **Page Container Padding (Desktop):** `px-8 py-6` (Max container width: 1280px).
- **Card Spacing:** `p-6 rounded-xl border border-slate-700 bg-slate-800`.

---

## Border Radius & Elevation

```
Buttons & Inputs:     rounded-lg (8px)
Cards & Container:    rounded-xl (12px)
Status Badges:        rounded-full (9999px)
Terminal Window:      rounded-xl (12px) with subtle blue glow
Shadows:              Subtle glow (`shadow-lg shadow-sky-500/10`)
```

---

## Key Component Specifications

### 1. Primary Action Button
```css
.btn-primary {
  background-color: #0ea5e9;
  color: #ffffff;
  font-weight: 600;
  padding: 0.75rem 1.5rem;
  border-radius: 0.5rem;
  transition: all 0.2s ease-in-out;
}

.btn-primary:hover {
  background-color: #0284c7;
  box-shadow: 0 0 15px rgba(14, 165, 233, 0.4);
}
```

### 2. Risk Level Status Badges
```html
<!-- High Risk Badge -->
<span class="badge badge-high">HIGH RISK</span>

<!-- Medium Risk Badge -->
<span class="badge badge-medium">MEDIUM RISK</span>

<!-- Low Risk Badge -->
<span class="badge badge-low">LOW RISK</span>
```

```css
.badge {
  padding: 0.25rem 0.75rem;
  border-radius: 9999px;
  font-size: 0.75rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
.badge-high   { background: rgba(239, 68, 68, 0.2);  color: #ef4444; border: 1px solid #ef4444; }
.badge-medium { background: rgba(245, 158, 11, 0.2); color: #f59e0b; border: 1px solid #f59e0b; }
.badge-low    { background: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid #10b981; }
```

### 3. Live Scan Terminal Console Window
- Header bar with window control dots (red, yellow, green) and title "Live Scan Logs".
- Dark background (`#020617`), monospace font, scrollable container (`max-height: 320px`).
- Log line timestamp in cyan, level badge (INFO, WARN, ERROR, SUCCESS), and message body.

---

## Screen-by-Screen Layout Specifications

### 1. New Scan Page (`frontend/pages/index.html`)
- **Header / Navigation:** Logo, links to New Scan, History, Dashboard.
- **Top Card — Target Configuration:**
  - Full-width Target URL text input field with placeholder `https://target-website.com`.
  - Scan Scope Selector (Dropdown: Quick Scan, Normal Scan, Deep Scan).
  - Security Checkboxes: SQL Injection, Reflected XSS, HTTPS Check, Security Headers, Cookie Flags.
  - "Start Security Scan" Primary Button with search icon.
- **Middle Section — Scan Progress & Progress Bar:**
  - Progress percentage bar (0% -> 100%) with animated cyan gradient fill.
  - Status indicator text ("Crawling website pages...", "Executing SQL Injection payloads...").
- **Bottom Section — Live Scan Terminal Console:**
  - Real-time streaming log lines.

### 2. Detailed Report View (`frontend/pages/report.html`)
- **Report Header Bar:** Target URL, scan timestamp, "Download PDF Report" action button.
- **Summary Metric Grid (4 Cards):**
  - Card 1: Overall Risk Level Badge (HIGH / MEDIUM / LOW).
  - Card 2: Total Discovered Links & Scanned Pages Count.
  - Card 3: Total Forms & Parameter Inputs Found.
  - Card 4: Identified Vulnerability Findings Count.
- **Vulnerability Findings Section:**
  - **SQL Injection Accordion / Card:** Status, tested parameters, DB error evidence snippet.
  - **XSS Reflection Accordion / Card:** Status, payload tested, reflection location.
  - **HTTPS & SSL Card:** HTTPS enabled check (Green Checkmark / Red Warning).
  - **Security Headers Table:** Table listing Header Name, Status (Present/Missing), Value, Security Assessment.
  - **Cookie Security Table:** Table listing Cookie Name, HttpOnly flag, Secure flag, SameSite value, Risk warning.

### 3. Dashboard Page (`frontend/pages/dashboard.html`)
- **Top Stat Cards:** Total Scans Performed, High Risk Targets Count, Vulnerability Resolution Rate.
- **Charts Row (2 Columns):**
  - Left: Risk Level Distribution (Donut Chart: High, Medium, Low).
  - Right: Vulnerability Category Counts (Bar Chart: SQLi, XSS, Headers, Cookies, HTTPS).
- **Recent Scans Table:** URL, Date, Risk Badge, Action "View Report".

### 4. Scan History Page (`frontend/pages/history.html`)
- Search bar (filter by URL) & Risk filter dropdown (All, High, Medium, Low).
- Data table listing Target URL, Final URL, Scanned Date, Risk Badge, Scanned Links Count, Findings Count, Action button.

---

## Responsive & Mobile UX Rules

- **Breakpoints:** Mobile (< 640px), Tablet (640px - 1024px), Desktop (> 1024px).
- **Mobile Adjustments:** Stack form fields vertically on mobile screens. Scrollable data tables. Touch target minimum height `44px`.
- **Contrast Compliance:** All text meets WCAG AA contrast against dark backgrounds.
