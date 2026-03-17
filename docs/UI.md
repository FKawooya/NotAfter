# NotAfter — Dashboard UI Documentation

**Version:** 0.2.0
**Last Updated:** 2026-03-16

---

## Overview

NotAfter generates a self-contained interactive HTML dashboard via the `--html` flag.
The dashboard works for both single-host scans and fleet (multi-host) scans, automatically
adapting its layout based on the number of targets.

The dashboard is a single `.html` file with inline CSS and JavaScript — no external
dependencies except optional Google Fonts (falls back to system fonts offline).

---

## Generating a Dashboard

### Single host

```bash
notafter scan example.com --html > report.html
notafter scan --file cert.pem --html > report.html
```

### Fleet scan

```bash
notafter fleet hosts.txt --html > fleet-report.html
notafter fleet 10.0.0.0/24 --html > fleet-report.html
```

### Options that affect the dashboard

| Flag | Effect |
|------|--------|
| `--no-pqc` | Omit PQC Posture tab |
| `--no-revocation` | Omit Revocation tab |
| `--warn-days N` | Adjust expiry warning threshold |
| `--timeout N` | Connection and revocation check timeout |

---

## Dashboard Sections

### 1. Stat Cards

Top-level summary visible on all tabs. Shows aggregate counts:

| Card | Description |
|------|-------------|
| **Hosts** | Total hosts scanned (fleet mode only) |
| **Critical** | Total critical findings across all hosts |
| **Warnings** | Total warning findings across all hosts |
| **Clean** | Hosts with zero critical or warning findings |
| **Errors** | Hosts that failed to connect (shown only if > 0) |
| **Avg PQC Score** | Fleet-wide average PQC readiness score (shown only if PQC enabled) |

### 2. Overview Tab

The primary view. Shows a fleet-wide host table with inline findings.

**Columns:**
- **Host** — clickable; expands inline findings panel below the row
- **TLS** — negotiated TLS version
- **Critical / Warnings** — finding counts
- **PQC** — score and grade (if PQC enabled)
- **Status** — CLEAN / WARNING / CRITICAL / ERROR pill

**Inline expand:** Click any host row to toggle a findings panel directly below it. Each finding shows a severity icon, the issue message, and the recommended action — all in one line. A "Full details" link navigates to the Host Details tab for the full deep-dive.

The tab label shows the total finding count (e.g., "Overview (18 findings)").

**Features:**
- Text filter input (searches all columns)
- Sortable column headers (click to toggle asc/desc)
- Inline expand per host (click row to toggle)

### 3. Certificate Inventory Tab

Flat table listing every certificate seen across all hosts:

| Column | Content |
|--------|---------|
| Host | Origin host (fleet mode only) |
| Role | Leaf / Root / Int #N |
| Subject | Certificate subject DN |
| Expires | Expiry date with days-remaining counter, color-coded |
| Key | Key type and size (RSA 2048, EC-P256, etc.) |
| Signature | Signature algorithm |
| SAN | Subject Alternative Names |

Color coding for expiry:
- **Green**: > 30 days remaining
- **Yellow**: < 30 days remaining
- **Red**: expired

Includes text filter and **CSV export**.

### 4. Timeline Tab

Visual timeline showing certificate validity periods as horizontal bars on a time axis.

- Each certificate is a row with a colored bar spanning its validity period (not_before to not_after)
- Color-coded: **red** (expired), **yellow** (expiring within 30 days), **green** (valid)
- Vertical "Today" marker shows current position on the timeline
- Sorted by expiry date (soonest first)
- Labels show host:port, role, certificate subject, and days remaining
- Time axis labels at top (start date, "Today", end date)

Appears whenever scanned hosts have certificate chains.

### 5. PQC Posture Tab

Per-host PQC readiness assessment panels:

- Score circle (0-10) with color-coded border
- Grade letter (A-F)
- Overall quantum safety status
- Component breakdown table (TLS version, key exchange, each cert in chain)
- CNSA 2.0 compliance status and next deadline
- Actionable recommendations list

Only appears when `--no-pqc` is not set.

### 6. Revocation Tab

Aggregated revocation check results:

| Column | Content |
|--------|---------|
| Host | Origin host (fleet mode only) |
| Method | OCSP / CRL / CT |
| Status | GOOD / REVOKED / SKIPPED / ERROR / NOT FOUND |
| Details | Human-readable status message |
| URL | Responder URL, CRL URL, or crt.sh link |

Only appears when `--no-revocation` is not set.

### 7. CBOM Tab

Cryptographic Bill of Materials — CycloneDX 1.6 asset inventory inline in the dashboard.

| Column | Content |
|--------|---------|
| Host | Origin host (fleet mode only) |
| Asset | CycloneDX component name |
| Type | CERTIFICATE or PROTOCOL |
| Algorithm | Signature algorithm or cipher suite |
| Key | Key type or key exchange method |
| Size | Key size in bits |
| Quantum Readiness | Quantum-Safe / Hybrid / Vulnerable pill |

Includes text filter, **CSV export**, and a collapsible raw CycloneDX JSON view.

Appears whenever scanned hosts have certificate chains.

### 8. Host Details Tab

Expandable accordion for each host. Click a host to expand and see:

- **Audit Findings** — full findings table with severity icons and remediation
- **Certificate Chain** — detailed cert info (subject, issuer, validity, key, sig, serial, SAN)
- **TLS Connection** — protocol version, cipher suite, key exchange, peer address

Features:
- Text filter to search hosts
- Click "Full details" in Overview inline expand to jump directly here

---

## Interactivity

| Feature | How it works |
|---------|-------------|
| **Tab navigation** | Click tab buttons; active tab highlighted with blue underline |
| **Inline expand** | Click a host row in Overview to expand findings panel inline (no tab switch) |
| **Text filtering** | Type in filter input to hide non-matching rows/hosts (case-insensitive) |
| **Column sorting** | Click any column header marked with arrows to sort asc/desc |
| **Host deep-dive** | Click "Full details" link in inline expand to switch to Host Details tab |
| **Expand/collapse** | Click host summary bars in Host Details to toggle detail sections |
| **CSV export** | Click "Export CSV" on Inventory or CBOM tabs to download visible rows |
| **Theme toggle** | Click moon/sun icon in header to switch between dark and light themes; persists via localStorage |
| **Print** | Use browser print (Ctrl+P) — all tabs shown, details expanded, white background, filters/buttons hidden |

---

## Accessibility

- Tab navigation uses `role="tablist"`, `role="tab"`, and `role="tabpanel"` ARIA attributes
- Tab buttons track `aria-selected` state
- Filter inputs have `aria-label` attributes
- Status indicators use both color and text (not color-only)

---

## Technical Notes

- **Self-contained**: No external JS dependencies. CSS and JS are inlined.
- **Offline-capable**: Google Fonts are optional; falls back to system sans-serif and monospace.
- **XSS protected**: All certificate-derived and user-controlled data is HTML-escaped via `_e()`.
- **CSP**: `script-src 'unsafe-inline'` (required for inline JavaScript).
- **UTF-8**: Output is written as UTF-8 bytes to handle international characters in cert subjects.
- **Theming**: Dark theme (default) and light theme, switchable via header toggle. Uses CSS custom properties (`--bg-primary`, `--text-primary`, etc.). Theme choice persists in localStorage. No flash on reload — theme is applied in `<head>` before body renders.
- **Print-friendly**: `@media print` stylesheet switches to white background, shows all tabs, expands all host details, hides interactive controls. JS `beforeprint`/`afterprint` handlers expand and restore `<details>` elements.
- **Responsive**: Layout adapts to mobile viewports (stacked stat cards, smaller fonts).

---

## Roadmap

Future dashboard enhancements (not yet implemented):

- [ ] Trend tracking — historical score graphs (requires persistent storage)
- [ ] Webhook / CI integration — dashboard as build artifact

Completed in v0.2.0:
- [x] Export filtered results as CSV
- [x] Print-friendly stylesheet with auto-expand
- [x] CBOM integration — show cryptographic bill of materials inline
- [x] Inline expand on Overview — click host to see findings without tab-switching
- [x] ARIA accessibility attributes
- [x] Certificate timeline visualization (Gantt-style expiry bars)
- [x] Light/dark theme toggle with localStorage persistence
- [x] Terminal output polish (column truncation with ellipsis)
- [x] Diff mode — compare two scan runs via `notafter diff`
