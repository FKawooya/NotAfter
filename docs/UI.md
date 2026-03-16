# NotAfter — Dashboard UI Documentation

**Version:** 0.2.0
**Last Updated:** 2026-03-13

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
| **Clean** | Hosts with zero findings |
| **Errors** | Hosts that failed to connect (shown only if > 0) |
| **Avg PQC Score** | Fleet-wide average PQC readiness score (shown only if PQC enabled) |

### 2. Overview Tab

Fleet-wide host table with columns:
- **Host** — clickable; navigates to Host Details tab and expands that host
- **TLS** — negotiated TLS version
- **Critical / Warnings** — finding counts
- **PQC** — score and grade (if PQC enabled)
- **Status** — CLEAN / WARNING / CRITICAL / ERROR pill

Features:
- Text filter input (searches all columns)
- Sortable column headers (click to toggle asc/desc)

### 3. Action Items Tab

Flat table of all non-PASS findings that have remediation guidance, sorted by severity
(critical first). Columns:

| Column | Content |
|--------|---------|
| Severity icon | Visual indicator |
| Severity | CRITICAL / WARNING / INFO |
| Host | Which host the finding belongs to |
| Check | Check name (expiry, key_strength, etc.) |
| Component | Certificate CN or TLS property |
| Finding | What was detected |
| Remediation | Recommended fix |

Only appears when there are actionable findings. Includes text filter.

### 4. Certificate Inventory Tab

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

### 7. Host Details Tab

Expandable accordion for each host. Click a host to expand and see:

- **Audit Findings** — full findings table with severity icons and remediation
- **Certificate Chain** — detailed cert info (subject, issuer, validity, key, sig, serial, SAN)
- **TLS Connection** — protocol version, cipher suite, key exchange, peer address

Features:
- Text filter to search hosts
- Click a host in the Overview tab to jump directly here

---

## Interactivity

| Feature | How it works |
|---------|-------------|
| **Tab navigation** | Click tab buttons; active tab highlighted with blue underline |
| **Text filtering** | Type in filter input to hide non-matching rows/hosts (case-insensitive) |
| **Column sorting** | Click any column header marked with arrows to sort asc/desc |
| **Host drill-down** | Click a host name in Overview to switch to Host Details and expand that host |
| **Expand/collapse** | Click host summary bars in Host Details to toggle detail sections |

---

## Technical Notes

- **Self-contained**: No external JS dependencies. CSS and JS are inlined.
- **Offline-capable**: Google Fonts are optional; falls back to system sans-serif and monospace.
- **XSS protected**: All certificate-derived and user-controlled data is HTML-escaped.
- **CSP**: `script-src 'unsafe-inline'` (required for inline JavaScript).
- **UTF-8**: Output is written as UTF-8 bytes to handle international characters in cert subjects.
- **Dark theme**: GitHub-inspired dark color scheme (`#0d1117` background).
- **Responsive**: Layout adapts to mobile viewports (stacked stat cards, smaller fonts).

---

## Roadmap

Future dashboard enhancements (not yet implemented):

- [ ] Certificate timeline visualization (Gantt-style expiry view)
- [ ] Export filtered results as CSV
- [ ] Diff mode — compare two scan runs
- [ ] Trend tracking — historical score graphs (requires persistent storage)
- [ ] Print-friendly stylesheet
- [ ] Light theme toggle
- [ ] CBOM integration — show cryptographic bill of materials inline
- [ ] Webhook / CI integration — dashboard as build artifact
