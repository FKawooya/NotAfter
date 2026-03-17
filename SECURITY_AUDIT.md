# NotAfter — Security & QA Audit Report

**Version:** 0.2.0
**Date:** 2026-03-16
**Auditors:** QA Agent, Security Audit Agent, Code Quality Agent (3 review rounds)

---

## Executive Summary

Four automated review rounds audited the NotAfter codebase. Round 1 (v0.1) produced 61 findings; 16 fixed immediately, 45 deferred. Round 2 (v0.1.1) addressed all deferred items. Round 3 (v0.2.0) reviewed the dashboard, CSV export, CBOM tab, and print stylesheet. Round 4 (v0.2.0) reviewed the timeline visualization, light theme toggle, and terminal polish.

| Phase | Found | Fixed | Deferred |
|-------|-------|-------|----------|
| Round 1 (v0.1) | 61 | 16 | 45 |
| Round 2 — fix deferred items | 45 | 45 | 0 |
| Round 2 — review findings | 42 | 11 | 6 |
| Round 3 — dashboard (v0.2.0) | 29 | 13 | 6 |
| Round 4 — timeline/theme (v0.2.0) | 24 | 7 | 0 |
| Round 5 — diff feature (v0.2.0) | 24 | 10 | 0 |
| **Cumulative** | **180** | **102** | **6** |

**Test coverage:** 251 tests, all passing.

---

## Round 1 Fixes (commit `7962f89`)

| ID(s) | Finding | Fix |
|--------|---------|-----|
| S-H1 | CRL response no size limit | `MAX_CRL_RESPONSE_SIZE = 20MB` |
| S-M1 | OCSP/CRL URL scheme not validated | `_validate_url()` rejects non-http/https |
| S-M5 | OCSP response no size limit | `MAX_OCSP_RESPONSE_SIZE = 1MB` |
| S-L8 | crt.sh string interpolation | httpx `params=` keyword |
| S-L9 | No redirect limit | `max_redirects=5` |
| S-L10 | CT response no size limit | `MAX_CT_RESPONSE_SIZE = 10MB` |
| C-H1, Q-BUG4, S-L5 | File handle leak | `with` statement |
| C-H2, Q-BUG3 | Private `_name` on OID | `_resolve_sig_name()` |
| C-H3 | ThreadPoolExecutor per-task | Shared executor |
| C-H4 | Deprecated `get_event_loop()` | `get_running_loop()` |
| C-H5 | `callable` type hint | `Callable` from `collections.abc` |
| C-H7 | CBOM version hardcoded | `__version__` import |
| C-M1, Q-M2, Q-BUG2 | DRY `_parse_host_port` | Delegates to `fleet.parse_target()` |
| C-L3 | DSA substring false positive | `kt == "DSA"` exact match |
| Q-BUG1, Q-M8, C-M6 | CIDR ValueError swallowed | `try/except/else` |
| C-L6 | `try/except` in test | `pytest.raises` |

---

## Round 2 Code Fixes (v0.1.1)

### Deferred Items — Now Fixed

| ID(s) | Finding | Fix Applied |
|--------|---------|-------------|
| C-M2 | DRY: chain_algos duplicated | Extracted `_build_chain_algos()` helper in cli.py |
| C-M3 | DRY: spinner duplicated | Extracted `_spinner()` context manager in cli.py |
| C-M8 | Duplicate `console` globals | cli.py imports shared console from output/terminal.py |
| C-M4 | OID map via `dir()` introspection | Explicit `_ALL_ALGORITHMS` list, `_OID_MAP` dict comprehension |
| C-M5 | `all_algorithms()` excludes KEMs | Now returns full `_ALL_ALGORITHMS` including key exchange entries |
| C-L1 | No `__all__` exports | Added to all 7 `__init__.py` files |
| C-L5 | Naive RFC 4514 parsing | `_parse_rdn_parts()` handles escaped commas |
| C-M7 | Tests import private functions | Check functions made public (no underscore prefix) |
| Q-H5 | RSA `key_size=None` silent skip | WARNING finding for missing key size |
| C-L2 | `CertInfo.cert` non-serializable | Documented, `field(default=None, repr=False)` |
| C-L4 | Redundant single-PEM strategy | Explanatory comment added |
| C-H6 | Synchronous HTTP in revocation | `check_revocation_async()` with `httpx.AsyncClient`; sync wrapper via `asyncio.run()` |

### Test Coverage Gaps — Now Filled

| ID | Test Added | File |
|----|-----------|------|
| Q-H1 | `scan_host()` — success, connection refused, timeout, TLS failure, malformed chain | tests/test_scanner.py |
| Q-H2 | `scan_file()` — valid PEM, bundle, DER, oversized, missing, empty | tests/test_scanner.py |
| Q-H3 | Revocation — OCSP good/revoked/error, CRL good/revoked/fail, CT success/empty/error | tests/test_revocation.py |
| Q-H4 | `scan_fleet()` — multiple hosts, concurrency, errors, callback | tests/test_fleet.py |
| Q-H5 | RSA `key_size=None` produces WARNING | tests/test_checks.py |
| Q-M1 | CLI integration — --json, --cbom, --no-revocation, --no-pqc, --file, exit codes | tests/test_cli.py |
| Q-M3 | `_build_json` with None pqc/revocation | tests/test_cli.py |
| Q-M4 | `run_checks` empty chain → CRITICAL finding | tests/test_checks.py |
| Q-M5 | Self-signed root CA — no false warning | tests/test_checks.py |
| Q-M6 | TLS version None → empty findings | tests/test_checks.py |
| Q-M7 | CBOM with PQC algorithm OID | tests/test_cbom.py |
| Q-M9 | SHA-1 deducts baseline point in PQC scorer | tests/test_pqc_scorer.py |
| Q-L1 | Terminal output rendering smoke tests | tests/test_cli.py |
| Q-L2 | `_cert_label` no-CN fallback | tests/test_checks.py |
| Q-L3 | `_short_cn` truncation | tests/test_checks.py |
| Q-L4 | CBOM self-signed intermediate → "root" label | tests/test_cbom.py |
| Q-L5 | `all_algorithms()` specific entries | tests/test_pqc_oids.py |
| Q-L6 | PQC grade boundaries 0-10 | tests/test_pqc_scorer.py |
| Q-L7 | OID map registry caching | tests/test_pqc_oids.py |

### Round 2 Review Findings — Fixed

| ID | Agent | Finding | Fix |
|----|-------|---------|-----|
| CQ-R1/QA-R1 | Code/QA | ~200 lines sync/async duplication in revocation checker | Removed sync internals; sync wrapper delegates to async via `asyncio.run()` |
| QA-R2/CQ-R2 | QA/Code | CT domain extraction uses naive comma split | Uses `_parse_rdn_parts()` with escaped comma support |
| CQ-R6 | Code | `build_chain_algos` public-named but internal | Renamed to `_build_chain_algos()` |
| CQ-R8 | Code | `_parse_host_port` trivial wrapper | Inlined direct call to `fleet.parse_target()` |
| QA-R6 | QA | CN extraction uses `in` not `startswith` | `startswith("CN=")` + `removeprefix("CN=")` |
| QA-R7 | QA | Unknown key types produce no finding | INFO finding for unrecognized key types |
| CQ-R4 | Code | `_ALL_ALGORITHMS` can drift from constants | Test verifying all module AlgorithmInfo instances are in list |
| CQ-R7 | Code | `_build_oid_map()` misleading docstring | Updated to "Returns the pre-built OID map" |
| QA-R5 | QA | `except (ValueError, Exception)` too broad | Narrowed to `(ValueError, TypeError, AttributeError)` |
| QA-R8 | QA | `_make_cert` type hint wrong | `key_size: int | None = 2048` |
| CQ-R13 | Code | Redundant `import pytest` in test methods | Removed |

---

## Remaining Known Limitations

These items are documented, accepted risks — either inherent to the tool's design or requiring significant infrastructure that is not justified for v1.

| ID | Severity | Finding | Rationale |
|----|----------|---------|-----------|
| S-M2 | MEDIUM | No hostname validation before TLS connection | CLI tool — operator controls input. Add if exposed as API/service. |
| S-M6 | MEDIUM | OCSP response signature not verified | Complex; common limitation across OCSP clients including OpenSSL CLI. |
| S-M7 | MEDIUM | CRL signature not verified | Same as S-M6. Would need issuer public key through call chain. |
| CQ-R3 | MEDIUM | RFC 4514 parser doesn't handle hex escapes or quoted values | Used for display labels only, not security decisions. No injection risk. |
| SEC-R14 | LOW | Response size check is post-download, not streaming | Timeout provides implicit limit. Acceptable for defined size caps. |
| S-L6 | LOW | No dependency lockfile | Recommended but not blocking for CLI distribution via PyPI. |

### Acceptable Risk — No Action Needed

| ID | Finding | Rationale |
|----|---------|-----------|
| S-M3 | Fleet SSRF via host file | Operator supplies the file — trusted input. |
| S-M4 | PEM certificates in memory/output | Public certificates, not secrets. |
| S-L1 | Port not range-checked | **FIXED in v0.2.0** — `click.IntRange(1, 65535)` |
| S-L2 | CIDR 65536 limit | Acceptable for CLI tool. |
| S-L3 | No bounds on warn_days/timeout | CLI user controls; harmless results. |
| S-L4 | No symlink protection | CLI-only; user controls paths. |
| S-L7 | Rich markup injection | Terminal-only; no exploit path. |
| S-I1–S-I6 | Informational notes | No action needed. |

---

## Review Round 2 — Full Findings Reference

### QA Agent (12 findings)

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| QA-R1 | MEDIUM | Sync/async duplication in revocation checker | **FIXED** |
| QA-R2 | MEDIUM | CT comma-split without escape handling | **FIXED** |
| QA-R3 | LOW | Terminal tests are smoke tests only | Acceptable |
| QA-R4 | LOW | Malformed chain test loose assertion | Acceptable |
| QA-R5 | LOW | `except (ValueError, Exception)` too broad | **FIXED** |
| QA-R6 | LOW | CN uses `in` not `startswith` | **FIXED** |
| QA-R7 | INFO | Unknown key types produce no finding | **FIXED** |
| QA-R8 | INFO | `_make_cert` type hint | **FIXED** |
| QA-R9 | INFO | KEM entries have empty OIDs | By design |
| QA-R10 | INFO | `all_algorithms` count assertion loose | Acceptable |
| QA-R11 | MEDIUM | Fallback chain parsing fragile | Acceptable — logic is correct |
| QA-R12 | HIGH | Test suite not independently verified | Verified: 140 passing |

### Security Agent (15 findings)

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| SEC-R1 | INFO | httpx clients properly context-managed | OK |
| SEC-R2 | INFO | Response size limits in async path | OK |
| SEC-R3 | INFO | URL validation in async path | OK |
| SEC-R4 | INFO | Redirect limits in place | OK |
| SEC-R5 | LOW | CT query safe via `params=` | OK |
| SEC-R6 | LOW | RFC 4514 handles escaped commas; hex not parsed | Accepted (display only) |
| SEC-R7 | INFO | No injection from crafted subjects | OK |
| SEC-R8 | INFO | Public check functions safe | OK |
| SEC-R9 | INFO | OID registry complete, correct | OK |
| SEC-R10 | INFO | `__all__` exports minimal, appropriate | OK |
| SEC-R11 | MEDIUM | OCSP sig not verified (S-M6) | Known limitation |
| SEC-R12 | MEDIUM | CRL sig not verified (S-M7) | Known limitation |
| SEC-R13 | MEDIUM | No hostname validation (S-M2) | CLI-acceptable |
| SEC-R14 | LOW | Size check post-download | Accepted |
| SEC-R15 | LOW | Sync wrapper event loop overhead | Not active in fleet path |

### Code Quality Agent (15 findings)

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| CQ-R1 | HIGH | Sync/async duplication (~200 lines) | **FIXED** |
| CQ-R2 | MEDIUM | CT domain extraction duplicated/naive | **FIXED** |
| CQ-R3 | MEDIUM | RFC 4514 parser incomplete | Accepted (display only) |
| CQ-R4 | MEDIUM | `_ALL_ALGORITHMS` can drift | **FIXED** (test added) |
| CQ-R5 | MEDIUM | Public API surface unclear | Acceptable — CLI-first tool |
| CQ-R6 | LOW | `build_chain_algos` should be private | **FIXED** |
| CQ-R7 | LOW | `_build_oid_map()` misleading docstring | **FIXED** |
| CQ-R8 | LOW | `_parse_host_port` trivial wrapper | **FIXED** |
| CQ-R9 | LOW | Sync wrapper ThreadPoolExecutor pattern | Acceptable with comment |
| CQ-R10 | LOW | Top-level exports only `__version__` | CLI-first; acceptable |
| CQ-R11 | INFO | Test cert factory helpers duplicated | Acceptable — test isolation |
| CQ-R12 | INFO | `all_algorithms()` called 7 times in test class | Minor |
| CQ-R13 | INFO | Redundant `import pytest` in test methods | **FIXED** |
| CQ-R14 | INFO | Type hints consistently applied | OK |
| CQ-R15 | INFO | `_OID_MAP` construction thread-safe | OK |

---

## Round 3 — Dashboard Review (v0.2.0)

Reviewed the interactive HTML dashboard (`output/dashboard.py`), CSV export, CBOM tab, print stylesheet, and CI pipeline. Two separate agents (QA and Security/Code Quality) ran independently.

### QA Agent (17 findings)

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| QA-B2-1 | HIGH | CBOM sort `data-col` indices wrong in single-host mode | **FIXED** |
| QA-B2-2 | HIGH | Fleet revocation exceptions silently swallowed | **FIXED** |
| QA-B2-3 | MEDIUM | Unused `field` import | **FIXED** |
| QA-B2-4 | MEDIUM | No ARIA attributes on tabs/filters | **FIXED** |
| QA-B2-5 | MEDIUM | `revokeObjectURL` after `removeChild` | **FIXED** |
| QA-B2-6 | MEDIUM | No test coverage for fleet revocation | Tests added |
| QA-B2-7 | MEDIUM | CBOM sort related to B2-1 | **FIXED** (same fix) |
| QA-B2-8 | MEDIUM | Overview PQC column not sortable | Acceptable |
| QA-B2-9 | LOW | Docs "zero findings" inaccuracy | **FIXED** |
| QA-B2-10 | LOW | CI no coverage reporting | Future enhancement |
| QA-B2-11 | LOW | CI no Windows matrix | Future enhancement |
| QA-B2-12 | LOW | Print doesn't expand collapsed details | **FIXED** |
| QA-B2-13 | LOW | CBOM CSV export test incomplete | Tests added |
| QA-B2-14 | LOW | Fleet CBOM drops metadata | Future enhancement |
| QA-B2-15 | LOW | Non-deterministic CBOM UUID | By design |
| QA-B2-16 | INFO | Action Items column indices | Documented |
| QA-B2-17 | INFO | Double-escape edge case in `_pill()` | **FIXED** |

### Security Agent (16 findings)

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| SEC-B2-1 | MEDIUM | Inconsistent `host_label` escaping pattern | **FIXED** |
| SEC-B2-2 | MEDIUM | CSP allows `unsafe-inline` | Accepted (required for inline JS) |
| SEC-B2-13 | MEDIUM | Double `asyncio.run()` in fleet | Accepted (correct behavior) |
| SEC-B2-3 | LOW | `crt_sh_url` not URL-encoded | Accepted (display only) |
| SEC-B2-4 | LOW | No path traversal protection in `scan_file()` | CLI tool — user controls input |
| SEC-B2-5 | LOW | No port range validation | **FIXED** (`click.IntRange`) |
| SEC-B2-6 | LOW | No concurrency upper bound | **FIXED** (`click.IntRange`) |
| SEC-B2-14 | LOW | CBOM sort column bug (dup of QA-B2-1) | **FIXED** |
| SEC-B2-16 | LOW | SSRF via redirect following in revocation | Accepted (CLI tool) |
| SEC-B2-7 | INFO | CIDR 65536 magic number | Acceptable |
| SEC-B2-8 | INFO | Error messages may expose exception details | Acceptable for CLI |
| SEC-B2-9 | INFO | `ssl.CERT_NONE` used intentionally | By design |
| SEC-B2-10 | INFO | Dependencies use `>=` pins | Standard Python convention |
| SEC-B2-11 | INFO | OCSP uses SHA-1 hash | Per RFC 6960 |
| SEC-B2-12 | INFO | `executor.shutdown(wait=False)` | Acceptable |
| SEC-B2-15 | INFO | `exportCSV` globally scoped | By design |

---

## Round 4 — Timeline, Theme, Terminal (v0.2.0)

Reviewed the certificate timeline visualization, light/dark theme toggle, and terminal output polish.

### QA Agent (14 findings)

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| QA-B3-1 | MEDIUM | Timezone-naive datetime subtraction TypeError | **FIXED** |
| QA-B3-2 | MEDIUM | Padding fallback never triggers (0.05s truthy) | **FIXED** |
| QA-B3-4 | MEDIUM | Hardcoded dark colors bypass light theme | **FIXED** |
| QA-B3-10 | MEDIUM | No test for timezone-naive cert dates | **FIXED** (test added) |
| QA-B3-3 | LOW | Timeline bar width can exceed 100% | **FIXED** (clamped) |
| QA-B3-5 | LOW | tl-label nowrap vs `<br>` | Acceptable (works in practice) |
| QA-B3-6 | LOW | Timeline shown for single-host (1 bar) | Acceptable (still useful) |
| QA-B3-8 | LOW | Flash of dark theme on light preference | **FIXED** (head init) |
| QA-B3-11 | LOW | No test for identical-date certs | Acceptable |
| QA-B3-12 | LOW | No test for all-error fleet timeline | **FIXED** (test added) |
| QA-B3-13 | LOW | No CSS variable parity test | Acceptable |
| QA-B3-14 | INFO | Inline import in function body | **FIXED** (module-level) |
| QA-B3-7 | INFO | Unicode moon/sun rendering varies | Acceptable |
| QA-B3-9 | INFO | Rich API usage correct | OK |

### Security Agent (10 findings)

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| SEC-B3-6 | MEDIUM | Percentage values unclamped | **FIXED** (clamped to [0,100]) |
| SEC-B3-1 | LOW | CSS selector injection (mitigated by _e()) | Acceptable |
| SEC-B3-5 | LOW | Inline onclick vs addEventListener | Acceptable |
| SEC-B3-8 | LOW | timedelta imported inside function | **FIXED** |
| SEC-B3-10 | LOW | Subject truncation threshold 33 vs 30 | **FIXED** |
| SEC-B3-2 | INFO | localStorage usage safe | OK |
| SEC-B3-3 | INFO | Timeline percentages from datetime math | OK |
| SEC-B3-4 | INFO | Timeline labels properly escaped | OK |
| SEC-B3-7 | INFO | Terminal column settings correct | OK |
| SEC-B3-9 | INFO | CSP well-configured | OK |

---

## Round 5 — Diff Feature (v0.2.0)

Reviewed the new `notafter diff` command for comparing scan outputs.

### QA Agent (15 findings)

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| QA-D4-1 | HIGH | Duplicate subjects silently drop certs | **FIXED** (group-based matching) |
| QA-D4-2 | HIGH | Duplicate findings silently dropped | **FIXED** (severity in key) |
| QA-D4-3 | HIGH | Baseline doesn't support stdin | Accepted (by design — documented) |
| QA-D4-4 | MEDIUM | Fleet KeyError on missing host/port | **FIXED** (`.get()` with fallback) |
| QA-D4-5 | MEDIUM | Empty subjects create false match | **FIXED** (skip empty) |
| QA-D4-6 | MEDIUM | detect_format rejects dict without `target` | **FIXED** (check chain/audit too) |
| QA-D4-7 | MEDIUM | tls_change emitted with empty strings | Acceptable |
| QA-D4-9 | MEDIUM | Unhandled JSONDecodeError | **FIXED** |
| QA-D4-10 | MEDIUM | No test for stdin input | Future enhancement |
| QA-D4-11 | LOW | Shallow copy in test | Acceptable |
| QA-D4-12 | LOW | Fleet diff is summary-only | By design (documented) |
| QA-D4-13 | LOW | No data on added/removed hosts | Future enhancement |
| QA-D4-14 | LOW | No multi-port test | **FIXED** (test added) |
| QA-D4-15 | INFO | print_diff silently returns on wrong type | Acceptable |

### Security Agent (9 findings)

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| SEC-D4-1 | MEDIUM | Rich markup injection via cert subjects | **FIXED** (`rich.markup.escape`) |
| SEC-D4-2 | MEDIUM | Rich markup injection via host field | **FIXED** (`rich.markup.escape`) |
| SEC-D4-3 | MEDIUM | No file size limit on JSON input | Accepted (CLI tool) |
| SEC-D4-4 | LOW | Unhandled JSONDecodeError | **FIXED** |
| SEC-D4-5 | LOW | Fleet KeyError on malformed entries | **FIXED** |
| SEC-D4-6 | LOW | Duplicate subjects collapse | **FIXED** |
| SEC-D4-7 | INFO | allow_dash asymmetry | By design |
| SEC-D4-8 | INFO | No malformed JSON test | **FIXED** (tests added) |
| SEC-D4-9 | INFO | No path traversal risk | OK |

---

## Appendix: CNSA 2.0 / PQC Notes

1. **PQC Scorer** — `pqc/scorer.py` grades chains on quantum readiness. Tests now cover quantum-vulnerable, quantum-safe, and hybrid scenarios, plus deprecated algorithm detection (SHA-1 baseline deduction).

2. **OID Registry** — `pqc/oids.py` uses an explicit `_ALL_ALGORITHMS` list with 35 entries. `all_algorithms()` includes key exchange entries (X25519Kyber768, X25519MLKEM768, SecP256r1MLKEM768). A guard test verifies the list stays in sync with module-level constants.

3. **OCSP/CRL Signature Verification** — S-M6 and S-M7 note that response signatures are not verified. In a post-quantum context, a quantum-capable adversary could forge revocation responses. Documented as known limitation for high-assurance environments.
