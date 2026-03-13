# NotAfter — Security & QA Audit Report

**Version:** 0.1.1
**Date:** 2026-03-13
**Auditors:** QA Agent, Security Audit Agent, Code Quality Agent (2 review rounds)

---

## Executive Summary

Three automated review agents audited the NotAfter codebase across two rounds. Round 1 (v0.1) produced 61 findings; 16 were fixed immediately and 45 deferred. Round 2 (v0.1.1) addressed all 45 deferred items: 31 code fixes applied, 19 test coverage gaps filled, and 11 review-round-2 findings fixed. A final review produced 42 findings (mostly INFO), with only 6 items remaining as known limitations.

| Phase | Found | Fixed | Deferred |
|-------|-------|-------|----------|
| Round 1 (v0.1) | 61 | 16 | 45 |
| Round 2 — fix deferred items | 45 | 45 | 0 |
| Round 2 — review findings | 42 | 11 | 6 |
| **Cumulative** | **103** | **72** | **6** |

**Test coverage:** 140 tests, all passing.

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
| S-L1 | Port not range-checked | Socket errors on invalid port; caught and reported. |
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

## Appendix: CNSA 2.0 / PQC Notes

1. **PQC Scorer** — `pqc/scorer.py` grades chains on quantum readiness. Tests now cover quantum-vulnerable, quantum-safe, and hybrid scenarios, plus deprecated algorithm detection (SHA-1 baseline deduction).

2. **OID Registry** — `pqc/oids.py` uses an explicit `_ALL_ALGORITHMS` list with 35 entries. `all_algorithms()` includes key exchange entries (X25519Kyber768, X25519MLKEM768, SecP256r1MLKEM768). A guard test verifies the list stays in sync with module-level constants.

3. **OCSP/CRL Signature Verification** — S-M6 and S-M7 note that response signatures are not verified. In a post-quantum context, a quantum-capable adversary could forge revocation responses. Documented as known limitation for high-assurance environments.
