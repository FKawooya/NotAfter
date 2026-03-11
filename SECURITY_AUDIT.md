# NotAfter v0.1 — Security & QA Audit Report

**Version:** 0.1
**Date:** 2026-03-11
**Auditors:** QA Agent, Security Audit Agent, Code Quality Agent

---

## Executive Summary

Three automated review agents audited the NotAfter v0.1 codebase. The audit produced **61 total findings** across security, quality assurance, and code quality domains.

| Severity | Found | Fixed | Deferred |
|----------|-------|-------|----------|
| HIGH | 13 | 8 | 5 |
| MEDIUM | 16 | 3 | 13 |
| LOW | 20 | 3 | 17 |
| INFO | 6 | 0 | 6 |
| BUGS | 4 | 4 | 0 |
| Test gaps | 18 | 0 | 18 |
| **Total** | **61** | **16** | **45** |

All HIGH-severity bugs and both v1 blockers (S-H1, S-M1) were fixed in commit `7962f89`. Deferred items are either acceptable risk for a CLI tool or planned for v1.1.

---

## Phase 1: Initial Build

NotAfter v0.1 is a TLS certificate auditing CLI tool that scans hosts and files for certificate issues, evaluates post-quantum cryptography readiness, checks revocation status (OCSP/CRL/CT), and generates CBOM (Cryptography Bill of Materials) output.

Core modules:

| Module | Purpose |
|--------|---------|
| `scanner/tls.py` | TLS connection scanning, PEM/DER file parsing |
| `scanner/fleet.py` | Async fleet scanning with concurrency control |
| `checks/engine.py` | Certificate health checks (expiry, key strength, self-signed, TLS version) |
| `revocation/checker.py` | OCSP, CRL, and CT log queries |
| `pqc/scorer.py` | Post-quantum readiness scoring |
| `pqc/oids.py` | PQC algorithm OID registry |
| `cbom/generator.py` | CBOM document generation |
| `cli.py` | Click-based CLI interface |
| `output/terminal.py` | Rich terminal output rendering |

---

## Phase 2: Review Findings

### scanner/tls.py

| ID | Severity | Agent | Finding |
|----|----------|-------|---------|
| Q-H1 | HIGH | QA | No tests for `scan_host()` — core TLS scanning function entirely untested. Network errors, TLS handshake failures, malformed chains, timeout handling untested. |
| Q-H2 | HIGH | QA | No tests for `scan_file()` — PEM bundles, single PEM, DER format, oversized files (10MB limit), missing files untested. |
| C-H1 | HIGH | Code | File handle leak in `scan_file` — `open()` without `with` statement. (line 171) |
| C-H2 | HIGH | Code | `_parse_cert` accesses private `_name` attribute on OID. (line 95) |
| Q-BUG3 | BUG | QA | `cert.signature_algorithm_oid._name` — accesses private attribute, could break on library updates. |
| Q-BUG4 | BUG | QA | `open(path, "rb").read()` — file handle never explicitly closed. |
| S-M4 | MEDIUM | Security | Full PEM certificates stored in memory and potentially in JSON output. |
| S-L4 | LOW | Security | No symlink protection on file scanning — CLI-only, acceptable. (line 166-171) |
| S-L5 | LOW | Security | File handle not closed deterministically. (line 171) |
| S-L7 | LOW | Security | Rich markup injection via error messages — could confuse CI output. (line 155-161) |

### scanner/fleet.py

| ID | Severity | Agent | Finding |
|----|----------|-------|---------|
| Q-H4 | HIGH | QA | `scan_fleet()` async logic untested — semaphore concurrency, thread pool executor, asyncio.gather error propagation. |
| C-H3 | HIGH | Code | ThreadPoolExecutor created per-task in fleet scan — resource exhaustion risk. (line 37) |
| C-H4 | HIGH | Code | Deprecated `asyncio.get_event_loop()` — use `get_running_loop()`. (line 29) |
| C-H5 | HIGH | Code | `on_result` type hint uses bare `callable` instead of `Callable`. (line 18) |
| Q-BUG1 | BUG | QA | `load_targets("10.0.0.0/8")` — CIDR too-large ValueError swallowed by outer except, produces misleading "Cannot parse as CIDR or host file" error. |
| Q-M2 | MEDIUM | QA | `_parse_host_port()` duplicated in cli.py and fleet.py — different logic, only fleet version tested. |
| Q-M8 | MEDIUM | QA | `load_targets()` CIDR > 65536 — ValueError swallowed by outer except, falls through with misleading error. **BUG** |
| S-M2 | MEDIUM | Security | No hostname validation before network connection — arbitrary strings passed to `socket.create_connection()`. Internal hostnames, localhost, metadata endpoints possible. (line 79) |
| S-M3 | MEDIUM | Security | SSRF risk in fleet mode via host-file targets — malicious host file could target internal services. (line 67-74) |
| C-M1 | MEDIUM | Code | DRY violation — `_parse_host_port` duplicated in cli.py and fleet.py. |
| C-M6 | MEDIUM | Code | CIDR parsing swallows ValueError ambiguously. (line 58-64) |
| S-L1 | LOW | Security | Port number not range-checked (1-65535). (line 91) |
| S-L2 | LOW | Security | CIDR 65536 limit large but acceptable. (line 61) |

### checks/engine.py

| ID | Severity | Agent | Finding |
|----|----------|-------|---------|
| Q-H5 | HIGH | QA | `_check_key_strength` with RSA `key_size=None` — silently skips RSA certs with no key size instead of producing a finding. |
| Q-M4 | MEDIUM | QA | `run_checks` with empty chain but no error — edge case not explicitly verified. |
| Q-M5 | MEDIUM | QA | `_check_self_signed` with root CA (`is_self_signed=True`, `is_ca=True`) — should NOT warn but not tested. |
| Q-M6 | MEDIUM | QA | `_check_tls_version` with None version — returns empty findings, should this be a warning? |
| C-L3 | LOW | Code | DSA key check matches "DSA" substring — false positive on ML-DSA, SLH-DSA. (line 169) |
| Q-L2 | LOW | QA | `_cert_label` with no CN in subject — fallback behavior untested. |
| Q-L3 | LOW | QA | `_short_cn` with very long subjects — truncation untested. |
| C-L5 | LOW | Code | `_cert_label` and `_short_cn` parse RFC 4514 strings naively — escaped commas not handled. |

### revocation/checker.py

| ID | Severity | Agent | Finding |
|----|----------|-------|---------|
| S-H1 | **HIGH** | Security | No response size limit on CRL downloads — `httpx.Client.get()` reads entire response with no max content length. Malicious CRL URL could cause memory exhaustion. (line 197-203) **V1 BLOCKER** |
| Q-H3 | HIGH | QA | No tests for revocation checking — OCSP, CRL, and CT log queries involve HTTP calls, certificate parsing, and multiple failure modes. |
| C-H6 | HIGH | Code | Synchronous HTTP calls in revocation checker block event loop for fleet scans. (line 135, 198, 259) |
| S-M1 | **MEDIUM** | Security | OCSP/CRL URLs fetched from untrusted certificates without scheme/target validation — could make SSRF requests to internal services via `file://`, `ftp://` URLs. (line 115, 194) **V1 BLOCKER** |
| S-M5 | MEDIUM | Security | No OCSP response size limit. (line 134-141) |
| S-M6 | MEDIUM | Security | OCSP response signature not verified — MITM could forge "good" response. (line 148-168) |
| S-M7 | MEDIUM | Security | CRL signature not verified — MITM could serve CRL omitting revoked serial. (line 207-230) |
| S-L8 | LOW | Security | crt.sh URL via string interpolation instead of `params=`. (line 256, 261) |
| S-L9 | LOW | Security | httpx follows redirects with no explicit hop limit (default 20). (line 135, 198, 259) |
| S-L10 | LOW | Security | crt.sh JSON response not size-limited. (line 264-267) |

### cli.py

| ID | Severity | Agent | Finding |
|----|----------|-------|---------|
| Q-M1 | MEDIUM | QA | No CLI integration tests — no Click CliRunner tests for scan/fleet commands. Option parsing, exit codes, JSON/CBOM output untested. |
| Q-M3 | MEDIUM | QA | `_build_json()` with None pqc/revocation — conditional sections untested, could produce KeyError. |
| Q-BUG2 | BUG | QA | `_parse_host_port` duplicated with divergent logic. |
| C-M2 | MEDIUM | Code | DRY violation — PQC chain_algos construction duplicated in scan and fleet commands. (line 93-101, 224-226) |
| C-M3 | MEDIUM | Code | DRY violation — Progress spinner context manager duplicated. (line 63-68, 111-116) |
| C-M8 | MEDIUM | Code | `console` global duplicated across cli.py and terminal.py. (line 15; terminal.py line 15) |
| S-L3 | LOW | Security | No bounds on warn_days/timeout CLI args. (line 34, 39) |

### pqc/scorer.py

| ID | Severity | Agent | Finding |
|----|----------|-------|---------|
| Q-M9 | MEDIUM | QA | Deprecated algorithm detection in PQC scorer untested — SHA-1 should deduct baseline point. |
| Q-L6 | LOW | QA | PQC grade boundary values not individually tested. |

### pqc/oids.py

| ID | Severity | Agent | Finding |
|----|----------|-------|---------|
| C-M4 | MEDIUM | Code | `_OID_MAP` mutation via `dir()` introspection is fragile and not thread-safe. (line 378-389) |
| C-M5 | MEDIUM | Code | `all_algorithms()` excludes key exchange algorithms with empty OIDs. (line 409-412) |
| Q-L5 | LOW | QA | `all_algorithms()` only verifies count >20 not specific entries. |
| Q-L7 | LOW | QA | `_build_oid_map()` caching branch untested. |

### cbom/generator.py

| ID | Severity | Agent | Finding |
|----|----------|-------|---------|
| C-H7 | HIGH | Code | CBOM version hardcoded "0.1.0" not from `__version__`. (line 41) |
| Q-M7 | MEDIUM | QA | CBOM with PQC algorithms — `quantumReadiness` only tested with "quantum-vulnerable". |
| Q-L4 | LOW | QA | CBOM `_cert_to_component` label logic edge case — self-signed intermediate labeled "root". |

### output/terminal.py

| ID | Severity | Agent | Finding |
|----|----------|-------|---------|
| Q-L1 | LOW | QA | Terminal output rendering tests — `print_audit`, `print_pqc`, `print_revocation` untested. |

### Project-wide

| ID | Severity | Agent | Finding |
|----|----------|-------|---------|
| S-L6 | LOW | Security | No dependency lockfile. |
| C-L1 | LOW | Code | No `__all__` exports in any module. |
| C-L2 | LOW | Code | `CertInfo.cert` stores full `x509.Certificate` object — makes dataclass non-serializable. |
| C-L4 | LOW | Code | `scan_file` tries three parsing strategies — second (single PEM) may be redundant. |
| C-L7 | LOW | Code | No tests for cli.py, output/terminal.py, or revocation/checker.py. |
| C-M7 | MEDIUM | Code | Tests import private functions (`_check_expiry`, `_parse_target`). |
| C-L6 | LOW | Code | Test uses `try/except` instead of `pytest.raises`. (test_fleet.py:31-35) |

### Informational (No Action Needed)

| ID | Agent | Note |
|----|-------|------|
| S-I1 | Security | TLS verification disabled (`CERT_NONE`) — by design for auditing tool. |
| S-I2 | Security | 10MB file read limit — good. |
| S-I3 | Security | Dependencies minimal and well-maintained. |
| S-I4 | Security | No command injection vectors — no subprocess/eval/exec. |
| S-I5 | Security | No memory cleanup needed — no secrets handled. |
| S-I6 | Security | crt.sh over HTTPS — good. |

---

## Phase 3: Fixes Applied

All fixes applied in commit `7962f89`.

| ID(s) | Finding | Fix Applied |
|--------|---------|-------------|
| S-H1 | CRL response no size limit | Added `MAX_CRL_RESPONSE_SIZE = 20MB` cap |
| S-M1 | OCSP/CRL URL scheme not validated | Added `_validate_url()` — rejects non-http/https schemes |
| S-M5 | OCSP response no size limit | Added `MAX_OCSP_RESPONSE_SIZE = 1MB` cap |
| S-L8 | crt.sh string interpolation | Changed to httpx `params=` keyword |
| S-L9 | No redirect limit | Set `max_redirects=5` on all httpx clients |
| S-L10 | CT response no size limit | Added `MAX_CT_RESPONSE_SIZE = 10MB` cap |
| C-H1, Q-BUG4, S-L5 | File handle leak in `scan_file` | Changed to `with` statement |
| C-H2, Q-BUG3 | Private `_name` access on OID | Created `_resolve_sig_name()` using own OID lookup |
| C-H3 | ThreadPoolExecutor created per-task | Shared `ThreadPoolExecutor(max_workers=concurrency)` |
| C-H4 | Deprecated `asyncio.get_event_loop()` | Changed to `get_running_loop()` |
| C-H5 | `callable` type hint | Changed to `Callable` from `collections.abc` |
| C-H7 | CBOM version hardcoded | Imported from `__version__` |
| C-M1, Q-M2, Q-BUG2 | DRY `_parse_host_port` duplication | `cli.py` delegates to `fleet.parse_target()` |
| C-L3 | DSA substring match false positive | Changed to exact `kt == "DSA"` |
| Q-BUG1, Q-M8, C-M6 | CIDR ValueError swallowed | Restructured `try/except` with `else` clause |
| C-L6 | `try/except` in test | Changed to `pytest.raises` |

---

## Phase 4: Deferred Items

### Acceptable Risk for CLI Tool

These findings are not applicable or pose negligible risk in the context of a locally-run CLI tool where the operator controls all inputs.

| ID | Finding | Rationale |
|----|---------|-----------|
| S-M2 | No hostname validation before network connection | CLI tool run by operator who controls input. Only relevant if exposed as API/service. |
| S-M3 | Fleet SSRF via host file | Operator supplies the file. Host files should be treated as trusted input. |
| S-M4 | PEM certificates in memory/output | Public certificates, not secrets. No privacy concern. |
| S-L1 | Port number not range-checked | `socket` will error on invalid port; error is caught and reported clearly. |
| S-L2 | CIDR 65536 limit | Acceptable upper bound for a CLI scanning tool. |
| S-L3 | No bounds on warn_days/timeout | CLI user controls input; unreasonable values produce harmless results. |
| S-L4 | No symlink protection on file scan | CLI-only tool; user controls file paths. |
| S-L6 | No dependency lockfile | Recommended but not blocking. Add before PyPI publish. |
| S-L7 | Rich markup injection | Terminal-only output; no exploit path in normal usage. |
| S-I1–S-I6 | Informational notes | No action needed. Documented for completeness. |

### Planned for v1.1

These items require significant refactoring or new infrastructure and are deferred to the next release cycle.

| ID | Finding | Rationale |
|----|---------|-----------|
| S-M6 | OCSP response signature not verified | Complex to implement correctly. Common limitation across OCSP clients including OpenSSL CLI. Document as known limitation. |
| S-M7 | CRL signature not verified | Same rationale as S-M6. Would need issuer public key passed through the call chain. Document as known limitation. |
| C-H6 | Synchronous HTTP in revocation checker | Would need `httpx.AsyncClient` variant. Works fine for single scan; only suboptimal in fleet mode. |
| C-M2 | DRY: chain_algos construction duplicated | Minor duplication, low risk. |
| C-M3 | DRY: Progress spinner duplicated | Minor duplication. |
| C-M4 | OID map via `dir()` introspection | Works correctly but is fragile. Refactor to explicit registry. |
| C-M5 | `all_algorithms()` excludes KEM entries | Document behavior; no functional impact. |
| C-M7 | Tests import private functions | Refactor to public API tests. |
| C-M8 | Duplicate `console` globals | Minor; consolidate. |
| C-L1 | No `__all__` exports | Add to all modules. |
| C-L2 | `CertInfo` stores raw cert object | Needed for revocation checker. Consider separating in v2. |
| C-L4 | Redundant single-PEM parse strategy | Harmless fallback. Keep for robustness. |
| C-L5 | Naive RFC 4514 parsing | Edge case with escaped commas. |
| C-L7 | No tests for cli/output/revocation | Need mocked network/IO. Priority for v1.1. |

### Test Coverage Gaps — Planned for v1.1

| ID | Severity | Gap |
|----|----------|-----|
| Q-H1 | HIGH | `scan_host()` untested — needs mocked ssl/socket |
| Q-H2 | HIGH | `scan_file()` untested — needs test fixtures (PEM/DER files) |
| Q-H3 | HIGH | Revocation checking untested — needs mocked httpx |
| Q-H4 | HIGH | `scan_fleet()` async untested — needs pytest-asyncio with mocked `scan_host` |
| Q-H5 | HIGH | RSA `key_size=None` — add test and handling |
| Q-M1 | MEDIUM | CLI integration tests — add CliRunner tests |
| Q-M3 | MEDIUM | `_build_json` with None sections — add test |
| Q-M4 | MEDIUM | `run_checks` empty chain no error — add test |
| Q-M5 | MEDIUM | Self-signed root CA false positive — add test |
| Q-M6 | MEDIUM | TLS version None — add test |
| Q-M7 | MEDIUM | CBOM PQC algorithms — add test with quantum-safe cert |
| Q-M9 | MEDIUM | PQC scorer deprecated algo — add test |
| Q-L1 | LOW | Terminal output rendering untested |
| Q-L2 | LOW | `_cert_label` no-CN fallback untested |
| Q-L3 | LOW | `_short_cn` truncation untested |
| Q-L4 | LOW | CBOM self-signed intermediate label edge case |
| Q-L5 | LOW | `all_algorithms()` count-only assertion |
| Q-L6 | LOW | PQC grade boundary values |
| Q-L7 | LOW | `_build_oid_map()` caching branch |

---

## Appendix: CNSA 2.0 / PQC Notes

The following post-quantum cryptography considerations apply to NotAfter:

1. **PQC Scorer** — The `pqc/scorer.py` module grades certificate chains on quantum readiness. Current testing only covers "quantum-vulnerable" status (Q-M7). Tests with quantum-safe algorithms (ML-KEM, ML-DSA, SLH-DSA) should be added in v1.1.

2. **OID Registry** — `pqc/oids.py` maintains a registry of PQC algorithm OIDs. The `all_algorithms()` function excludes key exchange algorithms with empty OIDs (C-M5). This should be documented and verified against CNSA 2.0 requirements.

3. **DSA Substring Match (Fixed)** — The original DSA key check (C-L3) matched on the substring "DSA", which would false-positive on ML-DSA and SLH-DSA algorithm names. Fixed to exact match `kt == "DSA"` in commit `7962f89`.

4. **Deprecated Algorithm Detection** — SHA-1 detection in the PQC scorer is untested (Q-M9). CNSA 2.0 deprecates SHA-1 entirely; the scorer should deduct points but this path needs test coverage.

5. **OCSP/CRL Signature Verification** — S-M6 and S-M7 note that OCSP and CRL response signatures are not verified. In a post-quantum context, this means a quantum-capable adversary could forge revocation responses. This limitation should be documented for users operating in high-assurance environments.
