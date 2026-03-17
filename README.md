# notafter

**One command. Full certificate audit. Quantum readiness score.**

Most PKI tools do one thing. `notafter` does four: certificate linting, revocation checking, post-quantum readiness scoring, and cryptographic inventory -- all from a single CLI. No browser extensions, no SaaS dashboards, no stitching five tools together.

```
pip install notafter
notafter scan example.com
```

---

## Why this exists

Certificate misconfigurations cause roughly 30% of production TLS outages. The NSA's CNSA 2.0 timeline gives you until 2030-2035 to migrate to quantum-resistant cryptography. Today, getting a complete picture requires:

- `openssl s_client` for chain inspection
- `certigo` or `zlint` for linting
- Manual OCSP/CRL checks for revocation
- No tooling at all for PQC readiness
- No standard way to inventory cryptographic assets

**notafter replaces all of that with one command that returns a score.**

---

## What you get

```
$ notafter scan github.com
```
```
                    Certificate Audit: github.com:443
 ┌──────┬────────────────┬────────────────────────────────┬─────────────────────────┐
 │      │ Check          │ Component                      │ Finding                 │
 ├──────┼────────────────┼────────────────────────────────┼─────────────────────────┤
 │ PASS │ expiry         │ CN=github.com                  │ Valid for 287 more days. │
 │ PASS │ key_strength   │ CN=github.com                  │ EC-secp256r1: good key. │
 │ PASS │ signature      │ CN=github.com                  │ Signature: ECDSA-SHA384 │
 │ PASS │ san            │ CN=github.com                  │ SAN present: github.com │
 │ PASS │ chain          │ Chain                          │ Chain has 3 certs.      │
 │ PASS │ tls_version    │ TLS                            │ TLSv1.3 (optimal).      │
 └──────┴────────────────┴────────────────────────────────┴─────────────────────────┘

  0 critical  0 warnings  6 passed

 ╭─ PQC Readiness Score: 2/10 (Grade: F)  Status: VULNERABLE ─────────────────╮
 │  Component          │ Algorithm              │ Quantum Safety │ Points      │
 │  TLS version        │ TLSv1.3                │ VULNERABLE     │ 1/1         │
 │  Key exchange       │ ECDHE (TLS 1.3)        │ VULNERABLE     │ 0/3         │
 │  Leaf (EC)          │ ECDSA-with-SHA384      │ VULNERABLE     │ 0/2         │
 │  Intermediate (RSA) │ SHA384WithRSA          │ VULNERABLE     │ 0/0         │
 │  Root (RSA)         │ SHA256WithRSA          │ VULNERABLE     │ 0/0         │
 ╰─────────────────────────────────────────────────────────────────────────────╯

  CNSA 2.0: NOT COMPLIANT
  Next deadline (295 days): Software/firmware signing must support CNSA 2.0

  Recommendations:
  > CRITICAL: No quantum protection. Begin PQC migration planning now.
  > Enable X25519MLKEM768 hybrid key exchange.
  > Migrate to ML-DSA-65 or composite (ML-DSA-65 + EC-secp256r1).

                         Revocation Status
 ┌────────┬────────────┬──────────────────────────────────────────┐
 │ Method │ Status     │ Details                                  │
 ├────────┼────────────┼──────────────────────────────────────────┤
 │ OCSP   │ GOOD       │ Certificate is not revoked (OCSP)        │
 │ CRL    │ GOOD       │ Certificate not found in CRL             │
 │ CT     │ LOGGED     │ Found 1847 CT log entries for github.com │
 └────────┴────────────┴──────────────────────────────────────────┘
```

One command. Seven checks. PQC score. Revocation status. Done.

---

## Install

```bash
pip install notafter
```

Requires Python 3.10+. No external binaries, no OpenSSL CLI, no root access.

---

## Commands

### `notafter scan` -- single host or file

```bash
# Full audit: lint + revocation + PQC
notafter scan example.com

# Non-standard port
notafter scan example.com:8443

# Certificate file (PEM or DER)
notafter scan --file cert.pem

# JSON output (for CI/CD pipelines)
notafter scan example.com --json

# CycloneDX CBOM (cryptographic bill of materials)
notafter scan example.com --cbom > inventory.json

# Skip specific checks
notafter scan example.com --no-revocation
notafter scan example.com --no-pqc

# Custom warning threshold and timeout
notafter scan example.com --warn-days 60 --timeout 15
```

**All `scan` flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--file` | | off | Treat TARGET as a file path instead of a hostname |
| `--port` | `-p` | 443 | TLS port |
| `--warn-days` | `-w` | 30 | Days before expiry to raise a warning |
| `--json` | | off | Output JSON instead of rich terminal tables |
| `--cbom` | | off | Output CycloneDX 1.6 CBOM (implies JSON) |
| `--html` | | off | Output interactive HTML dashboard (see [UI docs](docs/UI.md)) |
| `--no-revocation` | | off | Skip OCSP, CRL, and CT checks |
| `--no-pqc` | | off | Skip PQC readiness assessment |
| `--timeout` | `-t` | 10.0 | Connection timeout in seconds |

### `notafter fleet` -- bulk scanning

Scan hundreds of hosts from a file or CIDR range with async concurrency.

```bash
# Host list (one per line, supports host:port, # comments)
notafter fleet hosts.txt

# CIDR range (up to /16)
notafter fleet 10.0.0.0/24

# JSON report for all hosts
notafter fleet hosts.txt --json > report.json

# Fleet-wide cryptographic inventory
notafter fleet hosts.txt --cbom > fleet-cbom.json

# Crank up concurrency
notafter fleet hosts.txt --concurrency 100 --timeout 5
```

```
$ notafter fleet internal-hosts.txt
Scanning 12 hosts (concurrency: 50)...
  [1/12]  app1.internal:443 OK
  [2/12]  app2.internal:443 OK
  [3/12]  db.internal:5432  OK
  ...

                         Fleet Scan Results
 ┌────────────────────────────────┬──────┬──────┬──────┬──────────┬──────────┐
 │ Host                           │ TLS  │ Crit │ Warn │ PQC      │ Status   │
 ├────────────────────────────────┼──────┼──────┼──────┼──────────┼──────────┤
 │ app1.internal:443              │ 1.3  │  0   │  0   │ 2/10 F   │ CLEAN    │
 │ app2.internal:443              │ 1.3  │  0   │  1   │ 2/10 F   │ WARNING  │
 │ db.internal:5432               │ 1.2  │  1   │  0   │ 1/10 F   │ CRITICAL │
 │ legacy.internal:443            │ 1.0  │  2   │  1   │ 0/10 F   │ CRITICAL │
 └────────────────────────────────┴──────┴──────┴──────┴──────────┴──────────┘

  Total: 12 hosts scanned  3 critical  2 warnings
```

**All `fleet` flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--port` | `-p` | 443 | Default TLS port |
| `--concurrency` | `-c` | 50 | Max concurrent connections |
| `--timeout` | `-t` | 10.0 | Per-host timeout in seconds |
| `--warn-days` | `-w` | 30 | Days before expiry to warn |
| `--json` | | off | Output JSON |
| `--html` | | off | Output interactive HTML dashboard (see [UI docs](docs/UI.md)) |
| `--cbom` | | off | Output fleet-wide CycloneDX CBOM |
| `--no-revocation` | | off | Skip revocation checks |
| `--no-pqc` | | off | Skip PQC assessment |

---

### `notafter diff` -- compare scans

Compare two JSON scan outputs to see what changed.

```bash
# Save a baseline
notafter scan example.com --json > baseline.json

# Later, diff against a new scan
notafter scan example.com --json > current.json
notafter diff baseline.json current.json

# JSON output (for CI/CD)
notafter diff baseline.json current.json --json

# Fleet diff
notafter fleet hosts.txt --json > baseline.json
notafter diff baseline.json current.json
```

```
$ notafter diff baseline.json current.json
  1 change(s): 1 changed

                         Diff Results
 ┌────────────────┬──────────┬────────────────────────────┐
 │ Host           │ Status   │ Changes                    │
 ├────────────────┼──────────┼────────────────────────────┤
 │ example.com:443│ CHANGED  │ Renewed: CN=example.com    │
 │                │          │   (2026-04-27 -> 2027-12-31)│
 │                │          │ PQC: 2/10 F -> 7/10 B      │
 └────────────────┴──────────┴────────────────────────────┘
```

**Diff exit codes:** 0 = no changes, 1 = changes detected.

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | All checks passed |
| `1` | Warnings found |
| `2` | Critical issues or connection errors |

Use exit codes in CI/CD to gate deployments:

```bash
notafter scan production.example.com --json || exit 1
```

---

## PQC readiness scoring

Every scan produces a quantum readiness score from **0 to 10**. The score is a weighted composite of six factors:

| Factor | Points | What earns full marks |
|--------|--------|----------------------|
| TLS version | 1 | TLS 1.3 (required for PQC KEMs) |
| Key exchange | 3 | Hybrid PQC KEM (e.g., X25519MLKEM768) |
| Leaf certificate | 2 | PQC or hybrid signature (ML-DSA, composite) |
| Chain certificates | 2 | All intermediates/root use PQC signatures |
| Clean baseline | 1 | No deprecated algorithms (SHA-1, MD5, DSA) |
| CNSA 2.0 compliance | 1 | All algorithms on the CNSA 2.0 approved list |

**Grades:**

| Score | Grade | Interpretation |
|-------|-------|----------------|
| 9-10 | **A** | Quantum-safe. PQC algorithms deployed. |
| 7-8 | **B** | Hybrid protection. Migration underway. |
| 5-6 | **C** | Partial. TLS 1.3 but no PQC algorithms yet. |
| 3-4 | **D** | Minimal. Significant work remaining. |
| 0-2 | **F** | No quantum protection. Start planning now. |

### Supported PQC algorithms

**NIST standards (FIPS 203/204/205):**
- **ML-DSA** (Dilithium): ML-DSA-44, ML-DSA-65, ML-DSA-87 -- lattice-based signatures
- **SLH-DSA** (SPHINCS+): 12 variants (SHA2/SHAKE, 128/192/256, s/f) -- hash-based signatures
- **ML-KEM** (Kyber): ML-KEM-512, ML-KEM-768, ML-KEM-1024 -- lattice-based key encapsulation

**IETF composite/hybrid (LAMPS WG drafts):**
- MLDSA65-RSA3072-PSS, MLDSA65-ECDSA-P256, MLDSA65-Ed25519
- MLDSA87-ECDSA-P384, MLDSA87-Ed448

**TLS hybrid key exchange:**
- X25519Kyber768Draft00, X25519MLKEM768, SecP256r1MLKEM768

---

## CNSA 2.0 deadlines

notafter tracks compliance against the NSA's CNSA 2.0 migration timeline and shows days remaining to each milestone:

| Deadline | Requirement |
|----------|-------------|
| **End of 2025** | Software/firmware signing must *support* CNSA 2.0 |
| **End of 2026** | Networking equipment must *support* CNSA 2.0 |
| **2027** | New NSS acquisitions must be CNSA 2.0 compliant |
| **2030** | Software signing + networking *exclusively* CNSA 2.0 |
| **2033** | Web browsers/servers *exclusively* CNSA 2.0 |
| **2035** | All National Security Systems fully quantum-resistant |

These are not suggestions. They are federally mandated deadlines for national security systems.

---

## Cryptographic Bill of Materials (CBOM)

Generate a machine-readable inventory of every cryptographic asset in a TLS connection, following the [CycloneDX 1.6](https://cyclonedx.org/) specification:

```bash
notafter scan example.com --cbom | jq '.components[0].cryptoProperties'
```

```json
{
  "assetType": "certificate",
  "algorithmProperties": {
    "algorithm": "EC-secp256r1",
    "keySize": 256,
    "signatureAlgorithm": "ECDSA-with-SHA256",
    "signatureAlgorithmOID": "1.2.840.10045.4.3.2"
  },
  "certificateProperties": {
    "subjectName": "CN=example.com",
    "issuerName": "CN=DigiCert SHA2 Extended Validation Server CA",
    "notBefore": "2024-01-15T00:00:00+00:00",
    "notAfter": "2025-01-15T23:59:59+00:00",
    "subjectAlternativeNames": ["example.com", "www.example.com"],
    "isSelfSigned": false,
    "isCA": false
  },
  "quantumReadiness": "quantum-vulnerable"
}
```

Fleet-wide CBOM aggregates all hosts into a single inventory -- useful for enterprise cryptographic asset management and compliance reporting.

---

## Checks reference

notafter runs seven checks on every certificate in the chain:

| Check | Severity | What it catches |
|-------|----------|-----------------|
| **expiry** | CRIT/WARN/PASS | Expired, not-yet-valid, expiring within `--warn-days` |
| **key_strength** | CRIT/WARN/PASS | RSA < 2048 (crit), RSA < 3072 (warn), DSA (crit) |
| **signature** | CRIT/PASS | SHA-1, MD5, MD2 signatures |
| **san** | WARN/INFO/PASS | Missing SAN, wildcard detection |
| **self_signed** | WARN | Leaf certificate is self-signed |
| **chain** | WARN/PASS | Missing intermediates |
| **tls_version** | CRIT/WARN/PASS | SSLv3/TLS 1.0 (crit), TLS 1.1 (warn) |

Revocation checks (run separately unless `--no-revocation`):

| Method | What it does |
|--------|-------------|
| **OCSP** | Builds and sends OCSP request to the AIA responder |
| **CRL** | Downloads CRL from distribution points, checks serial |
| **CT** | Queries crt.sh for Certificate Transparency log entries |

---

## Architecture

```
notafter/
  cli.py                    # Click CLI — scan and fleet commands
  scanner/
    tls.py                  # TLS connection, cert chain extraction, PEM/DER parsing
    fleet.py                # Async fleet scanner, CIDR/file loader, concurrency control
  checks/
    engine.py               # 7 lint checks: expiry, key, sig, SAN, self-signed, chain, TLS
  pqc/
    oids.py                 # 40+ algorithm OID database (NIST FIPS 203/204/205, IETF LAMPS)
    scorer.py               # 0-10 scoring model, CNSA 2.0 milestone tracking
  revocation/
    checker.py              # OCSP, CRL download+parse, crt.sh CT lookup
  diff.py                    # Scan diff engine — compare two JSON outputs
  cbom/
    generator.py            # CycloneDX 1.6 CBOM generation
  output/
    terminal.py             # Rich tables, panels, color-coded findings
    dashboard.py            # Interactive HTML dashboard (single-file, inline CSS/JS)
```

Key design decisions:
- **Pure Python** -- no shelling out to `openssl`, no C extensions beyond `cryptography`
- **Async fleet scanning** -- `asyncio` + `ThreadPoolExecutor` for I/O-bound TLS connections
- **Structured output** -- every finding has severity, component, message, and remediation
- **Exit codes** -- machine-readable results for CI/CD integration
- **OID database** -- covers NIST PQC standards, IETF composite drafts, and all common classical algorithms

---

## License

MIT

---

Built by [Fred Kawooya](https://github.com/FKawooya).
