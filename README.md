# notafter

**The last certificate problem you didn't see coming.**

PKI certificate auditor with PQC readiness scoring. Scans live hosts or certificate files, runs lint checks, verifies revocation status, and tells you how ready you are for post-quantum cryptography — all in one command.

```
$ notafter scan example.com
```

## The problem

Certificate misconfigurations cause ~30% of production TLS outages. Post-quantum migration deadlines are 18 months away. Today you need 5 different tools to get a complete picture. notafter gives you one.

## What it checks

| Category | Checks |
|----------|--------|
| **Certificate hygiene** | Expiry, key strength, signature algorithm, SAN, self-signed, chain completeness |
| **TLS configuration** | Protocol version, cipher suite, forward secrecy |
| **Revocation** | OCSP, CRL, Certificate Transparency logs — all in one pass |
| **PQC readiness** | Algorithm classification, readiness score (0-10), CNSA 2.0 compliance |
| **Inventory** | CycloneDX CBOM (Cryptographic Bill of Materials) generation |

## Install

```bash
pip install notafter
```

Requires Python 3.10+. No external binaries needed.

## Usage

### Single host audit

```bash
# Full audit (lint + revocation + PQC)
notafter scan example.com

# Custom port
notafter scan example.com:8443

# From certificate file
notafter scan --file cert.pem

# JSON output for CI/CD
notafter scan example.com --json

# Generate CBOM
notafter scan example.com --cbom > inventory.json

# Skip revocation or PQC checks
notafter scan example.com --no-revocation
notafter scan example.com --no-pqc
```

### Fleet scanning

```bash
# From a host list (one per line)
notafter fleet hosts.txt

# From CIDR range
notafter fleet 10.0.0.0/24

# JSON report
notafter fleet hosts.txt --json > report.json

# Fleet-wide CBOM
notafter fleet hosts.txt --cbom > fleet-inventory.json

# Control concurrency
notafter fleet hosts.txt --concurrency 100
```

## PQC Readiness Scoring

Every scan includes a quantum readiness score from 0-10:

| Score | Grade | Meaning |
|-------|-------|---------|
| 9-10 | A | Quantum-safe. PQC algorithms in use. |
| 7-8 | B | Hybrid protection. Migration in progress. |
| 5-6 | C | Partial. TLS 1.3 ready but no PQC algorithms. |
| 3-4 | D | Minimal. Significant migration needed. |
| 0-2 | F | No quantum protection. |

Scoring factors: TLS 1.3 support, hybrid key exchange (X25519MLKEM768), PQC signature algorithms (ML-DSA, SLH-DSA), chain-wide PQC, clean baseline (no deprecated algorithms), CNSA 2.0 compliance.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed |
| 1 | Warnings found |
| 2 | Critical issues found |

## CNSA 2.0 Timeline

notafter tracks your compliance against NSA CNSA 2.0 deadlines:

- **2027**: New acquisitions must be CNSA 2.0 compliant
- **2030**: Software signing + networking exclusively CNSA 2.0
- **2033**: Web browsers/servers exclusively CNSA 2.0
- **2035**: All National Security Systems quantum-resistant

## License

MIT
