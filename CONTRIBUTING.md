# Contributing to notafter

## Dev environment setup

```bash
# Clone
git clone https://github.com/FKawooya/NotAfter.git
cd NotAfter

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate    # Linux/macOS
.venv\Scripts\activate       # Windows

# Install with dev dependencies
pip install -e ".[dev]"
```

Requires Python 3.10+.

## Running tests

```bash
# All tests
pytest

# With coverage
pytest --cov=notafter --cov-report=term-missing

# Single test file
pytest tests/test_pqc_scorer.py -v
```

Tests live in `tests/`. The test suite covers PQC OID lookups, scoring logic, CBOM generation, check engine findings, and fleet target parsing.

## Code style

This project uses [ruff](https://docs.astral.sh/ruff/) for linting and formatting.

```bash
# Lint
ruff check .

# Auto-fix
ruff check --fix .

# Format
ruff format .
```

Configuration is in `pyproject.toml`:
- Target: Python 3.10
- Line length: 100
- Rules: E, F, I, W (pycodestyle errors, pyflakes, isort, warnings)

## Project structure

```
notafter/
  cli.py              # CLI entry point (Click)
  scanner/tls.py      # TLS scanner
  scanner/fleet.py    # Async fleet scanner
  checks/engine.py    # Certificate lint checks
  pqc/oids.py         # Algorithm OID database
  pqc/scorer.py       # PQC scoring model
  revocation/checker.py  # OCSP, CRL, CT
  cbom/generator.py   # CycloneDX CBOM
  output/terminal.py  # Rich terminal output
tests/
  test_pqc_oids.py
  test_pqc_scorer.py
  test_cbom.py
  test_checks.py
  test_fleet.py
```

## Pull request process

1. Fork the repo and create a branch from `master`.
2. Make your changes. Add tests for new functionality.
3. Run `ruff check .` and `pytest` -- both must pass.
4. Keep PRs focused. One feature or fix per PR.
5. Write a clear description of what changed and why.

## Adding a new PQC algorithm

1. Add the `AlgorithmInfo` entry in `notafter/pqc/oids.py`.
2. The OID map is built automatically from module-level constants.
3. Add a test case in `tests/test_pqc_oids.py`.
4. If the algorithm affects scoring, update `tests/test_pqc_scorer.py`.

## Adding a new check

1. Write a function in `notafter/checks/engine.py` matching the signature `(ScanResult, int) -> list[Finding]`.
2. Add it to the `_ALL_CHECKS` list at the bottom of the file.
3. Add test cases in `tests/test_checks.py`.
