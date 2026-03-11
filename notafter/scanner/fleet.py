"""Async fleet scanner for bulk host scanning."""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from notafter.scanner.tls import ScanResult, scan_host


async def scan_fleet(
    targets: list[str],
    port: int = 443,
    concurrency: int = 50,
    timeout: float = 10.0,
    on_result: Callable[[ScanResult, int, int], None] | None = None,
) -> list[ScanResult]:
    """Scan multiple hosts concurrently.

    Args:
        targets: List of hostnames or IPs
        port: Default port (can be overridden per-target with host:port)
        concurrency: Max concurrent connections
        timeout: Per-host timeout in seconds
        on_result: Optional callback(result, index, total) for progress reporting
    """
    loop = asyncio.get_running_loop()
    semaphore = asyncio.Semaphore(concurrency)
    total = len(targets)
    executor = ThreadPoolExecutor(max_workers=min(concurrency, 100))

    async def _scan_one(target: str, index: int) -> ScanResult:
        host, target_port = parse_target(target, port)
        async with semaphore:
            result = await loop.run_in_executor(
                executor, scan_host, host, target_port, timeout
            )
        if on_result:
            on_result(result, index, total)
        return result

    try:
        tasks = [_scan_one(t, i) for i, t in enumerate(targets)]
        results = await asyncio.gather(*tasks)
        return list(results)
    finally:
        executor.shutdown(wait=False)


def load_targets(source: str) -> list[str]:
    """Load targets from a file (one per line) or CIDR notation.

    Supports:
        - File path (one host:port per line, # comments)
        - CIDR notation (e.g., 10.0.0.0/24)
    """
    # Try CIDR first
    try:
        network = ipaddress.ip_network(source, strict=False)
    except ValueError:
        pass  # Not a valid CIDR — try file
    else:
        if network.num_addresses > 65536:
            raise ValueError(
                f"CIDR {source} too large ({network.num_addresses} hosts, max 65536)"
            )
        return [str(ip) for ip in network.hosts()]

    # Try file
    path = Path(source)
    if path.is_file():
        targets = []
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
        return targets

    raise ValueError(f"Cannot parse '{source}' as CIDR or host file")


def parse_target(target: str, default_port: int) -> tuple[str, int]:
    """Parse host:port from a target string. Supports IPv6 brackets."""
    target = target.strip()
    if target.startswith("["):
        # IPv6 with brackets: [::1]:8443
        bracket_end = target.find("]")
        if bracket_end == -1:
            return target[1:], default_port
        host = target[1:bracket_end]
        rest = target[bracket_end + 1:]
        if rest.startswith(":"):
            try:
                return host, int(rest[1:])
            except ValueError:
                pass
        return host, default_port

    # Check for IPv6 without brackets (contains multiple colons)
    if target.count(":") > 1:
        return target, default_port

    # Standard host:port
    if ":" in target:
        parts = target.rsplit(":", 1)
        try:
            return parts[0], int(parts[1])
        except ValueError:
            pass

    return target, default_port
