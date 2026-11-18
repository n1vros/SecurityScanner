#!/usr/bin/env python3
"""
clear_resolvers.py <input_file> <output_file>

Reads a resolver list (one IP per line), probes each one, and writes
only the live ones to the output file. No dependencies outside stdlib.
"""

import asyncio
import re
import socket
import struct
import sys
import time
from pathlib import Path
from typing import List, Set

TIMEOUT     = 1.0   # seconds per probe attempt
ATTEMPTS    = 2     # retries before marking dead
CONCURRENCY = 500   # parallel probes

# ── DNS probe ─────────────────────────────────────────────────────────────────

# Minimal SOA query for "." (root zone) — always cached by any live resolver
_QUERY = (
    struct.pack(">HHHHHH", 0xAB12, 0x0100, 1, 0, 0, 0)  # header
    + b"\x00"                                              # root label
    + struct.pack(">HH", 6, 1)                            # QTYPE=SOA, QCLASS=IN
)


def _sync_probe(ip: str) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(TIMEOUT)
            s.sendto(_QUERY, (ip, 53))
            data, _ = s.recvfrom(512)
            return len(data) >= 12 and data[:2] == b"\xab\x12" and bool(data[2] & 0x80)
    except Exception:
        return False


async def _probe(ip: str, loop: asyncio.AbstractEventLoop) -> bool:
    for _ in range(ATTEMPTS):
        try:
            alive = await asyncio.wait_for(
                loop.run_in_executor(None, _sync_probe, ip),
                timeout=TIMEOUT + 0.5,
            )
            if alive:
                return True
        except Exception:
            pass
    return False


# ── Parsing ───────────────────────────────────────────────────────────────────

_IPV4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def _valid_ipv4(s: str) -> bool:
    return bool(_IPV4.match(s)) and all(0 <= int(p) <= 255 for p in s.split("."))


def load(path: Path) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        ip = line.split("#")[0].strip()
        if ":" in ip and ip.count(":") == 1:
            ip = ip.split(":")[0]
        if _valid_ipv4(ip) and ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


# ── Main ──────────────────────────────────────────────────────────────────────

async def run(input_path: Path, output_path: Path) -> None:
    resolvers = load(input_path)
    if not resolvers:
        sys.exit(f"No valid IPs found in {input_path}")

    total = len(resolvers)
    print(f"Loaded {total} resolvers  ->  probing ({CONCURRENCY} concurrent, {TIMEOUT}s timeout) ...")

    loop  = asyncio.get_running_loop()
    sem   = asyncio.Semaphore(CONCURRENCY)
    live: Set[str] = set()
    done  = 0
    t0    = time.monotonic()

    async def check(ip: str) -> None:
        nonlocal done
        async with sem:
            if await _probe(ip, loop):
                live.add(ip)
        done += 1
        if done % 1000 == 0 or done == total:
            elapsed = time.monotonic() - t0
            print(f"  {done}/{total}  live={len(live)}  dead={done - len(live)}  "
                  f"{done / elapsed:.0f}/s", flush=True)

    await asyncio.gather(*[check(ip) for ip in resolvers])

    elapsed  = time.monotonic() - t0
    dead     = total - len(live)
    print(f"\n{elapsed:.1f}s -- kept {len(live)}/{total}  ({dead} dead, {100*dead/total:.0f}%)")

    ordered = [ip for ip in resolvers if ip in live]
    output_path.write_text("\n".join(ordered) + "\n", encoding="utf-8")
    print(f"Written -> {output_path}")


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit("Usage: clear_resolvers.py <input_file> <output_file>")

    src, dst = Path(sys.argv[1]), Path(sys.argv[2])

    if not src.exists():
        sys.exit(f"File not found: {src}")
    if src.resolve() == dst.resolve():
        sys.exit("Input and output must be different files")

    asyncio.run(run(src, dst))


if __name__ == "__main__":
    main()