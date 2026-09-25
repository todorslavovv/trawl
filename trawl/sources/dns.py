"""DNS re-check through the host's own resolver.

A liveness check only: does the name currently resolve, and to which addresses.
It never opens a connection to the resolved addresses and never fetches content -
a suspicious domain is data here, not a destination.

Outcomes are kept distinct, for the same reason the crt.sh collector keeps them
distinct: "the name does not exist" is a finding, "the lookup failed" is not.

    resolved           one or more addresses returned
    nxdomain           resolver says the name does not exist (EAI_NONAME)
    no_address         name exists but has no A/AAAA data (EAI_NODATA)
    temporary_failure  resolver could not answer now (EAI_AGAIN, e.g. SERVFAIL)
    failure            non-recoverable resolver error
    timeout            no answer within our wall-clock limit

ponytail: getaddrinfo cannot report TTLs, CNAME chains or raw rcodes. The upgrade
path is a small UDP DNS client against an explicit resolver; outcomes stay the same.
"""
from __future__ import annotations

import concurrent.futures as cf
import ipaddress
import socket
from pathlib import Path

SOURCE = {
    "id": "dns",
    "name": "DNS resolution (host resolver)",
    "kind": "dns",
    "endpoint": "getaddrinfo() via the deployment host's configured resolver",
    "description": (
        "Re-checks whether flagged names still resolve and records the A/AAAA "
        "addresses returned at the time of the check. Each check is appended; "
        "history is never overwritten."),
    "provenance": (
        "Each observation stores the check time, the resolver description (from "
        "/etc/resolv.conf at run time), the classified outcome and the sorted "
        "address list. Resolving a name is visible to that name's DNS operator "
        "through the recursive resolver; no connection is made to the addresses."),
}

_NODATA = getattr(socket, "EAI_NODATA", None)


def resolver_description(path: str = "/etc/resolv.conf") -> str:
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return "system resolver (resolv.conf unreadable)"
    servers = [ln.split()[1] for ln in lines
               if ln.strip().startswith("nameserver") and len(ln.split()) > 1]
    desc = "getaddrinfo; nameservers=" + (",".join(servers) or "none")
    if "127.0.0.53" in servers or "127.0.0.54" in servers:
        desc += " (systemd-resolved stub; upstream per host configuration)"
    return desc


def classify(host: str, resolve=socket.getaddrinfo) -> tuple[str, list[str], str | None]:
    """Resolve one host. Returns (outcome, sorted addresses, error)."""
    try:
        infos = resolve(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        if e.errno == socket.EAI_NONAME:
            return "nxdomain", [], None
        if _NODATA is not None and e.errno == _NODATA:
            return "no_address", [], None
        if e.errno == socket.EAI_AGAIN:
            return "temporary_failure", [], str(e)[:120]
        return "failure", [], str(e)[:120]
    except (UnicodeError, ValueError) as e:
        return "failure", [], f"invalid name: {str(e)[:100]}"
    except OSError as e:
        return "failure", [], str(e)[:120]
    addrs = sorted({str(ipaddress.ip_address(i[4][0].split("%")[0])) for i in infos})
    return ("resolved", addrs, None) if addrs else ("no_address", [], None)


def check_many(hosts: list[str], *, workers: int, timeout_s: float,
               resolve=socket.getaddrinfo) -> dict[str, tuple[str, list[str], str | None]]:
    """Resolve hosts concurrently with a wall-clock limit per lookup.

    getaddrinfo has no timeout parameter, so the limit is enforced on the future;
    a stuck lookup is recorded as 'timeout' and its thread is abandoned.
    """
    out: dict = {}
    pool = cf.ThreadPoolExecutor(max_workers=max(1, workers))
    try:
        futs = {h: pool.submit(classify, h, resolve) for h in hosts}
        for h, fut in futs.items():
            try:
                out[h] = fut.result(timeout=timeout_s)
            except cf.TimeoutError:
                out[h] = ("timeout", [], f"no answer within {timeout_s:.0f} s")
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return out
