"""Утилиты OSINT: resolve IP, подсети, дедупликация."""

from __future__ import annotations

import ipaddress
import socket
from typing import Dict, Iterable, List, Set


def normalize_domain(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def resolve_host(hostname: str, timeout: float = 3.0) -> List[str]:
    """Резолв A/AAAA записей хоста."""
    hostname = normalize_domain(hostname)
    if not hostname:
        return []
    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        ips: Set[str] = set()
        for info in infos:
            ip = info[4][0]
            if "%" in ip:
                ip = ip.split("%", 1)[0]
            try:
                ipaddress.ip_address(ip)
                ips.add(ip)
            except ValueError:
                continue
        return sorted(ips)
    except (socket.gaierror, OSError):
        return []
    finally:
        socket.setdefaulttimeout(previous_timeout)


def resolve_hosts(hosts: Iterable[str], timeout: float = 3.0) -> Dict[str, List[str]]:
    """Резолв списка хостов → {hostname: [ip, ...]}."""
    result: Dict[str, List[str]] = {}
    seen_hosts: Set[str] = set()
    for host in hosts:
        host = normalize_domain(host)
        if not host or host in seen_hosts:
            continue
        seen_hosts.add(host)
        ips = resolve_host(host, timeout=timeout)
        if ips:
            result[host] = ips
    return result


def collect_unique_ips(resolved: Dict[str, List[str]]) -> List[str]:
    ips: Set[str] = set()
    for host_ips in resolved.values():
        ips.update(host_ips)
    return sorted(ips, key=lambda ip: (ipaddress.ip_address(ip).version, str(ipaddress.ip_address(ip))))


def derive_subnets(ips: Iterable[str], prefix: int = 24) -> List[str]:
    """Строит уникальные подсети /24 (или другой prefix) из IP."""
    networks: Set[str] = set()
    for raw in ips:
        try:
            addr = ipaddress.ip_address(raw)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                continue
            net = ipaddress.ip_network(f"{addr}/{prefix}", strict=False)
            networks.add(str(net))
        except ValueError:
            continue
    return sorted(networks)


def dedupe_sorted(items: Iterable[str]) -> List[str]:
    return sorted({item.strip().lower() for item in items if item and item.strip()})
