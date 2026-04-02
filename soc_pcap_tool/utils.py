from __future__ import annotations

import math
from collections import Counter
from ipaddress import ip_address

from .constants import KNOWN_BENIGN_DOMAINS, NOISY_PORTS, PRIVATE_MULTICAST_PREFIXES
from .models import Finding, PacketRecord


def safe_decode(data: bytes) -> str:
    for enc in ("utf-8", "latin-1"):
        try:
            return data.decode(enc, errors="ignore")
        except Exception:
            pass
    return ""


def is_private_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        return ip_address(value).is_private
    except ValueError:
        return False


def is_multicast_or_broadcast_ip(value: str | None) -> bool:
    if not value:
        return False
    if value == "255.255.255.255":
        return True
    if any(value.lower().startswith(prefix) for prefix in PRIVATE_MULTICAST_PREFIXES):
        return True
    try:
        return ip_address(value).is_multicast
    except ValueError:
        return False


def is_link_local_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        return ip_address(value).is_link_local
    except ValueError:
        return value.lower().startswith("fe80:")


def is_noisy_service_port(port: int | None) -> bool:
    return port in NOISY_PORTS if port is not None else False


def domain_is_known_benign(domain: str | None) -> bool:
    if not domain:
        return False
    d = domain.lower().strip(".")
    return d in KNOWN_BENIGN_DOMAINS or any(d.endswith("." + base) for base in KNOWN_BENIGN_DOMAINS)


def is_probably_noise_record(record: PacketRecord) -> bool:
    if is_multicast_or_broadcast_ip(record.src_ip) or is_multicast_or_broadcast_ip(record.dst_ip):
        return True
    if is_link_local_ip(record.src_ip) or is_link_local_ip(record.dst_ip):
        return True
    if is_noisy_service_port(record.src_port) or is_noisy_service_port(record.dst_port):
        return True
    if domain_is_known_benign(record.dns_query) or domain_is_known_benign(record.tls_sni) or domain_is_known_benign(record.http_host):
        return True
    return False


def score_findings(findings: list[Finding]) -> int:
    caps = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}
    weights = {"critical": 45, "high": 22, "medium": 10, "low": 4, "info": 1}
    counts = Counter(f.severity for f in findings)
    score = 0
    for severity, count in counts.items():
        score += min(count, caps.get(severity, 1)) * weights.get(severity, 0)
    return min(score, 100)


def rating_from_score(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    if score >= 15:
        return "low"
    return "informational"


def entropy_from_counts(counter: Counter) -> float:
    total = sum(counter.values())
    if total <= 0:
        return 0.0
    result = 0.0
    for count in counter.values():
        p = count / total
        if p > 0:
            result -= p * math.log2(p)
    return round(result, 4)


def pretty_severity_label(sev: str) -> str:
    labels = {
        "critical": "high confidence",
        "high": "elevated",
        "medium": "review",
        "low": "low confidence",
        "info": "context",
    }
    return labels.get(sev, sev)
