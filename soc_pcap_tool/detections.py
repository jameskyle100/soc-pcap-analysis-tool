from __future__ import annotations

import json
import statistics
from collections import Counter, defaultdict
from datetime import datetime

from .constants import COMMON_PORTS, DNS_TUNNEL_KEYWORDS, SUSPICIOUS_PORTS
from .models import Finding, PacketRecord
from .utils import (
    domain_is_known_benign,
    is_multicast_or_broadcast_ip,
    is_private_ip,
    is_link_local_ip,
    is_probably_noise_record,
    pretty_severity_label,
)


def detect_external_connections(records: list[PacketRecord], top_n: int = 10) -> list[Finding]:
    filtered = [r for r in records if r.dst_ip and not is_private_ip(r.dst_ip) and not is_probably_noise_record(r)]
    external = Counter(r.dst_ip for r in filtered)
    if not external:
        return []
    return [Finding(
        severity="info",
        title="External network communication detected",
        why_it_matters="Shows outbound traffic leaving the local/private network after common noisy traffic was filtered out.",
        evidence={
            "top_external_destinations": external.most_common(top_n),
            "note": "Multicast, link-local, service discovery, and known benign background domains were de-prioritized.",
        },
        next_step="Review the top external IPs and correlate with DNS, TLS SNI, proxy logs, or EDR telemetry.",
    )]


def detect_uncommon_ports(records: list[PacketRecord], top_n: int = 10) -> list[Finding]:
    filtered = [
        r for r in records
        if r.dst_port is not None
        and r.dst_port not in COMMON_PORTS
        and r.dst_port < 49152
        and not is_probably_noise_record(r)
        and r.dst_ip
        and not is_private_ip(r.dst_ip)
    ]
    ports = Counter(r.dst_port for r in filtered)
    uncommon = [(p, c) for p, c in ports.most_common() if c >= 3][:top_n]
    if not uncommon:
        return []
    return [Finding(
        severity="medium",
        title="Repeated traffic to uncommon destination service ports",
        why_it_matters="Repeated external traffic to non-standard service ports can indicate custom services, tunnels, malware C2, or shadow IT. High ephemeral client ports were excluded.",
        evidence={"ports": uncommon},
        next_step="Check the destination IPs behind these ports and validate whether the service is expected in the environment.",
    )]


def detect_known_suspicious_ports(records: list[PacketRecord], top_n: int = 10) -> list[Finding]:
    filtered = [r for r in records if r.dst_port in SUSPICIOUS_PORTS and not is_probably_noise_record(r)]
    suspicious = Counter(r.dst_port for r in filtered)
    if not suspicious:
        return []
    return [Finding(
        severity="high",
        title="Traffic seen on ports commonly abused by tools or backdoors",
        why_it_matters="These ports are often associated with tunnels, remote shells, and non-standard admin channels.",
        evidence={"ports": suspicious.most_common(top_n)},
        next_step="Pivot to flows and identify which host initiated the traffic and whether the service is authorized.",
    )]


def detect_dns_volume(records: list[PacketRecord], top_n: int = 10) -> list[Finding]:
    dns = Counter(r.dns_query for r in records if r.dns_query and not domain_is_known_benign(r.dns_query))
    noisy = [(d, c) for d, c in dns.most_common(top_n) if c >= 10]
    if not noisy:
        return []
    return [Finding(
        severity="low",
        title="High-volume DNS query activity",
        why_it_matters="Could be normal application behavior, but can also indicate beaconing or DNS-based data staging. Common benign domains were excluded.",
        evidence={"domains": noisy},
        next_step="Review repeated domains and confirm whether the volume aligns with expected software or browser behavior.",
    )]


def detect_suspicious_dns_patterns(records: list[PacketRecord], top_n: int = 10) -> list[Finding]:
    suspicious_domains: list[tuple[str, int, int]] = []
    dns = Counter(r.dns_query for r in records if r.dns_query and not domain_is_known_benign(r.dns_query))
    for domain, count in dns.items():
        first_label = domain.split(".")[0] if "." in domain else domain
        long_label = len(first_label) >= 25
        many_digits = sum(ch.isdigit() for ch in first_label) >= 8
        keyword_hit = any(k in domain.lower() for k in DNS_TUNNEL_KEYWORDS)
        if (long_label or many_digits or keyword_hit) and count >= 3:
            suspicious_domains.append((domain, count, len(first_label)))
    suspicious_domains.sort(key=lambda x: x[1], reverse=True)
    if not suspicious_domains:
        return []
    return [Finding(
        severity="medium",
        title="DNS queries with suspicious naming patterns",
        why_it_matters="Very long or oddly structured subdomains may indicate encoded data, tracking, or tunneling behavior. Common benign domains were excluded.",
        evidence={"domains": suspicious_domains[:top_n]},
        next_step="Inspect the full DNS request pattern and verify whether the queried domains are legitimate for the environment.",
    )]


def detect_http_interesting(records: list[PacketRecord], top_n: int = 10) -> list[Finding]:
    hits = []
    keywords = ("login", "admin", "upload", "shell", "api", "token", "auth", "cmd")
    for r in records:
        if is_probably_noise_record(r):
            continue
        if r.http_uri and any(k in r.http_uri.lower() for k in keywords):
            hits.append((r.http_host or "unknown-host", r.http_uri))
    counter = Counter(hits)
    if not counter:
        return []
    return [Finding(
        severity="low",
        title="Interesting HTTP request paths observed",
        why_it_matters="Administrative, upload, auth, or command-like paths can be useful leads during triage when common background noise is filtered out.",
        evidence={"http_paths": [{"host": h, "uri": u, "count": c} for (h, u), c in counter.most_common(top_n)]},
        next_step="Review whether these web requests were expected and identify the originating client.",
    )]


def detect_beaconing(records: list[PacketRecord]) -> list[Finding]:
    buckets: dict[tuple[str, str, int | None, str], list[float]] = defaultdict(list)
    for r in records:
        if not r.src_ip or not r.dst_ip:
            continue
        if is_probably_noise_record(r):
            continue
        if is_private_ip(r.dst_ip) or is_multicast_or_broadcast_ip(r.dst_ip) or is_link_local_ip(r.dst_ip):
            continue
        if r.protocol not in {"TCP", "TLS/HTTPS", "HTTP", "UDP"}:
            continue
        key = (r.src_ip, r.dst_ip, r.dst_port, r.protocol)
        buckets[key].append(datetime.fromisoformat(r.timestamp).timestamp())

    findings: list[Finding] = []
    for (src, dst, port, proto), times in buckets.items():
        if len(times) < 8:
            continue
        times.sort()
        deltas = [round(times[i] - times[i - 1], 2) for i in range(1, len(times))]
        if len(deltas) < 7:
            continue
        try:
            avg = statistics.mean(deltas)
            stdev = statistics.pstdev(deltas)
        except statistics.StatisticsError:
            continue
        if avg < 5:
            continue
        if stdev > max(2.0, avg * 0.20):
            continue
        severity = "high" if avg >= 15 and len(times) >= 10 else "medium"
        findings.append(Finding(
            severity=severity,
            title="Possible beaconing pattern detected",
            why_it_matters="Regular repeated outbound communication to the same external destination can indicate automated check-ins or command-and-control traffic. Short noisy intervals and local chatter were filtered out.",
            evidence={
                "source": src,
                "destination": f"{dst}:{port}" if port is not None else dst,
                "protocol": proto,
                "events": len(times),
                "average_interval_seconds": round(avg, 2),
                "interval_stdev_seconds": round(stdev, 2),
                "confidence": pretty_severity_label(severity),
            },
            next_step="Pivot on the source host in EDR, review process lineage, and check whether this destination appears in DNS, proxy, or firewall logs.",
        ))
    return findings


def detect_large_data_transfer(records: list[PacketRecord], top_n: int = 10) -> list[Finding]:
    byte_count: dict[tuple[str, str], int] = defaultdict(int)
    for r in records:
        if r.src_ip and r.dst_ip and not is_probably_noise_record(r):
            byte_count[(r.src_ip, r.dst_ip)] += r.length
    heavy = sorted(byte_count.items(), key=lambda x: x[1], reverse=True)[:top_n]
    suspicious = [x for x in heavy if x[1] >= 500000 and not is_private_ip(x[0][1])]
    if not suspicious:
        return []
    return [Finding(
        severity="medium",
        title="Large outbound data transfer observed",
        why_it_matters="Large transfers to external destinations may indicate downloads, uploads, backups, or possible exfiltration depending on business context.",
        evidence={"flows": [{"source": src, "destination": dst, "bytes": total} for (src, dst), total in suspicious]},
        next_step="Validate whether each destination is sanctioned and whether the transfer volume aligns with expected application behavior.",
    )]


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str]] = set()
    result: list[Finding] = []
    for finding in findings:
        key = (finding.title, json.dumps(finding.evidence, sort_keys=True, default=str))
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    return result


def run_detections(records: list[PacketRecord], mode: str) -> list[Finding]:
    findings: list[Finding] = []
    if mode in {"quick", "hunt", "web"}:
        findings.extend(detect_external_connections(records))
        findings.extend(detect_uncommon_ports(records))
        findings.extend(detect_beaconing(records))
    if mode in {"quick", "hunt"}:
        findings.extend(detect_known_suspicious_ports(records))
        findings.extend(detect_large_data_transfer(records))
    if mode in {"quick", "web", "dns", "hunt"}:
        findings.extend(detect_dns_volume(records))
        findings.extend(detect_suspicious_dns_patterns(records))
        findings.extend(detect_http_interesting(records))
    findings = deduplicate_findings(findings)
    severity_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    findings.sort(key=lambda f: severity_order.get(f.severity, 0), reverse=True)
    return findings
