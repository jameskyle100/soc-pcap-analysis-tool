from __future__ import annotations

import json
import statistics
from collections import Counter, defaultdict
from dataclasses import asdict
from typing import Any

from .detections import run_detections
from .models import PacketRecord
from .utils import domain_is_known_benign, entropy_from_counts, is_private_ip, is_probably_noise_record, rating_from_score, score_findings


def build_host_summary(records: list[PacketRecord], top_n: int = 10) -> list[dict[str, Any]]:
    host_map: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "external_destinations": Counter(),
        "dns_queries": Counter(),
        "ports": Counter(),
        "bytes_sent": 0,
        "packet_count": 0,
    })
    for r in records:
        if not r.src_ip or is_probably_noise_record(r):
            continue
        host = host_map[r.src_ip]
        host["packet_count"] += 1
        host["bytes_sent"] += r.length
        if r.dst_ip and not is_private_ip(r.dst_ip):
            host["external_destinations"][r.dst_ip] += 1
        if r.dns_query and not domain_is_known_benign(r.dns_query):
            host["dns_queries"][r.dns_query] += 1
        if r.dst_port is not None:
            host["ports"][r.dst_port] += 1
    ranked = []
    for src_ip, info in host_map.items():
        ranked.append({
            "source_ip": src_ip,
            "packet_count": info["packet_count"],
            "bytes_sent": info["bytes_sent"],
            "top_external_destinations": info["external_destinations"].most_common(3),
            "top_dns_queries": info["dns_queries"].most_common(3),
            "top_ports": info["ports"].most_common(3),
        })
    ranked.sort(key=lambda x: (len(x["top_external_destinations"]), x["bytes_sent"], x["packet_count"]), reverse=True)
    return ranked[:top_n]


def build_report(records: list[PacketRecord], mode: str, top_n: int, file_name: str | None = None) -> dict[str, Any]:
    proto_counter = Counter(r.protocol for r in records)
    src_counter = Counter(r.src_ip for r in records if r.src_ip)
    dst_counter = Counter(r.dst_ip for r in records if r.dst_ip)
    dns_counter = Counter(r.dns_query for r in records if r.dns_query and not domain_is_known_benign(r.dns_query))
    sni_counter = Counter(r.tls_sni for r in records if r.tls_sni and not domain_is_known_benign(r.tls_sni))
    http_counter = Counter(
        f"{r.http_host}{r.http_uri}"
        for r in records
        if r.http_host and r.http_uri and not domain_is_known_benign(r.http_host)
    )
    dst_port_counter = Counter(r.dst_port for r in records if r.dst_port is not None)
    conversations = Counter((r.src_ip, r.dst_ip) for r in records if r.src_ip and r.dst_ip and not is_probably_noise_record(r))
    packet_sizes = Counter(r.length for r in records)
    findings = run_detections(records, mode)
    triage_score = score_findings(findings)
    triage_rating = rating_from_score(triage_score)
    first_seen = records[0].timestamp if records else None
    last_seen = records[-1].timestamp if records else None

    summary = {
        "mode": mode,
        "packet_count": len(records),
        "first_seen_utc": first_seen,
        "last_seen_utc": last_seen,
        "unique_source_ips": len(src_counter),
        "unique_destination_ips": len(dst_counter),
        "top_protocol": proto_counter.most_common(1)[0][0] if proto_counter else None,
        "avg_packet_size": round(statistics.mean([r.length for r in records]), 2) if records else 0,
        "median_packet_size": round(statistics.median([r.length for r in records]), 2) if records else 0,
        "packet_size_entropy": entropy_from_counts(packet_sizes),
        "triage_score": triage_score,
        "triage_rating": triage_rating,
        "finding_count": len(findings),
    }

    analyst_takeaway = []
    if findings:
        analyst_takeaway.append(f"Top concern: {findings[0].title}")
    if dns_counter:
        analyst_takeaway.append(f"Most queried domain: {dns_counter.most_common(1)[0][0]}")
    if sni_counter:
        analyst_takeaway.append(f"Most seen TLS SNI: {sni_counter.most_common(1)[0][0]}")
    if dst_port_counter:
        analyst_takeaway.append(f"Most used destination port: {dst_port_counter.most_common(1)[0][0]}")

    return {
        "fileName": file_name or "capture",
        "summary": summary,
        "analyst_takeaway": analyst_takeaway,
        "top_source_ips": src_counter.most_common(top_n),
        "top_destination_ips": dst_counter.most_common(top_n),
        "top_protocols": proto_counter.most_common(top_n),
        "top_destination_ports": dst_port_counter.most_common(top_n),
        "top_dns_queries": dns_counter.most_common(top_n),
        "top_tls_sni": sni_counter.most_common(top_n),
        "top_http_requests": http_counter.most_common(top_n),
        "top_conversations": [{"src_ip": src, "dst_ip": dst, "count": count} for (src, dst), count in conversations.most_common(top_n)],
        "host_summary": build_host_summary(records, top_n=top_n),
        "findings": [asdict(f) for f in findings],
    }


def export_markdown(report: dict[str, Any], notice: str, product: str, copyright_text: str, path) -> None:
    lines: list[str] = [f"# {product}", "", f"{copyright_text}", "", "## Summary"]
    for key, value in report["summary"].items():
        lines.append(f"- {key}: {value}")
    lines += ["", "## Analyst Takeaway"]
    for line in report["analyst_takeaway"] or ["No immediate high-signal takeaway generated."]:
        lines.append(f"- {line}")
    lines += ["", "## Prioritized Findings"]
    if report["findings"]:
        for i, f in enumerate(report["findings"], start=1):
            lines += [
                f"### {i}. {f['severity'].upper()} - {f['title']}",
                f"- Why it matters: {f['why_it_matters']}",
                f"- Evidence: `{json.dumps(f['evidence'], ensure_ascii=False)}`",
                f"- Next step: {f['next_step']}",
                "",
            ]
    else:
        lines += ["No notable findings detected by current heuristics.", ""]
    lines += ["---", notice]
    path.write_text("\n".join(lines), encoding="utf-8")
