from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .constants import MAX_PACKET_READ
from .models import PacketRecord
from .utils import safe_decode


def _scapy():
    from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, Raw  # type: ignore
    return {
        "PcapReader": PcapReader, "IP": IP, "IPv6": IPv6, "TCP": TCP, "UDP": UDP,
        "ICMP": ICMP, "DNS": DNS, "DNSQR": DNSQR, "Raw": Raw,
    }


def get_ips(pkt: Any, layers: dict[str, Any]) -> tuple[str | None, str | None]:
    if pkt.haslayer(layers["IP"]):
        return pkt[layers["IP"]].src, pkt[layers["IP"]].dst
    if pkt.haslayer(layers["IPv6"]):
        return pkt[layers["IPv6"]].src, pkt[layers["IPv6"]].dst
    return None, None


def get_ports(pkt: Any, layers: dict[str, Any]) -> tuple[int | None, int | None]:
    if pkt.haslayer(layers["TCP"]):
        return int(pkt[layers["TCP"]].sport), int(pkt[layers["TCP"]].dport)
    if pkt.haslayer(layers["UDP"]):
        return int(pkt[layers["UDP"]].sport), int(pkt[layers["UDP"]].dport)
    return None, None


def guess_protocol(pkt: Any, layers: dict[str, Any]) -> str:
    if pkt.haslayer(layers["DNS"]):
        return "DNS"
    if pkt.haslayer(layers["TCP"]):
        ports = {int(pkt[layers["TCP"]].sport), int(pkt[layers["TCP"]].dport)}
        if 443 in ports:
            return "TLS/HTTPS"
        if 80 in ports or 8080 in ports:
            return "HTTP"
        return "TCP"
    if pkt.haslayer(layers["UDP"]):
        ports = {int(pkt[layers["UDP"]].sport), int(pkt[layers["UDP"]].dport)}
        if 53 in ports:
            return "DNS"
        if 123 in ports:
            return "NTP"
        return "UDP"
    if pkt.haslayer(layers["ICMP"]):
        return "ICMP"
    return "OTHER"


def extract_dns_query(pkt: Any, layers: dict[str, Any]) -> str | None:
    if pkt.haslayer(layers["DNS"]) and pkt.haslayer(layers["DNSQR"]):
        try:
            qname = pkt[layers["DNSQR"]].qname
            if isinstance(qname, bytes):
                return qname.decode(errors="ignore").rstrip(".")
            return str(qname).rstrip(".")
        except Exception:
            return None
    return None


def extract_http(pkt: Any, layers: dict[str, Any]) -> tuple[str | None, str | None]:
    if not pkt.haslayer(layers["Raw"]):
        return None, None
    data = safe_decode(bytes(pkt[layers["Raw"]].load))
    if not data:
        return None, None
    methods = ("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ")
    if not data.startswith(methods):
        return None, None
    lines = data.splitlines()
    uri = None
    host = None
    if lines:
        parts = lines[0].split()
        if len(parts) >= 2:
            uri = parts[1]
    for line in lines[1:30]:
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip()
            break
    return host, uri


def extract_tls_sni(pkt: Any, layers: dict[str, Any]) -> str | None:
    if not pkt.haslayer(layers["TCP"]) or not pkt.haslayer(layers["Raw"]):
        return None
    sport, dport = int(pkt[layers["TCP"]].sport), int(pkt[layers["TCP"]].dport)
    if 443 not in {sport, dport}:
        return None
    payload = bytes(pkt[layers["Raw"]].load)
    if not payload or payload[:1] not in {b"\x16", b"\x17"}:
        return None
    text = safe_decode(payload)
    if not text:
        return None
    for token in text.replace("\x00", " ").split():
        token = token.strip()
        if "." in token and 4 <= len(token) <= 255:
            if all(ch.isalnum() or ch in "-._" for ch in token) and not token.replace(".", "").isdigit():
                return token
    return None


def packet_to_record(pkt: Any, layers: dict[str, Any]) -> PacketRecord:
    src_ip, dst_ip = get_ips(pkt, layers)
    src_port, dst_port = get_ports(pkt, layers)
    http_host, http_uri = extract_http(pkt, layers)
    return PacketRecord(
        timestamp=datetime.fromtimestamp(float(pkt.time), tz=timezone.utc).isoformat(),
        src_ip=src_ip, dst_ip=dst_ip, protocol=guess_protocol(pkt, layers),
        src_port=src_port, dst_port=dst_port, length=len(pkt),
        dns_query=extract_dns_query(pkt, layers), http_host=http_host, http_uri=http_uri,
        tls_sni=extract_tls_sni(pkt, layers),
    )


def analyze_pcap_file(pcap_path: str | Path, mode: str = "quick", top_n: int = 10):
    from .reporting import build_report
    layers = _scapy()
    records: list[PacketRecord] = []
    with layers["PcapReader"](str(pcap_path)) as packets:
        for idx, pkt in enumerate(packets):
            if idx >= MAX_PACKET_READ:
                break
            try:
                records.append(packet_to_record(pkt, layers))
            except Exception:
                continue
    records.sort(key=lambda r: r.timestamp)
    report = build_report(records, mode=mode, top_n=top_n, file_name=Path(pcap_path).name)
    if len(records) >= MAX_PACKET_READ:
        report.setdefault("warnings", []).append(f"Packet read cap reached at {MAX_PACKET_READ:,} packets.")
    return records, report
