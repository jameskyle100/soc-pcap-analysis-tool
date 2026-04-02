from __future__ import annotations
from dataclasses import dataclass
from typing import Any

@dataclass
class PacketRecord:
    timestamp: str
    src_ip: str | None
    dst_ip: str | None
    protocol: str
    src_port: int | None
    dst_port: int | None
    length: int
    dns_query: str | None = None
    http_host: str | None = None
    http_uri: str | None = None
    tls_sni: str | None = None


@dataclass
class Finding:
    severity: str
    title: str
    why_it_matters: str
    evidence: dict[str, Any]
    next_step: str
