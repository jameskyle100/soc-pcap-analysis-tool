# PCAP Analysis Tool

Investigation-ready PCAP analysis for faster SOC triage and deeper network insight.

This tool helps analysts review `.pcap` and `.pcapng` files without spending long hours manually digging through traffic in Wireshark. It parses network captures, reconstructs flows, extracts HTTP transactions where possible, highlights suspicious activity, and presents the results in a compact investigation dashboard with exportable reports.

It is designed for:

- SOC analysts
- incident responders
- threat hunters
- blue team investigators
- security engineers performing rapid PCAP review

---

# Purpose

The purpose of this project is to turn raw packet captures into investigation-ready findings.

Instead of showing only packet counts and protocol breakdowns, the tool aims to provide:

- fast triage visibility
- suspicious behavior detection
- host-centric analysis
- DNS, TLS, and HTTP visibility
- conversation and flow inspection
- evidence-rich findings
- downloadable analyst reports

This makes it useful for first-pass analysis, escalation support, and security investigations where speed matters.

---

# Main Capabilities

## PCAP triage and analysis

- Upload `.pcap` or `.pcapng` files through the web dashboard
- Analyze packet captures locally
- Detect suspicious behavior using SOC-oriented heuristics
- Generate host, network, DNS, TLS, web, and flow summaries
- Produce a triage score based on observed findings
- Export results for documentation and handoff

## Protocol visibility

- DNS query and response inspection
- TLS ClientHello SNI extraction
- HTTP request and response inspection
- TCP flow reconstruction
- request/response transaction view for supported HTTP traffic
- extracted object identification from HTTP responses where possible

## Investigation features

- clickable metric cards
- clickable finding details
- right-side investigation drawer
- host-centric investigation view
- timeline panel
- sticky filters
- compact header search
- flow inspection
- richer evidence for findings

## Enrichment support

- settings page for API-based integrations
- VirusTotal integration support
- OTX integration support
- AbuseIPDB integration support

When configured, enrichment can show information such as:

- reputation
- detection counts
- tags
- pulse matches
- abuse confidence score
- first seen / last seen

## Export options

- PDF report
- JSON evidence export
- CSV findings export
- Markdown analyst summary
- analyst handoff bundle

Flows  
Conversation flows between hosts.
<img width="659" height="175" alt="Screenshot 2026-04-14 141329" src="https://github.com/user-attachments/assets/fa8d49a7-486c-4a1d-807f-ad5cc66a8457" />
<img width="937" height="469" alt="Screenshot 2026-04-14 141230" src="https://github.com/user-attachments/assets/1fc98df5-5435-4523-8d79-71c1dcb48d93" />
<img width="935" height="469" alt="Screenshot 2026-04-14 141057" src="https://github.com/user-attachments/assets/872f4fa0-511f-4006-92e0-bc333ea7b201" />


---

# Formal Analysis Report

<img width="562" height="752" alt="5" src="https://github.com/user-attachments/assets/b26d1733-a2d2-4a2e-9d80-4ed74ef6ea1b" />

# Dashboard Overview

The dashboard is designed to provide fast visibility into suspicious traffic while staying compact and responsive.

## Top summary cards

The main top cards provide quick pivot points into the analysis:

- High Severity Alerts
- All Alerts
- Packets
- Unique Destinations
- Triage Score
- Window

Each card is clickable and opens relevant result details in the investigation drawer.

## Investigation sections

### Findings
Prioritized suspicious observations detected during analysis.

### Hosts
Most active systems, communication behavior, and host pivots.

### Network
Top source and destination IP activity, protocols, and conversations.

### DNS and TLS
DNS queries, response behavior, SNI extraction, and domain visibility.

### Web
HTTP requests, paths, hosts, methods, and reconstructed transaction details.

### Flows
Conversation flows, packet counts, transfer visibility, stream details, and extracted objects when available.

### Timeline
Time-bucketed event view to help identify spikes and focus investigation windows.

---

# Analysis Modes

The tool supports multiple analysis modes depending on the workflow.

| Mode  | Description |
|-------|-------------|
| quick | Fast high-signal triage mode |
| hunt  | Full investigation mode with broader detection coverage |
| web   | Focus on HTTP, web traffic, and TLS-related activity |
| dns   | Focus on DNS-heavy activity, rare domains, entropy, and tunneling-style indicators |

Recommended default mode for most investigations:

`hunt`

---

# Evidence and Findings

Findings are designed to be investigation-ready rather than simple alerts.

Each finding may include:

- source host
- destination host or domain
- first seen and last seen timestamps
- packet count
- representative sample packets
- related DNS evidence
- related TLS SNI
- related HTTP evidence
- related flows
- confidence and scoring context

The goal is to help analysts understand not only what triggered, but also why it triggered.

---

# HTTP Transaction and Flow Reconstruction

The tool now includes deeper packet and flow visibility for common traffic patterns.

Supported improvements include:

- reconstructed client/server TCP streams
- HTTP request/response pairing where possible
- method, host, URI, user-agent, and response status extraction
- response object identification
- file or object type hints from HTTP content

Detected object types may include:

- PE executables
- ZIP archives
- PDF files
- PNG
- JPEG
- GIF
- JSON
- HTML
- JavaScript

This is intended to improve investigation quality and reduce the need to leave the dashboard for basic transaction review.

---

# Formal Reporting

The tool can generate a formal investigation summary suitable for documentation and handoff.

Report content can include:

- executive overview
- analyst takeaway
- priority findings
- top hosts
- capture metrics
- recommended next steps

Supported export formats include:

- PDF
- JSON
- CSV
- Markdown
- analyst handoff bundle

---

# Security and Privacy Notice

This tool is designed for local analysis.

It does not execute payloads and is intended for passive packet inspection only.

By default, the tool does not upload PCAP data anywhere.

External integrations such as VirusTotal, OTX, and AbuseIPDB are optional and only used if the analyst enables them and supplies API credentials.

Recommended usage:

- run locally on an analyst workstation
- use enrichment only when policy allows
- avoid sending sensitive indicators externally unless approved

---

# Installation

Clone the repository and install the dependencies.

```bash
git clone https://github.com/jameskyle100/pcap-analysis-tool.git
cd pcap-analysis-tool
pip install -r requirements.txt



If needed, use Python 3 explicitly:

pip3 install -r requirements.txt
Running the Tool

Start the dashboard:

python3 run_dashboard.py

Then open your browser and go to:

http://127.0.0.1:8765
How to Use
Open the dashboard in your browser.
Upload a .pcap or .pcapng file.
Select an analysis mode.
Click Analyze PCAP.
Review results in the dashboard sections.
Click findings, hosts, flows, or top cards to inspect evidence.
Open the report or export the results if needed.

For best overall results, start with:

hunt
Integration Settings

The dashboard includes a small settings button in the upper-right corner.

Inside Settings, you can configure API-based integrations for:

VirusTotal
OTX
AbuseIPDB

These integrations can be used to enrich clicked indicators such as:

IP addresses
domains
hashes

This allows the drawer or finding details to show additional threat intelligence when configured.

Recommended Workflow

A practical investigation flow is:

Upload a PCAP file
Run hunt mode
Review high severity alerts
Check the timeline for spikes
pivot into the most suspicious host
inspect related DNS, TLS, HTTP, and flows
review enriched indicators if enabled
export the report and evidence bundle
Project Structure
pcap-analysis-tool/
├── run_dashboard.py
├── requirements.txt
├── README.md
├── tests/
├── soc_pcap_tool/
│   ├── webapp.py
│   ├── models.py
│   ├── parsers.py
│   ├── detections.py
│   ├── reporting.py
│   ├── pdf_report.py
│   ├── allowlist.py
│   ├── ioc.py
│   ├── utils.py
│   └── templates/
│       └── dashboard.html
