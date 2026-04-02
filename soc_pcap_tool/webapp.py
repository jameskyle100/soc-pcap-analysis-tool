from __future__ import annotations

import logging
import tempfile
import threading
import webbrowser
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file

from .constants import ALLOWED_EXTENSIONS, MAX_UPLOAD_MB, SCRIPT_COPYRIGHT, SCRIPT_NOTICE, SCRIPT_PRODUCT
from .parsers import analyze_pcap_file
from .pdf_report import generate_summary_pdf

app = Flask(__name__, template_folder="templates")
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
log = logging.getLogger(__name__)


def _allowed_file(name: str) -> bool:
    return Path(name).suffix.lower() in ALLOWED_EXTENSIONS


def _looks_like_pcap(data: bytes) -> bool:
    return data.startswith((b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"))


@app.get("/")
def dashboard() -> str:
    return render_template("dashboard.html", script_product=SCRIPT_PRODUCT, script_copyright=SCRIPT_COPYRIGHT, script_notice=SCRIPT_NOTICE)


@app.get("/health")
def health():
    return jsonify({"ok": True})


@app.post("/analyze")
def analyze_endpoint():
    uploaded = request.files.get("pcap")
    mode = request.form.get("mode", "hunt")
    if uploaded is None or uploaded.filename == "":
        return jsonify({"error": "No PCAP file uploaded."}), 400
    if mode not in {"quick", "hunt", "web", "dns"}:
        return jsonify({"error": "Invalid mode."}), 400
    if not _allowed_file(uploaded.filename):
        return jsonify({"error": "Unsupported file type."}), 400

    head = uploaded.stream.read(8)
    uploaded.stream.seek(0)
    if not _looks_like_pcap(head):
        return jsonify({"error": "File does not look like a PCAP/PCAPNG capture."}), 400

    suffix = Path(uploaded.filename).suffix or ".pcap"
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            uploaded.save(tmp.name)
            tmp_path = tmp.name
        _, report = analyze_pcap_file(tmp_path, mode=mode, top_n=10)
        report["fileName"] = uploaded.filename
        return jsonify(report)
    except Exception:
        log.exception("Failed to analyze PCAP")
        return jsonify({"error": "Failed to analyze PCAP."}), 500
    finally:
        if tmp_path:
            try:
                Path(tmp_path).unlink(missing_ok=True)
            except Exception:
                pass


@app.post("/download-summary-pdf")
def download_summary_pdf():
    try:
        report = request.get_json(silent=True) or {}
        pdf_buffer = generate_summary_pdf(report)
        file_name = str(report.get("fileName", "analysis-summary"))
        safe_name = Path(file_name).stem
        return send_file(pdf_buffer, mimetype="application/pdf", as_attachment=True, download_name=f"{safe_name}-analysis-summary.pdf")
    except Exception:
        log.exception("Failed to generate PDF")
        return jsonify({"error": "Failed to generate PDF."}), 500


def launch_dashboard(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> None:
    url = f"http://{host}:{port}"
    print(f"[*] Starting SOC PCAP dashboard on {url}")
    print("[*] Open the page, upload a PCAP, and analyze from the UI.")
    if open_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    app.run(host=host, port=port, debug=False, use_reloader=False)
