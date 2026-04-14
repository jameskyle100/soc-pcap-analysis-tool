from soc_pcap_tool.models import PacketRecord
from soc_pcap_tool.reporting import build_report


def test_http_transaction_and_object_extraction_present():
    req = b'GET /dropper.exe HTTP/1.1\r\nHost: evil-example.test\r\nUser-Agent: UnitTest\r\n\r\n'
    resp_hdr = b'HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 6\r\n\r\n'
    resp_body = b'MZP123'
    records = [
        PacketRecord(timestamp='2026-04-14T00:00:00+00:00', src_ip='10.0.0.5', dst_ip='1.2.3.4', protocol='HTTP', src_port=50124, dst_port=80, length=60, flow_id='HTTP|1', tcp_flags='S', tcp_seq=1000, tcp_ack=0),
        PacketRecord(timestamp='2026-04-14T00:00:01+00:00', src_ip='10.0.0.5', dst_ip='1.2.3.4', protocol='HTTP', src_port=50124, dst_port=80, length=len(req)+54, flow_id='HTTP|1', tcp_seq=1001, raw_payload=req, payload_length=len(req), http_method='GET', http_host='evil-example.test', http_uri='/dropper.exe'),
        PacketRecord(timestamp='2026-04-14T00:00:02+00:00', src_ip='1.2.3.4', dst_ip='10.0.0.5', protocol='HTTP', src_port=80, dst_port=50124, length=len(resp_hdr)+len(resp_body)+54, flow_id='HTTP|1', tcp_seq=2000, tcp_ack=1001+len(req), raw_payload=resp_hdr+resp_body, payload_length=len(resp_hdr)+len(resp_body), http_status=200),
    ]
    report = build_report(records, mode='web', top_n=10, file_name='http.pcap')
    detail = report['flow_details']['HTTP|1']
    assert detail['http_transactions']
    assert detail['http_transactions'][0]['uri'] == '/dropper.exe'
    assert detail['extracted_objects']
    assert detail['extracted_objects'][0]['detected_type'] == 'PE executable'
