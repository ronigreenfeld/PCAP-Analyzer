"""
pcap_parser.py - Robust PCAP/PCAPNG network packet analysis and HTTP transaction reassembler.
Uses Scapy to extract packets, track TCP sessions, match HTTP requests to responses,
and produce structured datasets without passing raw capture files to external models.
"""

import datetime
from collections import defaultdict, deque
from typing import Dict, List, Any, Optional, Tuple

import scapy.all as scapy
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.utils import PcapReader


HTTP_METHODS = {b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH", b"TRACE", b"CONNECT"}


def _decode_bytes(val: Any) -> str:
    """Safely decode bytes or convert object to string."""
    if val is None:
        return ""
    if isinstance(val, bytes):
        return val.decode("utf-8", errors="replace")
    return str(val)


def _extract_headers(layer) -> Dict[str, str]:
    """Extract all HTTP headers from a Scapy HTTP layer."""
    headers = {}
    if not hasattr(layer, "fields_desc"):
        return headers
    for f in layer.fields_desc:
        name = f.name
        # Skip Scapy's internal/positional fields
        if name in ("Method", "Path", "Http_Version", "Status_Code", "Reason_Phrase"):
            continue
        val = getattr(layer, name, None)
        if val is not None and val != b"" and val != "":
            headers[name.replace("_", "-")] = _decode_bytes(val)
    return headers


def _extract_body(layer_or_pkt) -> Optional[str]:
    """Extract and decode body from Raw payload if present."""
    if layer_or_pkt.haslayer(scapy.Raw):
        raw_data = layer_or_pkt[scapy.Raw].load
        try:
            return raw_data.decode("utf-8")
        except UnicodeDecodeError:
            # If binary or compressed, return informative string or truncated representation
            return f"<Binary data: {len(raw_data)} bytes>"
    return None


def _check_raw_http(payload: bytes) -> Tuple[Optional[str], Any]:
    """
    Fallback parser for TCP segments on non-standard ports or when
    Scapy doesn't automatically attach HTTP layer.
    Returns ('request' or 'response', parsed_http_layer).
    """
    if not payload:
        return None, None

    first_line = payload.split(b"\r\n", 1)[0].split(b"\n", 1)[0]
    parts = first_line.split()

    if len(parts) >= 2 and parts[0] in HTTP_METHODS:
        try:
            parsed = HTTP(payload)
            if parsed.haslayer(HTTPRequest):
                return "request", parsed[HTTPRequest]
        except Exception:
            pass

    if len(parts) >= 2 and parts[0].startswith(b"HTTP/"):
        try:
            parsed = HTTP(payload)
            if parsed.haslayer(HTTPResponse):
                return "response", parsed[HTTPResponse]
        except Exception:
            pass

    return None, None


def parse_pcap(filepath: str) -> Dict[str, Any]:
    """
    Reads a PCAP or PCAPNG file, parses general packet statistics,
    identifies protocol distributions, and reassembles HTTP request/response
    transactions over TCP streams.
    
    Returns a dictionary containing:
      - 'summary': General capture metrics (packet count, timestamps, endpoints, protocols)
      - 'transactions': List of structured HTTP transaction dicts
      - 'streams': Overview of TCP streams
    """
    total_packets = 0
    first_timestamp: Optional[float] = None
    last_timestamp: Optional[float] = None

    protocol_counts: Dict[str, int] = defaultdict(int)
    ip_counter: Dict[str, int] = defaultdict(int)

    # Session tracking: stream_key -> deque of pending requests
    # stream_key = (min(endpointA, endpointB), max(endpointA, endpointB))
    pending_requests: Dict[Tuple, deque] = defaultdict(deque)
    completed_transactions: List[Dict[str, Any]] = []

    # Stream counters
    stream_packet_counts: Dict[str, int] = defaultdict(int)

    with PcapReader(filepath) as reader:
        for frame_num, pkt in enumerate(reader, start=1):
            total_packets += 1
            pkt_time = float(pkt.time) if hasattr(pkt, "time") else 0.0

            if first_timestamp is None or pkt_time < first_timestamp:
                first_timestamp = pkt_time
            if last_timestamp is None or pkt_time > last_timestamp:
                last_timestamp = pkt_time

            # IP extraction & Protocol tracking
            src_ip = None
            dst_ip = None
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                ip_counter[src_ip] += 1
                ip_counter[dst_ip] += 1
            elif pkt.haslayer("IPv6"):
                src_ip = pkt["IPv6"].src
                dst_ip = pkt["IPv6"].dst
                ip_counter[src_ip] += 1
                ip_counter[dst_ip] += 1

            # Protocol categorization
            is_http = False
            if pkt.haslayer(HTTPRequest) or pkt.haslayer(HTTPResponse):
                is_http = True
                protocol_counts["HTTP"] += 1
            elif pkt.haslayer(TCP):
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                if sport == 443 or dport == 443 or pkt.haslayer("TLS"):
                    protocol_counts["TLS/HTTPS"] += 1
                elif sport == 80 or dport == 80 or sport == 8080 or dport == 8080:
                    protocol_counts["HTTP"] += 1
                else:
                    protocol_counts["TCP"] += 1
            elif pkt.haslayer(UDP):
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                if sport == 53 or dport == 53 or pkt.haslayer("DNS"):
                    protocol_counts["DNS"] += 1
                else:
                    protocol_counts["UDP"] += 1
            elif pkt.haslayer(ICMP):
                protocol_counts["ICMP"] += 1
            elif pkt.haslayer(ARP):
                protocol_counts["ARP"] += 1
            else:
                protocol_counts["Other"] += 1

            # TCP & HTTP Reassembly
            if not (pkt.haslayer(TCP) and src_ip and dst_ip):
                continue

            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
            endpoint_a = (src_ip, sport)
            endpoint_b = (dst_ip, dport)
            stream_key = (min(endpoint_a, endpoint_b), max(endpoint_a, endpoint_b))
            stream_id = f"{stream_key[0][0]}:{stream_key[0][1]} <-> {stream_key[1][0]}:{stream_key[1][1]}"
            stream_packet_counts[stream_id] += 1

            # Detect HTTP Request or Response
            http_type = None
            http_layer = None

            if pkt.haslayer(HTTPRequest):
                http_type = "request"
                http_layer = pkt[HTTPRequest]
            elif pkt.haslayer(HTTPResponse):
                http_type = "response"
                http_layer = pkt[HTTPResponse]
            elif pkt.haslayer(scapy.Raw):
                http_type, http_layer = _check_raw_http(pkt[scapy.Raw].load)

            if http_type == "request" and http_layer is not None:
                method = _decode_bytes(getattr(http_layer, "Method", "GET")).upper()
                uri = _decode_bytes(getattr(http_layer, "Path", "/"))
                host = _decode_bytes(getattr(http_layer, "Host", ""))
                http_ver = _decode_bytes(getattr(http_layer, "Http_Version", "HTTP/1.1"))
                req_headers = _extract_headers(http_layer)
                req_body = _extract_body(pkt if pkt.haslayer(scapy.Raw) else http_layer)

                req_obj = {
                    "frame_num": frame_num,
                    "timestamp": pkt_time,
                    "formatted_time": datetime.datetime.fromtimestamp(pkt_time).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] if pkt_time else "",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": sport,
                    "dst_port": dport,
                    "method": method,
                    "uri": uri,
                    "host": host,
                    "version": http_ver,
                    "headers": req_headers,
                    "body": req_body,
                    "stream_id": stream_id,
                }
                pending_requests[stream_key].append(req_obj)

            elif http_type == "response" and http_layer is not None:
                status_raw = getattr(http_layer, "Status_Code", None)
                reason_raw = getattr(http_layer, "Reason_Phrase", None)

                status_code = None
                if status_raw is not None:
                    try:
                        status_code = int(_decode_bytes(status_raw))
                    except (ValueError, TypeError):
                        pass

                reason_phrase = _decode_bytes(reason_raw) if reason_raw else ""
                resp_headers = _extract_headers(http_layer)
                resp_body = _extract_body(pkt if pkt.haslayer(scapy.Raw) else http_layer)

                # Match with pending request on this stream (FIFO)
                if pending_requests[stream_key]:
                    req_obj = pending_requests[stream_key].popleft()
                    response_time = max(0.0, pkt_time - req_obj["timestamp"])
                    response_time_ms = round(response_time * 1000.0, 2)

                    trans_id = len(completed_transactions) + 1
                    is_error = bool(status_code and status_code >= 400)

                    transaction = {
                        "transaction_id": trans_id,
                        "method": req_obj["method"],
                        "uri": req_obj["uri"],
                        "host": req_obj["host"] or f"{req_obj['dst_ip']}:{req_obj['dst_port']}",
                        "src_ip": req_obj["src_ip"],
                        "dst_ip": req_obj["dst_ip"],
                        "src_port": req_obj["src_port"],
                        "dst_port": req_obj["dst_port"],
                        "status_code": status_code,
                        "reason_phrase": reason_phrase,
                        "response_time_sec": round(response_time, 4),
                        "response_time_ms": response_time_ms,
                        "req_frame_num": req_obj["frame_num"],
                        "resp_frame_num": frame_num,
                        "req_timestamp": req_obj["formatted_time"],
                        "resp_timestamp": datetime.datetime.fromtimestamp(pkt_time).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] if pkt_time else "",
                        "is_error": is_error,
                        "tcp_stream_id": stream_id,
                        "req_headers": req_obj["headers"],
                        "resp_headers": resp_headers,
                        "req_body": req_obj["body"],
                        "resp_body": resp_body,
                    }
                    completed_transactions.append(transaction)

    # Format summary stats
    start_str = datetime.datetime.fromtimestamp(first_timestamp).strftime("%Y-%m-%d %H:%M:%S") if first_timestamp else "N/A"
    end_str = datetime.datetime.fromtimestamp(last_timestamp).strftime("%Y-%m-%d %H:%M:%S") if last_timestamp else "N/A"
    duration_sec = round(max(0.0, (last_timestamp - first_timestamp)), 2) if (first_timestamp and last_timestamp) else 0.0

    sorted_endpoints = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)
    total_http_errors = sum(1 for t in completed_transactions if t["is_error"])

    summary = {
        "total_packets": total_packets,
        "start_time": start_str,
        "end_time": end_str,
        "duration_sec": duration_sec,
        "protocol_counts": dict(protocol_counts),
        "top_endpoints": sorted_endpoints[:10],
        "all_endpoints_count": len(ip_counter),
        "total_http_transactions": len(completed_transactions),
        "total_http_errors": total_http_errors,
        "total_tcp_streams": len(stream_packet_counts),
    }

    return {
        "summary": summary,
        "transactions": completed_transactions,
    }


def serialize_transactions_for_rag(transactions: List[Dict[str, Any]], summary: Dict[str, Any]) -> str:
    """
    Serializes extracted structured HTTP data into a clean JSON representation
    for LLM prompt injection (RAG context). Never includes raw packet bytes!
    """
    import json

    # Slim down fields slightly for token efficiency while retaining all critical data
    clean_txs = []
    for tx in transactions:
        clean_txs.append({
            "id": tx["transaction_id"],
            "method": tx["method"],
            "uri": tx["uri"],
            "host": tx["host"],
            "status_code": tx["status_code"],
            "reason_phrase": tx["reason_phrase"],
            "response_time_ms": tx["response_time_ms"],
            "req_frame": tx["req_frame_num"],
            "resp_frame": tx["resp_frame_num"],
            "req_time": tx["req_timestamp"],
            "resp_time": tx["resp_timestamp"],
            "client": f"{tx['src_ip']}:{tx['src_port']}",
            "server": f"{tx['dst_ip']}:{tx['dst_port']}",
            "tcp_stream": tx["tcp_stream_id"],
            "req_headers": tx["req_headers"],
            "resp_headers": tx["resp_headers"],
            "req_body": tx["req_body"] if tx["req_body"] else None,
            "resp_body": tx["resp_body"] if tx["resp_body"] else None,
        })

    payload = {
        "capture_summary": {
            "total_packets": summary["total_packets"],
            "start_time": summary["start_time"],
            "end_time": summary["end_time"],
            "duration_sec": summary["duration_sec"],
            "total_http_transactions": summary["total_http_transactions"],
            "total_http_errors": summary["total_http_errors"],
            "protocol_distribution": summary["protocol_counts"],
            "top_endpoints": summary["top_endpoints"][:5],
        },
        "http_transactions": clean_txs,
    }

    return json.dumps(payload, indent=2, ensure_ascii=False)
