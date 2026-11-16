import os
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.l2 import Ether, ARP

def create_sample_pcap(filepath_pcap, filepath_pcapng=None):
    pkts = []
    t = 1700000000.0

    # 1. ARP query and reply
    arp_req = Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff")/ARP(op="who-has", psrc="192.168.1.100", pdst="192.168.1.1")
    arp_req.time = t
    pkts.append(arp_req)

    arp_rep = Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff")/ARP(op="is-at", psrc="192.168.1.1", pdst="192.168.1.100")
    arp_rep.time = t + 0.002
    pkts.append(arp_rep)

    # 2. DNS query and response for example.com
    dns_q = Ether()/IP(src="192.168.1.100", dst="1.1.1.1")/UDP(sport=53123, dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com"))
    dns_q.time = t + 0.010
    pkts.append(dns_q)

    dns_r = Ether()/IP(src="1.1.1.1", dst="192.168.1.100")/UDP(sport=53, dport=53123)/DNS(qr=1, rd=1, qd=DNSQR(qname="example.com"), an=DNSRR(rrname="example.com", rdata="93.184.216.34"))
    dns_r.time = t + 0.025
    pkts.append(dns_r)

    # 3. Stream 1 (Client: 192.168.1.100:50123 <-> Server: 93.184.216.34:80)
    # Handshake
    s1_syn = Ether()/IP(src="192.168.1.100", dst="93.184.216.34")/TCP(sport=50123, dport=80, flags="S", seq=100)
    s1_syn.time = t + 0.030
    pkts.append(s1_syn)

    s1_synack = Ether()/IP(src="93.184.216.34", dst="192.168.1.100")/TCP(sport=80, dport=50123, flags="SA", seq=500, ack=101)
    s1_synack.time = t + 0.045
    pkts.append(s1_synack)

    s1_ack = Ether()/IP(src="192.168.1.100", dst="93.184.216.34")/TCP(sport=50123, dport=80, flags="A", seq=101, ack=501)
    s1_ack.time = t + 0.050
    pkts.append(s1_ack)

    # Tx 1: GET /index.html -> 200 OK (fast: 80 ms)
    req1_raw = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nAccept: text/html\r\n\r\n"
    req1 = Ether()/IP(src="192.168.1.100", dst="93.184.216.34")/TCP(sport=50123, dport=80, flags="PA", seq=101, ack=501)/req1_raw
    req1.time = t + 0.060
    pkts.append(req1)

    resp1_raw = b"HTTP/1.1 200 OK\r\nDate: Wed, 15 Nov 2023 00:13:20 GMT\r\nServer: Apache/2.4.41\r\nContent-Type: text/html\r\nContent-Length: 48\r\n\r\n<html><body><h1>Welcome to Example!</h1></body></html>"
    resp1 = Ether()/IP(src="93.184.216.34", dst="192.168.1.100")/TCP(sport=80, dport=50123, flags="PA", seq=501, ack=101 + len(req1_raw))/resp1_raw
    resp1.time = t + 0.140  # 80ms response time
    pkts.append(resp1)

    # Tx 2: POST /api/v1/auth/login -> 401 Unauthorized (250 ms)
    req2_raw = b"POST /api/v1/auth/login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 35\r\nUser-Agent: MobileApp/2.1\r\n\r\n{\"username\":\"admin\",\"password\":\"root\"}"
    req2 = Ether()/IP(src="192.168.1.100", dst="93.184.216.34")/TCP(sport=50123, dport=80, flags="PA", seq=101 + len(req1_raw), ack=501 + len(resp1_raw))/req2_raw
    req2.time = t + 0.300
    pkts.append(req2)

    resp2_raw = b"HTTP/1.1 401 Unauthorized\r\nServer: Apache/2.4.41\r\nContent-Type: application/json\r\nContent-Length: 38\r\n\r\n{\"error\":\"Invalid login credentials\"}"
    resp2 = Ether()/IP(src="93.184.216.34", dst="192.168.1.100")/TCP(sport=80, dport=50123, flags="PA", seq=501 + len(resp1_raw), ack=101 + len(req1_raw) + len(req2_raw))/resp2_raw
    resp2.time = t + 0.550  # 250ms response time
    pkts.append(resp2)

    # 4. Stream 2 (Client: 192.168.1.150:41234 <-> Server: 104.21.45.67:8080)
    # Tx 3: GET /api/v2/items?category=shoes -> 301 Moved Permanently (110 ms)
    req3_raw = b"GET /api/v2/items?category=shoes HTTP/1.1\r\nHost: cdn.shopzone.net:8080\r\nUser-Agent: curl/7.81.0\r\nAccept: */*\r\n\r\n"
    req3 = Ether()/IP(src="192.168.1.150", dst="104.21.45.67")/TCP(sport=41234, dport=8080, flags="PA", seq=1000, ack=2000)/req3_raw
    req3.time = t + 0.700
    pkts.append(req3)

    resp3_raw = b"HTTP/1.1 301 Moved Permanently\r\nLocation: https://cdn.shopzone.net/api/v3/items?category=shoes\r\nContent-Length: 0\r\n\r\n"
    resp3 = Ether()/IP(src="104.21.45.67", dst="192.168.1.150")/TCP(sport=8080, dport=41234, flags="PA", seq=2000, ack=1000 + len(req3_raw))/resp3_raw
    resp3.time = t + 0.810  # 110ms response time
    pkts.append(resp3)

    # 5. Stream 3 (Client: 192.168.1.150:41235 <-> Server: 172.217.16.206:80)
    # Tx 4: POST /api/checkout/process -> 500 Internal Server Error (420 ms)
    req4_raw = b"POST /api/checkout/process HTTP/1.1\r\nHost: payment.gateway.io\r\nContent-Type: application/json\r\nContent-Length: 42\r\n\r\n{\"cart_id\":9872,\"payment_token\":\"tok_test\"}"
    req4 = Ether()/IP(src="192.168.1.150", dst="172.217.16.206")/TCP(sport=41235, dport=80, flags="PA", seq=3000, ack=4000)/req4_raw
    req4.time = t + 1.100
    pkts.append(req4)

    resp4_raw = b"HTTP/1.1 500 Internal Server Error\r\nServer: nginx/1.22.0\r\nContent-Type: application/json\r\nContent-Length: 53\r\n\r\n{\"error\":\"Database connection timeout during payment\"}"
    resp4 = Ether()/IP(src="172.217.16.206", dst="192.168.1.150")/TCP(sport=80, dport=41235, flags="PA", seq=4000, ack=3000 + len(req4_raw))/resp4_raw
    resp4.time = t + 1.520  # 420ms response time
    pkts.append(resp4)

    # 6. Stream 4 (Client: 192.168.1.100:50888 <-> Server: 198.51.100.12:80)
    # Tx 5: GET /downloads/large_report.pdf -> 404 Not Found (SLOOWEST: 2350 ms!)
    req5_raw = b"GET /downloads/large_report.pdf HTTP/1.1\r\nHost: files.corp.net\r\nUser-Agent: Mozilla/5.0\r\nAccept: application/pdf\r\n\r\n"
    req5 = Ether()/IP(src="192.168.1.100", dst="198.51.100.12")/TCP(sport=50888, dport=80, flags="PA", seq=5000, ack=6000)/req5_raw
    req5.time = t + 2.000
    pkts.append(req5)

    resp5_raw = b"HTTP/1.1 404 Not Found\r\nServer: Microsoft-IIS/10.0\r\nContent-Type: text/html\r\nContent-Length: 32\r\n\r\n<h1>404 File Not Found on IIS</h1>"
    resp5 = Ether()/IP(src="198.51.100.12", dst="192.168.1.100")/TCP(sport=80, dport=50888, flags="PA", seq=6000, ack=5000 + len(req5_raw))/resp5_raw
    resp5.time = t + 4.350  # 2350ms response time! Slowest request
    pkts.append(resp5)

    # 7. Some HTTPS / TLS traffic (port 443)
    tls_syn = Ether()/IP(src="192.168.1.100", dst="142.250.190.46")/TCP(sport=59999, dport=443, flags="S", seq=7000)
    tls_syn.time = t + 4.400
    pkts.append(tls_syn)

    tls_synack = Ether()/IP(src="142.250.190.46", dst="192.168.1.100")/TCP(sport=443, dport=59999, flags="SA", seq=8000, ack=7001)
    tls_synack.time = t + 4.420
    pkts.append(tls_synack)

    scapy.wrpcap(filepath_pcap, pkts)
    print(f"Generated sample PCAP at {filepath_pcap} ({len(pkts)} packets).")

    if filepath_pcapng:
        scapy.wrpcapng(filepath_pcapng, pkts)
        print(f"Generated sample PCAPNG at {filepath_pcapng}.")

if __name__ == "__main__":
    pcap_path = r"C:\Users\ronig\.gemini\antigravity\scratch\pcap_analyzer\sample.pcap"
    pcapng_path = r"C:\Users\ronig\.gemini\antigravity\scratch\pcap_analyzer\sample.pcapng"
    create_sample_pcap(pcap_path, pcapng_path)
