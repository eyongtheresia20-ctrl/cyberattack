"""
Self-test script for CyberGuard System Agent.
Runs verification queries against local DNS and Proxy without affecting OS network settings.
"""
import socket
import struct
import urllib.request
import json
import sys

def build_dns_query(domain: str, qtype: int = 1) -> bytes:
    # Transaction ID: 0x1234, Flags: Standard query (0x0100)
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(part)]) + part.encode("ascii") for part in domain.split(".")) + b"\x00"
    qtail = struct.pack("!HH", qtype, 1) # Type A, Class IN
    return header + qname + qtail

def parse_dns_response(data: bytes) -> list:
    if len(data) < 12:
        return []
    ancount = struct.unpack("!H", data[6:8])[0]
    # Skip question section
    idx = 12
    while idx < len(data) and data[idx] != 0:
        idx += 1 + data[idx]
    idx += 5 # 0x00 + QTYPE (2) + QCLASS (2)
    ips = []
    for _ in range(ancount):
        if idx >= len(data): break
        # Skip name (either pointer 2 bytes or labels)
        if (data[idx] & 0xC0) == 0xC0:
            idx += 2
        else:
            while idx < len(data) and data[idx] != 0:
                idx += 1 + data[idx]
            idx += 1
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[idx:idx+10])
        idx += 10
        if rtype == 1 and rdlen == 4:
            ips.append(".".join(str(b) for b in data[idx:idx+4]))
        idx += rdlen
    return ips

def query_dns(domain: str, port: int = 5353) -> list:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(4.0)
    try:
        sock.sendto(build_dns_query(domain), ("127.0.0.1", port))
        data, _ = sock.recvfrom(2048)
        return parse_dns_response(data)
    except Exception as e:
        return [f"ERR: {e}"]
    finally:
        sock.close()

def query_proxy(url: str, proxy_url: str = "http://127.0.0.1:8899"):
    proxy_handler = urllib.request.ProxyHandler({'http': proxy_url, 'https': proxy_url})
    opener = urllib.request.build_opener(proxy_handler)
    req = urllib.request.Request(url, headers={'User-Agent': 'CyberGuard-SelfTest/1.0'})
    try:
        with opener.open(req, timeout=5.0) as resp:
            return resp.status, resp.read().decode('utf-8', errors='ignore')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', errors='ignore')
    except Exception as e:
        return 0, str(e)

if __name__ == "__main__":
    print("[*] 1. Test DNS Sinkhole (port 5353)")
    porn_ips = query_dns("pornhub.com", 5353)
    print("    - pornhub.com DNS answer:", porn_ips)
    google_ips = query_dns("google.com", 5353)
    print("    - google.com DNS answer :", google_ips)

    print("\n[*] 2. Test Proxy Interception (port 8899)")
    code_block, body_block = query_proxy("http://pornhub.com/")
    print(f"    - http://pornhub.com/ -> Status: {code_block}, Contains block page: {'CyberGuard' in body_block}")

    code_allow, body_allow = query_proxy("http://example.com/")
    print(f"    - http://example.com/ -> Status: {code_allow}")

    print("\n[*] 3. Test Backend Heartbeat & Events check")
    try:
        with urllib.request.urlopen("http://localhost:8000/api/v1/enterprise/agent/status", timeout=3.0) as resp:
            st = json.loads(resp.read().decode("utf-8"))
            print("    - Backend Agent Status:", st)
    except Exception as e:
        print("    - Backend error:", e)
