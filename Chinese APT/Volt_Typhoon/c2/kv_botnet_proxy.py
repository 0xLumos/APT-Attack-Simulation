# KV-Botnet SOCKS5 Proxy Module
# Implements a SOCKS5 proxy server mimicking Volt Typhoon's compromised router infrastructure
# MITRE ATT&CK: T1090.002 (External Proxy), T1572 (Protocol Tunneling)

# For educational and research purposes only
# Author: Nour A
# Reference: https://blog.lumen.com/routers-roasting-on-an-open-fire/

import socket
import struct
import select
import threading
import hashlib
import time
import sys
import os
from datetime import datetime

# SOCKS5 protocol constants (RFC 1928)
SOCKS_VERSION = 0x05
AUTH_NONE = 0x00
AUTH_USERPASS = 0x02
AUTH_REJECT = 0xFF
CMD_CONNECT = 0x01
CMD_BIND = 0x02
CMD_UDP = 0x03
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04
REP_SUCCESS = 0x00
REP_FAILURE = 0x01
REP_NOT_ALLOWED = 0x02
REP_NET_UNREACHABLE = 0x03
REP_HOST_UNREACHABLE = 0x04
REP_REFUSED = 0x05
REP_CMD_NOT_SUPPORTED = 0x07
REP_ATYP_NOT_SUPPORTED = 0x08

# KV-Botnet specific configuration
# These simulate the authentication tokens used between botnet nodes
KV_MAGIC = b"\x4b\x56\x42\x4e"  # "KVBN" - botnet identification header
KV_AUTH_TOKEN = hashlib.sha256(b"kv-botnet-node-auth").digest()[:16]


class KVBotnetNode:
    """Simulates a compromised SOHO router acting as a SOCKS5 proxy node.

    The KV-Botnet targeted end-of-life Cisco RV320/325 and NetGear ProSAFE
    routers. Each compromised device runs a SOCKS5 proxy to relay traffic,
    making attribution extremely difficult.
    """

    def __init__(self, listen_host="127.0.0.1", listen_port=1080,
                 auth_required=True):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.auth_required = auth_required
        self.running = False
        self.connections = []
        self.stats = {
            "total_connections": 0,
            "active_connections": 0,
            "bytes_relayed": 0,
            "start_time": None,
        }
        # simulated upstream proxy chain (multi-hop through botnet)
        self.upstream_proxies = [
            ("192.168.1.1", 1080, "Cisco RV320 (compromised)"),
            ("10.0.0.1", 1080, "NetGear ProSAFE (compromised)"),
            ("172.16.0.1", 1080, "DrayTek Vigor (compromised)"),
        ]

    def _kv_authenticate(self, client_sock):
        """Custom KV-Botnet node authentication.
        Before SOCKS5 negotiation, botnet nodes exchange a custom header.
        """
        try:
            # send magic bytes
            client_sock.settimeout(5)
            data = client_sock.recv(4)
            if data != KV_MAGIC:
                # not a botnet node, proceed with standard SOCKS5
                return data
            # exchange auth tokens
            client_sock.send(KV_AUTH_TOKEN)
            response = client_sock.recv(16)
            if response == KV_AUTH_TOKEN:
                print(f"  [KV] Authenticated botnet node")
                return None
            return data
        except socket.timeout:
            return None

    def _socks5_auth(self, client_sock):
        """Handle SOCKS5 authentication negotiation (RFC 1928 Section 3)"""
        # greeting: VER | NMETHODS | METHODS
        header = client_sock.recv(2)
        if len(header) < 2:
            return False

        version, nmethods = struct.unpack("!BB", header)
        if version != SOCKS_VERSION:
            return False

        methods = client_sock.recv(nmethods)

        if self.auth_required and AUTH_USERPASS in methods:
            # select username/password auth
            client_sock.send(struct.pack("!BB", SOCKS_VERSION, AUTH_USERPASS))
            return self._handle_userpass_auth(client_sock)
        elif AUTH_NONE in methods:
            client_sock.send(struct.pack("!BB", SOCKS_VERSION, AUTH_NONE))
            return True
        else:
            client_sock.send(struct.pack("!BB", SOCKS_VERSION, AUTH_REJECT))
            return False

    def _handle_userpass_auth(self, client_sock):
        """Handle SOCKS5 username/password auth (RFC 1929)"""
        version = client_sock.recv(1)
        ulen = struct.unpack("!B", client_sock.recv(1))[0]
        username = client_sock.recv(ulen).decode("utf-8", errors="ignore")
        plen = struct.unpack("!B", client_sock.recv(1))[0]
        password = client_sock.recv(plen).decode("utf-8", errors="ignore")

        # in the real botnet, credentials are hardcoded from the router compromise
        valid = (username == "admin" and password == "proxy")
        status = 0x00 if valid else 0x01
        client_sock.send(struct.pack("!BB", 0x01, status))
        return valid

    def _socks5_request(self, client_sock):
        """Parse SOCKS5 connection request (RFC 1928 Section 4)"""
        # VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
        header = client_sock.recv(4)
        if len(header) < 4:
            return None, None, None

        version, cmd, _, atyp = struct.unpack("!BBBB", header)

        if cmd != CMD_CONNECT:
            # only CONNECT is supported
            reply = struct.pack("!BBBBIH", SOCKS_VERSION, REP_CMD_NOT_SUPPORTED,
                                0x00, ATYP_IPV4, 0, 0)
            client_sock.send(reply)
            return None, None, None

        # parse destination address
        if atyp == ATYP_IPV4:
            raw_addr = client_sock.recv(4)
            dst_addr = socket.inet_ntoa(raw_addr)
        elif atyp == ATYP_DOMAIN:
            domain_len = struct.unpack("!B", client_sock.recv(1))[0]
            dst_addr = client_sock.recv(domain_len).decode("utf-8")
        elif atyp == ATYP_IPV6:
            raw_addr = client_sock.recv(16)
            dst_addr = socket.inet_ntop(socket.AF_INET6, raw_addr)
        else:
            reply = struct.pack("!BBBBIH", SOCKS_VERSION, REP_ATYP_NOT_SUPPORTED,
                                0x00, ATYP_IPV4, 0, 0)
            client_sock.send(reply)
            return None, None, None

        dst_port = struct.unpack("!H", client_sock.recv(2))[0]
        return cmd, dst_addr, dst_port

    def _relay(self, client_sock, remote_sock):
        """Bidirectional relay between client and remote (data forwarding)"""
        sockets = [client_sock, remote_sock]
        while self.running:
            try:
                readable, _, exceptional = select.select(sockets, [], sockets, 1)
            except (ValueError, OSError):
                break

            if exceptional:
                break

            for sock in readable:
                try:
                    data = sock.recv(8192)
                    if not data:
                        return
                    if sock is client_sock:
                        remote_sock.sendall(data)
                    else:
                        client_sock.sendall(data)
                    self.stats["bytes_relayed"] += len(data)
                except (ConnectionError, OSError):
                    return

    def handle_client(self, client_sock, addr):
        """Handle a single SOCKS5 client connection"""
        self.stats["active_connections"] += 1
        self.stats["total_connections"] += 1
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            print(f"  [{timestamp}] Connection from {addr[0]}:{addr[1]}")

            # SOCKS5 authentication
            if not self._socks5_auth(client_sock):
                print(f"  [{timestamp}] Authentication failed from {addr[0]}")
                return

            # parse request
            cmd, dst_addr, dst_port = self._socks5_request(client_sock)
            if dst_addr is None:
                return

            print(f"  [{timestamp}] CONNECT -> {dst_addr}:{dst_port}")

            # connect to destination
            try:
                remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote_sock.settimeout(10)
                remote_sock.connect((dst_addr, dst_port))

                # send success reply
                bind_addr = remote_sock.getsockname()
                reply = struct.pack("!BBBB", SOCKS_VERSION, REP_SUCCESS, 0x00, ATYP_IPV4)
                reply += socket.inet_aton(bind_addr[0])
                reply += struct.pack("!H", bind_addr[1])
                client_sock.send(reply)

                # relay data
                self._relay(client_sock, remote_sock)
                remote_sock.close()

            except socket.timeout:
                reply = struct.pack("!BBBBIH", SOCKS_VERSION, REP_HOST_UNREACHABLE,
                                    0x00, ATYP_IPV4, 0, 0)
                client_sock.send(reply)
            except ConnectionRefusedError:
                reply = struct.pack("!BBBBIH", SOCKS_VERSION, REP_REFUSED,
                                    0x00, ATYP_IPV4, 0, 0)
                client_sock.send(reply)
            except OSError:
                reply = struct.pack("!BBBBIH", SOCKS_VERSION, REP_NET_UNREACHABLE,
                                    0x00, ATYP_IPV4, 0, 0)
                client_sock.send(reply)

        except Exception as e:
            print(f"  [!] Error handling {addr}: {e}")
        finally:
            client_sock.close()
            self.stats["active_connections"] -= 1

    def start(self):
        """Start the SOCKS5 proxy server"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.listen_host, self.listen_port))
        server.listen(5)
        server.settimeout(1)
        self.running = True
        self.stats["start_time"] = datetime.now()

        print(f"[+] KV-Botnet SOCKS5 proxy listening on {self.listen_host}:{self.listen_port}")
        print(f"[+] Auth required: {self.auth_required}")
        print(f"[+] Simulated upstream chain:")
        for ip, port, desc in self.upstream_proxies:
            print(f"    -> {ip}:{port} ({desc})")
        print()

        try:
            while self.running:
                try:
                    client, addr = server.accept()
                    t = threading.Thread(target=self.handle_client,
                                        args=(client, addr), daemon=True)
                    t.start()
                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            print("\n[*] Shutting down proxy...")
        finally:
            self.running = False
            server.close()
            self._print_stats()

    def _print_stats(self):
        """Print session statistics"""
        print()
        print("=" * 50)
        print("KV-BOTNET NODE STATISTICS")
        print("=" * 50)
        print(f"  Total connections: {self.stats['total_connections']}")
        print(f"  Bytes relayed: {self.stats['bytes_relayed']}")
        if self.stats["start_time"]:
            uptime = datetime.now() - self.stats["start_time"]
            print(f"  Uptime: {uptime}")
        print("=" * 50)


def main():
    print("=" * 70)
    print("KV-BOTNET SOCKS5 PROXY NODE")
    print("Compromised SOHO Router C2 Proxy Simulation")
    print("=" * 70)
    print()
    print("[!] FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY")
    print("[!] Reference: Black Lotus Labs - KV-Botnet Analysis")
    print()

    host = "127.0.0.1"
    port = 1080

    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    if len(sys.argv) > 2:
        host = sys.argv[2]

    node = KVBotnetNode(listen_host=host, listen_port=port, auth_required=False)
    node.start()


if __name__ == "__main__":
    main()
