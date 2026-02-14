# Volt Typhoon LOTL Reconnaissance Module
# Demonstrates living-off-the-land techniques using native Windows binaries
# MITRE ATT&CK: T1082, T1016, T1049, T1057, T1018

# For educational and research purposes only
# Author: Nour A
# Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a

import subprocess
import os
import sys
import re
import json
import socket
import struct
import ctypes
from ctypes import wintypes
from datetime import datetime


# -- WMI via COM for stealthy host enumeration --

def wmi_query(wql):
    """Execute a WMI query via wmic.exe and parse structured output."""
    try:
        result = subprocess.run(
            ["wmic", "path", wql.split(" FROM ")[-1].split()[0],
             "get", "/format:list"],
            capture_output=True, text=True, timeout=15
        )
        entries = []
        current = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if "=" in line:
                key, val = line.split("=", 1)
                current[key.strip()] = val.strip()
            elif not line and current:
                entries.append(current)
                current = {}
        if current:
            entries.append(current)
        return entries
    except Exception as e:
        return [{"error": str(e)}]


def lotl_systeminfo():
    """T1082 - System Information Discovery via native systeminfo.exe"""
    print("[*] Running systeminfo.exe (T1082)...")
    try:
        proc = subprocess.run(
            ["systeminfo"], capture_output=True, text=True, timeout=30
        )
        info = {}
        for line in proc.stdout.splitlines():
            if ":" in line:
                parts = line.split(":", 1)
                info[parts[0].strip()] = parts[1].strip()
        return info
    except subprocess.TimeoutExpired:
        return {"error": "systeminfo timed out"}


def lotl_network_config():
    """T1016 - System Network Configuration Discovery via netsh/ipconfig"""
    results = {}

    # ipconfig /all for adapter details
    try:
        proc = subprocess.run(
            ["ipconfig", "/all"], capture_output=True, text=True, timeout=10
        )
        results["ipconfig"] = proc.stdout
    except Exception:
        pass

    # netsh interface show interface - adapter states
    try:
        proc = subprocess.run(
            ["netsh", "interface", "show", "interface"],
            capture_output=True, text=True, timeout=10
        )
        adapters = []
        for line in proc.stdout.splitlines()[3:]:
            parts = line.split()
            if len(parts) >= 4:
                adapters.append({
                    "state": parts[0],
                    "type": parts[1],
                    "name": " ".join(parts[3:])
                })
        results["adapters"] = adapters
    except Exception:
        pass

    # ARP table for neighbor discovery
    try:
        proc = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=10
        )
        results["arp_table"] = proc.stdout
    except Exception:
        pass

    # Route table
    try:
        proc = subprocess.run(
            ["route", "print"], capture_output=True, text=True, timeout=10
        )
        results["routes"] = proc.stdout
    except Exception:
        pass

    return results


def lotl_connections():
    """T1049 - System Network Connections Discovery via netstat"""
    try:
        proc = subprocess.run(
            ["netstat", "-ano"], capture_output=True, text=True, timeout=15
        )
        connections = []
        for line in proc.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0] in ("TCP", "UDP"):
                connections.append({
                    "proto": parts[0],
                    "local": parts[1],
                    "remote": parts[2] if parts[0] == "TCP" else "*:*",
                    "state": parts[3] if parts[0] == "TCP" else "N/A",
                    "pid": parts[-1]
                })
        return connections
    except Exception as e:
        return [{"error": str(e)}]


def lotl_process_discovery():
    """T1057 - Process Discovery via tasklist and WMIC"""
    try:
        proc = subprocess.run(
            ["tasklist", "/V", "/FO", "CSV"],
            capture_output=True, text=True, timeout=15
        )
        processes = []
        lines = proc.stdout.strip().splitlines()
        if lines:
            headers = [h.strip('"') for h in lines[0].split('","')]
            for line in lines[1:]:
                values = [v.strip('"') for v in line.split('","')]
                if len(values) == len(headers):
                    processes.append(dict(zip(headers, values)))
        return processes
    except Exception as e:
        return [{"error": str(e)}]


def lotl_security_product_enum():
    """Enumerate installed security products via WMI - key Volt Typhoon recon step"""
    products = []

    # AntiVirus products (Security Center)
    try:
        proc = subprocess.run(
            ["wmic", "/namespace:\\\\root\\SecurityCenter2", "path",
             "AntiVirusProduct", "get", "displayName,productState",
             "/format:list"],
            capture_output=True, text=True, timeout=10
        )
        current = {}
        for line in proc.stdout.splitlines():
            line = line.strip()
            if "=" in line:
                k, v = line.split("=", 1)
                current[k] = v
            elif not line and current:
                products.append(current)
                current = {}
        if current:
            products.append(current)
    except Exception:
        pass

    # Firewall state via netsh
    try:
        proc = subprocess.run(
            ["netsh", "advfirewall", "show", "allprofiles", "state"],
            capture_output=True, text=True, timeout=10
        )
        products.append({"FirewallState": proc.stdout.strip()})
    except Exception:
        pass

    return products


def lotl_event_log_clearing():
    """T1070.001 - Clear Windows Event Logs via wevtutil
    Volt Typhoon clears Security/System logs to cover tracks.
    """
    log_names = ["Security", "System", "Application"]
    results = {}
    for log in log_names:
        # Query log size first (non-destructive recon)
        try:
            proc = subprocess.run(
                ["wevtutil", "gli", log],
                capture_output=True, text=True, timeout=10
            )
            results[log] = proc.stdout.strip()
        except Exception as e:
            results[log] = str(e)
    return results


def lotl_scheduled_tasks():
    """Enumerate scheduled tasks for persistence opportunities"""
    try:
        proc = subprocess.run(
            ["schtasks", "/query", "/FO", "CSV", "/V"],
            capture_output=True, text=True, timeout=20
        )
        tasks = []
        lines = proc.stdout.strip().splitlines()
        if lines:
            headers = [h.strip('"') for h in lines[0].split('","')]
            for line in lines[1:]:
                values = [v.strip('"') for v in line.split('","')]
                if len(values) == len(headers):
                    task = dict(zip(headers, values))
                    # filter to interesting tasks
                    if task.get("Status") == "Ready":
                        tasks.append(task)
        return tasks[:50]  # cap output
    except Exception as e:
        return [{"error": str(e)}]


def lotl_dns_cache():
    """Dump DNS client cache to reveal recent network activity"""
    try:
        proc = subprocess.run(
            ["ipconfig", "/displaydns"],
            capture_output=True, text=True, timeout=10
        )
        entries = []
        current = {}
        for line in proc.stdout.splitlines():
            line = line.strip()
            if "Record Name" in line:
                if current:
                    entries.append(current)
                current = {"name": line.split(":", 1)[-1].strip()}
            elif "Record Type" in line:
                current["type"] = line.split(":", 1)[-1].strip()
            elif "A (Host)" in line or "AAAA" in line:
                current["data"] = line.split(":", 1)[-1].strip()
        if current:
            entries.append(current)
        return entries
    except Exception:
        return []


def check_domain_membership():
    """Check if the host is domain-joined - critical for Volt Typhoon targeting"""
    try:
        proc = subprocess.run(
            ["wmic", "computersystem", "get",
             "domain,partofdomain,name", "/format:list"],
            capture_output=True, text=True, timeout=10
        )
        info = {}
        for line in proc.stdout.splitlines():
            line = line.strip()
            if "=" in line:
                k, v = line.split("=", 1)
                info[k] = v
        return info
    except Exception as e:
        return {"error": str(e)}


def main():
    print("=" * 70)
    print("VOLT TYPHOON LOTL RECONNAISSANCE")
    print("Living-off-the-Land Technique Demonstration")
    print("=" * 70)
    print()
    print("[!] FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY")
    print("[!] Reference: CISA Advisory AA24-038A")
    print()

    # Stage 1: Host identification
    print("[STAGE 1] System Information Discovery (T1082)")
    print("-" * 50)
    sysinfo = lotl_systeminfo()
    for key in ["Host Name", "OS Name", "OS Version", "System Type",
                "Domain", "Logon Server"]:
        if key in sysinfo:
            print(f"  {key}: {sysinfo[key]}")
    print()

    # Stage 2: Domain membership check
    print("[STAGE 2] Domain Membership Check")
    print("-" * 50)
    domain = check_domain_membership()
    for k, v in domain.items():
        print(f"  {k}: {v}")
    print()

    # Stage 3: Network configuration
    print("[STAGE 3] Network Configuration Discovery (T1016)")
    print("-" * 50)
    net = lotl_network_config()
    if "adapters" in net:
        for adapter in net["adapters"]:
            print(f"  [{adapter.get('state', '?')}] {adapter.get('name', 'Unknown')}")
    print()

    # Stage 4: Active connections
    print("[STAGE 4] Network Connections (T1049)")
    print("-" * 50)
    conns = lotl_connections()
    established = [c for c in conns if isinstance(c, dict)
                   and c.get("state") == "ESTABLISHED"]
    for c in established[:15]:
        print(f"  {c['proto']} {c['local']} -> {c['remote']} (PID: {c['pid']})")
    print(f"  Total ESTABLISHED: {len(established)}")
    print()

    # Stage 5: Security product enumeration
    print("[STAGE 5] Security Product Enumeration")
    print("-" * 50)
    products = lotl_security_product_enum()
    for p in products:
        if "displayName" in p:
            print(f"  AV: {p['displayName']}")
        elif "FirewallState" in p:
            for line in p["FirewallState"].splitlines():
                if "State" in line:
                    print(f"  {line.strip()}")
    print()

    # Stage 6: Process enumeration
    print("[STAGE 6] Process Discovery (T1057)")
    print("-" * 50)
    procs = lotl_process_discovery()
    # look for security tools
    security_names = ["MsMpEng", "SentinelAgent", "CrowdStrike",
                      "cb.exe", "cylance", "tanium"]
    for p in procs:
        name = p.get("Image Name", "")
        for sec in security_names:
            if sec.lower() in name.lower():
                print(f"  [SECURITY] {name} - PID: {p.get('PID', '?')}")
                break
    print(f"  Total processes: {len(procs)}")
    print()

    # Stage 7: DNS cache dump
    print("[STAGE 7] DNS Cache Analysis")
    print("-" * 50)
    dns = lotl_dns_cache()
    for entry in dns[:20]:
        print(f"  {entry.get('name', '?')} -> {entry.get('data', 'N/A')}")
    print(f"  Total cached entries: {len(dns)}")
    print()

    # Stage 8: Event log info
    print("[STAGE 8] Event Log Reconnaissance (T1070.001)")
    print("-" * 50)
    logs = lotl_event_log_clearing()
    for name, info in logs.items():
        print(f"  [{name}] {info[:100]}")
    print()

    print("=" * 70)
    print("[+] LOTL RECONNAISSANCE COMPLETE")
    print("  All data gathered using native Windows binaries only.")
    print("  Zero custom malware deployed (Volt Typhoon signature TTP).")
    print("=" * 70)


if __name__ == "__main__":
    main()
