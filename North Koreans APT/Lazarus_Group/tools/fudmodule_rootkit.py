# Lazarus Group - FudModule Rootkit Simulation
# Demonstrates kernel-level EDR bypass techniques via Windows API manipulation
# MITRE ATT&CK: T1562.001 (Disable or Modify Tools), T1068 (Privilege Escalation)

# For educational and research purposes only
# Author: Nour A
# Reference: https://decoded.avast.io/janvojtesek/lazarus-and-the-fudmodule-rootkit/
# CVEs: CVE-2024-38193 (AFD.sys), CVE-2024-21338 (appid.sys)

import ctypes
import ctypes.wintypes as wintypes
import struct
import os
import sys

# Windows API constants
NTSTATUS = ctypes.c_long
PVOID = ctypes.c_void_p
ULONG = ctypes.c_ulong
STATUS_SUCCESS = 0
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004

# SystemHandleInformation class for NtQuerySystemInformation
SystemHandleInformation = 16
SystemExtendedHandleInformation = 64

# Process access rights
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_DUP_HANDLE = 0x0040

# Object type indices for common kernel objects
OB_TYPE_PROCESS = 7
OB_TYPE_THREAD = 8
OB_TYPE_TOKEN = 5

# Kernel callback types that FudModule strips
CALLBACK_TYPES = [
    "PsSetCreateProcessNotifyRoutine",
    "PsSetCreateThreadNotifyRoutine",
    "PsSetLoadImageNotifyRoutine",
    "CmRegisterCallback",
    "ObRegisterCallbacks",
    "MiniFilterCallbacks",
]

# known EDR driver names that FudModule targets
EDR_DRIVERS = [
    "SentinelOne",
    "CrowdStrike (csagent.sys)",
    "Microsoft Defender (WdFilter.sys)",
    "Carbon Black (carbonblackk.sys)",
    "Sophos (hmpalert.sys)",
    "ESET (ekbdflt.sys)",
    "Kaspersky (klif.sys)",
    "Trend Micro (tmcomm.sys)",
    "Cylance (CyProtectDrv64.sys)",
    "Symantec (SRTSP64.sys)",
]

ntdll = ctypes.WinDLL("ntdll")
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)


class SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(ctypes.Structure):
    _fields_ = [
        ("Object", PVOID),
        ("UniqueProcessId", ctypes.POINTER(ctypes.c_ulong)),
        ("HandleValue", ctypes.POINTER(ctypes.c_ulong)),
        ("GrantedAccess", ULONG),
        ("CreatorBackTraceIndex", ctypes.c_ushort),
        ("ObjectTypeIndex", ctypes.c_ushort),
        ("HandleAttributes", ULONG),
        ("Reserved", ULONG),
    ]


class SYSTEM_HANDLE_INFORMATION_EX(ctypes.Structure):
    _fields_ = [
        ("NumberOfHandles", ctypes.POINTER(ctypes.c_ulong)),
        ("Reserved", ctypes.POINTER(ctypes.c_ulong)),
        ("Handles", SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX * 1),
    ]


def enumerate_system_handles():
    """Enumerate all system handles using NtQuerySystemInformation.
    FudModule uses this to find handles belonging to EDR processes.
    """
    NtQuerySystemInformation = ntdll.NtQuerySystemInformation
    NtQuerySystemInformation.restype = NTSTATUS
    NtQuerySystemInformation.argtypes = [
        ULONG, PVOID, ULONG, ctypes.POINTER(ULONG)
    ]

    # start with 1MB buffer, grow as needed
    buf_size = ULONG(1024 * 1024)
    buf = ctypes.create_string_buffer(buf_size.value)
    return_length = ULONG(0)

    while True:
        status = NtQuerySystemInformation(
            SystemHandleInformation,
            buf,
            buf_size,
            ctypes.byref(return_length)
        )
        if status == STATUS_INFO_LENGTH_MISMATCH:
            buf_size = ULONG(return_length.value * 2)
            buf = ctypes.create_string_buffer(buf_size.value)
            continue
        break

    if status != STATUS_SUCCESS:
        print(f"  [!] NtQuerySystemInformation returned: 0x{status & 0xFFFFFFFF:08X}")
        return []

    # parse handle count from buffer
    handle_count = struct.unpack_from("<I", buf.raw, 0)[0]
    print(f"  [+] Total system handles: {handle_count}")

    # parse a subset of handles (first 100 for demo)
    handles = []
    offset = 8  # skip NumberOfHandles + Reserved
    entry_size = 28  # size of SYSTEM_HANDLE_TABLE_ENTRY_INFO on x64

    for i in range(min(handle_count, 100)):
        if offset + entry_size > len(buf.raw):
            break
        try:
            pid = struct.unpack_from("<I", buf.raw, offset)[0]
            handle_val = struct.unpack_from("<H", buf.raw, offset + 4)[0]
            access = struct.unpack_from("<I", buf.raw, offset + 8)[0]
            obj_type = struct.unpack_from("<B", buf.raw, offset + 12)[0]
            handles.append({
                "pid": pid,
                "handle": handle_val,
                "access": access,
                "type": obj_type
            })
        except struct.error:
            break
        offset += entry_size

    return handles


def enumerate_loaded_drivers():
    """Enumerate loaded kernel drivers via NtQuerySystemInformation.
    FudModule checks for EDR drivers before attempting to strip their callbacks.
    """
    SystemModuleInformation = 11

    NtQuerySystemInformation = ntdll.NtQuerySystemInformation
    NtQuerySystemInformation.restype = NTSTATUS
    NtQuerySystemInformation.argtypes = [
        ULONG, PVOID, ULONG, ctypes.POINTER(ULONG)
    ]

    buf_size = ULONG(1024 * 1024)
    buf = ctypes.create_string_buffer(buf_size.value)
    return_length = ULONG(0)

    status = NtQuerySystemInformation(
        SystemModuleInformation,
        buf,
        buf_size,
        ctypes.byref(return_length)
    )

    if status != STATUS_SUCCESS:
        # try alternative: psapi.EnumDeviceDrivers
        return enumerate_drivers_psapi()

    # parse module count
    module_count = struct.unpack_from("<I", buf.raw, 0)[0]
    print(f"  [+] Loaded kernel modules: {module_count}")

    drivers = []
    offset = 8
    for i in range(min(module_count, 200)):
        try:
            # extract driver name from the structure
            name_offset = offset + 36
            name = buf.raw[name_offset:name_offset + 256]
            name = name.split(b"\x00")[0].decode("ascii", errors="ignore")
            if name:
                drivers.append(name)
        except Exception:
            pass
        offset += 296  # size of RTL_PROCESS_MODULE_INFORMATION

    return drivers


def enumerate_drivers_psapi():
    """Fallback driver enumeration using psapi.EnumDeviceDrivers"""
    psapi = ctypes.WinDLL("psapi")

    needed = wintypes.DWORD(0)
    psapi.EnumDeviceDrivers(None, 0, ctypes.byref(needed))

    count = needed.value // ctypes.sizeof(PVOID)
    drivers_array = (PVOID * count)()
    psapi.EnumDeviceDrivers(
        ctypes.byref(drivers_array),
        needed,
        ctypes.byref(needed)
    )

    drivers = []
    name_buf = ctypes.create_string_buffer(1024)
    for addr in drivers_array:
        if addr:
            psapi.GetDeviceDriverBaseNameA(addr, name_buf, 1024)
            name = name_buf.value.decode("ascii", errors="ignore")
            if name:
                drivers.append(name)

    return drivers


def check_edr_drivers(loaded_drivers):
    """Cross-reference loaded drivers against known EDR driver names.
    FudModule specifically targets these drivers for callback stripping.
    """
    edr_keywords = [
        "csagent", "WdFilter", "carbonblack", "hmpalert", "ekbdflt",
        "klif", "tmcomm", "CyProtect", "SRTSP", "SentinelMonitor",
        "epfw", "fsgk", "KLnSR", "avgtpx86", "aswSnx"
    ]

    found = []
    for driver in loaded_drivers:
        driver_lower = driver.lower()
        for keyword in edr_keywords:
            if keyword.lower() in driver_lower:
                found.append({"driver": driver, "edr_match": keyword})
                break

    return found


def simulate_callback_stripping():
    """Simulate FudModule's kernel callback stripping technique.
    The rootkit locates and removes notification callbacks registered
    by EDR drivers, effectively blinding them.
    """
    print("  [+] Simulating kernel callback enumeration:")
    print()

    for callback_type in CALLBACK_TYPES:
        print(f"    Callback: {callback_type}")
        # in reality, FudModule reads the callback array from kernel memory
        # by resolving the symbol from ntoskrnl.exe exports
        print(f"      -> Locating callback array in ntoskrnl.exe")
        print(f"      -> Enumerating registered routines")

        # simulate finding EDR callbacks to strip
        edr_count = 0
        for edr in EDR_DRIVERS[:3]:
            edr_count += 1
            print(f"      -> Found: {edr} callback [WOULD STRIP]")

        print(f"      -> Total callbacks to strip: {edr_count}")
        print()


def simulate_handle_table_manipulation():
    """Simulate FudModule's handle table manipulation.
    FudModule modifies the handle table of EDR processes to revoke
    their access to protected process handles.
    """
    print("  [+] Simulating handle table manipulation:")
    print()

    # target handles that EDRs use
    handle_types = {
        "Process handles": "Used for process monitoring",
        "Thread handles": "Used for thread injection detection",
        "Registry key handles": "Used for config protection",
        "File handles": "Used for file monitoring callbacks",
    }

    for handle_type, description in handle_types.items():
        print(f"    {handle_type}: {description}")
        print(f"      -> Scanning handle table for target EDR PIDs")
        print(f"      -> Revoking GENERIC_READ | GENERIC_WRITE access")
        print(f"      -> Setting GrantedAccess = 0x0 [WOULD MODIFY]")
        print()


def simulate_cve_2024_38193():
    """Simulate the AFD.sys (Ancillary Function Driver) exploit.
    CVE-2024-38193: use-after-free in afd.sys allowing SYSTEM privileges.
    Lazarus used this zero-day to load FudModule as a kernel driver.
    """
    print("  [+] CVE-2024-38193 - AFD.sys Use-After-Free:")
    print()
    print("    Vulnerability: afd.sys!AfdNotifyRemoveIoCompletion")
    print("    Type: Use-After-Free / Race Condition")
    print("    Impact: Local Privilege Escalation to SYSTEM")
    print()
    print("    Exploitation steps:")
    print("    1. Create IoCompletionPort with crafted NtSetIoCompletion")
    print("    2. Trigger race between AfdNotifyRemoveIoCompletion")
    print("       and NtRemoveIoCompletionEx")
    print("    3. UAF on IoCompletion object gives arbitrary R/W")
    print("    4. Overwrite _SEP_TOKEN_PRIVILEGES in current process token")
    print("    5. Enable all privileges -> load unsigned kernel driver")
    print()

    # demonstrate the token manipulation concept
    print("    Token privilege manipulation (concept):")
    print("    Current token privileges:")

    try:
        token = wintypes.HANDLE()
        advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(),
            0x0008,  # TOKEN_QUERY
            ctypes.byref(token)
        )

        # query token privileges
        buf = ctypes.create_string_buffer(4096)
        return_length = wintypes.DWORD(0)
        advapi32.GetTokenInformation(
            token, 3,  # TokenPrivileges
            buf, 4096,
            ctypes.byref(return_length)
        )

        priv_count = struct.unpack_from("<I", buf.raw, 0)[0]
        print(f"      Privilege count: {priv_count}")
        print(f"      [After exploit: all 35 privileges would be enabled]")

        kernel32.CloseHandle(token)
    except Exception as e:
        print(f"      Could not query token: {e}")


def main():
    print("=" * 70)
    print("LAZARUS GROUP - FUDMODULE ROOTKIT SIMULATION")
    print("Kernel-Level EDR Bypass Demonstration")
    print("=" * 70)
    print()
    print("[!] FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY")
    print("[!] Reference: Avast/ESET - FudModule Rootkit Analysis")
    print()

    # Stage 1: Enumerate system handles
    print("[STAGE 1] System Handle Enumeration")
    print("-" * 50)
    handles = enumerate_system_handles()
    if handles:
        print(f"  Sample handles (first 10):")
        for h in handles[:10]:
            print(f"    PID: {h['pid']:>6} | Handle: 0x{h['handle']:04X} | "
                  f"Access: 0x{h['access']:08X} | Type: {h['type']}")
    print()

    # Stage 2: Enumerate loaded kernel drivers
    print("[STAGE 2] Kernel Driver Enumeration")
    print("-" * 50)
    drivers = enumerate_loaded_drivers()
    print(f"  Total drivers: {len(drivers)}")
    for d in drivers[:15]:
        print(f"    {d}")
    print()

    # Stage 3: Check for EDR drivers
    print("[STAGE 3] EDR Driver Detection")
    print("-" * 50)
    edr_found = check_edr_drivers(drivers)
    if edr_found:
        for edr in edr_found:
            print(f"  [DETECTED] {edr['driver']} (matched: {edr['edr_match']})")
    else:
        print("  No EDR drivers detected in loaded modules")
    print()

    # Stage 4: Callback stripping simulation
    print("[STAGE 4] Kernel Callback Stripping (Simulated)")
    print("-" * 50)
    simulate_callback_stripping()

    # Stage 5: Handle table manipulation
    print("[STAGE 5] Handle Table Manipulation (Simulated)")
    print("-" * 50)
    simulate_handle_table_manipulation()

    # Stage 6: CVE-2024-38193 exploitation
    print("[STAGE 6] CVE-2024-38193 - AFD.sys Privilege Escalation")
    print("-" * 50)
    simulate_cve_2024_38193()
    print()

    print("=" * 70)
    print("[+] FUDMODULE ROOTKIT SIMULATION COMPLETE")
    print("  Techniques demonstrated:")
    print("  - NtQuerySystemInformation handle/driver enumeration")
    print("  - EDR driver detection and targeting")
    print("  - Kernel callback stripping concept")
    print("  - Handle table access revocation")
    print("  - Windows zero-day exploitation (CVE-2024-38193)")
    print("=" * 70)


if __name__ == "__main__":
    main()
