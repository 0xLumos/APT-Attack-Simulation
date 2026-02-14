# Volt Typhoon LOTL Discovery Script - PowerShell
# Demonstrates native system enumeration using only built-in PowerShell cmdlets
# MITRE ATT&CK: T1082, T1016, T1087, T1069, T1018, T1083

# For educational and research purposes only
# Author: Nour A
# Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a

# ============================================================
# STAGE 1: Host Enumeration
# ============================================================

Write-Host "=" * 70
Write-Host "VOLT TYPHOON LOTL DISCOVERY MODULE"
Write-Host "PowerShell-Based Native Reconnaissance"
Write-Host "=" * 70
Write-Host ""
Write-Host "[!] FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY" -ForegroundColor Red
Write-Host ""

# System Information via WMI
Write-Host "[STAGE 1] System Information Discovery (T1082)" -ForegroundColor Cyan
Write-Host ("-" * 50)
$os = Get-WmiObject Win32_OperatingSystem
$cs = Get-WmiObject Win32_ComputerSystem
Write-Host "  Hostname: $($cs.Name)"
Write-Host "  Domain: $($cs.Domain)"
Write-Host "  OS: $($os.Caption) $($os.Version)"
Write-Host "  Architecture: $($os.OSArchitecture)"
Write-Host "  Last Boot: $($os.ConvertToDateTime($os.LastBootUpTime))"
Write-Host "  Install Date: $($os.ConvertToDateTime($os.InstallDate))"
Write-Host ""

# ============================================================
# STAGE 2: Network Configuration
# ============================================================
Write-Host "[STAGE 2] Network Configuration Discovery (T1016)" -ForegroundColor Cyan
Write-Host ("-" * 50)

$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
foreach ($adapter in $adapters) {
    Write-Host "  Adapter: $($adapter.Description)"
    Write-Host "    IP: $($adapter.IPAddress -join ', ')"
    Write-Host "    Subnet: $($adapter.IPSubnet -join ', ')"
    Write-Host "    Gateway: $($adapter.DefaultIPGateway -join ', ')"
    Write-Host "    DNS: $($adapter.DNSServerSearchOrder -join ', ')"
    Write-Host "    DHCP: $($adapter.DHCPEnabled)"
    Write-Host ""
}

# DNS client cache
Write-Host "  [+] DNS Cache Entries:" -ForegroundColor Yellow
Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object -First 15 Entry, RecordType, Data | Format-Table -AutoSize

# ============================================================
# STAGE 3: User and Group Enumeration
# ============================================================
Write-Host "[STAGE 3] Account Discovery (T1087)" -ForegroundColor Cyan
Write-Host ("-" * 50)

# Local users
Write-Host "  Local Users:"
$users = Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True"
foreach ($user in $users) {
    $status = if ($user.Disabled) { "[DISABLED]" } else { "[ACTIVE]" }
    Write-Host "    $status $($user.Name) (SID: $($user.SID))"
}
Write-Host ""

# Local groups
Write-Host "  Local Groups:"
$groups = Get-WmiObject Win32_Group -Filter "LocalAccount=True"
foreach ($group in $groups) {
    Write-Host "    $($group.Name)"
}
Write-Host ""

# Active Directory enumeration (if domain-joined)
if ($cs.PartOfDomain) {
    Write-Host "  [+] Domain-joined host detected. Enumerating AD..." -ForegroundColor Yellow

    # Domain controllers via nltest
    try {
        $dclist = nltest /dclist:$($cs.Domain) 2>$null
        Write-Host "  Domain Controllers:"
        foreach ($line in $dclist) {
            if ($line -match "\\\\") {
                Write-Host "    $($line.Trim())"
            }
        }
    } catch {
        Write-Host "    [!] nltest failed (may not have domain access)"
    }

    # Domain trusts
    try {
        $trusts = nltest /domain_trusts 2>$null
        Write-Host "  Domain Trusts:"
        foreach ($line in $trusts) {
            if ($line -match "\.") {
                Write-Host "    $($line.Trim())"
            }
        }
    } catch {}

    Write-Host ""
}

# ============================================================
# STAGE 4: Remote System Discovery
# ============================================================
Write-Host "[STAGE 4] Remote System Discovery (T1018)" -ForegroundColor Cyan
Write-Host ("-" * 50)

# Network shares
Write-Host "  Network Shares:"
$shares = Get-WmiObject Win32_Share
foreach ($share in $shares) {
    Write-Host "    \\$($cs.Name)\$($share.Name) - $($share.Path) ($($share.Description))"
}
Write-Host ""

# ARP neighbors
Write-Host "  ARP Table (nearby hosts):"
$arp = Get-NetNeighbor -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Reachable" }
foreach ($entry in $arp) {
    Write-Host "    $($entry.IPAddress) -> $($entry.LinkLayerAddress) ($($entry.InterfaceAlias))"
}
Write-Host ""

# ============================================================
# STAGE 5: Security Product Detection
# ============================================================
Write-Host "[STAGE 5] Security Product Detection" -ForegroundColor Cyan
Write-Host ("-" * 50)

# AV products via WMI SecurityCenter2
try {
    $av = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction Stop
    foreach ($product in $av) {
        # decode productState bitmask
        $state = $product.productState
        $enabled = ($state -band 0x1000) -ne 0
        $upToDate = ($state -band 0x10) -eq 0
        Write-Host "  AV: $($product.displayName)"
        Write-Host "    Enabled: $enabled | Updated: $upToDate"
    }
} catch {
    Write-Host "  [!] SecurityCenter2 not available (server OS?)"
}

# Windows Defender status
try {
    $defender = Get-MpComputerStatus -ErrorAction Stop
    Write-Host "  Defender:"
    Write-Host "    Real-Time Protection: $($defender.RealTimeProtectionEnabled)"
    Write-Host "    Behavior Monitor: $($defender.BehaviorMonitorEnabled)"
    Write-Host "    Last Scan: $($defender.QuickScanEndTime)"
    Write-Host "    Signature Version: $($defender.AntivirusSignatureVersion)"
} catch {
    Write-Host "  [!] Get-MpComputerStatus not available"
}

# Firewall profiles
Write-Host "  Firewall Profiles:"
$fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue
foreach ($profile in $fw) {
    Write-Host "    $($profile.Name): Enabled=$($profile.Enabled)"
}
Write-Host ""

# ============================================================
# STAGE 6: File and Directory Discovery
# ============================================================
Write-Host "[STAGE 6] File and Directory Discovery (T1083)" -ForegroundColor Cyan
Write-Host ("-" * 50)

$interesting = @(
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\Downloads",
    "$env:APPDATA",
    "C:\inetpub\wwwroot",
    "C:\Program Files",
    "$env:USERPROFILE\.ssh"
)

foreach ($path in $interesting) {
    $expanded = [Environment]::ExpandEnvironmentVariables($path)
    if (Test-Path $expanded) {
        $count = (Get-ChildItem $expanded -ErrorAction SilentlyContinue | Measure-Object).Count
        Write-Host "  [EXISTS] $expanded ($count items)"
    }
}
Write-Host ""

# Sensitive file search (common patterns)
Write-Host "  [+] Searching for sensitive files..." -ForegroundColor Yellow
$patterns = @("*.kdbx", "*.key", "*.pem", "*.pfx", "*.p12", "*.ppk", "id_rsa*", "*.rdp", "*.ovpn")
foreach ($pattern in $patterns) {
    $found = Get-ChildItem -Path $env:USERPROFILE -Recurse -Filter $pattern -ErrorAction SilentlyContinue | Select-Object -First 3
    foreach ($f in $found) {
        Write-Host "    [FOUND] $($f.FullName) ($($f.Length) bytes)"
    }
}
Write-Host ""

# ============================================================
# STAGE 7: Scheduled Task & Service Enumeration
# ============================================================
Write-Host "[STAGE 7] Persistence Opportunity Enumeration" -ForegroundColor Cyan
Write-Host ("-" * 50)

# Writable scheduled tasks
Write-Host "  Scheduled Tasks (non-Microsoft):"
$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notmatch "\\Microsoft\\" -and $_.State -eq "Ready" }
foreach ($task in $tasks | Select-Object -First 10) {
    Write-Host "    $($task.TaskPath)$($task.TaskName) [$($task.State)]"
}

# Services with unquoted paths (privilege escalation opportunity)
Write-Host "  Services with unquoted paths:"
$services = Get-WmiObject Win32_Service | Where-Object { $_.PathName -notlike '"*' -and $_.PathName -match " " -and $_.StartMode -eq "Auto" }
foreach ($svc in $services | Select-Object -First 5) {
    Write-Host "    $($svc.Name): $($svc.PathName)"
}
Write-Host ""

# ============================================================
# STAGE 8: Event Log Reconnaissance
# ============================================================
Write-Host "[STAGE 8] Event Log Reconnaissance (T1070.001)" -ForegroundColor Cyan
Write-Host ("-" * 50)

$logNames = @("Security", "System", "Application", "Windows PowerShell")
foreach ($logName in $logNames) {
    try {
        $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
        Write-Host "  $logName : $($log.RecordCount) records | Max: $($log.MaximumSizeInBytes / 1MB) MB"
    } catch {
        Write-Host "  $logName : [ACCESS DENIED]"
    }
}
Write-Host ""

# Check for recent logon events
Write-Host "  Recent logon events (last 5):"
try {
    $logons = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 5 -ErrorAction Stop
    foreach ($event in $logons) {
        Write-Host "    $($event.TimeCreated) - Logon Type: $($event.Properties[8].Value) User: $($event.Properties[5].Value)"
    }
} catch {
    Write-Host "    [!] Cannot read Security log (need admin)"
}
Write-Host ""

# ============================================================
# SUMMARY
# ============================================================
Write-Host "=" * 70
Write-Host "[+] LOTL DISCOVERY COMPLETE" -ForegroundColor Green
Write-Host "  All enumeration performed using native PowerShell cmdlets."
Write-Host "  No external tools or custom binaries were used."
Write-Host "  This is the hallmark of Volt Typhoon tradecraft."
Write-Host "=" * 70
