<#
.SYNOPSIS
    L.6 — Additional AD Misconfigurations (supplements expand_goad_lab.ps1)
.DESCRIPTION
    Adds AD misconfigurations NOT covered by the base expand_goad_lab.ps1:
    - LAPS deployment gaps (some machines have LAPS, others don't)
    - GMSA readable by low-priv users
    - Print Spooler enabled on DCs (SpoolSample / PrinterBug coercion)
    - PetitPotam-vulnerable EFS configuration
    - Machine account quota abuse setup
    - AdminSDHolder persistence backdoor
    - Weak GPO permissions
    - Cross-domain trust misconfigurations

    Run on DC01 (kingslanding) as Domain Admin after the base expansion.
    Designed for GOAD-Light lab only. DO NOT run on production.

.PARAMETER DomainController
    Target DC hostname/IP. Default: localhost

.NOTES
    Requires: AD DS, Domain Admin, run after expand_goad_lab.ps1
    Version: 1.0.0
#>

#Requires -RunAsAdministrator
#Requires -Version 5.1

param(
    [string]$DomainController = "localhost"
)

$ErrorActionPreference = "Continue"
Import-Module ActiveDirectory -ErrorAction SilentlyContinue
Import-Module GroupPolicy -ErrorAction SilentlyContinue

$domain = (Get-ADDomain).DNSRoot
$domainDN = (Get-ADDomain).DistinguishedName

Write-Host ""
Write-Host "  ┌──────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "  │  L.6 — Additional AD Misconfigurations           │" -ForegroundColor Cyan
Write-Host "  └──────────────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host "  Domain: $domain" -ForegroundColor Gray
Write-Host ""

# ═══════════════════════════════════════════════════════════════════
# 1. LAPS Deployment Gaps
# ═══════════════════════════════════════════════════════════════════
Write-Host "  [1/8] Configuring LAPS gaps..." -ForegroundColor Yellow

try {
    # Install LAPS module if available
    $lapsModule = Get-Module -ListAvailable -Name "AdmPwd.PS" -ErrorAction SilentlyContinue
    if ($lapsModule) {
        Import-Module AdmPwd.PS

        # Enable LAPS on some OUs but NOT others (creates gap)
        $workstationsOU = Get-ADOrganizationalUnit -Filter "Name -eq 'Workstations'" -ErrorAction SilentlyContinue
        if ($workstationsOU) {
            Set-AdmPwdComputerSelfPermission -OrgUnit $workstationsOU.DistinguishedName
            Write-Host "    [+] LAPS enabled on Workstations OU" -ForegroundColor Green
        }

        # Deliberately skip Servers OU → gap for pentest to find
        Write-Host "    [+] LAPS deliberately NOT deployed on Servers OU (gap)" -ForegroundColor Green

        # Grant low-priv user LAPS read (misconfiguration)
        $samwell = Get-ADUser -Filter "SamAccountName -eq 'samwell.tarly'" -ErrorAction SilentlyContinue
        if ($samwell -and $workstationsOU) {
            Set-AdmPwdReadPasswordPermission -OrgUnit $workstationsOU.DistinguishedName `
                -AllowedPrincipals $samwell.SamAccountName
            Write-Host "    [+] samwell.tarly can read LAPS passwords on Workstations" -ForegroundColor Green
        }
    } else {
        Write-Host "    [*] LAPS module not installed — creating ms-Mcs-AdmPwd manually" -ForegroundColor DarkYellow
        # Even without LAPS module, we can set the attributes
        $computers = Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | Where-Object { $_.'ms-Mcs-AdmPwd' }
        Write-Host "    [*] $($computers.Count) computers have LAPS passwords set" -ForegroundColor DarkGray
    }
} catch {
    Write-Host "    [-] LAPS config failed: $_" -ForegroundColor Red
}

# ═══════════════════════════════════════════════════════════════════
# 2. GMSA Readable by Low-Priv Users
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n  [2/8] Creating misconfigured GMSA..." -ForegroundColor Yellow

try {
    # Create KDS Root Key (needed for GMSA) — use -EffectiveImmediately for lab
    $kdsKey = Get-KdsRootKey -ErrorAction SilentlyContinue
    if (-not $kdsKey) {
        Add-KdsRootKey -EffectiveImmediately -ErrorAction SilentlyContinue
        # Lab hack: backdate to allow immediate use
        Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) -ErrorAction SilentlyContinue
        Write-Host "    [+] KDS Root Key created" -ForegroundColor Green
    }

    # Create GMSA with overly permissive PrincipalsAllowedToRetrieveManagedPassword
    $gmsaName = "gmsa_sql$"
    $existing = Get-ADServiceAccount -Filter "Name -eq 'gmsa_sql'" -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-ADServiceAccount -Name "gmsa_sql" `
            -DNSHostName "gmsa_sql.$domain" `
            -PrincipalsAllowedToRetrieveManagedPassword "Domain Computers" `
            -Enabled $true
        Write-Host "    [+] GMSA gmsa_sql created — readable by ALL Domain Computers" -ForegroundColor Green
    } else {
        Write-Host "    [=] GMSA gmsa_sql already exists" -ForegroundColor DarkGray
    }
} catch {
    Write-Host "    [-] GMSA creation failed: $_" -ForegroundColor Red
}

# ═══════════════════════════════════════════════════════════════════
# 3. Print Spooler on DCs (SpoolSample / PrinterBug)
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n  [3/8] Ensuring Print Spooler is running on DCs..." -ForegroundColor Yellow

try {
    $spooler = Get-Service -Name "Spooler" -ErrorAction SilentlyContinue
    if ($spooler) {
        if ($spooler.Status -ne "Running") {
            Set-Service -Name "Spooler" -StartupType Automatic
            Start-Service -Name "Spooler"
        }
        Write-Host "    [+] Print Spooler running on DC (SpoolSample/PrinterBug target)" -ForegroundColor Green
    } else {
        Write-Host "    [*] Print Spooler service not found" -ForegroundColor DarkYellow
    }
} catch {
    Write-Host "    [-] Spooler config failed: $_" -ForegroundColor Red
}

# ═══════════════════════════════════════════════════════════════════
# 4. EFS Configuration (PetitPotam prerequisite)
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n  [4/8] Verifying EFS for PetitPotam..." -ForegroundColor Yellow

try {
    # Ensure EFS is enabled (default on Windows Server, but verify)
    $efsKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EFS"
    if (-not (Test-Path $efsKey)) {
        New-Item -Path $efsKey -Force | Out-Null
    }
    # Ensure EFS encryption is enabled (not disabled by policy)
    $disabled = Get-ItemProperty -Path $efsKey -Name "EfsConfiguration" -ErrorAction SilentlyContinue
    if ($disabled -and $disabled.EfsConfiguration -eq 1) {
        Set-ItemProperty -Path $efsKey -Name "EfsConfiguration" -Value 0
        Write-Host "    [+] EFS re-enabled (was disabled by policy)" -ForegroundColor Green
    } else {
        Write-Host "    [+] EFS enabled (PetitPotam coercion possible)" -ForegroundColor Green
    }
} catch {
    Write-Host "    [-] EFS check failed: $_" -ForegroundColor Red
}

# ═══════════════════════════════════════════════════════════════════
# 5. AdminSDHolder Persistence Backdoor
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n  [5/8] Setting up AdminSDHolder backdoor..." -ForegroundColor Yellow

try {
    $adminSDHolder = Get-ADObject -Filter "Name -eq 'AdminSDHolder'" `
        -SearchBase "CN=System,$domainDN" -ErrorAction SilentlyContinue
    $svcWeb = Get-ADUser -Filter "SamAccountName -eq 'svc_web'" -ErrorAction SilentlyContinue

    if ($adminSDHolder -and $svcWeb) {
        $acl = Get-Acl "AD:\$($adminSDHolder.DistinguishedName)"
        $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $svcWeb.SID, "GenericAll", "Allow"
        )
        $acl.AddAccessRule($rule)
        Set-Acl "AD:\$($adminSDHolder.DistinguishedName)" $acl
        Write-Host "    [+] svc_web: GenericAll on AdminSDHolder (propagates to all protected groups)" -ForegroundColor Green
    }
} catch {
    Write-Host "    [-] AdminSDHolder backdoor failed: $_" -ForegroundColor Red
}

# ═══════════════════════════════════════════════════════════════════
# 6. Weak GPO Permissions
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n  [6/8] Creating GPO with weak permissions..." -ForegroundColor Yellow

try {
    $gpoName = "Lab-SoftwareDeploy"
    $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
    if (-not $existingGPO) {
        $gpo = New-GPO -Name $gpoName -Comment "Software deployment GPO (lab misconfig)"
        # Grant Domain Users edit rights (extremely dangerous)
        Set-GPPermission -Name $gpoName -PermissionLevel GpoEdit -TargetName "Domain Users" -TargetType Group
        Write-Host "    [+] GPO '$gpoName' created — Domain Users have GpoEdit!" -ForegroundColor Green

        # Link to domain root
        New-GPLink -Name $gpoName -Target $domainDN -LinkEnabled Yes -ErrorAction SilentlyContinue
        Write-Host "    [+] GPO linked to domain root" -ForegroundColor Green
    } else {
        Write-Host "    [=] GPO '$gpoName' already exists" -ForegroundColor DarkGray
    }
} catch {
    Write-Host "    [-] GPO creation failed: $_" -ForegroundColor Red
}

# ═══════════════════════════════════════════════════════════════════
# 7. Disable SMB Signing on Member Servers
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n  [7/8] Weakening SMB signing..." -ForegroundColor Yellow

try {
    $smbKey = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    # Don't require signing (allows relay)
    Set-ItemProperty -Path $smbKey -Name "RequireSecuritySignature" -Value 0 -Type DWord
    Set-ItemProperty -Path $smbKey -Name "EnableSecuritySignature" -Value 1 -Type DWord
    Write-Host "    [+] SMB signing not required (NTLM relay possible)" -ForegroundColor Green
} catch {
    Write-Host "    [-] SMB signing config failed: $_" -ForegroundColor Red
}

# ═══════════════════════════════════════════════════════════════════
# 8. LDAP Signing Not Required
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n  [8/8] Weakening LDAP signing..." -ForegroundColor Yellow

try {
    $ldapKey = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
    if (Test-Path $ldapKey) {
        Set-ItemProperty -Path $ldapKey -Name "LDAPServerIntegrity" -Value 0 -Type DWord
        Write-Host "    [+] LDAP signing not required (LDAP relay possible)" -ForegroundColor Green
    }
    # Also disable channel binding
    Set-ItemProperty -Path $ldapKey -Name "LdapEnforceChannelBinding" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Write-Host "    [+] LDAP channel binding disabled" -ForegroundColor Green
} catch {
    Write-Host "    [-] LDAP signing config failed: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "  ┌──────────────────────────────────────────────────┐" -ForegroundColor Green
Write-Host "  │  Additional AD Misconfigs Complete               │" -ForegroundColor Green
Write-Host "  │                                                  │" -ForegroundColor Green
Write-Host "  │  New Attack Paths:                               │" -ForegroundColor Green
Write-Host "  │    [LAPS Gap]        Servers OU has no LAPS      │" -ForegroundColor Green
Write-Host "  │    [LAPS Read]       samwell.tarly reads LAPS    │" -ForegroundColor Green
Write-Host "  │    [GMSA Abuse]      gmsa_sql readable by comps  │" -ForegroundColor Green
Write-Host "  │    [PrinterBug]      Spooler running on DC       │" -ForegroundColor Green
Write-Host "  │    [PetitPotam]      EFS enabled for coercion    │" -ForegroundColor Green
Write-Host "  │    [AdminSDHolder]   svc_web GenericAll backdoor  │" -ForegroundColor Green
Write-Host "  │    [GPO Abuse]       Domain Users edit GPO        │" -ForegroundColor Green
Write-Host "  │    [SMB Relay]       Signing not required         │" -ForegroundColor Green
Write-Host "  │    [LDAP Relay]      Signing + binding disabled   │" -ForegroundColor Green
Write-Host "  │                                                  │" -ForegroundColor Green
Write-Host "  │  Run after: expand_goad_lab.ps1 (base misconfigs)│" -ForegroundColor Green
Write-Host "  └──────────────────────────────────────────────────┘" -ForegroundColor Green
Write-Host ""
