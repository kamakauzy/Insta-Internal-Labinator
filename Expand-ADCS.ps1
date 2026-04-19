<#
.SYNOPSIS
    L.1 — Install ADCS Role + Create Vulnerable Certificate Templates (ESC1-ESC8)
.DESCRIPTION
    Installs Active Directory Certificate Services on the target DC and creates
    intentionally vulnerable certificate templates for testing ESC1-ESC11 attack paths.

    Must be run as Domain Admin on DC01 (kingslanding) or the designated CA server.
    Designed for GOAD-Light lab only. DO NOT run on production systems.

.PARAMETER DomainController
    Target DC hostname/IP. Defaults to localhost.

.PARAMETER CAName
    Certificate Authority common name. Defaults to "{domain}-CA".

.NOTES
    Requires: Windows Server with AD DS role, Domain Admin privileges
    Run elevated (Administrator).
    Version: 1.0.0
#>

#Requires -RunAsAdministrator
#Requires -Version 5.1

param(
    [string]$DomainController = "localhost",
    [string]$CAName = ""
)

$ErrorActionPreference = "Continue"
Import-Module ActiveDirectory -ErrorAction SilentlyContinue

$domain = (Get-ADDomain).DNSRoot
$domainDN = (Get-ADDomain).DistinguishedName
$netbios = (Get-ADDomain).NetBIOSName
if (-not $CAName) { $CAName = "$netbios-CA" }

Write-Host ""
Write-Host "  ┌──────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "  │  L.1 — ADCS Role + Vulnerable Templates         │" -ForegroundColor Cyan
Write-Host "  └──────────────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host "  Domain: $domain | CA: $CAName" -ForegroundColor Gray
Write-Host ""

# ═══════════════════════════════════════════════════════════════════
# Step 1: Install ADCS Role (if not already installed)
# ═══════════════════════════════════════════════════════════════════
Write-Host "  [1/4] Installing ADCS Role..." -ForegroundColor Yellow

$adcsInstalled = Get-WindowsFeature -Name AD-Certificate -ErrorAction SilentlyContinue
if ($adcsInstalled -and $adcsInstalled.Installed) {
    Write-Host "    [=] ADCS already installed" -ForegroundColor DarkGray
} else {
    try {
        Install-WindowsFeature -Name AD-Certificate, ADCS-Cert-Authority, ADCS-Web-Enrollment -IncludeManagementTools
        Write-Host "    [+] ADCS role installed" -ForegroundColor Green

        # Configure as Enterprise Root CA
        Install-AdcsCertificationAuthority -CAType EnterpriseRootCA `
            -CACommonName $CAName `
            -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" `
            -KeyLength 2048 `
            -HashAlgorithmName SHA256 `
            -ValidityPeriod Years -ValidityPeriodUnits 10 `
            -Force

        Write-Host "    [+] Enterprise Root CA configured: $CAName" -ForegroundColor Green

        # Install Web Enrollment
        Install-AdcsWebEnrollment -Force -ErrorAction SilentlyContinue
        Write-Host "    [+] Web Enrollment installed (needed for ESC8 relay)" -ForegroundColor Green
    } catch {
        Write-Host "    [-] ADCS install failed: $_" -ForegroundColor Red
        Write-Host "    [*] Continuing with template creation (CA may already be configured)" -ForegroundColor DarkYellow
    }
}

# ═══════════════════════════════════════════════════════════════════
# Step 2: Ensure Web Enrollment is enabled (ESC8 prerequisite)
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n  [2/4] Verifying Web Enrollment..." -ForegroundColor Yellow

$webEnroll = Get-WindowsFeature -Name ADCS-Web-Enrollment -ErrorAction SilentlyContinue
if ($webEnroll -and $webEnroll.Installed) {
    Write-Host "    [+] Web Enrollment enabled (http://$DomainController/certsrv)" -ForegroundColor Green
} else {
    Write-Host "    [*] Web Enrollment not installed — ESC8 relay will not work" -ForegroundColor DarkYellow
}

# ═══════════════════════════════════════════════════════════════════
# Step 3: Create Vulnerable Certificate Templates
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n  [3/4] Creating vulnerable certificate templates..." -ForegroundColor Yellow

$configContext = (Get-ADRootDSE).configurationNamingContext
$templateContainer = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configContext"

# Helper: Duplicate a template
function New-VulnTemplate {
    param(
        [string]$Name,
        [string]$DisplayName,
        [string]$BasedOn = "CN=User,$templateContainer",
        [string]$Description,
        [scriptblock]$Customize
    )

    $dn = "CN=$Name,$templateContainer"
    $existing = Get-ADObject -Filter "distinguishedName -eq '$dn'" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "    [=] Template already exists: $Name" -ForegroundColor DarkGray
        return
    }

    try {
        # Get the base template
        $base = Get-ADObject $BasedOn -Properties * -ErrorAction Stop
        $newOID = "1.3.6.1.4.1.311.21.8.$(Get-Random).$(Get-Random).$(Get-Random)"

        # Create template object
        $attrs = @{
            'displayName'                     = $DisplayName
            'msPKI-Cert-Template-OID'         = $newOID
            'flags'                           = 131680  # CT_FLAG_AUTO_ENROLLMENT | CT_FLAG_PUBLISH_TO_DS
            'revision'                        = 100
            'pKIDefaultKeySpec'              = 1
            'pKIMaxIssuingDepth'             = 0
            'pKIDefaultCSPs'                 = "1,Microsoft RSA SChannel Cryptographic Provider"
            'msPKI-RA-Signature'             = 0       # No issuance requirement
            'msPKI-Enrollment-Flag'          = 0       # No enrollment flags (no manager approval)
            'msPKI-Private-Key-Flag'         = 16842752
            'msPKI-Certificate-Name-Flag'    = 1       # ENROLLEE_SUPPLIES_SUBJECT (ESC1 key flag!)
        }

        New-ADObject -Name $Name -Type "pKICertificateTemplate" -Path $templateContainer -OtherAttributes $attrs
        Write-Host "    [+] Created template: $Name ($DisplayName)" -ForegroundColor Green

        # Apply custom permissions
        if ($Customize) {
            & $Customize $dn
        }
    } catch {
        Write-Host "    [-] Failed to create $Name : $_" -ForegroundColor Red
    }
}

# --- ESC1: Enrollee Supplies Subject + Low-Priv Enrollment ---
New-VulnTemplate -Name "ESC1-VulnUser" -DisplayName "ESC1 - Vulnerable User Template" `
    -Description "Client auth + enrollee supplies subject name — any domain user can enroll and impersonate" `
    -Customize {
        param($dn)
        # Grant Domain Users enrollment rights
        $domainUsers = Get-ADGroup "Domain Users"
        $acl = Get-Acl "AD:\$dn"
        $enrollGuid = [GUID]"0e10c968-78fb-11d2-90d4-00c04f79dc55"
        $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $domainUsers.SID, "ExtendedRight", "Allow", $enrollGuid
        )
        $acl.AddAccessRule($rule)
        Set-Acl "AD:\$dn" $acl
        Write-Host "      [+] Domain Users granted Enroll on ESC1-VulnUser" -ForegroundColor Green
    }

# --- ESC4: Template with Write permissions for low-priv users ---
New-VulnTemplate -Name "ESC4-WritableTemplate" -DisplayName "ESC4 - Writable Template" `
    -Description "Template where Domain Users have WriteDACL — allows template modification" `
    -Customize {
        param($dn)
        $domainUsers = Get-ADGroup "Domain Users"
        $acl = Get-Acl "AD:\$dn"
        $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $domainUsers.SID, "WriteDacl", "Allow"
        )
        $acl.AddAccessRule($rule)
        Set-Acl "AD:\$dn" $acl
        Write-Host "      [+] Domain Users granted WriteDACL on ESC4-WritableTemplate" -ForegroundColor Green
    }

# --- ESC2: Any Purpose EKU template ---
New-VulnTemplate -Name "ESC2-AnyPurpose" -DisplayName "ESC2 - Any Purpose Template" `
    -Description "Template with Any Purpose or SubCA EKU — can be used for any auth" `
    -Customize {
        param($dn)
        # Set EKU to "Any Purpose" (OID 2.5.29.37.0)
        Set-ADObject $dn -Replace @{
            'pKIExtendedKeyUsage' = @("2.5.29.37.0")
        }
        $domainUsers = Get-ADGroup "Domain Users"
        $acl = Get-Acl "AD:\$dn"
        $enrollGuid = [GUID]"0e10c968-78fb-11d2-90d4-00c04f79dc55"
        $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $domainUsers.SID, "ExtendedRight", "Allow", $enrollGuid
        )
        $acl.AddAccessRule($rule)
        Set-Acl "AD:\$dn" $acl
        Write-Host "      [+] ESC2 Any Purpose EKU + Domain Users enroll" -ForegroundColor Green
    }

# --- Publish templates to the CA ---
Write-Host "`n  [4/4] Publishing templates to CA..." -ForegroundColor Yellow

$caContainer = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configContext"
$caObj = Get-ADObject -SearchBase $caContainer -Filter "Name -eq '$CAName'" -ErrorAction SilentlyContinue
if ($caObj) {
    $templates = @("ESC1-VulnUser", "ESC4-WritableTemplate", "ESC2-AnyPurpose")
    foreach ($tmpl in $templates) {
        try {
            Set-ADObject $caObj.DistinguishedName -Add @{
                'certificateTemplates' = $tmpl
            } -ErrorAction SilentlyContinue
            Write-Host "    [+] Published: $tmpl" -ForegroundColor Green
        } catch {
            Write-Host "    [*] Could not publish $tmpl (may already be published)" -ForegroundColor DarkYellow
        }
    }
} else {
    Write-Host "    [-] CA object not found — publish templates manually via certsrv.msc" -ForegroundColor Red
}

Write-Host ""
Write-Host "  ┌──────────────────────────────────────────────────┐" -ForegroundColor Green
Write-Host "  │  ADCS Setup Complete                             │" -ForegroundColor Green
Write-Host "  │                                                  │" -ForegroundColor Green
Write-Host "  │  Attack Paths Created:                           │" -ForegroundColor Green
Write-Host "  │    ESC1 — Enrollee supplies subject (any user)   │" -ForegroundColor Green
Write-Host "  │    ESC2 — Any Purpose EKU (any user)             │" -ForegroundColor Green
Write-Host "  │    ESC4 — Domain Users have WriteDACL            │" -ForegroundColor Green
Write-Host "  │    ESC8 — Web Enrollment for NTLM relay          │" -ForegroundColor Green
Write-Host "  │                                                  │" -ForegroundColor Green
Write-Host "  │  Verify with:                                    │" -ForegroundColor Green
Write-Host "  │    certipy find -u user@$domain -p Pass -dc $DomainController │" -ForegroundColor Green
Write-Host "  └──────────────────────────────────────────────────┘" -ForegroundColor Green
Write-Host ""
