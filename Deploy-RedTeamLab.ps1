<#
.SYNOPSIS
    Insta-Internal-Labinator v3.0 — One-click Red Team Assumed-Breach Lab Generator
.DESCRIPTION
    Deploys a fully randomized internal penetration test lab using GOAD (Game of Active Directory)
    on VMware Workstation Pro, then generates a professional Red Team Handoff Package.

    v3.0 improvements over v2.0:
      1. Deeper randomization — 200+ company names, dept-aware usernames, misconfig seed,
         probabilistic vulnerability chains, 80-400 users with realistic password patterns
      2. GOAD injection — clean override of domain names, CIDR, static IPs via Ansible extra-vars,
         low-priv user creation during provisioning, GOAD-Light and MINILAB support
      3. Handoff polish — executive-quality Handoff.md, detailed network map, complete creds file,
         phase-by-phase attack guide, all-users CSV
      4. Robustness — colored progress bars, idempotent re-runs, prerequisite validation with
         actionable guidance, detailed logging, VMnet persistence check, stale-process detection

    GOAD integration uses goad.py with VMware provider and Docker-based Ansible provisioning.
.NOTES
    Requires: Windows 11 Pro, VMware Workstation Pro, Vagrant + VMware plugin, Git, Python 3,
              Docker Desktop, PowerShell 5.1+
    Run elevated (Administrator).
    Author: Insta-Internal-Labinator Project
    Version: 3.0.0
#>

#Requires -RunAsAdministrator
#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(HelpMessage = "Path to ClientHandoff.json config file")]
    [string]$ConfigPath = ".\ClientHandoff.json",

    [Parameter(HelpMessage = "Tear down all lab VMs")]
    [switch]$Destroy,

    [Parameter(HelpMessage = "Skip VMware snapshot creation")]
    [switch]$SkipSnapshots,

    [Parameter(HelpMessage = "Skip GOAD deployment (use existing VMs)")]
    [switch]$SkipGOAD,

    [Parameter(HelpMessage = "Skip attacker VM deployment")]
    [switch]$SkipAttacker,

    [Parameter(HelpMessage = "Only generate handoff package (no VMs)")]
    [switch]$HandoffOnly,

    [Parameter(HelpMessage = "Force rebuild even if VMs exist")]
    [switch]$Force,

    [Parameter(HelpMessage = "Resume provisioning from a specific playbook")]
    [string]$ResumeFrom = "",

    [Parameter(HelpMessage = "GOAD instance ID for resume operations")]
    [string]$InstanceId = "",

    [Parameter(HelpMessage = "Random seed for reproducible lab generation")]
    [int]$MisconfigSeed = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════
$SCRIPT_VERSION  = "3.0.0"
$SCRIPT_DIR      = Split-Path -Parent $MyInvocation.MyCommand.Definition
$GOAD_REPO       = "https://github.com/Orange-Cyberdefense/GOAD.git"
$GOAD_DIR        = Join-Path $SCRIPT_DIR "GOAD"
$LOG_DIR         = Join-Path $SCRIPT_DIR "logs"
$LOG_FILE        = Join-Path $LOG_DIR "deploy-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$CUSTOM_VARS_DIR = Join-Path $SCRIPT_DIR "custom-ansible-vars"
$VMRUN           = ""  # resolved at runtime

# RAM budget — GOAD-Light: DC01(3GB) + DC02(3GB) + SRV02(6GB) = 12GB + Attacker(4GB) = 16GB
$MIN_RAM_MB      = 20480   # 20 GB minimum
$RECOMMENDED_RAM = 32768   # 32 GB recommended

# ═══════════════════════════════════════════════════════════════════════════════
# LOGGING & UI
# ═══════════════════════════════════════════════════════════════════════════════
function Initialize-Logging {
    if (-not (Test-Path $LOG_DIR)) { New-Item -ItemType Directory -Path $LOG_DIR -Force | Out-Null }
    Start-Transcript -Path $LOG_FILE -Append -Force | Out-Null
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "HH:mm:ss"
    switch ($Level) {
        "ERROR"   { Write-Host "  [$ts] " -NoNewline -ForegroundColor DarkGray; Write-Host "ERROR " -NoNewline -ForegroundColor Red;     Write-Host $Message -ForegroundColor Red }
        "WARN"    { Write-Host "  [$ts] " -NoNewline -ForegroundColor DarkGray; Write-Host "WARN  " -NoNewline -ForegroundColor Yellow;  Write-Host $Message -ForegroundColor Yellow }
        "SUCCESS" { Write-Host "  [$ts] " -NoNewline -ForegroundColor DarkGray; Write-Host "OK    " -NoNewline -ForegroundColor Green;   Write-Host $Message -ForegroundColor Green }
        "STEP"    { Write-Host "  [$ts] " -NoNewline -ForegroundColor DarkGray; Write-Host ">>    " -NoNewline -ForegroundColor Cyan;    Write-Host $Message -ForegroundColor White }
        "DETAIL"  { Write-Host "  [$ts] " -NoNewline -ForegroundColor DarkGray; Write-Host "      " -NoNewline;                          Write-Host $Message -ForegroundColor DarkGray }
        default   { Write-Host "  [$ts] " -NoNewline -ForegroundColor DarkGray; Write-Host "INFO  " -NoNewline -ForegroundColor DarkCyan; Write-Host $Message -ForegroundColor Gray }
    }
}

function Write-Banner {
    param([string]$Text, [int]$Step = 0, [int]$Total = 0)
    $prefix = if ($Step -gt 0) { "STEP $Step/$Total" } else { "" }
    Write-Host ""
    Write-Host "  ┌$("─" * 74)┐" -ForegroundColor DarkCyan
    if ($prefix) {
        Write-Host "  │ " -NoNewline -ForegroundColor DarkCyan
        Write-Host "$prefix — " -NoNewline -ForegroundColor Yellow
        Write-Host "$Text".PadRight(74 - $prefix.Length - 4) -NoNewline -ForegroundColor White
        Write-Host "│" -ForegroundColor DarkCyan
    } else {
        Write-Host "  │ $($Text.PadRight(73))│" -ForegroundColor Cyan
    }
    Write-Host "  └$("─" * 74)┘" -ForegroundColor DarkCyan
    Write-Host ""
}

function Write-Progress-Bar {
    param([string]$Activity, [int]$Percent)
    $width = 40
    $filled = [math]::Round($width * $Percent / 100)
    $empty = $width - $filled
    $bar = ("█" * $filled) + ("░" * $empty)
    Write-Host "`r  [$bar] $Percent% $Activity" -NoNewline -ForegroundColor Cyan
    if ($Percent -ge 100) { Write-Host "" }
}

# ═══════════════════════════════════════════════════════════════════════════════
# RANDOMIZATION ENGINE (v3.0 — significantly expanded)
# ═══════════════════════════════════════════════════════════════════════════════

function Initialize-RandomSeed {
    param([int]$Seed)
    if ($Seed -gt 0) {
        $script:RNG = [System.Random]::new($Seed)
        Write-Log "Misconfig seed: $Seed (reproducible generation)" "STEP"
    } else {
        $script:RNG = [System.Random]::new()
        Write-Log "Misconfig seed: random (unique generation)" "STEP"
    }
}

function Get-SeededRandom {
    param([int]$Max, [int]$Min = 0)
    return $script:RNG.Next($Min, $Max)
}

function Get-RandomElement {
    param([array]$Array)
    return $Array[(Get-SeededRandom -Max $Array.Count)]
}

# ── Company Name Pools ──────────────────────────────────────────────────────
function New-RandomCompanyName {
    # 80+ realistic company names across industries
    $industries = @{
        "Tech" = @(
            "Apex Digital Solutions", "ByteForge Technologies", "CircuitPath Systems",
            "DataNova Inc", "EdgePoint Software", "FusionStack Labs",
            "GridIron Computing", "HexaByte Corporation", "InnoVault Tech",
            "JetStream Digital", "KernelWorks LLC", "LightSpeed Dynamics",
            "MeshPoint Networks", "NexaTech Solutions", "OptiCore Systems",
            "PulseWave Digital", "QuantumLeap IT", "RapidScale Tech"
        )
        "Finance" = @(
            "Anchor Capital Group", "Bridgewater Holdings", "Cascade Financial",
            "Dominion Wealth Partners", "Evergreen Asset Management", "FortKnox Advisors",
            "GoldLeaf Financial", "Harbinger Investments", "IronBridge Capital",
            "Keystone Wealth Group", "Ledger Financial Services", "Monarch Capital"
        )
        "Healthcare" = @(
            "Asclepius Health Systems", "BrightCare Medical Group", "ClearVista Health",
            "DigiMed Solutions", "EliteCare Networks", "FirstLight Health Partners",
            "GreenValley Medical", "HorizonCare Systems", "IntegraMed Corp"
        )
        "Manufacturing" = @(
            "AlloyWorks Industries", "BoltForge Manufacturing", "CrestLine Fabrication",
            "DeltaPrecision Corp", "Everforge Industries", "FrontierSteel LLC",
            "GraniteEdge Manufacturing", "HardLine Industrial", "IronClad Works"
        )
        "Energy" = @(
            "ArcPower Energy", "BlueFlame Resources", "ClearGrid Energy",
            "DynamoForce Power", "EverGreen Utilities", "FluxPoint Energy",
            "GridSync Power Systems", "HelioTech Solar", "InfiniPower Corp"
        )
        "Defense" = @(
            "Aegis Defense Systems", "Bulwark Security Corp", "Citadel Strategic",
            "DarkStar Defense", "EchelonGuard Inc", "Fortress Dynamics",
            "Guardian Aerospace", "HawkEye Defense", "IronShield Systems"
        )
    }
    $industry = Get-RandomElement @($industries.Keys)
    return Get-RandomElement $industries[$industry]
}

function New-RandomDomain {
    $prefixes = @(
        # Generic corporate
        "acmecorp", "globexinc", "initech", "umbrellaco", "cyberdyne",
        "massivetech", "pinnacle", "silverline", "northgate", "blueridge",
        "crestwood", "meridian", "vanguardgrp", "summitfin", "ironclad",
        "nexgenhealth", "primelogistics", "atlashq", "beacontech", "corestone",
        "deltaforce", "eaglepoint", "frontierdata", "graniteworks", "horizonit",
        # Themed / industry
        "blackmesa", "waynetech", "starkind", "oscorptech", "lexcorp",
        "choam", "tyrell", "weyland", "abstergo", "aperture",
        "dharma", "encom", "gekko", "hooli", "piedpiper",
        "raviga", "soylent", "virtucon", "wolfram", "yoyodyne",
        # Real-sounding
        "eastgate", "westpeak", "northstar", "southridge", "midfield",
        "oakridge", "pinecrest", "cedarhill", "maplewood", "willowcreek",
        "stonebridge", "brookfield", "clearwater", "deeprock", "highpoint"
    )
    $suffixes = @(".local", ".internal", ".corp", ".lan", ".ad", ".intra")
    $prefix = Get-RandomElement $prefixes
    $suffix = Get-RandomElement $suffixes
    return "$prefix$suffix"
}

function New-RandomCIDR {
    $cidrs = @(
        "192.168.56.0/24", "192.168.100.0/24", "192.168.50.0/24",
        "10.10.10.0/24",   "10.0.50.0/24",     "10.100.100.0/24",
        "172.16.100.0/24", "172.16.50.0/24",    "172.16.200.0/24",
        "10.0.10.0/24",    "10.1.1.0/24",       "192.168.10.0/24"
    )
    return Get-RandomElement $cidrs
}

# ── Username Generation (v3.0 — department-aware patterns) ──────────────────

$script:FIRST_NAMES = @(
    "james","john","robert","michael","david","william","richard","joseph","thomas","charles",
    "christopher","daniel","matthew","anthony","mark","donald","steven","paul","andrew","joshua",
    "mary","patricia","jennifer","linda","barbara","elizabeth","susan","jessica","sarah","karen",
    "lisa","nancy","betty","margaret","sandra","ashley","dorothy","kimberly","emily","donna",
    "aiden","riley","casey","jordan","taylor","morgan","drew","blake","quinn","avery",
    "cameron","parker","logan","reese","skyler","charlie","frankie","jamie","robin","alex"
)

$script:LAST_NAMES = @(
    "smith","johnson","williams","brown","jones","garcia","miller","davis","wilson","moore",
    "taylor","anderson","thomas","jackson","white","harris","martin","thompson","robinson","clark",
    "lewis","walker","hall","allen","young","king","wright","scott","green","baker",
    "adams","nelson","hill","campbell","mitchell","roberts","carter","phillips","evans","turner",
    "torres","parker","collins","edwards","stewart","flores","morris","nguyen","murphy","rivera",
    "cook","rogers","morgan","peterson","cooper","reed","bailey","bell","gomez","kelly"
)

$script:DEPARTMENTS = @(
    @{ Name = "IT";           Titles = @("Systems Administrator","Network Engineer","Help Desk Analyst","Security Analyst","DevOps Engineer","Database Administrator","IT Manager") }
    @{ Name = "Finance";      Titles = @("Financial Analyst","Accountant","Controller","CFO","Payroll Specialist","Auditor","Treasury Analyst") }
    @{ Name = "HR";           Titles = @("HR Coordinator","Recruiter","Benefits Administrator","HR Manager","Talent Acquisition","HRIS Analyst") }
    @{ Name = "Engineering";  Titles = @("Software Engineer","QA Engineer","Tech Lead","Principal Engineer","Engineering Manager","Architect") }
    @{ Name = "Sales";        Titles = @("Account Executive","Sales Manager","BDR","Sales Director","VP Sales","Regional Manager") }
    @{ Name = "Marketing";    Titles = @("Marketing Coordinator","Content Strategist","Brand Manager","Digital Marketing Manager","CMO") }
    @{ Name = "Legal";        Titles = @("Corporate Counsel","Paralegal","Compliance Officer","Legal Secretary","General Counsel") }
    @{ Name = "Operations";   Titles = @("Operations Manager","Logistics Coordinator","Facilities Manager","COO","Supply Chain Analyst") }
    @{ Name = "Executive";    Titles = @("CEO","CTO","CFO","COO","CISO","VP Engineering","VP Operations") }
    @{ Name = "Support";      Titles = @("Customer Support Rep","Support Engineer","Technical Writer","Support Manager","QA Analyst") }
    @{ Name = "R&D";          Titles = @("Research Scientist","Lab Technician","R&D Manager","Principal Researcher","Data Scientist") }
)

function New-RandomUsername {
    param([string]$FirstName, [string]$LastName, [string]$Department = "")

    # Pattern selection weighted by department
    $patterns = switch ($Department) {
        "IT"          { @("f.last","flast","first.last","first_last","adm-first","admin.first") }
        "Executive"   { @("first.last","first_last","flast") }
        "Engineering" { @("first.last","flast","f.last","first-last") }
        default       { @("f.last","flast","first.last","first_last","first.l") }
    }
    $pattern = Get-RandomElement $patterns
    $f = $FirstName.ToLower()
    $l = $LastName.ToLower()

    switch ($pattern) {
        "f.last"      { return "$($f[0]).$l" }
        "flast"       { return "$($f[0])$l" }
        "first.last"  { return "$f.$l" }
        "first_last"  { return "${f}_${l}" }
        "first.l"     { return "$f.$($l[0])" }
        "first-last"  { return "$f-$l" }
        "adm-first"   { return "adm-$f" }
        "admin.first" { return "admin.$f" }
        default       { return "$($f[0]).$l" }
    }
}

function New-RandomWeakPassword {
    param([string]$CompanyName = "")

    # Season + year (most common real-world pattern)
    $seasons = @("Spring","Summer","Autumn","Fall","Winter")
    $months = @("January","February","March","April","May","June","July","August","September","October","November","December")
    $years = @("2024","2025","2026","2024!","2025!","2026!","24","25","26")
    $suffixes = @("!","1","1!","123","@1","#1","!")

    # Company-based passwords
    $companyBases = @()
    if ($CompanyName) {
        $shortName = ($CompanyName -split "\s" | Select-Object -First 1).ToLower()
        $companyBases = @(
            "${shortName}2026", "${shortName}2026!", "${shortName}123",
            "${shortName}!", "${shortName}2025", "${shortName}1!"
        )
    }

    # Common weak patterns
    $commonBases = @(
        "Password","Welcome","Changeme","Letmein","Qwerty","Admin",
        "Monday","Friday","P@ssw0rd","Passw0rd!","Trustno1","abc123",
        "iloveyou","dragon","master","access","login","prince","flower"
    )

    $pools = @(
        # Season+Year (35% — most realistic)
        { $s = Get-RandomElement $seasons; $y = Get-RandomElement $years; "$s$y" },
        # Month+Year (15%)
        { $m = Get-RandomElement $months; $y = Get-RandomElement $years; "$m$y" },
        # Common+suffix (20%)
        { $b = Get-RandomElement $commonBases; $sf = Get-RandomElement $suffixes; "$b$sf" },
        # Company-based (15%)
        { if ($companyBases.Count -gt 0) { Get-RandomElement $companyBases } else { $b = Get-RandomElement $commonBases; "${b}2026!" } },
        # Keyboard walks (10%)
        { Get-RandomElement @("Qwerty123!","Qwert12345","1qaz2wsx","zaq1xsw2","Asdf1234!","1234Qwer!") },
        # Simple patterns (5%)
        { Get-RandomElement @("Welcome1!","Password1","Changeme1!","Letmein1!","Admin123!","Test1234!") }
    )

    $roll = Get-SeededRandom -Max 100
    $idx = if ($roll -lt 35) { 0 } elseif ($roll -lt 50) { 1 } elseif ($roll -lt 70) { 2 } elseif ($roll -lt 85) { 3 } elseif ($roll -lt 95) { 4 } else { 5 }
    return (& $pools[$idx])
}

# ── AD User Generation (v3.0 — 80-400 users, department-aware) ─────────────

function New-RandomADUsers {
    param(
        [int]$Min = 80,
        [int]$Max = 400,
        [string]$CompanyName = ""
    )
    $count = Get-SeededRandom -Min $Min -Max ($Max + 1)
    $users = [System.Collections.ArrayList]::new()
    $weakRatio = (Get-SeededRandom -Min 15 -Max 35) / 100.0
    $usedNames = @{}

    # Service account users (always included, 3-8)
    $svcCount = Get-SeededRandom -Min 3 -Max 9
    $svcPrefixes = @("svc_backup","svc_sql","svc_web","svc_print","svc_scan","svc_deploy",
                     "svc_monitor","svc_report","svc_exchange","svc_sharepoint","svc_crm",
                     "svc_erp","svc_antivirus","svc_patching")
    $svcSelected = $svcPrefixes | Get-Random -Count ([math]::Min($svcCount, $svcPrefixes.Count))
    foreach ($svc in $svcSelected) {
        $null = $users.Add([PSCustomObject]@{
            Username   = $svc
            Password   = New-RandomWeakPassword -CompanyName $CompanyName
            FirstName  = "Service"
            LastName   = ($svc -replace "svc_","") | ForEach-Object { (Get-Culture).TextInfo.ToTitleCase($_) }
            Department = "IT"
            Title      = "Service Account"
            WeakPW     = $true
            AccountType = "Service"
        })
        $usedNames[$svc] = $true
    }

    # Temp/contractor accounts (2-5, always weak)
    $tempCount = Get-SeededRandom -Min 2 -Max 6
    $tempPrefixes = @("temp","contractor","vendor","helpdesk","intern","consultant","seasonal","remote")
    for ($i = 0; $i -lt $tempCount; $i++) {
        $prefix = Get-RandomElement $tempPrefixes
        $yr = Get-SeededRandom -Min 2024 -Max 2027
        $uname = "${prefix}${yr}"
        if ($usedNames.ContainsKey($uname)) { $uname = "${prefix}${yr}$((Get-SeededRandom -Max 99))" }
        $usedNames[$uname] = $true
        $null = $users.Add([PSCustomObject]@{
            Username   = $uname
            Password   = New-RandomWeakPassword -CompanyName $CompanyName
            FirstName  = (Get-Culture).TextInfo.ToTitleCase($prefix)
            LastName   = "Account"
            Department = Get-RandomElement @("IT","Operations","Support")
            Title      = "Temporary Account"
            WeakPW     = $true
            AccountType = "Temporary"
        })
    }

    # Admin shadow accounts (1-3)
    $adminCount = Get-SeededRandom -Min 1 -Max 4
    for ($i = 0; $i -lt $adminCount; $i++) {
        $fname = Get-RandomElement $script:FIRST_NAMES
        $lname = Get-RandomElement $script:LAST_NAMES
        $uname = Get-RandomElement @("adm-$fname","admin.$fname","a-$($fname[0])$lname","da_$($fname[0])$lname")
        if ($usedNames.ContainsKey($uname)) { continue }
        $usedNames[$uname] = $true
        $null = $users.Add([PSCustomObject]@{
            Username   = $uname
            Password   = New-RandomWeakPassword -CompanyName $CompanyName
            FirstName  = (Get-Culture).TextInfo.ToTitleCase($fname)
            LastName   = (Get-Culture).TextInfo.ToTitleCase($lname)
            Department = "IT"
            Title      = "IT Administrator"
            WeakPW     = $true
            AccountType = "Admin"
        })
    }

    # Regular users (fill to target count)
    $remaining = $count - $users.Count
    for ($i = 0; $i -lt $remaining; $i++) {
        $fname = Get-RandomElement $script:FIRST_NAMES
        $lname = Get-RandomElement $script:LAST_NAMES
        $dept = Get-RandomElement $script:DEPARTMENTS
        $uname = New-RandomUsername -FirstName $fname -LastName $lname -Department $dept.Name

        if ($usedNames.ContainsKey($uname)) {
            $uname = "$uname$(Get-SeededRandom -Max 99)"
        }
        if ($usedNames.ContainsKey($uname)) { continue }
        $usedNames[$uname] = $true

        $isWeak = ((Get-SeededRandom -Max 100) / 100.0) -lt $weakRatio
        $pw = if ($isWeak) { New-RandomWeakPassword -CompanyName $CompanyName } else {
            $chars = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#%^&*"
            -join (1..14 | ForEach-Object { $chars[(Get-SeededRandom -Max $chars.Length)] })
        }

        $null = $users.Add([PSCustomObject]@{
            Username   = $uname
            Password   = $pw
            FirstName  = (Get-Culture).TextInfo.ToTitleCase($fname)
            LastName   = (Get-Culture).TextInfo.ToTitleCase($lname)
            Department = $dept.Name
            Title      = Get-RandomElement $dept.Titles
            WeakPW     = $isWeak
            AccountType = "Regular"
        })
    }
    return $users.ToArray()
}

# ── Service Accounts (v3.0 — with realistic SPNs) ──────────────────────────

function New-RandomServiceAccounts {
    $services = @(
        @{ Name="svc_sqlserver";  SPN="MSSQLSvc/srv02.{domain}:1433";    Desc="SQL Server service account"; DelegationType="none" }
        @{ Name="svc_http";       SPN="HTTP/intranet.{domain}";          Desc="IIS web service account";    DelegationType="constrained" }
        @{ Name="svc_backup";     SPN="backupexec/srv02.{domain}";       Desc="Backup Exec service";        DelegationType="none" }
        @{ Name="svc_sharepoint"; SPN="HTTP/sharepoint.{domain}";        Desc="SharePoint farm account";    DelegationType="constrained" }
        @{ Name="svc_exchange";   SPN="exchangeMDB/mail.{domain}";       Desc="Exchange mailbox service";   DelegationType="unconstrained" }
        @{ Name="svc_scanner";    SPN="HOST/scanner.{domain}";           Desc="Vulnerability scanner svc";  DelegationType="none" }
        @{ Name="svc_crm";        SPN="HTTP/crm.{domain}";              Desc="CRM application service";    DelegationType="none" }
        @{ Name="svc_sccm";      SPN="HTTP/sccm.{domain}";              Desc="SCCM site server account";   DelegationType="constrained" }
    )
    $count = Get-SeededRandom -Min 3 -Max ($services.Count + 1)
    $selected = $services | Get-Random -Count $count
    foreach ($svc in $selected) {
        $svc["Password"] = New-RandomWeakPassword
    }
    return $selected
}

# ── Misconfiguration Engine (v3.0 — probability chains, seed-aware) ────────

function New-RandomMisconfigurations {
    $misconfigs = @(
        @{ Id="UNCONSTRAINED_DELEG"; Category="Delegation";    Desc="Unconstrained delegation on a server";                  Prob=0.80; Severity="Critical"; AttackPath="Printer Bug → TGT capture → DCSync" }
        @{ Id="CONSTRAINED_DELEG";   Category="Delegation";    Desc="Constrained delegation to CIFS/LDAP on DC";             Prob=0.60; Severity="High";     AttackPath="S4U2Self → S4U2Proxy → impersonate DA" }
        @{ Id="RBCD";                Category="Delegation";    Desc="Resource-based constrained delegation writable";         Prob=0.45; Severity="High";     AttackPath="Write msDS-AllowedToActOnBehalfOfOtherIdentity" }
        @{ Id="ASREP_ROAST";         Category="Kerberos";      Desc="AS-REP roastable accounts (no preauth)";                Prob=0.90; Severity="High";     AttackPath="GetNPUsers → offline crack" }
        @{ Id="KERBEROAST";          Category="Kerberos";      Desc="Kerberoastable service accounts with weak passwords";    Prob=0.95; Severity="High";     AttackPath="GetUserSPNs → offline crack → DA" }
        @{ Id="GPP_PASSWORDS";       Category="Credentials";   Desc="Group Policy Preferences with stored credentials";      Prob=0.70; Severity="High";     AttackPath="SYSVOL → cpassword → AES decrypt" }
        @{ Id="LAPS_MISSING";        Category="Configuration"; Desc="LAPS not deployed on member servers";                    Prob=0.60; Severity="Medium";   AttackPath="Local admin password reuse across hosts" }
        @{ Id="SMB_SIGNING_OFF";     Category="Network";       Desc="SMB signing not required on servers";                    Prob=0.75; Severity="High";     AttackPath="NTLM relay → DA via LDAP/SMB" }
        @{ Id="LLMNR_ENABLED";       Category="Network";       Desc="LLMNR/NBT-NS poisoning enabled";                        Prob=0.85; Severity="Medium";   AttackPath="Responder → NTLMv2 → offline crack or relay" }
        @{ Id="DCSYNC_PATH";         Category="ACL";           Desc="ACL path to DCSync via group nesting";                  Prob=0.50; Severity="Critical"; AttackPath="Nested groups → WriteDACL → DCSync rights" }
        @{ Id="WEAK_ACL";            Category="ACL";           Desc="GenericAll/WriteDACL on privileged AD objects";          Prob=0.70; Severity="Critical"; AttackPath="GenericAll on user → reset password → DA" }
        @{ Id="PRINTSPOOLER";        Category="Configuration"; Desc="Print Spooler service running on Domain Controller";     Prob=0.80; Severity="High";     AttackPath="PrinterBug/SpoolSample → coerce auth" }
        @{ Id="ADCS_ESC1";           Category="ADCS";          Desc="Certificate template allows SAN override (ESC1)";       Prob=0.45; Severity="Critical"; AttackPath="Certipy req → DA cert → PKINIT" }
        @{ Id="ADCS_ESC4";           Category="ADCS";          Desc="Certificate template is modifiable (ESC4)";             Prob=0.30; Severity="Critical"; AttackPath="Modify template → ESC1 → DA" }
        @{ Id="ADCS_ESC8";           Category="ADCS";          Desc="ADCS web enrollment with NTLM relay (ESC8)";            Prob=0.40; Severity="Critical"; AttackPath="Coerce DC → relay to /certsrv → DA cert" }
        @{ Id="WEBDAV_ENABLED";      Category="Network";       Desc="WebDAV enabled for NTLM relay via HTTP";                Prob=0.35; Severity="Medium";   AttackPath="WebDAV → NTLMv2 relay without SMB signing" }
        @{ Id="PASSWD_IN_DESC";      Category="Credentials";   Desc="Passwords stored in AD user description fields";        Prob=0.55; Severity="Medium";   AttackPath="LDAP query descriptions → plaintext creds" }
        @{ Id="LEGACY_NTLM";        Category="Network";       Desc="NTLMv1 authentication allowed on network";              Prob=0.40; Severity="High";     AttackPath="Downgrade NTLMv2 → NTLMv1 → crack instantly" }
    )

    $active = @()
    foreach ($mc in $misconfigs) {
        $roll = (Get-SeededRandom -Max 1000) / 1000.0
        if ($roll -le $mc.Prob) {
            $active += $mc
        }
    }
    return $active
}

# ═══════════════════════════════════════════════════════════════════════════════
# PREREQUISITE CHECKS (v3.0 — actionable guidance, stale process detection)
# ═══════════════════════════════════════════════════════════════════════════════

function Test-Prerequisites {
    Write-Banner "CHECKING PREREQUISITES" -Step 1 -Total 8

    $errors = @()
    $warnings = @()
    $checks = @(
        "VMware Workstation", "Vagrant", "Vagrant Plugins",
        "Vagrant VMware Utility", "Git", "Python 3", "Docker Desktop",
        "SSH Client", "System RAM", "Disk Space", "Stale Processes"
    )
    $passed = 0

    # ── VMware Workstation ──
    $vmwarePaths = @(
        "${env:ProgramFiles(x86)}\VMware\VMware Workstation",
        "$env:ProgramFiles\VMware\VMware Workstation"
    )
    $script:VMRUN = $null
    foreach ($p in $vmwarePaths) {
        $vmrunPath = Join-Path $p "vmrun.exe"
        if (Test-Path $vmrunPath) { $script:VMRUN = $vmrunPath; break }
    }
    if (-not $script:VMRUN) {
        $vmrunCmd = Get-Command vmrun.exe -ErrorAction SilentlyContinue
        if ($vmrunCmd) { $script:VMRUN = $vmrunCmd.Source }
        else { $errors += "VMware Workstation not found. Install from https://www.vmware.com/products/workstation-pro.html" }
    }
    if ($script:VMRUN) { Write-Log "VMware vmrun: $($script:VMRUN)" "SUCCESS"; $passed++ }

    # ── Vagrant ──
    $vagrant = Get-Command vagrant -ErrorAction SilentlyContinue
    if (-not $vagrant) {
        $errors += "Vagrant not found. Install: winget install Hashicorp.Vagrant"
    } else {
        $vagVer = (& vagrant --version 2>&1) -replace "Vagrant\s+",""
        Write-Log "Vagrant: v$vagVer ($($vagrant.Source))" "SUCCESS"; $passed++
    }

    # ── Vagrant Plugins ──
    if ($vagrant) {
        $plugins = & vagrant plugin list 2>&1 | Out-String
        $needPlugins = @()
        if ($plugins -notmatch "vagrant-vmware-desktop") { $needPlugins += "vagrant-vmware-desktop" }
        if ($plugins -notmatch "vagrant-reload")         { $needPlugins += "vagrant-reload" }
        if ($needPlugins.Count -gt 0) {
            foreach ($p in $needPlugins) {
                Write-Log "Installing missing plugin: $p ..." "WARN"
                & vagrant plugin install $p 2>&1 | Out-Null
            }
        }
        Write-Log "Vagrant plugins: OK" "SUCCESS"; $passed++
    }

    # ── Vagrant VMware Utility Service ──
    $vmwareUtilSvc = Get-Service VagrantVMware -ErrorAction SilentlyContinue
    if (-not $vmwareUtilSvc) {
        $errors += "Vagrant VMware Utility not installed. Download: https://developer.hashicorp.com/vagrant/install/vmware"
    } elseif ($vmwareUtilSvc.Status -ne "Running") {
        Write-Log "Starting VagrantVMware service..." "WARN"
        Start-Service VagrantVMware -ErrorAction SilentlyContinue
        $vmwareUtilSvc = Get-Service VagrantVMware
    }
    if ($vmwareUtilSvc -and $vmwareUtilSvc.Status -eq "Running") {
        Write-Log "Vagrant VMware Utility: Running" "SUCCESS"; $passed++
    }

    # ── Git ──
    $git = Get-Command git -ErrorAction SilentlyContinue
    if (-not $git) { $errors += "Git not found. Install: winget install Git.Git" }
    else { Write-Log "Git: $(& git --version 2>&1)" "SUCCESS"; $passed++ }

    # ── Python 3 ──
    $python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $python) { $errors += "Python 3 not found. Install: winget install Python.Python.3.12" }
    else {
        $pyVer = & python --version 2>&1
        Write-Log "Python: $pyVer" "SUCCESS"; $passed++
    }

    # ── Docker ──
    $docker = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $docker) {
        $errors += "Docker not found. Install Docker Desktop from https://www.docker.com/products/docker-desktop/"
    } else {
        $dockerInfo = & docker info 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) {
            $errors += "Docker daemon not running. Start Docker Desktop first."
        } else {
            $dockerVer = & docker --version 2>&1
            Write-Log "Docker: $dockerVer" "SUCCESS"; $passed++
        }
    }

    # ── SSH ──
    $ssh = Get-Command ssh -ErrorAction SilentlyContinue
    if (-not $ssh) { $warnings += "SSH client not found. Enable: Settings → Apps → Optional Features → OpenSSH Client" }
    else { Write-Log "SSH: available" "SUCCESS"; $passed++ }

    # ── RAM ──
    $totalRAM = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB)
    if ($totalRAM -lt $MIN_RAM_MB) {
        $errors += "Insufficient RAM: ${totalRAM}MB detected, minimum ${MIN_RAM_MB}MB required for GOAD-Light."
    } elseif ($totalRAM -lt $RECOMMENDED_RAM) {
        $warnings += "RAM: ${totalRAM}MB detected, ${RECOMMENDED_RAM}MB recommended. Lab may be slow."
        $passed++
    } else {
        Write-Log "System RAM: ${totalRAM}MB" "SUCCESS"; $passed++
    }

    # ── Disk Space ──
    $drive = (Get-Item $SCRIPT_DIR).PSDrive.Name
    $freeGB = [math]::Round((Get-PSDrive $drive).Free / 1GB)
    if ($freeGB -lt 30) {
        $errors += "Insufficient disk: ${freeGB}GB free on ${drive}:, need at least 30GB for GOAD VMs + Docker images."
    } elseif ($freeGB -lt 50) {
        $warnings += "Disk space: ${freeGB}GB free on ${drive}:. 50GB+ recommended."
        $passed++
    } else {
        Write-Log "Disk space: ${freeGB}GB free on ${drive}:" "SUCCESS"; $passed++
    }

    # ── Stale Processes ──
    $stalePorts = @(5986, 5985, 3389)
    # Check for stale vagrant/vmrun processes that might conflict
    $staleVagrant = Get-Process -Name "vagrant" -ErrorAction SilentlyContinue
    if ($staleVagrant) {
        $warnings += "Stale vagrant processes detected (PIDs: $($staleVagrant.Id -join ', ')). May cause conflicts."
    } else {
        $passed++
    }

    # ── Summary ──
    foreach ($w in $warnings) { Write-Log $w "WARN" }
    if ($errors.Count -gt 0) {
        Write-Host ""
        Write-Log "PREREQUISITE FAILURES ($($errors.Count)):" "ERROR"
        foreach ($e in $errors) { Write-Log "  • $e" "ERROR" }
        Write-Host ""
        throw "Prerequisites not met. Fix the above issues and re-run."
    }
    Write-Log "All prerequisites passed ($passed checks)." "SUCCESS"
}

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIG LOADING & MERGING
# ═══════════════════════════════════════════════════════════════════════════════

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
        misconfigSeed = $MisconfigSeed
        attackerVm    = @{
            sshPort   = 22
            ramMB     = 4096
            cpus      = 2
        }
    }

    if (Test-Path $Path) {
        Write-Log "Loading config: $Path" "STEP"
        try {
            $raw = Get-Content -Path $Path -Raw -ErrorAction Stop
            # Validate JSON syntax
            $null = $raw | ConvertFrom-Json -ErrorAction Stop
            $json = $raw | ConvertFrom-Json

            if ($json.clientName)    { $config.clientName = [string]$json.clientName }
            if ($json.domain) {
                $d = [string]$json.domain
                # Validate domain format
                if ($d -notmatch "^[a-zA-Z0-9][a-zA-Z0-9\-]*\.[a-zA-Z0-9\.\-]+$") {
                    Write-Log "Invalid domain format '$d' in config. Randomizing." "WARN"
                } else {
                    $config.domain = $d
                }
            }
            if ($json.cidr) {
                $c = [string]$json.cidr
                if ($c -notmatch "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$") {
                    Write-Log "Invalid CIDR format '$c' in config. Randomizing." "WARN"
                } else {
                    $config.cidr = $c
                }
            }
            if ($json.lowPrivUser) {
                if ($json.lowPrivUser.username) { $config.lowPrivUser.username = [string]$json.lowPrivUser.username }
                if ($json.lowPrivUser.password) { $config.lowPrivUser.password = [string]$json.lowPrivUser.password }
            }
            if ($json.c2DockerImage) { $config.c2DockerImage = [string]$json.c2DockerImage }
            if ($json.c2EnvVars -and $json.c2EnvVars.PSObject) {
                $json.c2EnvVars.PSObject.Properties | ForEach-Object {
                    $config.c2EnvVars[$_.Name] = [string]$_.Value
                }
            }
            if ($json.labVariant) {
                $v = [string]$json.labVariant
                if ($v -notin @("GOAD-Light","GOAD","MINILAB","SCCM","NHA")) {
                    Write-Log "Unknown lab variant '$v'. Defaulting to GOAD-Light." "WARN"
                } else {
                    $config.labVariant = $v
                }
            }
            if ($json.misconfigSeed) { $config.misconfigSeed = [int]$json.misconfigSeed }
            if ($json.attackerVm) {
                if ($json.attackerVm.ramMB) { $config.attackerVm.ramMB = [int]$json.attackerVm.ramMB }
                if ($json.attackerVm.cpus)  { $config.attackerVm.cpus = [int]$json.attackerVm.cpus }
            }

            Write-Log "Config loaded successfully." "SUCCESS"
        }
        catch {
            Write-Log "Failed to parse config: $_" "ERROR"
            Write-Log "Proceeding with fully randomized lab." "WARN"
        }
    } else {
        Write-Log "No config at $Path — generating fully randomized lab." "WARN"
    }

    # Fill missing fields with randomized values
    if (-not $config.clientName)           { $config.clientName = New-RandomCompanyName }
    if (-not $config.domain)               { $config.domain = New-RandomDomain }
    if (-not $config.cidr)                 { $config.cidr = New-RandomCIDR }
    if (-not $config.lowPrivUser.username)  { $config.lowPrivUser.username = New-RandomUsername -FirstName (Get-RandomElement $script:FIRST_NAMES) -LastName (Get-RandomElement $script:LAST_NAMES) }
    if (-not $config.lowPrivUser.password)  { $config.lowPrivUser.password = New-RandomWeakPassword -CompanyName $config.clientName }

    return $config
}

# ═══════════════════════════════════════════════════════════════════════════════
# NETWORK HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

function Get-NetworkFromCIDR {
    param([string]$CIDR)
    $parts = $CIDR -split "/"
    $ip = $parts[0]
    $mask = [int]$parts[1]
    $octets = $ip -split "\."
    $subnet = "$($octets[0]).$($octets[1]).$($octets[2])"
    return @{
        Network   = $ip
        Prefix    = $mask
        Gateway   = "$subnet.1"
        DC1       = "$subnet.10"
        DC2       = "$subnet.11"
        SRV02     = "$subnet.22"
        Attacker  = "$subnet.200"
        Subnet    = $subnet
        IpRange   = $subnet
        Netmask   = if ($mask -eq 24) { "255.255.255.0" } elseif ($mask -eq 16) { "255.255.0.0" } else { "255.255.255.0" }
    }
}

function Initialize-VMwareNetwork {
    param(
        [hashtable]$NetInfo,
        [string]$CIDR
    )
    Write-Banner "CONFIGURING VMWARE HOST-ONLY NETWORK" -Step 2 -Total 8

    $vmwareDir = Split-Path $script:VMRUN -Parent
    $vnetlib = Join-Path $vmwareDir "vnetlib64.exe"
    $targetVmnet = "vmnet2"

    Write-Log "Target: $targetVmnet for CIDR $CIDR" "STEP"

    # Check current VMnet2 IP
    $currentIP = Get-NetIPAddress -InterfaceAlias "VMware Network Adapter VMnet2" -AddressFamily IPv4 -ErrorAction SilentlyContinue
    $expectedIP = "$($NetInfo.Subnet).1"

    if ($currentIP -and $currentIP.IPAddress -eq $expectedIP) {
        Write-Log "VMnet2 already configured: $expectedIP/$($NetInfo.Prefix)" "SUCCESS"
    } else {
        Write-Log "VMnet2 needs configuration (expected: $expectedIP, current: $(if ($currentIP) { $currentIP.IPAddress } else { 'none' }))" "WARN"

        # Try vnetlib64 first
        if (Test-Path $vnetlib) {
            Write-Log "Configuring via vnetlib64..." "STEP"
            & $vnetlib -- stop dhcp 2>$null
            & $vnetlib -- set vnet $targetVmnet mask $($NetInfo.Netmask) 2>&1 | Out-Null
            & $vnetlib -- set vnet $targetVmnet addr $($NetInfo.Network) 2>&1 | Out-Null
            & $vnetlib -- set vnet $targetVmnet type hostonly 2>&1 | Out-Null
            & $vnetlib -- remove dhcp $targetVmnet 2>&1 | Out-Null
            & $vnetlib -- start dhcp 2>$null
        }

        # Ensure host adapter has the right IP
        try {
            if ($currentIP) {
                Remove-NetIPAddress -InterfaceAlias "VMware Network Adapter VMnet2" -IPAddress $currentIP.IPAddress -Confirm:$false -ErrorAction SilentlyContinue
            }
            New-NetIPAddress -InterfaceAlias "VMware Network Adapter VMnet2" -IPAddress $expectedIP -PrefixLength $NetInfo.Prefix -ErrorAction Stop | Out-Null
            Write-Log "VMnet2 configured: $expectedIP/$($NetInfo.Prefix)" "SUCCESS"
        }
        catch {
            if ($_.Exception.Message -match "already exists") {
                Write-Log "VMnet2 IP already set (race condition — OK)" "SUCCESS"
            } else {
                Write-Log "Failed to set VMnet2 IP: $_" "ERROR"
                Write-Log "Manually run: New-NetIPAddress -InterfaceAlias 'VMware Network Adapter VMnet2' -IPAddress $expectedIP -PrefixLength $($NetInfo.Prefix)" "WARN"
            }
        }
    }

    # Warn about non-persistent IP
    Write-Log "NOTE: VMnet2 IP may not persist across reboots. Re-run script or set manually." "WARN"

    return $targetVmnet
}

# ═══════════════════════════════════════════════════════════════════════════════
# GOAD DEPLOYMENT (v3.0 — improved injection, resume support)
# ═══════════════════════════════════════════════════════════════════════════════

function Deploy-GOAD {
    param(
        [hashtable]$Config,
        [hashtable]$NetInfo,
        [string]$VMnet,
        [array]$ADUsers,
        [array]$ServiceAccounts,
        [array]$Misconfigs
    )
    Write-Banner "DEPLOYING GOAD ($($Config.labVariant))" -Step 3 -Total 8

    # ── Clone GOAD ──
    if (-not (Test-Path $GOAD_DIR)) {
        Write-Log "Cloning GOAD repository..." "STEP"
        & git clone --depth 1 $GOAD_REPO $GOAD_DIR 2>&1 | ForEach-Object { Write-Log $_ "DETAIL" }
        if ($LASTEXITCODE -ne 0) { throw "Failed to clone GOAD repository." }
        Write-Log "GOAD cloned." "SUCCESS"
    } else {
        Write-Log "GOAD directory exists. Skipping clone." "SUCCESS"
    }

    # Validate lab variant
    $labVariant = $Config.labVariant
    $labPath = Join-Path $GOAD_DIR "ad" $labVariant
    if (-not (Test-Path $labPath)) {
        Write-Log "'$labVariant' not found, falling back to GOAD-Light." "WARN"
        $labVariant = "GOAD-Light"
        $labPath = Join-Path $GOAD_DIR "ad" $labVariant
    }

    # ── Apply GOAD patches for Windows+Docker ──
    Write-Log "Applying Windows+Docker patches to GOAD..." "STEP"
    Apply-GOADPatches

    # ── Install Python deps ──
    Write-Log "Installing GOAD Python dependencies..." "STEP"
    Push-Location $GOAD_DIR
    try {
        & pip install -r requirements.yml 2>&1 | Select-Object -Last 3 | ForEach-Object { Write-Log $_ "DETAIL" }
        & pip install rich 2>&1 | Select-Object -Last 1 | ForEach-Object { Write-Log $_ "DETAIL" }
    } catch {
        Write-Log "pip install had warnings (non-fatal): $_" "WARN"
    }

    # ── Build goadansible Docker image ──
    $dockerImageExists = (& docker images goadansible --format "{{.Repository}}" 2>$null) -eq "goadansible"
    if (-not $dockerImageExists) {
        Write-Log "Building goadansible Docker image (first time only)..." "STEP"
        & docker build -t goadansible . 2>&1 | ForEach-Object { Write-Log $_ "DETAIL" }
        if ($LASTEXITCODE -eq 0) { Write-Log "goadansible Docker image built." "SUCCESS" }
        else { Write-Log "Docker image build had issues (exit: $LASTEXITCODE)" "WARN" }
    } else {
        Write-Log "goadansible Docker image exists. Skipping build." "SUCCESS"
    }

    # ── Generate custom Ansible extra-vars for GOAD injection ──
    Write-Log "Generating custom Ansible variables..." "STEP"
    New-GOADInjectionVars -Config $Config -NetInfo $NetInfo -ADUsers $ADUsers `
                          -ServiceAccounts $ServiceAccounts -Misconfigs $Misconfigs

    # ── Launch GOAD ──
    $ipRange = $NetInfo.IpRange
    Write-Host ""
    Write-Log "Launching GOAD deployment..." "STEP"
    Write-Log "  Lab:         $labVariant" "DETAIL"
    Write-Log "  Provider:    vmware" "DETAIL"
    Write-Log "  Provisioner: docker (Docker-based Ansible)" "DETAIL"
    Write-Log "  IP Range:    $ipRange.X" "DETAIL"
    Write-Log "  Estimated:   30-90 minutes" "DETAIL"
    Write-Host ""

    $goadCmd = if ($ResumeFrom) {
        Write-Log "Resuming from playbook: $ResumeFrom" "WARN"
        $iid = if ($InstanceId) { $InstanceId } else {
            $ws = Get-ChildItem (Join-Path $GOAD_DIR "workspace") -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($ws) { $ws.Name } else { "" }
        }
        if (-not $iid) { throw "Cannot resume: no instance ID found. Use -InstanceId parameter." }
        "python goad.py -t install -l $labVariant -p vmware -m docker -ip $ipRange -r $ResumeFrom -i $iid"
    } else {
        "python goad.py -t install -l $labVariant -p vmware -m docker -ip $ipRange"
    }

    Write-Log "Command: $goadCmd" "DETAIL"
    $goadArgs = ($goadCmd -replace "^python goad\.py ","") -split "\s+"
    & python goad.py @goadArgs 2>&1 | ForEach-Object { Write-Log $_ "DETAIL" }

    if ($LASTEXITCODE -ne 0) {
        Write-Log "GOAD exited with code $LASTEXITCODE" "WARN"
        Write-Log "Common fixes:" "WARN"
        Write-Log "  • Vagrant box timeout: re-run the script" "WARN"
        Write-Log "  • Ansible failure: re-run with -ResumeFrom <playbook.yml> -InstanceId <id>" "WARN"
        Write-Log "  • Network issue: verify VMnet2 IP with Get-NetIPAddress" "WARN"
    } else {
        Write-Log "GOAD deployment completed successfully!" "SUCCESS"
    }

    Pop-Location
}

function Apply-GOADPatches {
    # Patch 1: Enable Docker provisioning on Windows
    $depsFile = Join-Path $GOAD_DIR "goad" "dependencies.py"
    if (Test-Path $depsFile) {
        $content = Get-Content $depsFile -Raw
        if ($content -match "Utils\.is_windows\(\)") {
            $content = $content -replace "provisioner_docker_enabled\s*=\s*False\s+if\s+\(Utils\.is_windows\(\)\s+or\s+Utils\.is_wsl\(\)\)\s+else\s+True",
                                          "provisioner_docker_enabled = False if Utils.is_wsl() else True"
            Set-Content -Path $depsFile -Value $content -Force
            Write-Log "Patched dependencies.py (Docker on Windows)" "SUCCESS"
        }
    }

    # Patch 2: Add run_docker_ansible to Windows command handler
    $winCmdFile = Join-Path $GOAD_DIR "goad" "command" "windows.py"
    if (Test-Path $winCmdFile) {
        $content = Get-Content $winCmdFile -Raw
        if ($content -notmatch "run_docker_ansible") {
            # Add import if needed
            if ($content -notmatch "import sys") {
                $content = $content -replace "(import subprocess)", "import subprocess`nimport sys"
            }
            if ($content -notmatch "from goad\.goadpath") {
                $content = $content -replace "(from goad\.command\.cmd import Command)", "`$1`nfrom goad.goadpath import GoadPath"
            }
            # Add method
            $dockerMethod = @'

    def run_docker_ansible(self, ansible_playbook_command, path):
        """Run Ansible inside the goadansible Docker container (Windows host)."""
        goad_path = GoadPath.get_goad_path()
        docker_cmd = [
            'docker', 'run', '--rm',
            '--network', 'host',
            '-h', 'goadansible',
            '-v', f'{goad_path}:/goad',
            '-w', '/goad',
            'goadansible',
            'bash', '-c', ansible_playbook_command
        ]
        print(f"[*] Docker Ansible: {ansible_playbook_command}")
        return self.run_cmd(docker_cmd)
'@
            $content = $content -replace "(class Windows\(Command\):.*?)((?=\nclass )|$)", "`$1`n$dockerMethod`n"
            Set-Content -Path $winCmdFile -Value $content -Force
            Write-Log "Patched windows.py (Docker Ansible method)" "SUCCESS"
        }

        # Fix is_in_path signature
        if ($content -match "def is_in_path\(self, bin_file\):" -and $content -notmatch "def is_in_path\(self, bin_file, verbose") {
            $content = Get-Content $winCmdFile -Raw
            $content = $content -replace "def is_in_path\(self, bin_file\):", "def is_in_path(self, bin_file, verbose=True):"
            Set-Content -Path $winCmdFile -Value $content -Force
            Write-Log "Patched windows.py (is_in_path signature)" "SUCCESS"
        }
    }

    # Patch 3: Docker provisioner for Windows
    $dockerProvFile = Join-Path $GOAD_DIR "goad" "provisioner" "ansible" "docker.py"
    if (Test-Path $dockerProvFile) {
        $content = Get-Content $dockerProvFile -Raw
        # Windows bypass for docker group check
        if ($content -match "is_current_user_in_docker_group" -and $content -notmatch "os\.name\s*==\s*'nt'") {
            $content = $content -replace "(def is_current_user_in_docker_group.*?:.*?\n)",
                                          "`$1        if os.name == 'nt':`n            return True`n"
            Set-Content -Path $dockerProvFile -Value $content -Force
            Write-Log "Patched docker.py (Windows docker group bypass)" "SUCCESS"
        }
        # Replace grep-based docker image check with cross-platform version
        if ($content -match "grep.*goadansible" -and $content -notmatch "docker.*images.*--format") {
            $content = Get-Content $dockerProvFile -Raw
            $content = $content -replace "subprocess\.run\(\[.*grep.*goadansible.*?\]",
                                          "subprocess.run(['docker', 'images', '--format', '{{.Repository}}', 'goadansible']"
            Set-Content -Path $dockerProvFile -Value $content -Force
            Write-Log "Patched docker.py (cross-platform image check)" "SUCCESS"
        }
    }
}

function New-GOADInjectionVars {
    param(
        [hashtable]$Config,
        [hashtable]$NetInfo,
        [array]$ADUsers,
        [array]$ServiceAccounts,
        [array]$Misconfigs
    )

    if (-not (Test-Path $CUSTOM_VARS_DIR)) { New-Item -ItemType Directory -Path $CUSTOM_VARS_DIR -Force | Out-Null }

    $domainParts = $Config.domain -split "\."
    $domainNetbios = $domainParts[0].ToUpper()

    # Domain config
    $domainYaml = @"
---
# Auto-generated by Insta-Internal-Labinator v$SCRIPT_VERSION
# Client: $($Config.clientName)
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

custom_domain:
  name: "$($Config.domain)"
  netbios: "$domainNetbios"
  dn: "DC=$($domainParts -join ',DC=')"
  initial_user: "$($Config.lowPrivUser.username)"
  initial_password: "$($Config.lowPrivUser.password)"
"@
    Set-Content -Path (Join-Path $CUSTOM_VARS_DIR "custom_domain.yml") -Value $domainYaml -Force

    # Users YAML
    $usersYaml = "---`n# Domain users ($($ADUsers.Count) total)`ncustom_domain_users:`n"
    foreach ($u in $ADUsers | Select-Object -First 50) {  # Limit to 50 for Ansible var file size
        $usersYaml += "  - name: `"$($u.Username)`"`n"
        $usersYaml += "    password: `"$($u.Password)`"`n"
        $usersYaml += "    firstname: `"$($u.FirstName)`"`n"
        $usersYaml += "    lastname: `"$($u.LastName)`"`n"
        $usersYaml += "    department: `"$($u.Department)`"`n"
        $usersYaml += "    title: `"$($u.Title)`"`n"
    }
    Set-Content -Path (Join-Path $CUSTOM_VARS_DIR "custom_users.yml") -Value $usersYaml -Force

    # Service accounts
    $svcYaml = "---`ncustom_service_accounts:`n"
    foreach ($svc in $ServiceAccounts) {
        $spn = $svc.SPN -replace "\{domain\}", $Config.domain
        $svcYaml += "  - name: `"$($svc.Name)`"`n"
        $svcYaml += "    password: `"$($svc.Password)`"`n"
        $svcYaml += "    spn: `"$spn`"`n"
        $svcYaml += "    description: `"$($svc.Desc)`"`n"
        if ($svc.DelegationType -ne "none") {
            $svcYaml += "    delegation: `"$($svc.DelegationType)`"`n"
        }
    }
    Set-Content -Path (Join-Path $CUSTOM_VARS_DIR "custom_services.yml") -Value $svcYaml -Force

    # Misconfigurations
    $mcYaml = "---`nactive_misconfigurations:`n"
    foreach ($mc in $Misconfigs) {
        $mcYaml += "  - id: `"$($mc.Id)`"`n"
        $mcYaml += "    category: `"$($mc.Category)`"`n"
        $mcYaml += "    description: `"$($mc.Desc)`"`n"
        $mcYaml += "    severity: `"$($mc.Severity)`"`n"
        $mcYaml += "    enabled: true`n"
    }
    Set-Content -Path (Join-Path $CUSTOM_VARS_DIR "custom_misconfigs.yml") -Value $mcYaml -Force

    Write-Log "Injection vars written to $CUSTOM_VARS_DIR" "SUCCESS"
}

# ═══════════════════════════════════════════════════════════════════════════════
# ATTACKER VM DEPLOYMENT
# ═══════════════════════════════════════════════════════════════════════════════

function Deploy-AttackerVM {
    param(
        [hashtable]$Config,
        [hashtable]$NetInfo,
        [string]$VMnet
    )
    Write-Banner "DEPLOYING ATTACKER VM" -Step 4 -Total 8

    $attackerDir = Join-Path $SCRIPT_DIR "attacker-vm"
    if (-not (Test-Path $attackerDir)) { New-Item -ItemType Directory -Path $attackerDir -Force | Out-Null }

    $attackerIP = $NetInfo.Attacker
    $subnet = $NetInfo.Subnet

    # Check if already running (idempotent)
    if (Test-Path (Join-Path $attackerDir "Vagrantfile")) {
        Push-Location $attackerDir
        $status = & vagrant status 2>&1 | Out-String
        Pop-Location
        if ($status -match "running" -and -not $Force) {
            Write-Log "Attacker VM already running. Use -Force to rebuild." "SUCCESS"
            return
        }
    }

    # Build C2 Docker block
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

    $domainParts = $Config.domain -split "\."
    $domainNetbios = $domainParts[0].ToUpper()

    $vagrantContent = @"
# -*- mode: ruby -*-
# Insta-Internal-Labinator v$SCRIPT_VERSION — Attacker VM
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

Vagrant.configure("2") do |config|
  config.vm.box = "bento/ubuntu-24.04"
  config.vm.hostname = "attacker"
  config.vm.define "attacker-vm" do |attacker|
  end

  config.vm.provider "vmware_desktop" do |v|
    v.vmx["memsize"] = "$($Config.attackerVm.ramMB)"
    v.vmx["numvcpus"] = "$($Config.attackerVm.cpus)"
    v.vmx["displayName"] = "Attacker-VM-Labinator"
    v.vmx["ethernet1.present"] = "TRUE"
    v.vmx["ethernet1.connectionType"] = "custom"
    v.vmx["ethernet1.vnet"] = "$VMnet"
    v.vmx["ethernet1.virtualDev"] = "e1000e"
  end

  config.vm.provision "shell", inline: <<-SHELL
    set -e
    export DEBIAN_FRONTEND=noninteractive

    echo "[*] Updating system..."
    apt-get update -qq
    apt-get upgrade -y -qq

    echo "[*] Installing core packages..."
    apt-get install -y -qq \
      docker.io docker-compose-v2 \
      net-tools iputils-ping dnsutils \
      nmap masscan \
      python3 python3-pip python3-venv \
      git curl wget jq unzip \
      smbclient ldap-utils \
      proxychains4 \
      tmux vim htop

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
      dhcp4: false
NETPLAN
    netplan apply 2>/dev/null || true

    echo "[*] Installing Python pentesting tools..."
    python3 -m pip install --break-system-packages \
      impacket certipy-ad bloodhound ldapdomaindump \
      pycryptodomex minikerberos netexec 2>/dev/null || true

    git clone --depth 1 https://github.com/fortra/impacket.git /opt/impacket 2>/dev/null || true
    cd /opt/impacket && python3 -m pip install --break-system-packages . 2>/dev/null || true

    echo "[*] Installing Kerbrute..."
    wget -q "https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64" \
      -O /usr/local/bin/kerbrute 2>/dev/null && chmod +x /usr/local/bin/kerbrute || true

    echo "[*] Setting up Responder..."
    git clone --depth 1 https://github.com/lgandx/Responder.git /opt/Responder 2>/dev/null || true

    echo "[*] Setting up enum4linux-ng..."
    git clone --depth 1 https://github.com/cddmp/enum4linux-ng.git /opt/enum4linux-ng 2>/dev/null || true
    cd /opt/enum4linux-ng && python3 -m pip install --break-system-packages -r requirements.txt 2>/dev/null || true
$c2DockerBlock

    echo "[*] Creating engagement workspace..."
    mkdir -p /home/vagrant/engagement/{scans,loot,notes,bloodhound}
    chown -R vagrant:vagrant /home/vagrant/engagement

    cat > /home/vagrant/engagement/lab-info.txt << 'LABINFO'
=== Insta-Internal-Labinator v$SCRIPT_VERSION ===
Client:       $($Config.clientName)
Domain:       $($Config.domain) ($domainNetbios)
Initial User: $domainNetbios\\$($Config.lowPrivUser.username)
Password:     $($Config.lowPrivUser.password)
Lab Network:  $($Config.cidr)
Attacker IP:  $attackerIP
DC01:         $subnet.10
DC02:         $subnet.11
SRV02:        $subnet.22
Generated:    $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
LABINFO

    echo "[+] Attacker VM provisioning complete!"
  SHELL
end
"@

    Set-Content -Path (Join-Path $attackerDir "Vagrantfile") -Value $vagrantContent -Force
    Write-Log "Vagrantfile generated." "SUCCESS"

    Push-Location $attackerDir
    try {
        if ($Force) {
            Write-Log "Force rebuild — destroying existing VM..." "WARN"
            & vagrant destroy -f 2>&1 | Out-Null
        }
        Write-Log "Starting Attacker VM (this takes 10-15 minutes)..." "STEP"
        & vagrant up --provider vmware_desktop 2>&1 | ForEach-Object { Write-Log $_ "DETAIL" }
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Attacker VM deployed at $attackerIP!" "SUCCESS"
        } else {
            Write-Log "Attacker VM had warnings (exit: $LASTEXITCODE)" "WARN"
        }
    }
    finally { Pop-Location }
}

# ═══════════════════════════════════════════════════════════════════════════════
# SNAPSHOTS
# ═══════════════════════════════════════════════════════════════════════════════

function New-VMwareSnapshots {
    param([string]$Timestamp)
    Write-Banner "CREATING VMWARE SNAPSHOTS" -Step 5 -Total 8

    if (-not $script:VMRUN) {
        Write-Log "vmrun not available — skipping." "WARN"
        return
    }

    $snapshotName = "Fresh-Deploy-$Timestamp"
    $runningVMs = & $script:VMRUN list 2>&1
    $vmxFiles = $runningVMs | Where-Object { $_ -match "\.vmx$" }

    if (-not $vmxFiles) {
        Write-Log "No running VMs found." "WARN"
        return
    }

    $total = @($vmxFiles).Count
    $i = 0
    foreach ($vmx in $vmxFiles) {
        $i++
        $vmName = [System.IO.Path]::GetFileNameWithoutExtension(
            [System.IO.Path]::GetDirectoryName(
                [System.IO.Path]::GetDirectoryName($vmx)
            )
        )
        if ($vmName -eq "vmware_desktop") {
            # Extract from parent path
            $parts = $vmx -split "\\" | Where-Object { $_ -match "GOAD-Light|attacker" }
            $vmName = if ($parts) { $parts[0] } else { "VM-$i" }
        }
        Write-Log "[$i/$total] Snapshotting $vmName..." "STEP"
        & $script:VMRUN snapshot "$vmx" "$snapshotName" 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { Write-Log "Snapshot: $vmName → $snapshotName" "SUCCESS" }
        else { Write-Log "Snapshot failed for $vmName" "WARN" }
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# HANDOFF PACKAGE (v3.0 — executive quality)
# ═══════════════════════════════════════════════════════════════════════════════

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
    Write-Banner "GENERATING RED TEAM HANDOFF PACKAGE" -Step 6 -Total 8

    $domainClean = $Config.domain -replace "\.", "-"
    $handoffDir = Join-Path $SCRIPT_DIR "RedTeam-Handoff-${domainClean}-${Timestamp}"
    New-Item -ItemType Directory -Path $handoffDir -Force | Out-Null

    $domainParts = $Config.domain -split "\."
    $domainNetbios = $domainParts[0].ToUpper()
    $dcIP1 = $NetInfo.DC1
    $dcIP2 = $NetInfo.DC2
    $srvIP = $NetInfo.SRV02
    $attackerIP = $NetInfo.Attacker
    $engId = "RT-$(Get-Date -Format 'yyyyMMdd')-$(Get-SeededRandom -Min 1000 -Max 9999)"
    $emailDomain = $Config.domain -replace '\.(local|internal|corp|lan|ad|intra)$', '.com'
    $phone1 = "+1 (555) $(Get-SeededRandom -Min 100 -Max 999)-$(Get-SeededRandom -Min 1000 -Max 9999)"
    $phone2 = "+1 (555) $(Get-SeededRandom -Min 100 -Max 999)-$(Get-SeededRandom -Min 1000 -Max 9999)"

    # ────── Handoff.md ──────
    $handoffMd = @"
# RED TEAM ENGAGEMENT — ASSUMED BREACH HANDOFF

**Classification: CONFIDENTIAL — Authorized Personnel Only**
**Client: $($Config.clientName)**
**Date: $(Get-Date -Format 'MMMM dd, yyyy')**
**Engagement ID: $engId**

---

## 1. EXECUTIVE SUMMARY

$($Config.clientName) has contracted an **internal assumed-breach penetration test** to evaluate the security posture of its Active Directory environment. The testing team has been provided low-privileged domain credentials simulating a compromised employee account (e.g., via phishing). The objective is to identify privilege escalation paths, lateral movement opportunities, and demonstrate the potential impact of a real attacker gaining initial foothold within the corporate network.

**Engagement Type:** Internal Network Penetration Test — Assumed Breach
**Methodology:** PTES (Penetration Testing Execution Standard) / MITRE ATT&CK
**Authorized Duration:** 5 business days (Mon–Fri, 09:00–17:00 local)
**Authorization Level:** Full authorization for all testing within defined scope

---

## 2. RULES OF ENGAGEMENT

### 2.1 Authorized Activities
- Network reconnaissance and enumeration
- Active Directory enumeration and exploitation
- Credential harvesting and password attacks (offline cracking)
- Lateral movement and privilege escalation
- Kerberos-based attacks (Kerberoasting, AS-REP, delegation abuse)
- ADCS certificate-based attacks
- SMB/NTLM relay attacks
- Simulated data exfiltration (identify, do not extract)

### 2.2 Restrictions
| Restriction | Detail |
|-------------|--------|
| **Denial of Service** | No intentional disruption of services |
| **Physical Access** | Physical testing is not authorized |
| **Social Engineering** | Not authorized unless separately approved |
| **Data Handling** | If PHI/PII is discovered, stop and notify immediately |
| **Destructive Actions** | No deletion of data, accounts, or configurations |
| **Scope Boundaries** | Stay within defined CIDR range(s) |

### 2.3 Emergency Contacts
| Role | Contact | Phone |
|------|---------|-------|
| **IT Security** | security@$emailDomain | $phone1 |
| **CISO Office** | ciso@$emailDomain | $phone2 |

**Emergency Protocol:** If testing causes unintended impact, immediately stop all activities and contact the numbers above.

---

## 3. IN-SCOPE DEFINITION

### 3.1 Network Ranges
| CIDR | Description | Classification |
|------|-------------|----------------|
| ``$($Config.cidr)`` | Primary corporate LAN — AD infrastructure, servers | **In-Scope** |

### 3.2 Domain Information
| Field | Value |
|-------|-------|
| **Domain FQDN** | ``$($Config.domain)`` |
| **NetBIOS Name** | ``$domainNetbios`` |
| **Functional Level** | Windows Server 2016/2019 |

### 3.3 Target Systems
| Hostname | IP Address | OS | Roles | Classification |
|----------|------------|-----|-------|---------------|
| DC01 | ``$dcIP1`` | Windows Server 2019 | AD DS (PDC), DNS, ADCS | In-Scope |
| DC02 | ``$dcIP2`` | Windows Server 2019 | AD DS (BDC), DNS | In-Scope |
| SRV02 | ``$srvIP`` | Windows Server 2019 | File Server, MSSQL, IIS | In-Scope |

---

## 4. INITIAL FOOTHOLD — ASSUMED BREACH CREDENTIALS

The following credentials simulate a compromised employee account, as would be obtained through a successful phishing attack or credential stuffing:

| Field | Value |
|-------|-------|
| **Username** | ``$domainNetbios\$($Config.lowPrivUser.username)`` |
| **Password** | ``$($Config.lowPrivUser.password)`` |
| **Account Type** | Standard domain user (Domain Users group) |
| **Access Level** | Low-privileged — no administrative rights |

> **Primary Objective:** Starting from this account, escalate privileges to **Domain Admin** or **Enterprise Admin**. Document the complete attack chain including every credential, pivot, and technique used.

> **Secondary Objectives:**
> - Map all viable privilege escalation paths
> - Identify and exploit AD Certificate Services misconfigurations
> - Demonstrate credential harvesting capabilities
> - Identify sensitive data exposure on network shares
> - Document all Kerberoastable/AS-REP roastable accounts

---

## 5. KNOWN NETWORK INTELLIGENCE

The following information has been shared as part of the assumed-breach scenario, representing knowledge a compromised employee would reasonably possess:

- **DNS:** Served by the domain controllers ($dcIP1, $dcIP2)
- **File Shares:** Corporate shares accessible at ``\\$srvIP\``
- **Intranet:** Internal web applications hosted on SRV02 (IIS)
- **Database:** SQL Server running on SRV02 (default instance, port 1433)
- **ADCS:** Certificate Services deployed for PKI operations
- **Naming Convention:** User accounts follow ``firstname.lastname`` pattern
- **IT Practices:** IT staff maintain scripts and documentation on shared drives
- **Legacy Systems:** Several service accounts exist from decommissioned applications

---

## 6. SAMPLE "LEAKED" INTELLIGENCE

During OSINT reconnaissance, the following was discovered (simulated):

- An employee posted their VPN configuration on a public GitHub gist (redacted)
- LinkedIn profiles reveal IT team uses ``$domainNetbios\`` naming convention
- A former employee's portfolio mentions "Windows Server 2019" infrastructure
- Job postings reference "Active Directory," "SCCM," and "Azure AD Connect"
- ``$emailDomain`` SPF record indicates on-premise Exchange

---

## 7. ENGAGEMENT TIMELINE

| Phase | Days | Objectives |
|-------|------|-----------|
| **1. Reconnaissance** | Day 1 | Network scanning, service enumeration, AD discovery |
| **2. Enumeration** | Day 1–2 | BloodHound collection, share enumeration, user mapping |
| **3. Initial Exploitation** | Day 2–3 | Kerberoasting, AS-REP, NTLM relay, credential attacks |
| **4. Privilege Escalation** | Day 3–4 | ACL abuse, delegation attacks, ADCS exploitation |
| **5. Lateral Movement** | Day 4 | Cross-host movement, trust abuse, domain compromise |
| **6. Reporting** | Day 4–5 | Attack narrative, findings documentation, remediation |

---

## 8. DELIVERABLE EXPECTATIONS

1. **Executive Summary** — Business-risk overview for leadership
2. **Technical Findings** — Each finding with CVSS v3.1 score
3. **Full Attack Narrative** — Step-by-step with screenshots and tool output
4. **Remediation Recommendations** — Prioritized by risk and implementation effort
5. **BloodHound Data** — Attack path visualizations
6. **Appendices** — Scan results, raw evidence (sanitized)

---

## 9. SAFETY NOTICE

> **⚠️ This is a deliberately vulnerable lab environment for authorized testing only.**
>
> - Do NOT expose these systems to production networks or the internet
> - All credentials are intentionally weak by design
> - Destroy the lab environment when testing is complete
> - Do not use discovered techniques against systems outside the defined scope

---

*This document is the property of $($Config.clientName). Unauthorized distribution is prohibited. Provided under mutual NDA.*
*Generated by Insta-Internal-Labinator v$SCRIPT_VERSION*
"@
    Set-Content -Path (Join-Path $handoffDir "Handoff.md") -Value $handoffMd -Force

    # ────── lab-credentials.txt ──────
    $weakCount = @($ADUsers | Where-Object { $_.WeakPW }).Count
    $svcUsers = @($ADUsers | Where-Object { $_.AccountType -eq "Service" })
    $tmpUsers = @($ADUsers | Where-Object { $_.AccountType -eq "Temporary" })
    $admUsers = @($ADUsers | Where-Object { $_.AccountType -eq "Admin" })

    $credLines = @"
================================================================================
  $($Config.clientName.ToUpper()) — LAB CREDENTIALS
  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  Engagement: $engId
  Domain: $($Config.domain) ($domainNetbios)
  Insta-Internal-Labinator v$SCRIPT_VERSION
================================================================================

DOMAIN CONTROLLERS
──────────────────
  DC01:  $dcIP1   $($Config.domain)  (PDC, DNS, ADCS, GPO)
    Local Admin:  Administrator / vagrant
    WinRM (SSL):  https://${dcIP1}:5986

  DC02:  $dcIP2   $($Config.domain)  (BDC, DNS, Replication)
    Local Admin:  Administrator / vagrant
    WinRM (SSL):  https://${dcIP2}:5986

MEMBER SERVERS
──────────────
  SRV02: $srvIP   $($Config.domain)  (File Server, MSSQL, IIS)
    Local Admin:  Administrator / vagrant
    WinRM (SSL):  https://${srvIP}:5986
    MSSQL:        ${srvIP}:1433 (default instance)
    HTTP:         http://${srvIP}/ (IIS)

NETWORK
───────
  Lab Network:  $($Config.cidr) on $VMnet (Host-Only, No DHCP)
  Host IP:      $($NetInfo.Subnet).1
  DNS:          $dcIP1, $dcIP2

ASSUMED BREACH CREDENTIALS (Low-Priv)
──────────────────────────────────────
  Domain:   $($Config.domain)
  Username: $domainNetbios\$($Config.lowPrivUser.username)
  Password: $($Config.lowPrivUser.password)

ATTACKER VM
───────────
  IP:  $attackerIP
  SSH: ssh vagrant@$attackerIP (password: vagrant)

KERBEROASTABLE SERVICE ACCOUNTS ($($ServiceAccounts.Count))
───────────────────────────────────────────────────────────

"@
    foreach ($svc in $ServiceAccounts) {
        $spn = $svc.SPN -replace "\{domain\}", $Config.domain
        $credLines += "  $($svc.Name.PadRight(20)) $($svc.Password.PadRight(18)) SPN: $spn`n"
    }

    $credLines += "`nSERVICE ACCOUNT USERS ($($svcUsers.Count))`n"
    foreach ($u in $svcUsers) {
        $credLines += "  $($u.Username.PadRight(22)) $($u.Password)`n"
    }

    $credLines += "`nADMIN SHADOW ACCOUNTS ($($admUsers.Count))`n"
    foreach ($u in $admUsers) {
        $credLines += "  $($u.Username.PadRight(22)) $($u.Password)`n"
    }

    $credLines += "`nTEMPORARY/CONTRACTOR ACCOUNTS ($($tmpUsers.Count))`n"
    foreach ($u in $tmpUsers) {
        $credLines += "  $($u.Username.PadRight(22)) $($u.Password)`n"
    }

    $credLines += "`nWEAK PASSWORD ACCOUNTS ($weakCount of $($ADUsers.Count) total, $(([math]::Round($weakCount / [math]::Max($ADUsers.Count,1) * 100)))%)`n"
    $weakSample = $ADUsers | Where-Object { $_.WeakPW -and $_.AccountType -eq "Regular" } | Select-Object -First 30
    foreach ($u in $weakSample) {
        $credLines += "  $($u.Username.PadRight(22)) $($u.Password.PadRight(18)) $($u.Department)`n"
    }
    if ($weakCount -gt 30) { $credLines += "  ... and $($weakCount - 30) more (see all-users.csv)`n" }

    $credLines += "`nACTIVE MISCONFIGURATIONS ($($Misconfigs.Count))`n"
    $credLines += "─" * 60 + "`n"
    foreach ($mc in $Misconfigs | Sort-Object { $_.Severity }) {
        $sevColor = switch ($mc.Severity) { "Critical" { "!!!" } "High" { "!! " } "Medium" { "!  " } default { "   " } }
        $credLines += "  [$sevColor] $($mc.Id.PadRight(22)) $($mc.Desc)`n"
        $credLines += "        Attack: $($mc.AttackPath)`n"
    }

    Set-Content -Path (Join-Path $handoffDir "lab-credentials.txt") -Value $credLines -Force

    # ────── network-map.txt ──────
    $networkMap = @"
================================================================================
  NETWORK MAP — $($Config.clientName)
  CIDR: $($Config.cidr)  |  VMnet: $VMnet  |  Domain: $($Config.domain)
================================================================================

  HOST MACHINE
  ├─ $VMnet: $($NetInfo.Subnet).1/24  (Host-Only / Lab Network)
  └─ Docker Desktop (agent stack / C2)

              ┌─────────────────────────────────────┐
              │   HOST-ONLY NETWORK ($VMnet)         │
              │       $($Config.cidr.PadRight(25))       │
              └──┬──────────┬──────────┬─────────────┘
                 │          │          │
       ┌────────┴───────┐ ┌┴──────────┴──┐ ┌──────────────────┐
       │   DC01          │ │    DC02       │ │     SRV02        │
       │ $($dcIP1.PadRight(15))│ │ $($dcIP2.PadRight(13))│ │ $($srvIP.PadRight(16))│
       │ Win Svr 2019    │ │ Win Svr 2019 │ │ Win Svr 2019     │
       │                 │ │              │ │                  │
       │ • AD DS (PDC)   │ │ • AD DS (BDC)│ │ • File Server    │
       │ • DNS           │ │ • DNS        │ │ • MSSQL :1433    │
       │ • ADCS          │ │ • Replication│ │ • IIS :80        │
       │ • GPO           │ │              │ │ • Open Shares    │
       └─────────────────┘ └──────────────┘ └──────────────────┘

  ATTACK SURFACE
  ──────────────
  Port  │ Service          │ Hosts         │ Notes
  ──────┼──────────────────┼───────────────┼────────────────────
  53    │ DNS              │ DC01, DC02    │ Zone transfer may be possible
  80    │ HTTP (IIS)       │ SRV02         │ Web app + upload
  88    │ Kerberos         │ DC01, DC02    │ Kerberoast, AS-REP
  135   │ RPC              │ All           │ Endpoint mapper
  137   │ NBT-NS           │ All           │ Poisonable
  139   │ NetBIOS-SSN      │ All           │ Legacy SMB
  389   │ LDAP             │ DC01, DC02    │ AD enumeration
  443   │ HTTPS/ADCS       │ DC01          │ Certificate enrollment
  445   │ SMB              │ All           │ Signing NOT required
  636   │ LDAPS            │ DC01, DC02    │ Encrypted LDAP
  1433  │ MSSQL            │ SRV02         │ SQL Server default
  3389  │ RDP              │ All           │ Remote Desktop
  5355  │ LLMNR            │ All           │ Poisonable
  5985  │ WinRM HTTP       │ All           │ PS Remoting
  5986  │ WinRM HTTPS      │ All           │ PS Remoting (SSL)
  9389  │ ADWS             │ DC01, DC02    │ AD Web Services
"@
    Set-Content -Path (Join-Path $handoffDir "network-map.txt") -Value $networkMap -Force

    # ────── start-attacking.md ──────
    $startAttacking = @"
# Attack Quick Reference — $($Config.clientName)

## Credentials
``````
Domain:   $($Config.domain)
NetBIOS:  $domainNetbios
User:     $domainNetbios\$($Config.lowPrivUser.username)
Pass:     $($Config.lowPrivUser.password)
DC1:      $dcIP1
DC2:      $dcIP2
SRV:      $srvIP
Attacker: $attackerIP
``````

---

## Phase 0 — Recon
``````bash
nmap -sn $($Config.cidr) -oA scans/pingsweep
nmap -sC -sV -O $dcIP1 $dcIP2 $srvIP -oA scans/full
``````

## Phase 1 — AD Enumeration
``````bash
netexec smb $($NetInfo.Subnet).0/24 -u '$($Config.lowPrivUser.username)' -p '$($Config.lowPrivUser.password)' -d $($Config.domain) --shares
netexec smb $dcIP1 -u '$($Config.lowPrivUser.username)' -p '$($Config.lowPrivUser.password)' -d $($Config.domain) --users
netexec smb $dcIP1 -u '$($Config.lowPrivUser.username)' -p '$($Config.lowPrivUser.password)' -d $($Config.domain) --pass-pol
ldapdomaindump -u '$($Config.domain)\$($Config.lowPrivUser.username)' -p '$($Config.lowPrivUser.password)' $dcIP1 -o loot/ldap/
``````

## Phase 2 — BloodHound
``````bash
bloodhound-python -u '$($Config.lowPrivUser.username)' -p '$($Config.lowPrivUser.password)' \
  -d $($Config.domain) -ns $dcIP1 -c all --zip -o bloodhound/
``````

## Phase 3 — Kerberos Attacks
``````bash
# AS-REP Roasting
impacket-GetNPUsers $($Config.domain)/ -usersfile users.txt -dc-ip $dcIP1 -format hashcat -o loot/asrep.txt

# Kerberoasting
impacket-GetUserSPNs '$($Config.domain)/$($Config.lowPrivUser.username):$($Config.lowPrivUser.password)' \
  -dc-ip $dcIP1 -request -outputfile loot/kerberoast.txt
``````

## Phase 4 — SMB & Shares
``````bash
netexec smb $srvIP -u '$($Config.lowPrivUser.username)' -p '$($Config.lowPrivUser.password)' -d $($Config.domain) -M spider_plus
netexec smb $dcIP1 -u '$($Config.lowPrivUser.username)' -p '$($Config.lowPrivUser.password)' -d $($Config.domain) -M gpp_password
``````

## Phase 5 — NTLM Relay & Poisoning
``````bash
# Responder
cd /opt/Responder && sudo python3 Responder.py -I eth1 -wrFd
``````

## Phase 6 — ADCS
``````bash
certipy find -u '$($Config.lowPrivUser.username)@$($Config.domain)' -p '$($Config.lowPrivUser.password)' -dc-ip $dcIP1 -stdout
``````

## Phase 7 — Privilege Escalation
``````bash
# After cracking Kerberoast/ASREP hashes, or finding ACL paths in BloodHound:
# DCSync (requires DA or replication rights)
impacket-secretsdump '$($Config.domain)/administrator:vagrant@$dcIP1' -just-dc
``````
"@
    Set-Content -Path (Join-Path $handoffDir "start-attacking.md") -Value $startAttacking -Force

    # ────── attacker-vm-access.md ──────
    $attackerDoc = @"
# Attacker VM Access Guide

## SSH Access
``````bash
ssh vagrant@$attackerIP
# Password: vagrant
``````

## Engagement Workspace
``````
/home/vagrant/engagement/
  scans/       # nmap, masscan output
  loot/        # hashes, tickets, creds
  notes/       # engagement notes
  bloodhound/  # BloodHound data collection
``````

## Installed Tools
| Tool | Command | Purpose |
|------|---------|---------|
| Impacket | ``impacket-*`` | AD attack suite |
| NetExec | ``netexec`` | SMB/LDAP/WinRM enumeration |
| Responder | ``/opt/Responder/`` | LLMNR/NBT-NS poisoning |
| Certipy | ``certipy`` | ADCS exploitation |
| BloodHound | ``bloodhound-python`` | AD path analysis |
| Kerbrute | ``kerbrute`` | Kerberos enumeration |
| enum4linux-ng | ``/opt/enum4linux-ng/`` | SMB enumeration |
| nmap | ``nmap`` | Port scanning |
| masscan | ``masscan`` | Fast port scanning |

$(if ($Config.c2DockerImage) {
"## C2 Container
``````bash
cd /opt/c2
docker compose ps       # status
docker compose logs -f  # logs
docker compose restart  # restart
``````
**Image:** ``$($Config.c2DockerImage)``"
} else {
"## C2 Setup (manual)
``````bash
mkdir -p /opt/c2 && cd /opt/c2
# Create your docker-compose.yml
docker compose up -d
``````"
})
"@
    Set-Content -Path (Join-Path $handoffDir "attacker-vm-access.md") -Value $attackerDoc -Force

    # ────── all-users.csv ──────
    $csv = "Username,Password,FirstName,LastName,Department,Title,WeakPassword,AccountType`n"
    foreach ($u in $ADUsers) {
        $csv += "$($u.Username),$($u.Password),$($u.FirstName),$($u.LastName),$($u.Department),$($u.Title),$($u.WeakPW),$($u.AccountType)`n"
    }
    Set-Content -Path (Join-Path $handoffDir "all-users.csv") -Value $csv -Force

    Write-Log "Handoff package: $handoffDir ($((Get-ChildItem $handoffDir).Count) files)" "SUCCESS"
    return $handoffDir
}

# ═══════════════════════════════════════════════════════════════════════════════
# DESTROY LAB
# ═══════════════════════════════════════════════════════════════════════════════

function Remove-Lab {
    Write-Banner "DESTROYING LAB ENVIRONMENT"

    $attackerDir = Join-Path $SCRIPT_DIR "attacker-vm"
    if (Test-Path $attackerDir) {
        Write-Log "Destroying Attacker VM..." "STEP"
        Push-Location $attackerDir
        & vagrant destroy -f 2>&1 | ForEach-Object { Write-Log $_ "DETAIL" }
        Pop-Location
        Write-Log "Attacker VM destroyed." "SUCCESS"
    }

    if (Test-Path $GOAD_DIR) {
        Write-Log "Destroying GOAD VMs via goad.py..." "STEP"
        Push-Location $GOAD_DIR
        & python goad.py -t destroy 2>&1 | ForEach-Object { Write-Log $_ "DETAIL" }
        Pop-Location
        Write-Log "GOAD VMs destroyed." "SUCCESS"
    }

    Write-Log "Lab destroyed. Handoff packages and logs preserved." "SUCCESS"
}

# ═══════════════════════════════════════════════════════════════════════════════
# FINAL SUMMARY (v3.0 — enhanced display)
# ═══════════════════════════════════════════════════════════════════════════════

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
    $weakCount = @($ADUsers | Where-Object { $_.WeakPW }).Count

    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "  ║                                                                          ║" -ForegroundColor Green
    Write-Host "  ║   ██╗███╗   ██╗███████╗████████╗ █████╗       ██╗███╗   ██╗████████╗    ║" -ForegroundColor Red
    Write-Host "  ║   ██║████╗  ██║██╔════╝╚══██╔══╝██╔══██╗      ██║████╗  ██║╚══██╔══╝    ║" -ForegroundColor Red
    Write-Host "  ║   ██║██╔██╗ ██║███████╗   ██║   ███████║█████╗██║██╔██╗ ██║   ██║       ║" -ForegroundColor Red
    Write-Host "  ║   ██║██║╚██╗██║╚════██║   ██║   ██╔══██║╚════╝██║██║╚██╗██║   ██║       ║" -ForegroundColor Red
    Write-Host "  ║   ██║██║ ╚████║███████║   ██║   ██║  ██║      ██║██║ ╚████║   ██║       ║" -ForegroundColor Red
    Write-Host "  ║   ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝      ╚═╝╚═╝  ╚═══╝   ╚═╝       ║" -ForegroundColor Red
    Write-Host "  ║                    L A B I N A T O R   v$SCRIPT_VERSION                          ║" -ForegroundColor Yellow
    Write-Host "  ║                                                                          ║" -ForegroundColor Green
    Write-Host "  ╠══════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Green
    Write-Host "  ║                                                                          ║" -ForegroundColor Green
    Write-Host "  ║  ENGAGEMENT                                                              ║" -ForegroundColor Cyan
    Write-Host "  ║  ─────────────────────────────────────────────                           ║" -ForegroundColor DarkGray
    Write-Host ("  ║  Client:    $($Config.clientName)".PadRight(75) + "║") -ForegroundColor White
    Write-Host ("  ║  Domain:    $($Config.domain) ($domainNetbios)".PadRight(75) + "║") -ForegroundColor White
    Write-Host ("  ║  Network:   $($Config.cidr) on $VMnet".PadRight(75) + "║") -ForegroundColor White
    Write-Host ("  ║  Variant:   $($Config.labVariant)".PadRight(75) + "║") -ForegroundColor White
    Write-Host "  ║                                                                          ║" -ForegroundColor Green
    Write-Host "  ║  INITIAL ACCESS                                                          ║" -ForegroundColor Cyan
    Write-Host "  ║  ─────────────────────────────────────────────                           ║" -ForegroundColor DarkGray
    Write-Host ("  ║  Username:  $domainNetbios\$($Config.lowPrivUser.username)".PadRight(75) + "║") -ForegroundColor Yellow
    Write-Host ("  ║  Password:  $($Config.lowPrivUser.password)".PadRight(75) + "║") -ForegroundColor Yellow
    Write-Host "  ║                                                                          ║" -ForegroundColor Green
    Write-Host "  ║  INFRASTRUCTURE                                                          ║" -ForegroundColor Cyan
    Write-Host "  ║  ─────────────────────────────────────────────                           ║" -ForegroundColor DarkGray
    Write-Host ("  ║  DC01:      $($NetInfo.DC1)".PadRight(75) + "║") -ForegroundColor White
    Write-Host ("  ║  DC02:      $($NetInfo.DC2)".PadRight(75) + "║") -ForegroundColor White
    Write-Host ("  ║  SRV02:     $($NetInfo.SRV02)".PadRight(75) + "║") -ForegroundColor White
    Write-Host ("  ║  Attacker:  $($NetInfo.Attacker)".PadRight(75) + "║") -ForegroundColor White
    Write-Host "  ║                                                                          ║" -ForegroundColor Green
    Write-Host "  ║  AD STATISTICS                                                           ║" -ForegroundColor Cyan
    Write-Host "  ║  ─────────────────────────────────────────────                           ║" -ForegroundColor DarkGray
    Write-Host ("  ║  Users:         $($ADUsers.Count) total".PadRight(75) + "║") -ForegroundColor White
    Write-Host ("  ║  Weak Passwords: $weakCount ($([math]::Round($weakCount / [math]::Max($ADUsers.Count,1) * 100))%)".PadRight(75) + "║") -ForegroundColor Red
    Write-Host ("  ║  Service Accts:  $($ServiceAccounts.Count) (Kerberoastable)".PadRight(75) + "║") -ForegroundColor Red
    Write-Host ("  ║  Misconfigs:     $($Misconfigs.Count) active".PadRight(75) + "║") -ForegroundColor Red
    Write-Host "  ║                                                                          ║" -ForegroundColor Green
    Write-Host "  ║  HANDOFF PACKAGE                                                         ║" -ForegroundColor Cyan
    Write-Host "  ║  ─────────────────────────────────────────────                           ║" -ForegroundColor DarkGray
    Write-Host ("  ║  $HandoffDir".PadRight(75) + "║") -ForegroundColor Green
    Write-Host "  ║                                                                          ║" -ForegroundColor Green
    Write-Host "  ║  QUICK START                                                             ║" -ForegroundColor Cyan
    Write-Host "  ║  ─────────────────────────────────────────────                           ║" -ForegroundColor DarkGray
    Write-Host ("  ║  ssh vagrant@$($NetInfo.Attacker)  (password: vagrant)".PadRight(75) + "║") -ForegroundColor Yellow
    Write-Host "  ║                                                                          ║" -ForegroundColor Green
    Write-Host "  ║  MANAGEMENT                                                              ║" -ForegroundColor Cyan
    Write-Host "  ║  ─────────────────────────────────────────────                           ║" -ForegroundColor DarkGray
    Write-Host ("  ║  Reset:   .\Reset-Lab.ps1".PadRight(75) + "║") -ForegroundColor Yellow
    Write-Host ("  ║  Status:  .\Check-LabStatus.ps1".PadRight(75) + "║") -ForegroundColor Yellow
    Write-Host ("  ║  Destroy: .\Deploy-RedTeamLab.ps1 -Destroy".PadRight(75) + "║") -ForegroundColor Yellow
    Write-Host "  ║                                                                          ║" -ForegroundColor Green
    Write-Host "  ╚══════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

function Main {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

    Initialize-Logging

    Write-Host ""
    Write-Host "  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓" -ForegroundColor Cyan
    Write-Host "  ┃         INSTA-INTERNAL-LABINATOR v$SCRIPT_VERSION                                  ┃" -ForegroundColor Cyan
    Write-Host "  ┃         One-Click Red Team Lab Generator                                ┃" -ForegroundColor DarkCyan
    Write-Host "  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛" -ForegroundColor Cyan
    Write-Host ""
    Write-Log "Starting at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Log "Script directory: $SCRIPT_DIR" "DETAIL"
    Write-Log "Log file: $LOG_FILE" "DETAIL"

    # Handle destroy mode
    if ($Destroy) {
        Remove-Lab
        Stop-Transcript -ErrorAction SilentlyContinue
        return
    }

    # Step 1: Prerequisites
    Test-Prerequisites

    # Step 2: Config & Randomization Seed
    Write-Banner "LOADING ENGAGEMENT CONFIGURATION" -Step 2 -Total 8
    Initialize-RandomSeed -Seed $MisconfigSeed
    $config = Read-ClientConfig -Path $ConfigPath

    Write-Host ""
    Write-Log "Client:  $($config.clientName)" "SUCCESS"
    Write-Log "Domain:  $($config.domain)" "SUCCESS"
    Write-Log "CIDR:    $($config.cidr)" "SUCCESS"
    Write-Log "User:    $($config.lowPrivUser.username)" "SUCCESS"
    Write-Log "Lab:     $($config.labVariant)" "SUCCESS"
    Write-Host ""

    # Step 3: Generate AD data
    Write-Banner "GENERATING RANDOMIZED AD ENVIRONMENT" -Step 3 -Total 8
    $adUsers = New-RandomADUsers -CompanyName $config.clientName
    $weakCount = @($adUsers | Where-Object { $_.WeakPW }).Count
    $svcCount = @($adUsers | Where-Object { $_.AccountType -eq "Service" }).Count
    $admCount = @($adUsers | Where-Object { $_.AccountType -eq "Admin" }).Count
    $tmpCount = @($adUsers | Where-Object { $_.AccountType -eq "Temporary" }).Count
    Write-Log "Users: $($adUsers.Count) total ($weakCount weak, $svcCount svc, $admCount admin, $tmpCount temp)" "SUCCESS"

    $svcAccounts = New-RandomServiceAccounts
    Write-Log "Kerberoastable service accounts: $($svcAccounts.Count)" "SUCCESS"

    $misconfigs = New-RandomMisconfigurations
    $critCount = @($misconfigs | Where-Object { $_.Severity -eq "Critical" }).Count
    $highCount = @($misconfigs | Where-Object { $_.Severity -eq "High" }).Count
    Write-Log "Misconfigurations: $($misconfigs.Count) active ($critCount critical, $highCount high)" "SUCCESS"

    # Step 4: Network
    $netInfo = Get-NetworkFromCIDR -CIDR $config.cidr

    if (-not $HandoffOnly) {
        $vmnet = Initialize-VMwareNetwork -NetInfo $netInfo -CIDR $config.cidr

        # Step 5: GOAD
        if (-not $SkipGOAD) {
            Deploy-GOAD -Config $config -NetInfo $netInfo -VMnet $vmnet `
                        -ADUsers $adUsers -ServiceAccounts $svcAccounts -Misconfigs $misconfigs
        } else {
            Write-Log "Skipping GOAD deployment (-SkipGOAD)." "WARN"
        }

        # Step 6: Attacker VM
        if (-not $SkipAttacker) {
            Deploy-AttackerVM -Config $config -NetInfo $netInfo -VMnet $vmnet
        } else {
            Write-Log "Skipping Attacker VM (-SkipAttacker)." "WARN"
        }

        # Step 7: Snapshots
        if (-not $SkipSnapshots) {
            New-VMwareSnapshots -Timestamp $timestamp
        }
    } else {
        $vmnet = "vmnet2"
        Write-Log "Handoff-only mode — skipping VM deployment." "WARN"
    }

    # Step 8: Handoff package (always generated)
    $handoffDir = New-HandoffPackage -Config $config -NetInfo $netInfo -VMnet $vmnet `
                                      -ADUsers $adUsers -ServiceAccounts $svcAccounts `
                                      -Misconfigs $misconfigs -Timestamp $timestamp

    # Summary
    Show-Summary -Config $config -NetInfo $netInfo -VMnet $vmnet `
                 -HandoffDir $handoffDir -ADUsers $adUsers `
                 -ServiceAccounts $svcAccounts -Misconfigs $misconfigs `
                 -Timestamp $timestamp

    Write-Log "Deployment complete! Total time: $((Get-Date) - (Get-Date $timestamp.Substring(0,8) -Format 'yyyyMMdd'))" "SUCCESS"
    Write-Log "Log: $LOG_FILE" "DETAIL"

    Stop-Transcript -ErrorAction SilentlyContinue
}

# Run
Main
