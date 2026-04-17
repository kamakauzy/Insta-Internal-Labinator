<#
.SYNOPSIS
    Quick Lab Status — Check the health of all Insta-Internal-Labinator VMs.
.DESCRIPTION
    Shows running VMs, network reachability, service status, and Docker containers.
.NOTES
    Version: 3.0.0
#>

#Requires -Version 5.1

param(
    [string]$ConfigPath = ".\ClientHandoff.json",
    [switch]$Detailed
)

$ErrorActionPreference = "Continue"

function Write-Status {
    param([string]$Name, [bool]$OK, [string]$Detail = "")
    $icon = if ($OK) { "  [OK]" } else { "  [!!]" }
    $color = if ($OK) { "Green" } else { "Red" }
    $line = "$icon $($Name.PadRight(16))"
    if ($Detail) { $line += " $Detail" }
    Write-Host $line -ForegroundColor $color
}

Write-Host ""
Write-Host "  ┌────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "  │   INSTA-INTERNAL-LABINATOR v3.0 — LAB STATUS          │" -ForegroundColor Cyan
Write-Host "  └────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host ""

# ── VMware VMs ──
Write-Host "  VMWARE VMs" -ForegroundColor Yellow
Write-Host "  ──────────" -ForegroundColor DarkGray

$vmrunPaths = @(
    "${env:ProgramFiles(x86)}\VMware\VMware Workstation\vmrun.exe",
    "$env:ProgramFiles\VMware\VMware Workstation\vmrun.exe"
)
$vmrunExe = $null
foreach ($p in $vmrunPaths) { if (Test-Path $p) { $vmrunExe = $p; break } }
if (-not $vmrunExe) {
    $cmd = Get-Command vmrun.exe -ErrorAction SilentlyContinue
    if ($cmd) { $vmrunExe = $cmd.Source }
}

if ($vmrunExe) {
    $vmList = & $vmrunExe list 2>&1
    $vmxFiles = @($vmList | Where-Object { $_ -match "\.vmx$" })
    $totalLine = $vmList | Select-Object -First 1
    Write-Host "  $totalLine" -ForegroundColor Gray
    foreach ($vmx in $vmxFiles) {
        $name = if ($vmx -match "GOAD-Light-(\w+)") { "GOAD-Light-$($Matches[1])" }
                elseif ($vmx -match "attacker") { "Attacker-VM" }
                else { [System.IO.Path]::GetFileNameWithoutExtension($vmx) }
        Write-Status $name $true $vmx.Substring($vmx.Length - [math]::Min(60, $vmx.Length))
    }
} else {
    Write-Status "VMware vmrun" $false "Not found"
}
Write-Host ""

# ── Network Connectivity ──
Write-Host "  NETWORK" -ForegroundColor Yellow
Write-Host "  ───────" -ForegroundColor DarkGray

# Determine subnet
$subnet = "192.168.56"  # Default
if (Test-Path $ConfigPath) {
    try {
        $config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
        if ($config.cidr) {
            $parts = ($config.cidr -split "/")[0] -split "\."
            $subnet = "$($parts[0]).$($parts[1]).$($parts[2])"
        }
    } catch {}
}

# Check VMnet2 host IP
$vmnet2IP = Get-NetIPAddress -InterfaceAlias "VMware Network Adapter VMnet2" -AddressFamily IPv4 -ErrorAction SilentlyContinue
Write-Status "VMnet2 Host" ($null -ne $vmnet2IP) $(if ($vmnet2IP) { "$($vmnet2IP.IPAddress)/$($vmnet2IP.PrefixLength)" } else { "No IP assigned" })

# Check lab hosts
$targets = @(
    @{ Name = "DC01";     IP = "$subnet.10"; Port = 5986 },
    @{ Name = "DC02";     IP = "$subnet.11"; Port = 5986 },
    @{ Name = "SRV02";    IP = "$subnet.22"; Port = 5986 },
    @{ Name = "Attacker"; IP = "$subnet.200"; Port = 22 }
)
foreach ($t in $targets) {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $reachable = $false
    try { $tcp.Connect($t.IP, $t.Port); $reachable = $true; $tcp.Close() } catch {}
    $detail = "$($t.IP):$($t.Port)"
    if (-not $reachable) { $detail += " (unreachable)" }
    Write-Status $t.Name $reachable $detail
}
Write-Host ""

# ── Docker Containers ──
Write-Host "  DOCKER CONTAINERS" -ForegroundColor Yellow
Write-Host "  ─────────────────" -ForegroundColor DarkGray

$docker = Get-Command docker -ErrorAction SilentlyContinue
if ($docker) {
    $containers = docker ps --filter "name=ia-" --format "{{.Names}}\t{{.Status}}" 2>&1
    if ($containers) {
        $containers | ForEach-Object {
            $parts = $_ -split "`t"
            $name = if ($parts[0]) { $parts[0] } else { $_ }
            $status = if ($parts.Count -gt 1) { $parts[1] } else { "" }
            $ok = $status -match "Up|healthy"
            Write-Status $name $ok $status
        }
    } else {
        Write-Host "  No ia-* containers running." -ForegroundColor DarkGray
    }

    # Check GOAD ansible container
    $goadContainers = docker ps -a --filter "name=goad" --format "{{.Names}} {{.Status}}" 2>&1
    if ($goadContainers -and $goadContainers -notmatch "^$") {
        $goadContainers | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
    }
} else {
    Write-Host "  Docker not available." -ForegroundColor DarkGray
}
Write-Host ""

# ── Snapshots ──
if ($vmrunExe -and $vmxFiles.Count -gt 0) {
    Write-Host "  SNAPSHOTS" -ForegroundColor Yellow
    Write-Host "  ─────────" -ForegroundColor DarkGray
    foreach ($vmx in $vmxFiles | Select-Object -First 3) {
        $snaps = & $vmrunExe listSnapshots "$vmx" 2>&1
        $name = if ($vmx -match "GOAD-Light-(\w+)") { $Matches[1] } else { "VM" }
        $snapList = @($snaps | Where-Object { $_ -notmatch "^Total" -and $_.Trim() })
        if ($snapList.Count -gt 0) {
            Write-Host "  $name : $($snapList -join ', ')" -ForegroundColor Gray
        }
    }
    Write-Host ""
}

# ── Handoff Packages ──
$handoffs = Get-ChildItem -Path $PSScriptRoot -Directory -Filter "RedTeam-Handoff-*" -ErrorAction SilentlyContinue
if ($handoffs) {
    Write-Host "  HANDOFF PACKAGES" -ForegroundColor Yellow
    Write-Host "  ────────────────" -ForegroundColor DarkGray
    foreach ($h in $handoffs) {
        $fileCount = (Get-ChildItem $h.FullName -File).Count
        Write-Host "    $($h.Name) ($fileCount files)" -ForegroundColor Green
    }
    Write-Host ""
}

# ── GOAD Instance ──
$goadDir = Join-Path $PSScriptRoot "GOAD"
$wsDir = Join-Path $goadDir "workspace"
if (Test-Path $wsDir) {
    $instances = Get-ChildItem $wsDir -Directory -ErrorAction SilentlyContinue
    if ($instances) {
        Write-Host "  GOAD INSTANCES" -ForegroundColor Yellow
        Write-Host "  ──────────────" -ForegroundColor DarkGray
        foreach ($inst in $instances) {
            Write-Host "    $($inst.Name)" -ForegroundColor Gray
        }
        Write-Host ""
    }
}

Write-Host ""
Write-Host "=" * 60 -ForegroundColor Cyan
