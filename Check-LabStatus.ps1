<#
.SYNOPSIS
    Quick Lab Status — Check the health of all Insta-Internal-Labinator VMs.
.DESCRIPTION
    Shows running VMs, network reachability, and service status.
#>

#Requires -Version 5.1

param(
    [string]$ConfigPath = ".\ClientHandoff.json"
)

$ErrorActionPreference = "Continue"

function Write-Status {
    param([string]$Name, [bool]$OK, [string]$Detail = "")
    $icon = if ($OK) { "[OK]" } else { "[!!]" }
    $color = if ($OK) { "Green" } else { "Red" }
    $line = "  $icon $Name"
    if ($Detail) { $line += " — $Detail" }
    Write-Host $line -ForegroundColor $color
}

Write-Host ""
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host "  INSTA-INTERNAL-LABINATOR — LAB STATUS" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host ""

# Check VMware
$vmrun = Get-Command vmrun.exe -ErrorAction SilentlyContinue
if ($vmrun) {
    $vms = & vmrun.exe list 2>&1
    Write-Host "  VMware VMs:" -ForegroundColor Yellow
    $vms | ForEach-Object { Write-Host "    $_" }
    Write-Host ""
}
else {
    Write-Status "VMware vmrun" $false "Not found in PATH"
}

# Check Vagrant status for attacker VM
$attackerDir = Join-Path $PSScriptRoot "attacker-vm"
if (Test-Path $attackerDir) {
    Write-Host "  Attacker VM (Vagrant):" -ForegroundColor Yellow
    Push-Location $attackerDir
    $status = & vagrant status 2>&1
    $status | ForEach-Object { Write-Host "    $_" }
    Pop-Location
    Write-Host ""
}

# Check GOAD VMs
$goadDir = Join-Path $PSScriptRoot "GOAD"
if (Test-Path $goadDir) {
    $providerDirs = Get-ChildItem -Path $goadDir -Recurse -Filter "Vagrantfile" -Depth 5 |
        Select-Object -ExpandProperty DirectoryName -Unique
    foreach ($pd in $providerDirs) {
        if ($pd -match "providers") {
            Write-Host "  GOAD VMs ($pd):" -ForegroundColor Yellow
            Push-Location $pd
            $status = & vagrant status 2>&1
            $status | ForEach-Object { Write-Host "    $_" }
            Pop-Location
            Write-Host ""
        }
    }
}

# Network connectivity check
if (Test-Path $ConfigPath) {
    $config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
    $cidr = if ($config.cidr) { $config.cidr } else { "192.168.56.0/24" }
    $parts = ($cidr -split "/")[0] -split "\."
    $subnet = "$($parts[0]).$($parts[1]).$($parts[2])"

    Write-Host "  Network Reachability ($cidr):" -ForegroundColor Yellow
    $targets = @(
        @{ Name = "DC01";     IP = "$subnet.10" },
        @{ Name = "DC02";     IP = "$subnet.11" },
        @{ Name = "SRV02";    IP = "$subnet.22" },
        @{ Name = "Attacker"; IP = "$subnet.200" }
    )
    foreach ($t in $targets) {
        $ping = Test-Connection -ComputerName $t.IP -Count 1 -Quiet -ErrorAction SilentlyContinue
        Write-Status $t.Name $ping $t.IP
    }
}

# Handoff packages
$handoffs = Get-ChildItem -Path $PSScriptRoot -Directory -Filter "RedTeam-Handoff-*" -ErrorAction SilentlyContinue
if ($handoffs) {
    Write-Host ""
    Write-Host "  Handoff Packages:" -ForegroundColor Yellow
    foreach ($h in $handoffs) {
        Write-Host "    $($h.Name)" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "=" * 60 -ForegroundColor Cyan
