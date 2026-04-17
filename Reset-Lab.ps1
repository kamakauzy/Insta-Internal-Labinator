<#
.SYNOPSIS
    Reset Lab — Revert all VMs to their most recent snapshot.
.DESCRIPTION
    Finds the most recent Fresh-Deploy or GOAD-Clean-Provisioned snapshot for
    all running lab VMs and reverts them. Gives a clean slate without redeployment.
.NOTES
    Version: 3.0.0
#>

#Requires -RunAsAdministrator
#Requires -Version 5.1

param(
    [string]$SnapshotName = "",
    [switch]$ListOnly
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "  ┌────────────────────────────────────────────────────────┐" -ForegroundColor Yellow
Write-Host "  │   INSTA-INTERNAL-LABINATOR v3.0 — RESET TO SNAPSHOT   │" -ForegroundColor Yellow
Write-Host "  └────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
Write-Host ""

# Find vmrun
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

if (-not $vmrunExe) {
    Write-Host "  [ERROR] vmrun.exe not found. Ensure VMware is installed." -ForegroundColor Red
    exit 1
}

# Get running VMs
$vmList = & $vmrunExe list 2>&1
$vmxFiles = @($vmList | Where-Object { $_ -match "\.vmx$" })

if ($vmxFiles.Count -eq 0) {
    Write-Host "  No running VMs found." -ForegroundColor Yellow
    exit 0
}

Write-Host "  Found $($vmxFiles.Count) running VM(s):" -ForegroundColor Cyan
Write-Host ""

foreach ($vmx in $vmxFiles) {
    # Extract friendly name
    $vmName = if ($vmx -match "GOAD-Light-(\w+)") { "GOAD-Light-$($Matches[1])" }
              elseif ($vmx -match "attacker") { "Attacker-VM" }
              else { [System.IO.Path]::GetFileNameWithoutExtension($vmx) }

    Write-Host "  $vmName" -ForegroundColor Cyan

    # List snapshots
    $snapOutput = & $vmrunExe listSnapshots "$vmx" 2>&1
    $snapshots = @($snapOutput | Where-Object { $_ -notmatch "^Total" -and $_.Trim() } | ForEach-Object { $_.Trim() })

    if ($snapshots.Count -eq 0) {
        Write-Host "    [WARN] No snapshots found." -ForegroundColor Yellow
        continue
    }

    Write-Host "    Snapshots: $($snapshots -join ', ')" -ForegroundColor DarkGray

    if ($ListOnly) { continue }

    # Select snapshot
    $targetSnap = $null
    if ($SnapshotName) {
        $targetSnap = $snapshots | Where-Object { $_ -eq $SnapshotName } | Select-Object -First 1
        if (-not $targetSnap) {
            $targetSnap = $snapshots | Where-Object { $_ -like "*$SnapshotName*" } | Select-Object -Last 1
        }
    }
    if (-not $targetSnap) {
        # Default: prefer GOAD-Clean-Provisioned, then Fresh-Deploy-*, then last
        $targetSnap = $snapshots | Where-Object { $_ -eq "GOAD-Clean-Provisioned" } | Select-Object -First 1
        if (-not $targetSnap) { $targetSnap = $snapshots | Where-Object { $_ -like "Fresh-Deploy-*" } | Select-Object -Last 1 }
        if (-not $targetSnap) { $targetSnap = $snapshots | Select-Object -Last 1 }
    }

    Write-Host "    Reverting to: $targetSnap" -ForegroundColor Yellow
    & $vmrunExe revertToSnapshot "$vmx" "$targetSnap" 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "    Starting VM..." -ForegroundColor DarkGray
        & $vmrunExe start "$vmx" 2>&1 | Out-Null
        Write-Host "    [OK] Reverted and started." -ForegroundColor Green
    } else {
        Write-Host "    [ERROR] Revert failed (exit: $LASTEXITCODE)" -ForegroundColor Red
    }
    Write-Host ""
}

# Re-check VMnet2 IP after revert (may be lost on reboot)
$vmnet2 = Get-NetIPAddress -InterfaceAlias "VMware Network Adapter VMnet2" -AddressFamily IPv4 -ErrorAction SilentlyContinue
if (-not $vmnet2 -or $vmnet2.IPAddress -match "^169\.254") {
    Write-Host "  [WARN] VMnet2 IP may need reconfiguration." -ForegroundColor Yellow
    Write-Host "  Run:  New-NetIPAddress -InterfaceAlias 'VMware Network Adapter VMnet2' -IPAddress 192.168.56.1 -PrefixLength 24" -ForegroundColor Yellow
} else {
    Write-Host "  VMnet2: $($vmnet2.IPAddress)/$($vmnet2.PrefixLength)" -ForegroundColor Green
}

Write-Host ""
Write-Host "  Lab reset complete. Wait 2-3 minutes for AD services to start." -ForegroundColor Green
Write-Host ""
