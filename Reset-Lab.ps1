<#
.SYNOPSIS
    Reset Lab — Revert all VMs to their Fresh-Deploy snapshot.
.DESCRIPTION
    Finds the most recent Fresh-Deploy snapshot for all lab VMs and reverts them.
    This gives you a clean slate without full redeployment.
#>

#Requires -RunAsAdministrator
#Requires -Version 5.1

param(
    [string]$SnapshotPattern = "Fresh-Deploy-*"
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "=" * 60 -ForegroundColor Yellow
Write-Host "  INSTA-INTERNAL-LABINATOR — RESET TO SNAPSHOT" -ForegroundColor Yellow
Write-Host "=" * 60 -ForegroundColor Yellow
Write-Host ""

$vmrun = Get-Command vmrun.exe -ErrorAction SilentlyContinue
if (-not $vmrun) {
    Write-Host "  [ERROR] vmrun.exe not found. Ensure VMware is in PATH." -ForegroundColor Red
    exit 1
}

# List running VMs
$vms = & vmrun.exe list 2>&1
$vmxFiles = $vms | Where-Object { $_ -match "\.vmx$" }

if (-not $vmxFiles) {
    Write-Host "  No running VMs found." -ForegroundColor Yellow
    exit 0
}

foreach ($vmx in $vmxFiles) {
    $vmName = [System.IO.Path]::GetFileNameWithoutExtension($vmx)
    Write-Host "  Processing: $vmName" -ForegroundColor Cyan

    # List snapshots
    $snapshots = & vmrun.exe listSnapshots "$vmx" 2>&1
    $freshSnap = $snapshots | Where-Object { $_ -like $SnapshotPattern } | Select-Object -Last 1

    if ($freshSnap) {
        $freshSnap = $freshSnap.Trim()
        Write-Host "    Reverting to: $freshSnap" -ForegroundColor Yellow
        & vmrun.exe revertToSnapshot "$vmx" "$freshSnap" 2>&1 | ForEach-Object { Write-Host "    $_" }
        & vmrun.exe start "$vmx" 2>&1 | Out-Null
        Write-Host "    [OK] Reverted and started." -ForegroundColor Green
    }
    else {
        Write-Host "    [WARN] No matching snapshot found." -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "  Lab reset complete." -ForegroundColor Green
Write-Host ""
