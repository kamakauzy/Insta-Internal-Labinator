<#
.SYNOPSIS
    L.4 — Deploy AzureGoat vulnerable Azure environment
.DESCRIPTION
    Deploys AzureGoat via Terraform to create an intentionally vulnerable
    Azure tenant for practicing cloud attack paths:
    - IAM privilege escalation
    - Storage account misconfigurations
    - Function App SSRF
    - Key Vault exposure
    - Managed Identity abuse

    Requires an Azure subscription and Terraform installed.

.PARAMETER SubscriptionId
    Azure subscription ID for deployment.

.PARAMETER Region
    Azure region. Default: eastus

.PARAMETER Destroy
    Tear down the AzureGoat environment.

.NOTES
    Requires: az CLI logged in, Terraform >= 1.0
    Costs real money in Azure — destroy when done.
    Version: 1.0.0
#>

param(
    [string]$SubscriptionId,
    [string]$Region = "eastus",
    [switch]$Destroy
)

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "  ┌──────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "  │  L.4 — AzureGoat Deployment                     │" -ForegroundColor Cyan
Write-Host "  └──────────────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host ""

# ── Prerequisites Check ──
Write-Host "  [1/5] Checking prerequisites..." -ForegroundColor Yellow

$azCli = Get-Command az -ErrorAction SilentlyContinue
if (-not $azCli) {
    Write-Host "    [-] Azure CLI (az) not found. Install: https://aka.ms/installazurecli" -ForegroundColor Red
    return
}
Write-Host "    [+] Azure CLI found" -ForegroundColor Green

$terraform = Get-Command terraform -ErrorAction SilentlyContinue
if (-not $terraform) {
    Write-Host "    [-] Terraform not found. Install: https://www.terraform.io/downloads" -ForegroundColor Red
    return
}
Write-Host "    [+] Terraform found" -ForegroundColor Green

# Check Azure login
$account = az account show 2>&1 | ConvertFrom-Json -ErrorAction SilentlyContinue
if (-not $account) {
    Write-Host "    [-] Not logged in to Azure. Run: az login" -ForegroundColor Red
    return
}
Write-Host "    [+] Azure account: $($account.name)" -ForegroundColor Green

if ($SubscriptionId) {
    az account set --subscription $SubscriptionId
    Write-Host "    [+] Subscription: $SubscriptionId" -ForegroundColor Green
}

# ── Clone AzureGoat ──
Write-Host "`n  [2/5] Setting up AzureGoat repository..." -ForegroundColor Yellow

$goatDir = Join-Path $PSScriptRoot "AzureGoat"
if (Test-Path $goatDir) {
    Push-Location $goatDir
    git pull --quiet 2>&1
    Pop-Location
    Write-Host "    [=] AzureGoat repo updated" -ForegroundColor DarkGray
} else {
    git clone "https://github.com/ine-labs/AzureGoat.git" $goatDir
    Write-Host "    [+] AzureGoat cloned" -ForegroundColor Green
}

$tfDir = Join-Path $goatDir "modules"
if (-not (Test-Path $tfDir)) {
    # Some versions use root dir
    $tfDir = $goatDir
}

# ── Destroy if requested ──
if ($Destroy) {
    Write-Host "`n  [*] Destroying AzureGoat environment..." -ForegroundColor Yellow
    Push-Location $tfDir
    terraform destroy -auto-approve
    Pop-Location
    Write-Host "    [+] AzureGoat destroyed" -ForegroundColor Green
    return
}

# ── Terraform Init ──
Write-Host "`n  [3/5] Terraform init..." -ForegroundColor Yellow
Push-Location $tfDir
terraform init -input=false
if ($LASTEXITCODE -ne 0) {
    Write-Host "    [-] Terraform init failed" -ForegroundColor Red
    Pop-Location
    return
}
Write-Host "    [+] Initialized" -ForegroundColor Green

# ── Terraform Plan ──
Write-Host "`n  [4/5] Terraform plan..." -ForegroundColor Yellow
terraform plan -out=goatplan -input=false -var="region=$Region"
if ($LASTEXITCODE -ne 0) {
    Write-Host "    [-] Terraform plan failed" -ForegroundColor Red
    Pop-Location
    return
}
Write-Host "    [+] Plan created" -ForegroundColor Green

# ── Terraform Apply ──
Write-Host "`n  [5/5] Terraform apply..." -ForegroundColor Yellow
terraform apply goatplan
if ($LASTEXITCODE -ne 0) {
    Write-Host "    [-] Terraform apply failed" -ForegroundColor Red
    Pop-Location
    return
}

$outputs = terraform output -json 2>&1 | ConvertFrom-Json -ErrorAction SilentlyContinue
Pop-Location

Write-Host ""
Write-Host "  ┌──────────────────────────────────────────────────┐" -ForegroundColor Green
Write-Host "  │  AzureGoat Deployed                              │" -ForegroundColor Green
Write-Host "  │                                                  │" -ForegroundColor Green
Write-Host "  │  Attack Surfaces:                                │" -ForegroundColor Green
Write-Host "  │    - IAM privilege escalation paths              │" -ForegroundColor Green
Write-Host "  │    - Misconfigured storage accounts              │" -ForegroundColor Green
Write-Host "  │    - Function App SSRF to IMDS                   │" -ForegroundColor Green
Write-Host "  │    - Key Vault secrets exposure                  │" -ForegroundColor Green
Write-Host "  │    - Managed Identity token theft                │" -ForegroundColor Green
Write-Host "  │                                                  │" -ForegroundColor Green
Write-Host "  │  Scan with:                                      │" -ForegroundColor Green
Write-Host "  │    azurehound_collect -t <tenant> -u user -p pw  │" -ForegroundColor Green
Write-Host "  │    trivy_scan --target azure                     │" -ForegroundColor Green
Write-Host "  │                                                  │" -ForegroundColor Green
Write-Host "  │  IMPORTANT: Run -Destroy when done to avoid $$   │" -ForegroundColor Green
Write-Host "  └──────────────────────────────────────────────────┘" -ForegroundColor Green
Write-Host ""
