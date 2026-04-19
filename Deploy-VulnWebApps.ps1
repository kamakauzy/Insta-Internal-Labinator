<#
.SYNOPSIS
    L.2 — Deploy DVWA + OWASP Juice Shop as vulnerable web applications
.DESCRIPTION
    Deploys Damn Vulnerable Web Application (DVWA) and OWASP Juice Shop as
    Docker containers on the attacker VM or any Linux host accessible from
    the lab network. These provide web application attack surfaces for:
    - SQL injection, XSS, CSRF, command injection (DVWA)
    - Injection, broken auth, XSS, insecure deserialization (Juice Shop)

.PARAMETER TargetHost
    SSH target (user@ip) for the attacker VM. Default: root@192.168.56.200

.PARAMETER DVWAPort
    Port for DVWA. Default: 8081

.PARAMETER JuiceShopPort
    Port for Juice Shop. Default: 3000

.NOTES
    Requires Docker on the target host.
    Run from the lab management workstation.
    Version: 1.0.0
#>

param(
    [string]$TargetHost = "root@192.168.56.200",
    [int]$DVWAPort = 8081,
    [int]$JuiceShopPort = 3000,
    [switch]$Local
)

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "  ┌──────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "  │  L.2 — Vulnerable Web Applications               │" -ForegroundColor Cyan
Write-Host "  │  DVWA + OWASP Juice Shop                         │" -ForegroundColor Cyan
Write-Host "  └──────────────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host ""

$composeContent = @"
version: '3.8'

services:
  dvwa:
    image: vulnerables/web-dvwa:latest
    container_name: lab-dvwa
    ports:
      - "${DVWAPort}:80"
    environment:
      - MYSQL_ALLOW_EMPTY_PASSWORD=yes
    restart: unless-stopped
    networks:
      - vuln-web

  juice-shop:
    image: bkimminich/juice-shop:latest
    container_name: lab-juice-shop
    ports:
      - "${JuiceShopPort}:3000"
    restart: unless-stopped
    networks:
      - vuln-web

  # WebGoat for Java-based vulns (optional)
  webgoat:
    image: webgoat/webgoat:latest
    container_name: lab-webgoat
    ports:
      - "8082:8080"
    restart: unless-stopped
    networks:
      - vuln-web

networks:
  vuln-web:
    driver: bridge
"@

if ($Local) {
    Write-Host "  [*] Deploying locally..." -ForegroundColor Yellow
    $composePath = Join-Path $PSScriptRoot "docker-compose-vulnweb.yml"
    $composeContent | Out-File -FilePath $composePath -Encoding UTF8 -Force
    Write-Host "    [+] Wrote $composePath" -ForegroundColor Green

    docker compose -f $composePath up -d
    if ($LASTEXITCODE -eq 0) {
        Write-Host "    [+] Containers started" -ForegroundColor Green
    } else {
        Write-Host "    [-] Docker compose failed" -ForegroundColor Red
    }
} else {
    Write-Host "  [*] Deploying to $TargetHost via SSH..." -ForegroundColor Yellow

    # Upload compose file
    $tempFile = [System.IO.Path]::GetTempFileName()
    $composeContent | Out-File -FilePath $tempFile -Encoding UTF8 -Force

    scp $tempFile "${TargetHost}:/tmp/docker-compose-vulnweb.yml"
    Remove-Item $tempFile -Force

    # Deploy
    $sshCmd = "cd /tmp && docker compose -f docker-compose-vulnweb.yml up -d 2>&1"
    $result = ssh $TargetHost $sshCmd
    Write-Host $result -ForegroundColor Gray

    if ($LASTEXITCODE -eq 0) {
        Write-Host "    [+] Deployed successfully" -ForegroundColor Green
    } else {
        Write-Host "    [-] Deployment failed — check Docker on target" -ForegroundColor Red
    }
}

$targetIP = if ($Local) { "localhost" } else { ($TargetHost -split "@")[1] }
Write-Host ""
Write-Host "  ┌──────────────────────────────────────────────────┐" -ForegroundColor Green
Write-Host "  │  Web Apps Deployed:                              │" -ForegroundColor Green
Write-Host "  │    DVWA:       http://${targetIP}:${DVWAPort}    │" -ForegroundColor Green
Write-Host "  │    Juice Shop: http://${targetIP}:${JuiceShopPort} │" -ForegroundColor Green
Write-Host "  │    WebGoat:    http://${targetIP}:8082           │" -ForegroundColor Green
Write-Host "  │                                                  │" -ForegroundColor Green
Write-Host "  │  DVWA default login: admin / password            │" -ForegroundColor Green
Write-Host "  │  Scan with: nuclei, nikto, gobuster, sqlmap      │" -ForegroundColor Green
Write-Host "  └──────────────────────────────────────────────────┘" -ForegroundColor Green
Write-Host ""
