$ErrorActionPreference = "Continue"
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

Write-Host "=== Configuring VMnet2 with 192.168.56.1/24 ===" -ForegroundColor Cyan

# Remove existing IP and set new static IP on VMnet2
$adapter = Get-NetAdapter | Where-Object { $_.InterfaceAlias -eq "VMware Network Adapter VMnet2" }
if ($adapter) {
    # Remove existing IP config
    Remove-NetIPAddress -InterfaceAlias "VMware Network Adapter VMnet2" -Confirm:$false -ErrorAction SilentlyContinue
    Remove-NetRoute -InterfaceAlias "VMware Network Adapter VMnet2" -Confirm:$false -ErrorAction SilentlyContinue
    
    # Set static IP
    New-NetIPAddress -InterfaceAlias "VMware Network Adapter VMnet2" -IPAddress 192.168.56.1 -PrefixLength 24 -ErrorAction Stop
    Write-Host "[OK] VMnet2 set to 192.168.56.1/24" -ForegroundColor Green
} else {
    Write-Host "[ERROR] VMnet2 adapter not found!" -ForegroundColor Red
    pause
    exit 1
}

# Wait for the IP to take effect
Start-Sleep -Seconds 3

# Test connectivity
Write-Host "`n=== Testing connectivity to VMs ===" -ForegroundColor Cyan
$targets = @("192.168.56.10", "192.168.56.11", "192.168.56.22")
foreach ($t in $targets) {
    $result = Test-Connection $t -Count 1 -Quiet -ErrorAction SilentlyContinue
    Write-Host "$t : $( if($result){'REACHABLE'}else{'UNREACHABLE'} )" -ForegroundColor $(if($result){'Green'}else{'Yellow'})
}

# Wait for WinRM to become available (VMs might need time after network change)
Write-Host "`n=== Waiting for WinRM (port 5986) ===" -ForegroundColor Cyan
$ready = $false
for ($i = 0; $i -lt 30; $i++) {
    $tcp = Test-NetConnection -ComputerName 192.168.56.10 -Port 5986 -WarningAction SilentlyContinue
    if ($tcp.TcpTestSucceeded) {
        Write-Host "WinRM is ready on DC01!" -ForegroundColor Green
        $ready = $true
        break
    }
    Write-Host "Attempt $($i+1)/30 - WinRM not ready yet, waiting 10s..."
    Start-Sleep -Seconds 10
}

if (-not $ready) {
    Write-Host "[WARNING] WinRM still not available after 5 minutes. VMs may need more boot time." -ForegroundColor Yellow
    Write-Host "You can re-run provisioning later with:"
    Write-Host "  cd D:\HAK\internal-lab-inator\GOAD"
    Write-Host "  python goad.py -t install -l GOAD-Light -p vmware -m docker -ip 192.168.56 -a true -i c6bbf6-goad-light-vmware"
    pause
    exit 1
}

# Run Ansible provisioning
Write-Host "`n=== Starting Ansible Provisioning ===" -ForegroundColor Cyan
Set-Location "D:\HAK\internal-lab-inator\GOAD"
Start-Transcript -Path "D:\HAK\internal-lab-inator\goad-provision.log" -Force
python goad.py -t install -l GOAD-Light -p vmware -m docker -ip 192.168.56 -a true -i c6bbf6-goad-light-vmware
Write-Host "`n[$(Get-Date)] Provisioning finished with exit code: $LASTEXITCODE"
Stop-Transcript
pause
