$ErrorActionPreference = "Continue"
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
Set-Location "D:\HAK\internal-lab-inator\GOAD"
Start-Transcript -Path "D:\HAK\internal-lab-inator\goad-provision.log" -Force
Write-Host "[$(Get-Date)] Starting Ansible-only provisioning..."
python goad.py -t install -l GOAD-Light -p vmware -m docker -ip 192.168.56 -a true -i c6bbf6-goad-light-vmware
Write-Host "[$(Get-Date)] Provisioning finished with exit code: $LASTEXITCODE"
Stop-Transcript
pause
