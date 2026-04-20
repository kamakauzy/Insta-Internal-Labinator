$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
Set-Location "D:\HAK\internal-lab-inator\GOAD"
$logFile = "D:\HAK\internal-lab-inator\goad-provision.log"

Write-Host "[$(Get-Date)] Starting GOAD-Light Ansible provisioning (VMs already up)..."
"[$(Get-Date)] Starting GOAD-Light Ansible provisioning..." | Out-File $logFile

# Run install with -a flag (ansible-only provisioning, skips VM creation)
$proc = Start-Process -FilePath python -ArgumentList "goad.py -t install -l GOAD-Light -p vmware -m docker -ip 192.168.56 -a true -i c6bbf6-goad-light-vmware" -NoNewWindow -PassThru -RedirectStandardOutput "$logFile.stdout" -RedirectStandardError "$logFile.stderr" -Wait

"[$(Get-Date)] GOAD provision finished with exit code: $($proc.ExitCode)" | Out-File -Append $logFile
Get-Content "$logFile.stdout" | Out-File -Append $logFile
Get-Content "$logFile.stderr" | Out-File -Append $logFile
Write-Host "[$(Get-Date)] Done. Exit code: $($proc.ExitCode)"
Write-Host "Log at: $logFile, $logFile.stdout, $logFile.stderr"
Read-Host "Press Enter to close"
