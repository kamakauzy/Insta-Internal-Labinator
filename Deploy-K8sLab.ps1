<#
.SYNOPSIS
    L.3 — Deploy k3s single-node + Kubernetes Goat
.DESCRIPTION
    Installs a lightweight k3s Kubernetes cluster on the attacker VM (or any
    Linux host), then deploys Kubernetes Goat — an intentionally vulnerable
    Kubernetes cluster for practicing:
    - Container escape
    - RBAC misconfigs
    - Secrets exposure
    - Pod security bypass
    - SSRF in cloud metadata

.PARAMETER TargetHost
    SSH target (user@ip). Default: root@192.168.56.200

.PARAMETER K3sVersion
    k3s version channel. Default: stable

.NOTES
    Requires: Linux target with 2+ GB RAM, internet access for image pulls.
    Version: 1.0.0
#>

param(
    [string]$TargetHost = "root@192.168.56.200",
    [string]$K3sVersion = "stable",
    [switch]$Uninstall
)

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "  ┌──────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "  │  L.3 — k3s + Kubernetes Goat                    │" -ForegroundColor Cyan
Write-Host "  └──────────────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host ""

if ($Uninstall) {
    Write-Host "  [*] Uninstalling k3s from $TargetHost..." -ForegroundColor Yellow
    ssh $TargetHost "/usr/local/bin/k3s-uninstall.sh 2>/dev/null; echo 'Done'"
    Write-Host "    [+] k3s removed" -ForegroundColor Green
    return
}

# ── Step 1: Install k3s ──
Write-Host "  [1/4] Installing k3s on $TargetHost..." -ForegroundColor Yellow

$installScript = @'
#!/bin/bash
set -e

# Check if k3s already running
if systemctl is-active --quiet k3s 2>/dev/null; then
    echo "[=] k3s already running"
else
    # Install k3s single-node (no traefik to save RAM)
    curl -sfL https://get.k3s.io | INSTALL_K3S_CHANNEL=stable sh -s - \
        --disable traefik \
        --write-kubeconfig-mode 644
    echo "[+] k3s installed"
fi

# Wait for node ready
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
for i in $(seq 1 30); do
    if kubectl get nodes 2>/dev/null | grep -q " Ready"; then
        echo "[+] Node is Ready"
        break
    fi
    sleep 2
done
'@

# Upload and run install script
$tempFile = [System.IO.Path]::GetTempFileName()
$installScript | Out-File -FilePath $tempFile -Encoding UTF8 -Force -NoNewline
scp $tempFile "${TargetHost}:/tmp/install-k3s.sh"
Remove-Item $tempFile -Force

$result = ssh $TargetHost "chmod +x /tmp/install-k3s.sh && bash /tmp/install-k3s.sh"
$result | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }

# ── Step 2: Deploy Kubernetes Goat ──
Write-Host "`n  [2/4] Deploying Kubernetes Goat..." -ForegroundColor Yellow

$goatScript = @'
#!/bin/bash
set -e
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

# Clone or update Kubernetes Goat
GOAT_DIR="/opt/kubernetes-goat"
if [ -d "$GOAT_DIR" ]; then
    cd "$GOAT_DIR" && git pull --quiet
    echo "[=] Updated Kubernetes Goat repo"
else
    git clone https://github.com/madhuakula/kubernetes-goat.git "$GOAT_DIR"
    echo "[+] Cloned Kubernetes Goat"
fi

cd "$GOAT_DIR"

# Apply all manifests
kubectl apply -f scenarios/ 2>&1 | tail -5
echo "[+] Kubernetes Goat scenarios applied"

# Wait for pods
echo "[*] Waiting for pods..."
kubectl wait --for=condition=ready pod --all --timeout=120s 2>/dev/null || true
kubectl get pods -A --no-headers 2>/dev/null | wc -l | xargs -I{} echo "[+] {} pods running"
'@

$tempFile = [System.IO.Path]::GetTempFileName()
$goatScript | Out-File -FilePath $tempFile -Encoding UTF8 -Force -NoNewline
scp $tempFile "${TargetHost}:/tmp/deploy-goat.sh"
Remove-Item $tempFile -Force

$result = ssh $TargetHost "chmod +x /tmp/deploy-goat.sh && bash /tmp/deploy-goat.sh"
$result | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }

# ── Step 3: Create intentionally misconfigured RBAC ──
Write-Host "`n  [3/4] Adding RBAC misconfigurations..." -ForegroundColor Yellow

$rbacYaml = @'
apiVersion: v1
kind: ServiceAccount
metadata:
  name: overprivileged-sa
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: vuln-cluster-admin-binding
subjects:
- kind: ServiceAccount
  name: overprivileged-sa
  namespace: default
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: v1
kind: Pod
metadata:
  name: vuln-privileged-pod
  namespace: default
spec:
  serviceAccountName: overprivileged-sa
  hostPID: true
  hostNetwork: true
  containers:
  - name: vuln
    image: alpine:latest
    command: ["sleep", "infinity"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /
---
apiVersion: v1
kind: Secret
metadata:
  name: exposed-secret
  namespace: default
type: Opaque
data:
  admin-password: UEBzc3cwcmQxMjMh
  api-key: c2VjcmV0LWFwaS1rZXktZG9udC1leHBvc2U=
'@

$tempFile = [System.IO.Path]::GetTempFileName()
$rbacYaml | Out-File -FilePath $tempFile -Encoding UTF8 -Force -NoNewline
scp $tempFile "${TargetHost}:/tmp/vuln-rbac.yaml"
Remove-Item $tempFile -Force

$result = ssh $TargetHost "export KUBECONFIG=/etc/rancher/k3s/k3s.yaml && kubectl apply -f /tmp/vuln-rbac.yaml 2>&1"
$result | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }

# ── Step 4: Copy kubeconfig locally ──
Write-Host "`n  [4/4] Fetching kubeconfig..." -ForegroundColor Yellow

$kubeconfigDir = Join-Path $PSScriptRoot ".kube"
if (-not (Test-Path $kubeconfigDir)) { New-Item -ItemType Directory -Path $kubeconfigDir -Force | Out-Null }
$kubeconfigPath = Join-Path $kubeconfigDir "k3s-lab.yaml"

scp "${TargetHost}:/etc/rancher/k3s/k3s.yaml" $kubeconfigPath
if (Test-Path $kubeconfigPath) {
    # Fix server address from 127.0.0.1 to target IP
    $targetIP = ($TargetHost -split "@")[1]
    (Get-Content $kubeconfigPath -Raw) -replace "127\.0\.0\.1", $targetIP | Set-Content $kubeconfigPath
    Write-Host "    [+] Kubeconfig saved: $kubeconfigPath" -ForegroundColor Green
} else {
    Write-Host "    [-] Failed to fetch kubeconfig" -ForegroundColor Red
}

$targetIP = ($TargetHost -split "@")[1]
Write-Host ""
Write-Host "  ┌──────────────────────────────────────────────────┐" -ForegroundColor Green
Write-Host "  │  k3s + Kubernetes Goat Deployed                  │" -ForegroundColor Green
Write-Host "  │                                                  │" -ForegroundColor Green
Write-Host "  │  Cluster API: https://${targetIP}:6443           │" -ForegroundColor Green
Write-Host "  │  Kubeconfig:  .kube/k3s-lab.yaml                 │" -ForegroundColor Green
Write-Host "  │                                                  │" -ForegroundColor Green
Write-Host "  │  Attack Surfaces:                                │" -ForegroundColor Green
Write-Host "  │    - Kubernetes Goat scenarios (10+)             │" -ForegroundColor Green
Write-Host "  │    - Privileged pod with host mount              │" -ForegroundColor Green
Write-Host "  │    - Overprivileged service account              │" -ForegroundColor Green
Write-Host "  │    - Exposed secrets in default namespace        │" -ForegroundColor Green
Write-Host "  │                                                  │" -ForegroundColor Green
Write-Host "  │  Scan with:                                      │" -ForegroundColor Green
Write-Host "  │    trivy k8s --kubeconfig .kube/k3s-lab.yaml     │" -ForegroundColor Green
Write-Host "  │    kubescape scan --kubeconfig .kube/k3s-lab.yaml│" -ForegroundColor Green
Write-Host "  └──────────────────────────────────────────────────┘" -ForegroundColor Green
Write-Host ""
