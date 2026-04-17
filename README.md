# Insta-Internal-Labinator

> **One-click red team assumed-breach lab generator for VMware Workstation Pro.**

Simulates a realistic internal penetration test client handoff — complete with randomized Active Directory environments, misconfigurations, service accounts, and a professional Red Team Handoff Package. Every deployment is unique, just like real engagements.

---

## What It Does

A single elevated PowerShell script that:

1. **Reads** an optional `ClientHandoff.json` config (or randomizes everything)
2. **Generates** a unique AD environment: random domain, 80–400 users across 8 departments, weak passwords, Kerberoastable service accounts, and 19 misconfiguration categories
3. **Configures** an isolated VMware Host-Only network with static IPs, no DHCP
4. **Deploys** GOAD (Game of Active Directory) — real Microsoft AD with realistic vulnerabilities
5. **Injects** randomized GOAD overrides: domain names, user pools, service accounts, and misconfigurations
6. **Deploys** an Ubuntu 24.04 attacker VM with Docker, Impacket, BloodHound, and your C2
7. **Creates** an executive-quality Red Team Handoff Package — leaked intel section, attack surface port table, and phase-by-phase attack guide
8. **Snapshots** all VMs for instant rollback
9. **Supports** `-ResumeFrom` to continue interrupted deployments

---

## Requirements

| Component | Version | Notes |
|-----------|---------|-------|
| **Windows 11 Pro** | 23H2+ | Host OS |
| **RAM** | 32 GB | Lab uses ~20-24 GB |
| **Disk Space** | 50 GB free | Checked automatically |
| **VMware Workstation Pro** | 17+ | vmrun in PATH or auto-detected |
| **Vagrant** | 2.4+ | [vagrantup.com](https://www.vagrantup.com/) |
| **vagrant-vmware-desktop** | Latest | Auto-installed by script |
| **Docker Desktop** | Latest | For GOAD provisioning |
| **Git** | 2.40+ | [git-scm.com](https://git-scm.com/) |
| **OpenSSH Client** | Built-in | Windows Features |

---

## Quick Start

### 1. Clone This Repo

```powershell
git clone https://github.com/kamakauzy/Insta-Internal-Labinator.git
cd Insta-Internal-Labinator
```

### 2. (Optional) Create Your Config

```powershell
copy ClientHandoff.json.example ClientHandoff.json
notepad ClientHandoff.json
```

Or skip this step — the script will randomize everything.

### 3. Deploy

Run as **Administrator**:

```powershell
.\Deploy-RedTeamLab.ps1
```

With a custom config:

```powershell
.\Deploy-RedTeamLab.ps1 -ConfigPath .\ClientHandoff.json
```

With a reproducible seed (same misconfigurations every time):

```powershell
.\Deploy-RedTeamLab.ps1 -MisconfigSeed 42
```

Resume an interrupted deployment:

```powershell
.\Deploy-RedTeamLab.ps1 -ResumeFrom GOAD -InstanceId abc123
```

### 4. Start Hacking

Your handoff package is generated in `RedTeam-Handoff-[domain]-[timestamp]/` — it tells you everything you need to start.

### 5. Destroy When Done

```powershell
.\Deploy-RedTeamLab.ps1 -Destroy
```

---

## ClientHandoff.json

All fields are **optional**. Missing fields are randomized automatically.

```json
{
  "clientName": "Acme Corporation",
  "domain": "acmecorp.local",
  "cidr": "192.168.56.0/24",
  "lowPrivUser": {
    "username": "j.smith",
    "password": "Summer2026!"
  },
  "c2DockerImage": "",
  "c2EnvVars": {},
  "labVariant": "GOAD-Light",
  "misconfigSeed": 0,
  "attackerVm": {
    "ramMB": 4096,
    "cpus": 2
  }
}
```

### Field Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `clientName` | string | Random (80+ companies across 10+ industries) | Appears in handoff docs and GPOs |
| `domain` | string | Random (e.g. `acmecorp.local`) | AD domain FQDN |
| `cidr` | string | Random private range | Lab network CIDR |
| `lowPrivUser.username` | string | Random (e.g. `j.smith`) | Initial assumed-breach account |
| `lowPrivUser.password` | string | Random weak password | Company-context-aware |
| `c2DockerImage` | string | None | Docker image for C2 beacon on attacker VM |
| `c2EnvVars` | object | `{}` | Environment variables passed to C2 container |
| `labVariant` | string | `GOAD-Light` | `GOAD-Light` or `MINILAB` |
| `misconfigSeed` | int | `0` (random) | Seed for reproducible misconfiguration selection |
| `attackerVm.ramMB` | int | `4096` | Attacker VM RAM in MB |
| `attackerVm.cpus` | int | `2` | Attacker VM CPU cores |

---

## Randomization Engine (v3.0)

Every deployment generates unique data using a seeded RNG (reproducible with `-MisconfigSeed`):

| Element | Randomization |
|---------|---------------|
| **Company Name** | 80+ names across tech, finance, healthcare, energy, manufacturing, retail, defense, legal, education, logistics industries |
| **Domain Name** | Derived from company name with realistic TLD styles |
| **Network CIDR** | 9 private ranges |
| **AD Users** | 80–400 users with department-aware names and titles |
| **Departments** | 8 departments: IT, Finance, HR, Sales, Engineering, Marketing, Executive, Operations |
| **Account Types** | Regular, Service (svc_*), Admin (adm_*), Temporary (temp_*) |
| **Weak Passwords** | Company-context-aware (company name + year, season + year, etc.) |
| **Service Accounts** | 3–8 Kerberoastable accounts with realistic SPNs |
| **Misconfigurations** | Probabilistic selection from 19 categories with severity ratings |

### Misconfigurations Pool (19 categories)

Each misconfiguration includes a severity rating and mapped attack path:

| Misconfiguration | Probability | Severity | Attack Path |
|-----------------|-------------|----------|-------------|
| Unconstrained Delegation | 80% | Critical | Token impersonation → DC compromise |
| Constrained Delegation to DC | 60% | Critical | S4U2Proxy → DC service access |
| AS-REP Roastable accounts | 90% | High | Offline cracking → credential access |
| Kerberoastable service accounts | 95% | High | Offline cracking → service account compromise |
| GPP Passwords | 70% | High | SYSVOL read → plaintext credentials |
| LAPS not deployed | 60% | Medium | Local admin reuse → lateral movement |
| SMB Signing disabled | 75% | High | NTLM relay → arbitrary auth |
| LLMNR/NBT-NS enabled | 85% | High | Poisoning → credential capture |
| DCSync ACL path | 50% | Critical | Replication → full domain compromise |
| Weak ACLs (GenericAll/WriteDACL) | 70% | Critical | ACL abuse → privilege escalation |
| Print Spooler on DC | 80% | High | PrinterBug → coerced authentication |
| ADCS ESC1 | 40% | Critical | Certificate abuse → domain admin |
| **RBCD (Resource-Based Constrained Delegation)** | 55% | Critical | Write to msDS-AllowedToActOnBehalfOfOtherIdentity |
| **ADCS ESC4 (Template Modification)** | 35% | Critical | Template ACL abuse → arbitrary certificate |
| **ADCS ESC8 (NTLM Relay to HTTP)** | 45% | Critical | Relay to web enrollment → DC cert |
| **WebDAV on servers** | 50% | Medium | NTLM auth coercion over HTTP |
| **Passwords in AD Description** | 65% | High | LDAP query → plaintext credentials |
| **Legacy NTLMv1 allowed** | 40% | High | NTLMv1 downgrade → trivial cracking |
| **Null sessions permitted** | 30% | Medium | Anonymous enumeration → user/group listing |

---

## Red Team Handoff Package

After deployment, a folder is created: `RedTeam-Handoff-[domain]-[timestamp]/`

| File | Contents |
|------|----------|
| `Handoff.md` | Executive-quality engagement document with leaked intel section |
| `lab-credentials.txt` | All accounts, IPs, SPNs, misconfigs with severity + attack paths |
| `network-map.txt` | ASCII network diagram with attack surface port table |
| `start-attacking.md` | Phase-by-phase attack commands for both domains |

---

## Script Parameters

```powershell
.\Deploy-RedTeamLab.ps1
    [-ConfigPath <path>]     # Path to ClientHandoff.json (default: .\ClientHandoff.json)
    [-MisconfigSeed <int>]   # Seed for reproducible randomization (0 = random)
    [-Destroy]               # Tear down all lab VMs
    [-SkipSnapshots]         # Skip VMware snapshot creation
    [-SkipGOAD]              # Skip GOAD deployment (attacker + handoff only)
    [-SkipAttacker]          # Skip attacker VM deployment
    [-HandoffOnly]           # Generate handoff package without deploying
    [-ResumeFrom <step>]     # Resume from: Prerequisites, Network, GOAD, Attacker, Snapshots, Handoff
    [-InstanceId <id>]       # Resume a specific instance
    [-Force]                 # Force rebuild even if VMs exist
```

---

## Helper Scripts

| Script | Purpose |
|--------|---------|
| `Check-LabStatus.ps1` | Quick health check — VMs, network, Docker containers, snapshots |
| `Reset-Lab.ps1` | Revert all VMs to snapshot (supports `-SnapshotName`, `-ListOnly`) |

---

## Architecture

```
┌──────────────────────────────────────────────────┐
│     HOST (Windows 11 Pro)                        │
│     VMware Workstation Pro                       │
│                                                  │
│  ┌──────────────────────────────────────────┐    │
│  │   VMnet2 (Host-Only) 192.168.56.0/24    │    │
│  │   No DHCP / Static IPs                  │    │
│  │                                          │    │
│  │  ┌────────┐  ┌────────┐  ┌────────┐    │    │
│  │  │  DC01  │  │  DC02  │  │  SRV02 │    │    │
│  │  │  .10   │  │  .11   │  │  .22   │    │    │
│  │  │ Win19  │  │ Win19  │  │ Win19  │    │    │
│  │  └────────┘  └────────┘  └────────┘    │    │
│  │                                          │    │
│  │  ┌──────────────────────────────────┐   │    │
│  │  │      ATTACKER VM (.200)          │   │    │
│  │  │   Ubuntu 24.04 + Docker + C2     │───┼────┼── VMnet8 NAT
│  │  └──────────────────────────────────┘   │    │
│  └──────────────────────────────────────────┘    │
│                                                  │
│  ┌──────────────────────────────────────────┐    │
│  │   VMnet1 (Host-Only) 192.168.86.0/24    │    │
│  │   C2 / Management Network               │    │
│  │   ia-pentestagent Docker stack           │    │
│  └──────────────────────────────────────────┘    │
└──────────────────────────────────────────────────┘
```

---

## GOAD Integration

The script integrates with [GOAD (Game of Active Directory)](https://github.com/Orange-Cyberdefense/GOAD) to deploy real AD environments. v3.0 adds:

- **GOAD injection variables** — randomized domain names, user pools, and misconfigurations are exported as GOAD-compatible Ansible extra_vars
- **Automatic GOAD patching** — Windows Docker provisioner support (normally Linux-only)
- **Instance tracking** — each deployment gets a unique instance ID for resume support

---

## Safety & Warnings

> **⚠️ This tool creates intentionally vulnerable systems.**

- **NEVER** expose lab VMs to the internet or production networks
- The Host-Only network is **isolated by design** — do not bridge it
- All generated credentials are **intentionally weak** for training
- Destroy the lab when finished: `.\Deploy-RedTeamLab.ps1 -Destroy`
- This is for **authorized training and research only**

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| "VMware not found" | Script auto-detects standard install paths. If custom, add vmrun.exe to PATH |
| "Vagrant not found" | Install Vagrant and restart your terminal |
| VMs won't start | Check available RAM — lab needs ~20 GB free |
| Network conflicts | Change CIDR in `ClientHandoff.json` to avoid conflicts |
| GOAD provisioning fails | Ensure Docker Desktop is running and Vagrant VMware plugin is installed |
| VMnet2 APIPA address | Run `New-NetIPAddress -InterfaceAlias 'VMware Network Adapter VMnet2' -IPAddress 192.168.56.1 -PrefixLength 24` |
| WinRM unreachable | Check VMnet2 host IP first — this is the #1 cause |
| Stale VMs/processes | `Get-NetTCPConnection -LocalPort PORT -State Listen` to find stale processes |
| Interrupted deployment | Use `-ResumeFrom <step>` to continue where it left off |

---

## License

MIT — Use responsibly and only in authorized environments.

---

## Credits

- [GOAD — Game of Active Directory](https://github.com/Orange-Cyberdefense/GOAD) by Orange Cyberdefense
- Built for red team operators who want realistic practice environments
