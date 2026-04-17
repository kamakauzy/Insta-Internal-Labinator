# Insta-Internal-Labinator

> **One-click red team assumed-breach lab generator for VMware Workstation Pro.**

Simulates a realistic internal penetration test client handoff — complete with randomized Active Directory environments, misconfigurations, service accounts, and a professional Red Team Handoff Package. Every deployment is unique, just like real engagements.

---

## What It Does

A single elevated PowerShell script that:

1. **Reads** an optional `ClientHandoff.json` config (or randomizes everything)
2. **Generates** a unique AD environment: random domain, users, weak passwords, Kerberoastable service accounts, and misconfigurations
3. **Configures** an isolated VMware Host-Only network with static IPs, no DHCP
4. **Deploys** GOAD (Game of Active Directory) — real Microsoft AD with realistic vulnerabilities
5. **Deploys** an Ubuntu 24.04 attacker VM with Docker, Impacket, BloodHound, and your C2
6. **Creates** a professional Red Team Handoff Package — exactly like a real client engagement
7. **Snapshots** all VMs for instant rollback

---

## Requirements

| Component | Version | Notes |
|-----------|---------|-------|
| **Windows 11 Pro** | 23H2+ | Host OS |
| **RAM** | 32 GB | Lab uses ~20-24 GB |
| **VMware Workstation Pro** | 17+ | With vmrun in PATH |
| **Vagrant** | 2.4+ | [vagrantup.com](https://www.vagrantup.com/) |
| **vagrant-vmware-desktop** | Latest | Auto-installed by script |
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

Copy and edit the sample config:

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

### 4. Start Hacking

```bash
ssh vagrant@<attacker-ip>  # password: vagrant
cd engagement/
# Your handoff package tells you everything you need
```

### 5. Destroy When Done

```powershell
.\Deploy-RedTeamLab.ps1 -Destroy
```

---

## ClientHandoff.json

All fields are **optional**. Missing fields are randomized automatically.

```json
{
  "clientName": "Acme Corp",
  "domain": "acmecorp.local",
  "cidr": "192.168.56.0/24",
  "lowPrivUser": {
    "username": "j.smith",
    "password": "Summer2026!"
  },
  "c2DockerImage": "yourcompany/c2-beacon:latest",
  "c2EnvVars": {
    "SAAS_TOKEN": "your-token-here",
    "CALLBACK_URL": "https://c2.your-saas.com"
  },
  "labVariant": "GOAD-Light",
  "attackerVm": {
    "ramMB": 4096,
    "cpus": 2
  }
}
```

### Field Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `clientName` | string | Random company name | Appears in handoff docs and GPOs |
| `domain` | string | Random (e.g. `acmecorp.local`) | AD domain FQDN |
| `cidr` | string | Random private range | Lab network CIDR |
| `lowPrivUser.username` | string | Random (e.g. `j.smith`, `svc_backup`) | Initial assumed-breach account |
| `lowPrivUser.password` | string | Random weak password | e.g. `Summer2026!`, `Welcome123` |
| `c2DockerImage` | string | None | Docker image for C2 beacon on attacker VM |
| `c2EnvVars` | object | `{}` | Environment variables passed to C2 container |
| `labVariant` | string | `GOAD-Light` | `GOAD-Light` or `MINILAB` |
| `attackerVm.ramMB` | int | `4096` | Attacker VM RAM in MB |
| `attackerVm.cpus` | int | `2` | Attacker VM CPU cores |

---

## Randomization Engine

Every deployment generates unique data:

| Element | Randomization |
|---------|---------------|
| **Domain Name** | 30 realistic prefixes × 5 TLD styles |
| **Company Name** | 27 realistic corporate names |
| **Network CIDR** | 9 private ranges |
| **AD Users** | 50–300 users with realistic names, departments, titles |
| **Weak Passwords** | 15–35% of accounts get common weak passwords |
| **Service Accounts** | 2–6 Kerberoastable accounts with SPNs |
| **Misconfigurations** | Probabilistic selection from 12 common AD weaknesses |

### Misconfigurations Pool

Each has a probability of being active per deployment:

- Unconstrained Delegation (80%)
- Constrained Delegation to DC (60%)
- AS-REP Roastable accounts (90%)
- Kerberoastable service accounts (95%)
- GPP Passwords (70%)
- LAPS not deployed (60%)
- SMB Signing disabled (75%)
- LLMNR/NBT-NS enabled (85%)
- DCSync ACL path (50%)
- Weak ACLs (GenericAll/WriteDACL) (70%)
- Print Spooler on DC (80%)
- ADCS ESC1 misconfiguration (40%)

---

## Red Team Handoff Package

After deployment, a folder is created: `RedTeam-Handoff-[domain]-[timestamp]/`

| File | Contents |
|------|----------|
| `Handoff.md` | Professional engagement document — scope, ROE, initial creds, contacts |
| `lab-credentials.txt` | All generated accounts, DCs, IPs, service accounts, misconfigs |
| `network-map.txt` | ASCII network diagram |
| `attacker-vm-access.md` | SSH access, C2 container management, installed tools |
| `start-attacking.md` | Quick-reference attack commands for each phase |
| `all-users.csv` | Complete user list with passwords (for offline cracking practice) |

The `Handoff.md` reads exactly like a document a real client would hand to a red team before an assumed-breach engagement.

---

## Script Parameters

```powershell
.\Deploy-RedTeamLab.ps1
    [-ConfigPath <path>]     # Path to ClientHandoff.json (default: .\ClientHandoff.json)
    [-Destroy]               # Tear down all lab VMs
    [-SkipSnapshots]         # Skip VMware snapshot creation
    [-Force]                 # Force rebuild even if VMs exist
```

---

## Architecture

```
┌──────────────────────────────┐
│     HOST (Windows 11 Pro)    │
│     VMware Workstation Pro   │
│                              │
│  ┌────────────────────────┐  │
│  │   VMnet (Host-Only)    │  │
│  │   No DHCP / Static IPs │  │
│  │                        │  │
│  │  ┌──────┐ ┌──────┐    │  │
│  │  │ DC01 │ │ DC02 │    │  │
│  │  │ .10  │ │ .11  │    │  │
│  │  └──────┘ └──────┘    │  │
│  │      ┌──────┐         │  │
│  │      │SRV02 │         │  │
│  │      │ .22  │         │  │
│  │      └──────┘         │  │
│  │  ┌────────────────┐   │  │
│  │  │  ATTACKER VM   │   │  │
│  │  │  .200 (Lab)    │───┼──┼── NAT (Internet/C2)
│  │  │  Docker + C2   │   │  │
│  │  └────────────────┘   │  │
│  └────────────────────────┘  │
└──────────────────────────────┘
```

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
| "VMware not found" | Ensure VMware Workstation is installed and `vmrun.exe` is in PATH |
| "Vagrant not found" | Install Vagrant and restart your terminal |
| VMs won't start | Check available RAM — lab needs ~20 GB free |
| Network conflicts | Change CIDR in `ClientHandoff.json` to avoid conflicts |
| GOAD provisioning fails | Ensure Vagrant VMware plugin is installed: `vagrant plugin install vagrant-vmware-desktop` |
| Stale VMs | Run `.\Deploy-RedTeamLab.ps1 -Destroy` then redeploy |

---

## License

MIT — Use responsibly and only in authorized environments.

---

## Credits

- [GOAD — Game of Active Directory](https://github.com/Orange-Cyberdefense/GOAD) by Orange Cyberdefense
- Built for red team operators who want realistic practice environments
