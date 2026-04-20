"""Scenario engine — loads YAML scenarios, validates, generates Ansible playbooks.

Core flow:
  1. Load catalog.yaml (all available roles, services, vulns)
  2. Load/create scenario YAML (user's lab design)
  3. Validate scenario against catalog
  4. Generate Ansible playbook + inventory for the GOAD lab
"""

from __future__ import annotations

import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

BASE_DIR = Path(__file__).parent.parent.parent
SCENARIOS_DIR = BASE_DIR / "scenarios"
CATALOG_PATH = SCENARIOS_DIR / "catalog.yaml"
EXAMPLES_DIR = SCENARIOS_DIR / "examples"
GOAD_WORKSPACE = BASE_DIR / "GOAD" / "workspace"

# VM mapping: GOAD VM name → Ansible host / IP
GOAD_VM_MAP = {
    "dc01": {"hostname": "kingslanding", "ip": "192.168.56.10", "domain": "sevenkingdoms.local"},
    "dc02": {"hostname": "winterfell", "ip": "192.168.56.11", "domain": "north.sevenkingdoms.local"},
    "srv02": {"hostname": "castelblack", "ip": "192.168.56.22", "domain": "north.sevenkingdoms.local"},
    "lx01": {"hostname": "dragonstone", "ip": "192.168.56.32", "domain": "sevenkingdoms.local"},
}


def load_catalog() -> dict:
    """Load the vulnerability/service catalog."""
    with open(CATALOG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def list_scenarios() -> list[dict]:
    """List all saved scenarios (examples + user-created)."""
    scenarios = []
    for d in [EXAMPLES_DIR, SCENARIOS_DIR]:
        if not d.exists():
            continue
        for p in sorted(d.glob("*.yaml")):
            if p.name == "catalog.yaml":
                continue
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                if data and isinstance(data, dict) and "name" in data:
                    scenarios.append({
                        "id": p.stem,
                        "name": data.get("name", p.stem),
                        "description": data.get("description", ""),
                        "difficulty": data.get("difficulty", "medium"),
                        "machine_count": len(data.get("machines", [])),
                        "vuln_count": sum(
                            len(m.get("vulnerabilities", []))
                            for m in data.get("machines", [])
                        ),
                        "path": str(p),
                        "is_example": str(d) == str(EXAMPLES_DIR),
                    })
            except Exception:
                continue
    return scenarios


def load_scenario(scenario_id: str) -> dict:
    """Load a scenario by ID (filename stem)."""
    for d in [EXAMPLES_DIR, SCENARIOS_DIR]:
        p = d / f"{scenario_id}.yaml"
        if p.exists():
            with open(p, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            data["_path"] = str(p)
            data["_id"] = scenario_id
            return data
    raise FileNotFoundError(f"Scenario '{scenario_id}' not found")


def save_scenario(scenario: dict, scenario_id: str | None = None) -> str:
    """Save a scenario to disk. Returns the scenario ID."""
    if not scenario_id:
        # Sanitize name for filename
        name = scenario.get("name", "untitled")
        slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40]
        scenario_id = f"{slug}-{uuid.uuid4().hex[:6]}"

    SCENARIOS_DIR.mkdir(parents=True, exist_ok=True)
    path = SCENARIOS_DIR / f"{scenario_id}.yaml"

    # Strip internal fields
    clean = {k: v for k, v in scenario.items() if not k.startswith("_")}
    clean["updated_at"] = datetime.now(timezone.utc).isoformat()

    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(clean, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

    return scenario_id


def delete_scenario(scenario_id: str) -> bool:
    """Delete a user-created scenario. Cannot delete examples."""
    path = SCENARIOS_DIR / f"{scenario_id}.yaml"
    if path.exists():
        path.unlink()
        return True
    return False


def validate_scenario(scenario: dict, catalog: dict | None = None) -> list[str]:
    """Validate a scenario against the catalog. Returns list of errors (empty = valid)."""
    if catalog is None:
        catalog = load_catalog()

    errors = []
    valid_roles = set(catalog.get("roles", {}).keys())
    valid_vulns = set(catalog.get("vulnerabilities", {}).keys())
    valid_services = set(catalog.get("services", {}).keys())

    if not scenario.get("name"):
        errors.append("Scenario must have a name")

    machines = scenario.get("machines", [])
    if not machines:
        errors.append("Scenario must have at least one machine")

    for i, m in enumerate(machines):
        prefix = f"machines[{i}]"
        if not m.get("name"):
            errors.append(f"{prefix}: machine must have a name")
        role = m.get("role", "")
        if role not in valid_roles:
            errors.append(f"{prefix}: unknown role '{role}' (valid: {', '.join(sorted(valid_roles))})")

        for svc in m.get("services", []):
            svc_name = svc if isinstance(svc, str) else svc.get("name", "")
            if svc_name not in valid_services:
                errors.append(f"{prefix}: unknown service '{svc_name}'")

        for vuln in m.get("vulnerabilities", []):
            vuln_name = vuln if isinstance(vuln, str) else vuln.get("id", "")
            if vuln_name not in valid_vulns:
                errors.append(f"{prefix}: unknown vulnerability '{vuln_name}'")
            elif vuln_name in valid_vulns:
                vuln_def = catalog["vulnerabilities"][vuln_name]
                if role not in vuln_def.get("targets", []):
                    errors.append(
                        f"{prefix}: vulnerability '{vuln_name}' doesn't target role '{role}' "
                        f"(valid targets: {vuln_def['targets']})"
                    )

    return errors


def _resolve_target_vm(machine: dict, catalog: dict) -> str:
    """Map a machine's role to a GOAD VM name."""
    role = machine.get("role", "")
    role_def = catalog.get("roles", {}).get(role, {})
    maps_to = role_def.get("maps_to", [])
    # Use explicit target if provided, otherwise first available
    return machine.get("target_vm", maps_to[0] if maps_to else "srv02")


def generate_playbook(scenario: dict, catalog: dict | None = None) -> dict:
    """Generate Ansible playbook + variable files from a scenario.

    Returns:
        {
            "playbook": str (YAML),
            "inventory": str (INI),
            "vars": dict[str, Any],
            "summary": str,
        }
    """
    if catalog is None:
        catalog = load_catalog()

    errors = validate_scenario(scenario, catalog)
    if errors:
        raise ValueError(f"Invalid scenario: {'; '.join(errors)}")

    plays = []
    all_vars: dict[str, Any] = {
        "scenario_name": scenario["name"],
        "scenario_id": scenario.get("_id", "custom"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    summary_lines = [
        f"# Scenario: {scenario['name']}",
        f"# Difficulty: {scenario.get('difficulty', 'medium')}",
        f"# Machines: {len(scenario.get('machines', []))}",
        "",
    ]

    for machine in scenario.get("machines", []):
        vm_name = _resolve_target_vm(machine, catalog)
        vm_info = GOAD_VM_MAP.get(vm_name, {})
        host = vm_info.get("hostname", vm_name)
        ip = vm_info.get("ip", "unknown")

        tasks = []
        summary_lines.append(f"## {machine['name']} ({machine['role']}) → {host} ({ip})")

        # Service configuration tasks
        for svc in machine.get("services", []):
            svc_name = svc if isinstance(svc, str) else svc.get("name", "")
            svc_config = {} if isinstance(svc, str) else {k: v for k, v in svc.items() if k != "name"}

            if svc_name == "smb" and svc_config:
                if not svc_config.get("signing", True):
                    tasks.append({
                        "name": f"[{machine['name']}] Disable SMB signing",
                        "ansible.windows.win_regedit": {
                            "path": "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
                            "name": "RequireSecuritySignature",
                            "data": 0,
                            "type": "dword",
                        },
                    })
                for share in svc_config.get("shares", []):
                    share_name = share if isinstance(share, str) else share.get("name", share)
                    tasks.append({
                        "name": f"[{machine['name']}] Create share: {share_name}",
                        "ansible.windows.win_shell": (
                            f"New-Item -Path 'C:\\Shares\\{share_name}' -ItemType Directory -Force; "
                            f"New-SmbShare -Name '{share_name}' -Path 'C:\\Shares\\{share_name}' "
                            f"-FullAccess 'Everyone' -ErrorAction SilentlyContinue"
                        ),
                    })

            summary_lines.append(f"  - Service: {svc_name}")

        # Vulnerability injection tasks
        for vuln in machine.get("vulnerabilities", []):
            vuln_name = vuln if isinstance(vuln, str) else vuln.get("id", "")
            vuln_config = {} if isinstance(vuln, str) else {k: v for k, v in vuln.items() if k != "id"}
            vuln_def = catalog.get("vulnerabilities", {}).get(vuln_name, {})

            vuln_tasks = _generate_vuln_tasks(vuln_name, vuln_config, vuln_def, machine, vm_info)
            tasks.extend(vuln_tasks)
            summary_lines.append(f"  - Vuln: {vuln_def.get('label', vuln_name)} [{vuln_def.get('severity', '?')}]")

        if tasks:
            # Determine connection type
            is_linux = vm_name == "lx01"
            play = {
                "name": f"Configure {machine['name']} ({host})",
                "hosts": host,
                "gather_facts": False,
            }
            if not is_linux:
                play["vars"] = {"ansible_connection": "winrm", "ansible_winrm_transport": "kerberos"}
            play["tasks"] = tasks
            plays.append(play)

    playbook_yaml = yaml.dump(plays, default_flow_style=False, sort_keys=False, allow_unicode=True)

    # Generate inventory
    inventory_lines = ["[all:vars]", "ansible_user=vagrant", ""]
    for vm_name, vm_info in GOAD_VM_MAP.items():
        inventory_lines.append(f"[{vm_info['hostname']}]")
        inventory_lines.append(f"{vm_info['hostname']} ansible_host={vm_info['ip']}")
        inventory_lines.append("")

    return {
        "playbook": playbook_yaml,
        "inventory": "\n".join(inventory_lines),
        "vars": all_vars,
        "summary": "\n".join(summary_lines),
    }


def _generate_vuln_tasks(
    vuln_name: str,
    config: dict,
    vuln_def: dict,
    machine: dict,
    vm_info: dict,
) -> list[dict]:
    """Generate Ansible tasks for a specific vulnerability."""
    tasks = []
    machine_label = machine.get("name", "target")
    domain = vm_info.get("domain", "sevenkingdoms.local")

    # ─── Credential Access ───
    if vuln_name == "kerberoastable_spns":
        accounts = config.get("accounts", vuln_def.get("configurable", {}).get("accounts", {}).get("default", []))
        for acct in accounts:
            tasks.append({
                "name": f"[{machine_label}] Create Kerberoastable SPN: {acct}",
                "ansible.windows.win_shell": (
                    f"try {{ New-ADUser -Name '{acct}' -SamAccountName '{acct}' "
                    f"-UserPrincipalName '{acct}@{domain}' -AccountPassword "
                    f"(ConvertTo-SecureString 'Summer2026!' -AsPlainText -Force) "
                    f"-Enabled $true -PasswordNeverExpires $true -ErrorAction Stop; "
                    f"Set-ADUser '{acct}' -ServicePrincipalNames @{{Add='MSSQLSvc/{acct}.{domain}:1433'}} }} "
                    f"catch {{ Write-Host \"Account may already exist: $_\" }}"
                ),
            })

    elif vuln_name == "asrep_roastable":
        accounts = config.get("accounts", ["dev.legacy", "temp.contractor"])
        for acct in accounts:
            tasks.append({
                "name": f"[{machine_label}] Create AS-REP roastable: {acct}",
                "ansible.windows.win_shell": (
                    f"try {{ New-ADUser -Name '{acct}' -SamAccountName '{acct}' "
                    f"-AccountPassword (ConvertTo-SecureString 'Password123!' -AsPlainText -Force) "
                    f"-Enabled $true -ErrorAction Stop }} catch {{}}; "
                    f"Set-ADAccountControl -Identity '{acct}' -DoesNotRequirePreAuth $true"
                ),
            })

    elif vuln_name == "gpp_passwords":
        tasks.append({
            "name": f"[{machine_label}] Create GPP with embedded password",
            "ansible.windows.win_shell": (
                "$gpoPath = '\\\\' + $env:USERDNSDOMAIN + '\\SYSVOL\\' + $env:USERDNSDOMAIN + "
                "'\\Policies'; $targetDir = (Get-ChildItem $gpoPath -Directory | Select-Object -First 1).FullName + "
                "'\\Machine\\Preferences\\Groups'; New-Item -Path $targetDir -ItemType Directory -Force | Out-Null; "
                "@'<Groups><User name=\"LocalAdmin\" action=\"U\" newName=\"\" fullName=\"\" description=\"\" "
                "cpassword=\"j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw\" changeLogon=\"0\" "
                "noChange=\"0\" neverExpires=\"1\" acctDisabled=\"0\" userName=\"svc_deploy\"/></Groups>'@ | "
                "Set-Content \"$targetDir\\Groups.xml\" -Encoding UTF8"
            ),
        })

    elif vuln_name == "password_in_description":
        accounts = config.get("accounts", ["svc_backup"])
        for acct in accounts:
            tasks.append({
                "name": f"[{machine_label}] Set password in AD description: {acct}",
                "ansible.windows.win_shell": (
                    f"Set-ADUser -Identity '{acct}' -Description "
                    f"'Temp password: Backup2026! — TODO remove' -ErrorAction SilentlyContinue"
                ),
            })

    elif vuln_name == "credential_in_sysvol":
        tasks.append({
            "name": f"[{machine_label}] Plant credentials in SYSVOL script",
            "ansible.windows.win_shell": (
                "$sysvolScripts = \"$env:SystemRoot\\SYSVOL\\domain\\scripts\"; "
                "Set-Content \"$sysvolScripts\\deploy-backup.ps1\" @'\n"
                "# Backup deployment script\n"
                "$cred = New-Object PSCredential(\"svc_deploy\", "
                "(ConvertTo-SecureString \"D3pl0y!2026\" -AsPlainText -Force))\n"
                "Invoke-Command -ComputerName SRV02 -Credential $cred -ScriptBlock { Start-Service wuauserv }\n"
                "'@"
            ),
        })

    elif vuln_name == "autologon_credentials":
        tasks.append({
            "name": f"[{machine_label}] Configure autologon with domain credentials",
            "ansible.windows.win_regedit": {
                "path": "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                "name": "DefaultUserName",
                "data": f"{domain}\\svc_autologon",
                "type": "string",
            },
        })
        tasks.append({
            "name": f"[{machine_label}] Set autologon password",
            "ansible.windows.win_regedit": {
                "path": "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                "name": "DefaultPassword",
                "data": "Aut0L0gon!",
                "type": "string",
            },
        })

    # ─── AD Misconfiguration ───
    elif vuln_name == "no_laps":
        tasks.append({
            "name": f"[{machine_label}] Ensure LAPS is not deployed",
            "ansible.windows.win_shell": (
                "Get-Service 'AdmPwd' -ErrorAction SilentlyContinue | Stop-Service -Force -ErrorAction SilentlyContinue; "
                "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd' "
                "-Name 'AdmPwdEnabled' -Value 0 -ErrorAction SilentlyContinue; "
                "Write-Host 'LAPS disabled/not configured'"
            ),
        })

    elif vuln_name == "weak_acls":
        chains = config.get("chains", ["GenericAll", "WriteDACL"])
        for chain in chains:
            tasks.append({
                "name": f"[{machine_label}] Set weak ACL: {chain}",
                "ansible.windows.win_shell": (
                    f"Import-Module ActiveDirectory; "
                    f"$target = (Get-ADGroup 'Domain Admins').DistinguishedName; "
                    f"$user = (Get-ADUser -Filter \"SamAccountName -eq 'svc_helpdesk'\" -ErrorAction SilentlyContinue); "
                    f"if (-not $user) {{ New-ADUser -Name 'svc_helpdesk' -SamAccountName 'svc_helpdesk' "
                    f"-AccountPassword (ConvertTo-SecureString 'Help2026!' -AsPlainText -Force) -Enabled $true }}; "
                    f"$acl = Get-Acl \"AD:\\$target\"; "
                    f"$sid = (Get-ADUser 'svc_helpdesk').SID; "
                    f"$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, '{chain}', 'Allow'); "
                    f"$acl.AddAccessRule($ace); Set-Acl \"AD:\\$target\" $acl"
                ),
            })

    elif vuln_name == "dcsync_acl":
        tasks.append({
            "name": f"[{machine_label}] Grant DCSync rights to low-priv user",
            "ansible.windows.win_shell": (
                "$domainDN = (Get-ADDomain).DistinguishedName; "
                "$user = Get-ADUser -Filter \"SamAccountName -eq 'svc_replication'\" -ErrorAction SilentlyContinue; "
                "if (-not $user) { New-ADUser -Name 'svc_replication' -SamAccountName 'svc_replication' "
                "-AccountPassword (ConvertTo-SecureString 'Repl!2026' -AsPlainText -Force) -Enabled $true }; "
                "$sid = (Get-ADUser 'svc_replication').SID; "
                "$acl = Get-Acl \"AD:\\$domainDN\"; "
                # DS-Replication-Get-Changes + DS-Replication-Get-Changes-All
                "$guid1 = [GUID]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'; "
                "$guid2 = [GUID]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'; "
                "$ace1 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, 'ExtendedRight', 'Allow', $guid1); "
                "$ace2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, 'ExtendedRight', 'Allow', $guid2); "
                "$acl.AddAccessRule($ace1); $acl.AddAccessRule($ace2); "
                "Set-Acl \"AD:\\$domainDN\" $acl"
            ),
        })

    elif vuln_name == "null_sessions":
        tasks.append({
            "name": f"[{machine_label}] Enable null sessions",
            "ansible.windows.win_regedit": {
                "path": "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
                "name": "RestrictNullSessAccess",
                "data": 0,
                "type": "dword",
            },
        })

    elif vuln_name == "machine_account_quota":
        tasks.append({
            "name": f"[{machine_label}] Set MachineAccountQuota to 10",
            "ansible.windows.win_shell": (
                "Set-ADDomain -Identity (Get-ADDomain) -Replace @{'ms-DS-MachineAccountQuota'=10}"
            ),
        })

    # ─── Certificate Abuse ───
    elif vuln_name == "adcs_esc1":
        tasks.append({
            "name": f"[{machine_label}] Create ESC1 vulnerable template",
            "ansible.windows.win_shell": (
                "# ESC1: Template allows enrollee to supply subject\n"
                "$tpl = Get-ADObject -Filter \"Name -eq 'ESC1-Vuln'\" "
                "-SearchBase \"CN=Certificate Templates,CN=Public Key Services,CN=Services,"
                "CN=Configuration,$((Get-ADDomain).DistinguishedName)\" -ErrorAction SilentlyContinue; "
                "if (-not $tpl) { "
                "  $webTpl = Get-ADObject -Filter \"Name -eq 'WebServer'\" "
                "  -SearchBase \"CN=Certificate Templates,CN=Public Key Services,CN=Services,"
                "  CN=Configuration,$((Get-ADDomain).DistinguishedName)\"; "
                "  $clone = $webTpl | Copy-Item -PassThru; "
                "  Write-Host 'ESC1 template creation would need certutil — see ADCS expansion script' "
                "}"
            ),
        })

    elif vuln_name == "adcs_esc8":
        tasks.append({
            "name": f"[{machine_label}] Enable HTTP enrollment without EPA",
            "ansible.windows.win_shell": (
                "# Ensure web enrollment is installed and EPA is not required\n"
                "Install-WindowsFeature ADCS-Web-Enrollment -ErrorAction SilentlyContinue; "
                "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters' "
                "-Name 'SupportedEncryptionTypes' -Value 0x7fffffff -ErrorAction SilentlyContinue; "
                "Write-Host 'ADCS ESC8: HTTP enrollment enabled'"
            ),
        })

    # ─── Delegation Abuse ───
    elif vuln_name == "unconstrained_delegation":
        tasks.append({
            "name": f"[{machine_label}] Enable unconstrained delegation",
            "ansible.windows.win_shell": (
                f"$computer = Get-ADComputer -Identity '{vm_info.get('hostname', 'castelblack')}'; "
                f"Set-ADComputer $computer -TrustedForDelegation $true"
            ),
        })

    elif vuln_name == "constrained_delegation":
        target_spn = config.get("target_spn", "CIFS/kingslanding.sevenkingdoms.local")
        tasks.append({
            "name": f"[{machine_label}] Configure constrained delegation to {target_spn}",
            "ansible.windows.win_shell": (
                f"$computer = Get-ADComputer -Identity '{vm_info.get('hostname', 'castelblack')}'; "
                f"Set-ADComputer $computer -Add @{{'msDS-AllowedToDelegateTo'=@('{target_spn}')}}"
            ),
        })

    elif vuln_name == "rbcd":
        tasks.append({
            "name": f"[{machine_label}] Set up RBCD attack path",
            "ansible.windows.win_shell": (
                "# Create attacker machine account and set RBCD\n"
                "$pass = ConvertTo-SecureString 'RBCD2026!' -AsPlainText -Force; "
                "New-ADComputer -Name 'EVIL$' -SamAccountName 'EVIL$' "
                "-AccountPassword $pass -Enabled $true -ErrorAction SilentlyContinue; "
                f"$target = Get-ADComputer '{vm_info.get('hostname', 'castelblack')}'; "
                "$attacker = Get-ADComputer 'EVIL$'; "
                "Set-ADComputer $target -PrincipalsAllowedToDelegateToAccount $attacker"
            ),
        })

    # ─── Protocol Weakness ───
    elif vuln_name == "smb_signing_disabled":
        tasks.append({
            "name": f"[{machine_label}] Disable SMB signing requirement",
            "ansible.windows.win_regedit": {
                "path": "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
                "name": "RequireSecuritySignature",
                "data": 0,
                "type": "dword",
            },
        })
        tasks.append({
            "name": f"[{machine_label}] Disable SMB signing (client)",
            "ansible.windows.win_regedit": {
                "path": "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters",
                "name": "RequireSecuritySignature",
                "data": 0,
                "type": "dword",
            },
        })

    elif vuln_name == "llmnr_enabled":
        tasks.append({
            "name": f"[{machine_label}] Enable LLMNR",
            "ansible.windows.win_regedit": {
                "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient",
                "name": "EnableMulticast",
                "data": 1,
                "type": "dword",
            },
        })

    elif vuln_name == "ntlmv1_allowed":
        tasks.append({
            "name": f"[{machine_label}] Allow NTLMv1",
            "ansible.windows.win_regedit": {
                "path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
                "name": "LMCompatibilityLevel",
                "data": 0,
                "type": "dword",
            },
        })

    elif vuln_name == "ldap_signing_disabled":
        tasks.append({
            "name": f"[{machine_label}] Disable LDAP signing requirement",
            "ansible.windows.win_regedit": {
                "path": "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters",
                "name": "LDAPServerIntegrity",
                "data": 0,
                "type": "dword",
            },
        })

    # ─── Secret Exposure ───
    elif vuln_name == "share_with_passwords":
        share_name = config.get("share_name", "IT-Backup")
        tasks.append({
            "name": f"[{machine_label}] Create share with password files: {share_name}",
            "ansible.windows.win_shell": (
                f"$sharePath = 'C:\\Shares\\{share_name}'; "
                f"New-Item -Path $sharePath -ItemType Directory -Force | Out-Null; "
                f"New-SmbShare -Name '{share_name}' -Path $sharePath -FullAccess 'Everyone' -ErrorAction SilentlyContinue; "
                "'Admin Credentials\n================\nDomain Admin: administrator\nPassword: Wint3rIsComing!\n"
                "Service Account: svc_deploy\nPassword: D3pl0y!2026\n\n"
                "SQL SA: sa / SQLAdmin2026!' | Set-Content \"$sharePath\\admin-passwords.txt\"; "
                "'Server Access\n=============\nRDP: castelblack.north.sevenkingdoms.local\n"
                "User: north\\robb.stark / sexywolfy' | Set-Content \"$sharePath\\server-access.txt\""
            ),
        })

    elif vuln_name == "share_with_aws_keys":
        share_name = config.get("share_name", "DevOps-Backup")
        profile = config.get("profile", "prod")
        tasks.append({
            "name": f"[{machine_label}] Create share with AWS credentials: {share_name}",
            "ansible.windows.win_shell": (
                f"$sharePath = 'C:\\Shares\\{share_name}'; "
                f"New-Item -Path \"$sharePath\\.aws\" -ItemType Directory -Force | Out-Null; "
                f"New-SmbShare -Name '{share_name}' -Path $sharePath -FullAccess 'Everyone' -ErrorAction SilentlyContinue; "
                f"\"[{profile}]`naws_access_key_id = AKIA3EXAMPLE1234567`n"
                f"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`n"
                f"region = us-east-1\" | Set-Content \"$sharePath\\.aws\\credentials\"; "
                f"\"[{profile}]`nregion = us-east-1`noutput = json\" | Set-Content \"$sharePath\\.aws\\config\"; "
                "'#!/bin/bash\n# Deployment script\nexport AWS_PROFILE=" + profile + "\n"
                "aws s3 sync ./build s3://company-prod-deploy/\n' | Set-Content \"$sharePath\\deploy.sh\""
            ),
        })

    elif vuln_name == "share_with_ssh_keys":
        share_name = config.get("share_name", "Admin-Tools")
        tasks.append({
            "name": f"[{machine_label}] Create share with SSH keys: {share_name}",
            "ansible.windows.win_shell": (
                f"$sharePath = 'C:\\Shares\\{share_name}'; "
                f"New-Item -Path \"$sharePath\\.ssh\" -ItemType Directory -Force | Out-Null; "
                f"New-SmbShare -Name '{share_name}' -Path $sharePath -FullAccess 'Everyone' -ErrorAction SilentlyContinue; "
                "'-----BEGIN OPENSSH PRIVATE KEY-----\n"
                "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
                "QyNTUxOQAAACDkNm0iexXGmFNJb0wpKN/FAKE/EXAMPLE/KEY/DO/NOT/USE\n"
                "-----END OPENSSH PRIVATE KEY-----' | Set-Content \"$sharePath\\.ssh\\id_ed25519\"; "
                "'Host prod-*\n  User deploy\n  IdentityFile ~/.ssh/id_ed25519\n  StrictHostKeyChecking no\n"
                "\nHost prod-web01\n  HostName 10.100.1.50\n\nHost prod-db01\n  HostName 10.100.1.51\n' "
                "| Set-Content \"$sharePath\\.ssh\\config\""
            ),
        })

    elif vuln_name == "share_with_azure_tokens":
        tasks.append({
            "name": f"[{machine_label}] Create share with Azure SP credentials",
            "ansible.windows.win_shell": (
                "$sharePath = 'C:\\Shares\\Azure-Config'; "
                "New-Item -Path $sharePath -ItemType Directory -Force | Out-Null; "
                "New-SmbShare -Name 'Azure-Config' -Path $sharePath -FullAccess 'Everyone' -ErrorAction SilentlyContinue; "
                "'{\"appId\": \"a1b2c3d4-e5f6-7890-abcd-ef1234567890\", "
                "\"password\": \"Az~FAKE_SP_SECRET_DO_NOT_USE_12345\", "
                "\"tenant\": \"12345678-abcd-efgh-ijkl-123456789012\", "
                "\"displayName\": \"deploy-sp-prod\"}' | Set-Content \"$sharePath\\azure-sp-creds.json\"; "
                "'AZURE_CLIENT_ID=a1b2c3d4-e5f6-7890-abcd-ef1234567890\n"
                "AZURE_CLIENT_SECRET=Az~FAKE_SP_SECRET_DO_NOT_USE_12345\n"
                "AZURE_TENANT_ID=12345678-abcd-efgh-ijkl-123456789012\n' "
                "| Set-Content \"$sharePath\\.env\""
            ),
        })

    # ─── Lateral Movement ───
    elif vuln_name == "psremoting_open":
        tasks.append({
            "name": f"[{machine_label}] Enable PSRemoting for domain users",
            "ansible.windows.win_shell": (
                "Enable-PSRemoting -Force -SkipNetworkProfileCheck; "
                "Set-PSSessionConfiguration -Name Microsoft.PowerShell "
                "-SecurityDescriptorSddl 'O:NSG:BAD:P(A;;GA;;;DU)S:P(AU;FA;GA;;;WD)(AU;SA;GXGW;;;WD)' -Force"
            ),
        })

    elif vuln_name == "mssql_impersonation":
        tasks.append({
            "name": f"[{machine_label}] Set up MSSQL impersonation chain",
            "ansible.windows.win_shell": (
                "$q = @\"\n"
                "USE master;\n"
                "CREATE LOGIN [svc_web] WITH PASSWORD = 'Web2026!';\n"
                "GRANT IMPERSONATE ON LOGIN::[sa] TO [svc_web];\n"
                "CREATE LOGIN [svc_app] WITH PASSWORD = 'App2026!';\n"
                "GRANT IMPERSONATE ON LOGIN::[svc_web] TO [svc_app];\n"
                "\"@\n"
                "Invoke-Sqlcmd -Query $q -ServerInstance 'localhost' -ErrorAction SilentlyContinue"
            ),
        })

    # ─── Privilege Escalation ───
    elif vuln_name == "print_spooler_on_dc":
        tasks.append({
            "name": f"[{machine_label}] Ensure Print Spooler is running on DC",
            "ansible.windows.win_service": {
                "name": "Spooler",
                "state": "started",
                "start_mode": "auto",
            },
        })

    elif vuln_name == "webdav_enabled":
        tasks.append({
            "name": f"[{machine_label}] Install and enable WebDAV",
            "ansible.windows.win_shell": (
                "Install-WindowsFeature Web-DAV-Publishing -ErrorAction SilentlyContinue; "
                "Enable-WebDavPublishing -Force -ErrorAction SilentlyContinue"
            ),
        })

    elif vuln_name == "dnsadmins_abuse":
        tasks.append({
            "name": f"[{machine_label}] Add user to DnsAdmins",
            "ansible.windows.win_shell": (
                "$user = Get-ADUser -Filter \"SamAccountName -eq 'svc_dns'\" -ErrorAction SilentlyContinue; "
                "if (-not $user) { New-ADUser -Name 'svc_dns' -SamAccountName 'svc_dns' "
                "-AccountPassword (ConvertTo-SecureString 'Dns2026!' -AsPlainText -Force) -Enabled $true }; "
                "Add-ADGroupMember -Identity 'DnsAdmins' -Members 'svc_dns' -ErrorAction SilentlyContinue"
            ),
        })

    elif vuln_name == "adminsdh_backdoor":
        tasks.append({
            "name": f"[{machine_label}] Modify AdminSDHolder for persistence",
            "ansible.windows.win_shell": (
                "$domainDN = (Get-ADDomain).DistinguishedName; "
                "$adminSDH = \"CN=AdminSDHolder,CN=System,$domainDN\"; "
                "$user = Get-ADUser -Filter \"SamAccountName -eq 'svc_audit'\" -ErrorAction SilentlyContinue; "
                "if (-not $user) { New-ADUser -Name 'svc_audit' -SamAccountName 'svc_audit' "
                "-AccountPassword (ConvertTo-SecureString 'Aud1t!2026' -AsPlainText -Force) -Enabled $true }; "
                "$sid = (Get-ADUser 'svc_audit').SID; "
                "$acl = Get-Acl \"AD:\\$adminSDH\"; "
                "$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule("
                "$sid, 'GenericAll', 'Allow'); "
                "$acl.AddAccessRule($ace); Set-Acl \"AD:\\$adminSDH\" $acl; "
                "Write-Host 'AdminSDHolder backdoor set — will propagate within 60 minutes'"
            ),
        })

    return tasks
