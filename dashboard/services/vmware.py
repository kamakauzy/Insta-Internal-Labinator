"""VMware Workstation operations via vmrun.exe."""

import os
import re
import shutil
from pathlib import Path
from dataclasses import dataclass, field

from .shell import run_cmd

VM_META = {
    "GOAD-Light-DC01":  {"hostname": "kingslanding",  "domain": "sevenkingdoms.local",       "ip": "192.168.56.10", "role": "PDC, DNS, ADCS"},
    "GOAD-Light-DC02":  {"hostname": "winterfell",    "domain": "north.sevenkingdoms.local", "ip": "192.168.56.11", "role": "Child DC, DNS"},
    "GOAD-Light-SRV02": {"hostname": "castelblack",   "domain": "north.sevenkingdoms.local", "ip": "192.168.56.22", "role": "File/SQL/IIS"},
    "GOAD-Light-LX01":  {"hostname": "dragonstone",   "domain": "sevenkingdoms.local",       "ip": "192.168.56.32", "role": "Linux domain member, vuln web apps"},
}

_vmrun: str | None = None


def find_vmrun() -> str | None:
    global _vmrun
    if _vmrun:
        return _vmrun
    candidates = [
        os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
                     "VMware", "VMware Workstation", "vmrun.exe"),
        os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"),
                     "VMware", "VMware Workstation", "vmrun.exe"),
    ]
    for p in candidates:
        if os.path.isfile(p):
            _vmrun = p
            return _vmrun
    _vmrun = shutil.which("vmrun.exe")
    return _vmrun


def _name(vmx: str) -> str:
    if m := re.search(r"GOAD-Light-(\w+)", vmx):
        return f"GOAD-Light-{m.group(1)}"
    if "attacker" in vmx.lower():
        return "Attacker-VM"
    return Path(vmx).stem


@dataclass
class VMInfo:
    name: str
    vmx_path: str
    running: bool
    ip: str | None = None
    hostname: str | None = None
    domain: str | None = None
    role: str | None = None
    snapshots: list[str] = field(default_factory=list)


async def list_vms(workspace: Path) -> list[VMInfo]:
    vmrun = find_vmrun()
    if not vmrun:
        return []

    rc, out, _ = await run_cmd([vmrun, "list"])
    running = {l.strip() for l in out.splitlines() if l.strip().endswith(".vmx")} if rc == 0 else set()

    seen: dict[str, VMInfo] = {}

    if workspace.exists():
        for vmx in workspace.rglob("*.vmx"):
            s = str(vmx)
            name = _name(s)
            meta = VM_META.get(name, {})
            seen[s] = VMInfo(
                name=name, vmx_path=s, running=s in running,
                ip=meta.get("ip"), hostname=meta.get("hostname"),
                domain=meta.get("domain"), role=meta.get("role"),
            )

    for vmx in running:
        if vmx not in seen:
            name = _name(vmx)
            meta = VM_META.get(name, {})
            seen[vmx] = VMInfo(
                name=name, vmx_path=vmx, running=True,
                ip=meta.get("ip"), hostname=meta.get("hostname"),
                domain=meta.get("domain"), role=meta.get("role"),
            )

    return list(seen.values())


async def vm_action(vmx: str, action: str) -> tuple[bool, str]:
    vmrun = find_vmrun()
    if not vmrun:
        return False, "vmrun.exe not found"
    if not os.path.isfile(vmx):
        return False, "VMX file not found"

    cmds = {
        "start":     [vmrun, "start", vmx, "nogui"],
        "stop":      [vmrun, "stop", vmx, "soft"],
        "stop_hard": [vmrun, "stop", vmx, "hard"],
        "suspend":   [vmrun, "suspend", vmx],
        "reset":     [vmrun, "reset", vmx, "soft"],
    }
    args = cmds.get(action)
    if not args:
        return False, f"Unknown action: {action}"

    rc, out, err = await run_cmd(args, timeout=120)
    return rc == 0, (out + err).strip() or ("OK" if rc == 0 else "Failed")


async def get_snapshots(vmx: str) -> list[str]:
    vmrun = find_vmrun()
    if not vmrun or not os.path.isfile(vmx):
        return []
    rc, out, _ = await run_cmd([vmrun, "listSnapshots", vmx])
    if rc != 0:
        return []
    return [l.strip() for l in out.splitlines() if l.strip() and not l.startswith("Total")]


async def snapshot_action(vmx: str, action: str, name: str) -> tuple[bool, str]:
    vmrun = find_vmrun()
    if not vmrun or not os.path.isfile(vmx):
        return False, "VMX file not found"
    if not name or len(name) > 100:
        return False, "Invalid snapshot name"

    cmds = {
        "create": [vmrun, "snapshot", vmx, name],
        "revert": [vmrun, "revertToSnapshot", vmx, name],
        "delete": [vmrun, "deleteSnapshot", vmx, name],
    }
    args = cmds.get(action)
    if not args:
        return False, f"Unknown action: {action}"

    rc, out, err = await run_cmd(args, timeout=300)
    return rc == 0, (out + err).strip() or ("OK" if rc == 0 else "Failed")
