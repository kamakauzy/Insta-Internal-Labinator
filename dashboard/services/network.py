"""Network interface and firewall operations."""

import re
from dataclasses import dataclass

from .shell import run_ps

_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_ALIAS_RE = re.compile(r"^[a-zA-Z0-9 _\-().]+$")
_RULE_NAME_RE = re.compile(r"^[a-zA-Z0-9 _\-]+$")


def _valid_ip(ip: str) -> bool:
    if not _IP_RE.match(ip):
        return False
    return all(0 <= int(o) <= 255 for o in ip.split("."))


@dataclass
class InterfaceInfo:
    alias: str
    ip_address: str
    prefix_length: int
    status: str


@dataclass
class FirewallRule:
    name: str
    direction: str
    action: str
    protocol: str
    local_port: str
    remote_address: str
    enabled: bool


async def list_interfaces() -> list[InterfaceInfo]:
    rc, out, _ = await run_ps(
        "Get-NetIPAddress -AddressFamily IPv4 | "
        "Where-Object { $_.InterfaceAlias -like 'VMware*' -or $_.InterfaceAlias -like 'Ethernet*' -or $_.InterfaceAlias -like 'vEthernet*' } | "
        "Select-Object InterfaceAlias, IPAddress, PrefixLength | "
        "ForEach-Object { \"$($_.InterfaceAlias)`t$($_.IPAddress)`t$($_.PrefixLength)\" }"
    )
    if rc != 0:
        return []
    result = []
    for line in out.strip().splitlines():
        p = line.split("\t")
        if len(p) < 3:
            continue
        result.append(InterfaceInfo(
            alias=p[0].strip(),
            ip_address=p[1].strip(),
            prefix_length=int(p[2].strip()) if p[2].strip().isdigit() else 24,
            status="Up",
        ))
    return result


async def configure_interface(alias: str, ip: str, prefix: int = 24) -> tuple[bool, str]:
    if not _ALIAS_RE.match(alias) or len(alias) > 100:
        return False, "Invalid interface alias"
    if not _valid_ip(ip):
        return False, "Invalid IP address"
    if not (8 <= prefix <= 32):
        return False, "Invalid prefix length"

    script = (
        f"$a = '{alias}'; $ip = '{ip}'; $p = {prefix}; "
        "try { Remove-NetIPAddress -InterfaceAlias $a -Confirm:$false -ErrorAction SilentlyContinue } catch {{}}; "
        "New-NetIPAddress -InterfaceAlias $a -IPAddress $ip -PrefixLength $p -ErrorAction Stop | Out-Null; "
        "Write-Output 'OK'"
    )
    rc, out, err = await run_ps(script, timeout=15)
    return "OK" in out, (out + err).strip()


async def list_firewall_rules() -> list[FirewallRule]:
    rc, out, _ = await run_ps(
        "Get-NetFirewallRule | Where-Object { $_.DisplayName -like 'Lab*' -or $_.DisplayName -like 'GOAD*' -or $_.DisplayName -like 'VMnet*' } | "
        "ForEach-Object { "
        "  $pf = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue; "
        "  $af = $_ | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue; "
        "  \"$($_.DisplayName)`t$($_.Direction)`t$($_.Action)`t$($pf.Protocol)`t$($pf.LocalPort)`t$($af.RemoteAddress)`t$($_.Enabled)\" "
        "}"
    )
    if rc != 0:
        return []
    result = []
    for line in out.strip().splitlines():
        p = line.split("\t")
        if len(p) < 7:
            continue
        result.append(FirewallRule(
            name=p[0].strip(),
            direction=p[1].strip(),
            action=p[2].strip(),
            protocol=p[3].strip(),
            local_port=p[4].strip(),
            remote_address=p[5].strip(),
            enabled=p[6].strip().lower() == "true",
        ))
    return result


async def add_firewall_rule(name: str, direction: str, protocol: str,
                            local_port: str, remote_address: str,
                            action: str = "Allow") -> tuple[bool, str]:
    if not _RULE_NAME_RE.match(name) or len(name) > 100:
        return False, "Invalid rule name"
    if direction not in ("Inbound", "Outbound"):
        return False, "Direction must be Inbound or Outbound"
    if protocol not in ("TCP", "UDP", "Any"):
        return False, "Protocol must be TCP, UDP, or Any"
    if action not in ("Allow", "Block"):
        return False, "Action must be Allow or Block"
    if local_port and not re.match(r"^\d{1,5}(-\d{1,5})?$", local_port):
        return False, "Invalid port format"
    if remote_address and not _valid_ip(remote_address) and remote_address != "Any":
        return False, "Invalid remote address"

    port_param = f"-LocalPort '{local_port}'" if local_port else ""
    addr_param = f"-RemoteAddress '{remote_address}'" if remote_address and remote_address != "Any" else ""
    proto_param = f"-Protocol {protocol}" if protocol != "Any" else ""

    script = (
        f"New-NetFirewallRule -DisplayName '{name}' -Direction {direction} "
        f"-Action {action} {proto_param} {port_param} {addr_param} "
        "-ErrorAction Stop | Out-Null; Write-Output 'OK'"
    )
    rc, out, err = await run_ps(script, timeout=15)
    return "OK" in out, (out + err).strip()


async def remove_firewall_rule(name: str) -> tuple[bool, str]:
    if not _RULE_NAME_RE.match(name) or len(name) > 100:
        return False, "Invalid rule name"
    script = f"Remove-NetFirewallRule -DisplayName '{name}' -ErrorAction Stop; Write-Output 'OK'"
    rc, out, err = await run_ps(script, timeout=15)
    return "OK" in out, (out + err).strip()


async def check_connectivity(ip: str, port: int = 5986) -> bool:
    if not _valid_ip(ip):
        return False
    if not (1 <= port <= 65535):
        return False
    script = (
        f"$t = New-Object System.Net.Sockets.TcpClient; "
        f"try {{ $t.Connect('{ip}', {port}); $t.Close(); 'OK' }} catch {{ 'FAIL' }}"
    )
    rc, out, _ = await run_ps(script, timeout=5)
    return "OK" in out
