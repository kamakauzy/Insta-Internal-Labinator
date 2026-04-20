"""API route handlers."""

import asyncio
import base64
import json
import os
import time
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect, Query
from pydantic import BaseModel

from .services import vmware, docker_ops, network
from .services.shell import stream_cmd
from .services.scenarios import (
    load_catalog, list_scenarios, load_scenario, save_scenario,
    delete_scenario, validate_scenario, generate_playbook,
)

router = APIRouter(prefix="/api")

# ── Helpers ──────────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).parent.parent
GOAD_WORKSPACE = BASE_DIR / "GOAD" / "workspace"
AGENT_DIR = BASE_DIR / "internal-inator" / "ia-pentestagent"
SANDBOX_DOCKERFILE = str(AGENT_DIR / "docker" / "Dockerfile.sandbox")
AGENT_COMPOSE = str(AGENT_DIR / "docker" / "docker-compose.agent.yml")


def _enc(path: str) -> str:
    return base64.urlsafe_b64encode(path.encode()).decode().rstrip("=")


def _dec(encoded: str) -> str:
    padded = encoded + "=" * (-len(encoded) % 4)
    return base64.urlsafe_b64decode(padded).decode()


# ── Overview ─────────────────────────────────────────────────────────────────

@router.get("/overview")
async def overview():
    vms_task = vmware.list_vms(GOAD_WORKSPACE)
    containers_task = docker_ops.list_containers()
    interfaces_task = network.list_interfaces()

    vms, containers, interfaces = await asyncio.gather(
        vms_task, containers_task, interfaces_task
    )

    vmnet2 = next((i for i in interfaces if "VMnet2" in i.alias), None)
    connectivity = {}
    if vmnet2:
        checks = {name: network.check_connectivity(meta["ip"])
                  for name, meta in vmware.VM_META.items()}
        results = await asyncio.gather(*checks.values())
        connectivity = dict(zip(checks.keys(), results))

    return {
        "vms": [{
            "id": _enc(v.vmx_path), "name": v.name, "running": v.running,
            "ip": v.ip, "hostname": v.hostname, "domain": v.domain, "role": v.role,
            "reachable": connectivity.get(v.name),
        } for v in vms],
        "containers": [{
            "name": c.name, "status": c.status, "image": c.image,
            "ports": c.ports, "healthy": c.healthy,
        } for c in containers],
        "network": {
            "vmnet2": {"ip": vmnet2.ip_address, "prefix": vmnet2.prefix_length} if vmnet2 else None,
            "interfaces": [{"alias": i.alias, "ip": i.ip_address, "prefix": i.prefix_length} for i in interfaces],
        },
    }


# ── Virtual Machines ─────────────────────────────────────────────────────────

@router.get("/vms")
async def get_vms():
    vms = await vmware.list_vms(GOAD_WORKSPACE)
    result = []
    for v in vms:
        snaps = await vmware.get_snapshots(v.vmx_path)
        result.append({
            "id": _enc(v.vmx_path), "name": v.name, "running": v.running,
            "ip": v.ip, "hostname": v.hostname, "domain": v.domain,
            "role": v.role, "snapshots": snaps,
        })
    return result


class VMActionReq(BaseModel):
    vm_id: str
    action: Literal["start", "stop", "stop_hard", "suspend", "reset"]


@router.post("/vms/action")
async def do_vm_action(req: VMActionReq):
    vmx = _dec(req.vm_id)
    ok, msg = await vmware.vm_action(vmx, req.action)
    if not ok:
        raise HTTPException(500, msg)
    return {"ok": True, "message": msg}


class SnapshotReq(BaseModel):
    vm_id: str
    action: Literal["create", "revert", "delete"]
    name: str


@router.post("/vms/snapshots")
async def do_snapshot(req: SnapshotReq):
    vmx = _dec(req.vm_id)
    ok, msg = await vmware.snapshot_action(vmx, req.action, req.name)
    if not ok:
        raise HTTPException(500, msg)
    return {"ok": True, "message": msg}


@router.post("/vms/start-all")
async def start_all_vms():
    vms = await vmware.list_vms(GOAD_WORKSPACE)
    results = []
    for v in vms:
        if not v.running:
            ok, msg = await vmware.vm_action(v.vmx_path, "start")
            results.append({"name": v.name, "ok": ok, "message": msg})
    return results


@router.post("/vms/stop-all")
async def stop_all_vms():
    vms = await vmware.list_vms(GOAD_WORKSPACE)
    results = []
    for v in vms:
        if v.running:
            ok, msg = await vmware.vm_action(v.vmx_path, "stop")
            results.append({"name": v.name, "ok": ok, "message": msg})
    return results


# ── Docker Containers ────────────────────────────────────────────────────────

@router.get("/containers")
async def get_containers():
    containers = await docker_ops.list_containers()
    images = await docker_ops.list_images()
    return {
        "containers": [{"name": c.name, "status": c.status, "image": c.image,
                         "ports": c.ports, "healthy": c.healthy} for c in containers],
        "images": [{"repository": i.repository, "tag": i.tag, "id": i.image_id,
                     "size": i.size, "created": i.created} for i in images],
    }


class ContainerActionReq(BaseModel):
    name: str
    action: Literal["start", "stop", "restart"]


@router.post("/containers/action")
async def do_container_action(req: ContainerActionReq):
    ok, msg = await docker_ops.container_action(req.name, req.action)
    if not ok:
        raise HTTPException(500, msg)
    return {"ok": True, "message": msg}


@router.get("/containers/logs/{name}")
async def get_container_logs(name: str, tail: int = 200):
    logs = await docker_ops.get_logs(name, tail)
    return {"name": name, "logs": logs}


# ── Network ──────────────────────────────────────────────────────────────────

@router.get("/network/interfaces")
async def get_interfaces():
    return [{"alias": i.alias, "ip": i.ip_address, "prefix": i.prefix_length}
            for i in await network.list_interfaces()]


class InterfaceConfigReq(BaseModel):
    alias: str
    ip_address: str
    prefix_length: int = 24


@router.post("/network/interfaces")
async def configure_interface(req: InterfaceConfigReq):
    ok, msg = await network.configure_interface(req.alias, req.ip_address, req.prefix_length)
    if not ok:
        raise HTTPException(500, msg)
    return {"ok": True, "message": msg}


@router.get("/network/firewall")
async def get_firewall():
    rules = await network.list_firewall_rules()
    return [{"name": r.name, "direction": r.direction, "action": r.action,
             "protocol": r.protocol, "local_port": r.local_port,
             "remote_address": r.remote_address, "enabled": r.enabled} for r in rules]


class FirewallAddReq(BaseModel):
    name: str
    direction: Literal["Inbound", "Outbound"] = "Inbound"
    protocol: Literal["TCP", "UDP", "Any"] = "TCP"
    local_port: str = ""
    remote_address: str = ""
    action: Literal["Allow", "Block"] = "Allow"


@router.post("/network/firewall")
async def add_firewall(req: FirewallAddReq):
    ok, msg = await network.add_firewall_rule(
        req.name, req.direction, req.protocol,
        req.local_port, req.remote_address, req.action,
    )
    if not ok:
        raise HTTPException(500, msg)
    return {"ok": True, "message": msg}


@router.delete("/network/firewall/{name}")
async def delete_firewall(name: str):
    ok, msg = await network.remove_firewall_rule(name)
    if not ok:
        raise HTTPException(500, msg)
    return {"ok": True, "message": msg}


# ── Lab Deployment ───────────────────────────────────────────────────────────

@router.get("/lab/handoffs")
async def list_handoffs():
    handoff_dir = BASE_DIR
    handoffs = []
    for d in sorted(handoff_dir.glob("RedTeam-Handoff-*")):
        if d.is_dir():
            files = [f.name for f in d.iterdir() if f.is_file()]
            handoffs.append({"name": d.name, "files": files})
    return handoffs


# ── AD Expansion ─────────────────────────────────────────────────────────────

_GOAD_INSTANCE = "c6bbf6-goad-light-vmware"
_GOAD_DIR = GOAD_WORKSPACE / _GOAD_INSTANCE
_AD_STATE_FILE = _GOAD_DIR / "ad_expansion_state.json"

# Shared state for long-running jobs
_ad_expansion_running = False
_ad_expansion_output: list[str] = []
_lx01_provision_running = False
_lx01_provision_output: list[str] = []


@router.get("/lab/ad-expansion/status")
async def ad_expansion_status():
    state: dict = {"deployed": False, "last_run_at": None, "exit_code": None}
    if _AD_STATE_FILE.exists():
        try:
            state = json.loads(_AD_STATE_FILE.read_text())
        except Exception:
            pass
    return {
        **state,
        "running": _ad_expansion_running,
        "output_tail": _ad_expansion_output[-50:],
    }


@router.post("/lab/ad-expansion/deploy")
async def deploy_ad_expansion():
    global _ad_expansion_running
    if _ad_expansion_running:
        raise HTTPException(409, "AD expansion already running")
    asyncio.create_task(_run_ad_expansion())
    return {"ok": True, "message": "AD expansion deployment started — connect to /ws/ad-expansion for streaming output"}


async def _run_ad_expansion() -> None:
    global _ad_expansion_running, _ad_expansion_output
    _ad_expansion_running = True
    _ad_expansion_output = []
    goad_host_path = str(BASE_DIR / "GOAD").replace("\\", "/")
    inventory = f"/goad/workspace/{_GOAD_INSTANCE}/inventory_disable_vagrant"
    playbook = f"/goad/workspace/{_GOAD_INSTANCE}/run_expansion.yml"
    cmd = [
        "docker", "run", "--rm", "--network", "host", "-h", "goadansible",
        "-v", f"{goad_host_path}:/goad",
        "-w", "/goad/ansible",
        "goadansible",
        "/bin/bash", "-c",
        f"ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i {inventory} {playbook}",
    ]
    exit_code = -1
    try:
        async for line in stream_cmd(cmd):
            _ad_expansion_output.append(line)
        exit_code = 0
    except Exception as exc:
        _ad_expansion_output.append(f"ERROR: {exc}")
    finally:
        _ad_expansion_running = False
        _AD_STATE_FILE.write_text(json.dumps({
            "deployed": exit_code == 0,
            "last_run_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "exit_code": exit_code,
        }))


# ── LX01 Extension Provisioning ───────────────────────────────────────────────

@router.post("/lab/extensions/lx01/provision")
async def provision_lx01():
    global _lx01_provision_running
    if _lx01_provision_running:
        raise HTTPException(409, "LX01 provisioning already running")
    asyncio.create_task(_run_lx01_provision())
    return {"ok": True, "message": "LX01 provisioning started — connect to /ws/lx01-provision for streaming output"}


@router.get("/lab/extensions/lx01/status")
async def lx01_status():
    lx01_meta = vmware.VM_META.get("GOAD-Light-LX01", {})
    reachable = await network.check_connectivity(lx01_meta.get("ip", ""))
    return {
        "vm": lx01_meta,
        "reachable": reachable,
        "provisioning_running": _lx01_provision_running,
        "output_tail": _lx01_provision_output[-50:],
    }


async def _run_lx01_provision() -> None:
    global _lx01_provision_running, _lx01_provision_output
    _lx01_provision_running = True
    _lx01_provision_output = []
    goad_host_path = str(BASE_DIR / "GOAD").replace("\\", "/")
    key_path = f"/goad/workspace/{_GOAD_INSTANCE}/provider/.vagrant/machines/GOAD-Light-LX01/vmware_desktop/private_key"
    inventory = f"/goad/workspace/{_GOAD_INSTANCE}/lx01_inventory"
    playbook = f"/goad/workspace/{_GOAD_INSTANCE}/lx01_direct_provision.yml"
    bash_cmd = (
        f"cp {key_path} /tmp/lx01_key && chmod 600 /tmp/lx01_key && "
        f"ANSIBLE_ROLES_PATH=/goad/extensions/lx01/ansible/roles:/goad/ansible/roles "
        f"ANSIBLE_HOST_KEY_CHECKING=False "
        f"ansible-playbook -i {inventory} {playbook}"
    )
    cmd = [
        "docker", "run", "--rm", "--network", "host", "-h", "goadansible",
        "-v", f"{goad_host_path}:/goad",
        "-w", "/goad/ansible",
        "goadansible",
        "/bin/bash", "-c", bash_cmd,
    ]
    try:
        async for line in stream_cmd(cmd):
            _lx01_provision_output.append(line)
    except Exception as exc:
        _lx01_provision_output.append(f"ERROR: {exc}")
    finally:
        _lx01_provision_running = False


# ── Lab Scenarios (Scenario Designer) ────────────────────────────────────────

@router.get("/scenarios/catalog")
async def get_catalog():
    """Return the full vulnerability/service catalog for the UI."""
    return load_catalog()


@router.get("/scenarios")
async def get_scenarios():
    """List all saved scenarios."""
    return list_scenarios()


@router.get("/scenarios/{scenario_id}")
async def get_scenario(scenario_id: str):
    """Load a single scenario."""
    try:
        return load_scenario(scenario_id)
    except FileNotFoundError:
        raise HTTPException(404, f"Scenario '{scenario_id}' not found")


class ScenarioSaveReq(BaseModel):
    scenario: dict
    scenario_id: str | None = None


@router.post("/scenarios")
async def create_or_update_scenario(req: ScenarioSaveReq):
    """Save a scenario (create or update)."""
    catalog = load_catalog()
    errors = validate_scenario(req.scenario, catalog)
    if errors:
        raise HTTPException(422, {"errors": errors})
    sid = save_scenario(req.scenario, req.scenario_id)
    return {"ok": True, "scenario_id": sid}


@router.delete("/scenarios/{scenario_id}")
async def remove_scenario(scenario_id: str):
    """Delete a user-created scenario."""
    if delete_scenario(scenario_id):
        return {"ok": True}
    raise HTTPException(404, f"Scenario '{scenario_id}' not found")


@router.post("/scenarios/{scenario_id}/validate")
async def validate_scenario_endpoint(scenario_id: str):
    """Validate a scenario and return errors."""
    try:
        scenario = load_scenario(scenario_id)
    except FileNotFoundError:
        raise HTTPException(404, f"Scenario '{scenario_id}' not found")
    catalog = load_catalog()
    errors = validate_scenario(scenario, catalog)
    return {"valid": len(errors) == 0, "errors": errors}


@router.post("/scenarios/{scenario_id}/preview")
async def preview_playbook(scenario_id: str):
    """Generate and preview the Ansible playbook without deploying."""
    try:
        scenario = load_scenario(scenario_id)
    except FileNotFoundError:
        raise HTTPException(404, f"Scenario '{scenario_id}' not found")
    catalog = load_catalog()
    try:
        result = generate_playbook(scenario, catalog)
    except ValueError as e:
        raise HTTPException(422, str(e))
    return result


@router.post("/scenarios/preview-inline")
async def preview_playbook_inline(body: dict):
    """Generate preview from an inline scenario (not saved)."""
    catalog = load_catalog()
    try:
        result = generate_playbook(body, catalog)
    except ValueError as e:
        raise HTTPException(422, str(e))
    return result


# Scenario deployment state
_scenario_deploy_running = False
_scenario_deploy_output: list[str] = []


@router.get("/scenarios/deploy/status")
async def scenario_deploy_status():
    return {
        "running": _scenario_deploy_running,
        "output_tail": _scenario_deploy_output[-100:],
    }


@router.post("/scenarios/{scenario_id}/deploy")
async def deploy_scenario(scenario_id: str):
    """Deploy a scenario to the GOAD lab via Ansible."""
    global _scenario_deploy_running
    if _scenario_deploy_running:
        raise HTTPException(409, "A scenario deployment is already running")
    try:
        scenario = load_scenario(scenario_id)
    except FileNotFoundError:
        raise HTTPException(404, f"Scenario '{scenario_id}' not found")

    catalog = load_catalog()
    try:
        result = generate_playbook(scenario, catalog)
    except ValueError as e:
        raise HTTPException(422, str(e))

    asyncio.create_task(_run_scenario_deploy(scenario_id, result))
    return {"ok": True, "message": f"Deploying scenario '{scenario['name']}' — connect to /ws/scenario-deploy"}


async def _run_scenario_deploy(scenario_id: str, playbook_result: dict) -> None:
    """Execute the generated Ansible playbook against the GOAD lab."""
    global _scenario_deploy_running, _scenario_deploy_output
    _scenario_deploy_running = True
    _scenario_deploy_output = []

    goad_host_path = str(BASE_DIR / "GOAD").replace("\\", "/")
    workspace_path = f"/goad/workspace/{_GOAD_INSTANCE}"

    # Write playbook and inventory to the GOAD workspace
    playbook_file = _GOAD_DIR / f"scenario_{scenario_id}.yml"
    playbook_file.write_text(playbook_result["playbook"], encoding="utf-8")

    inventory = f"{workspace_path}/inventory_disable_vagrant"
    playbook = f"{workspace_path}/scenario_{scenario_id}.yml"

    cmd = [
        "docker", "run", "--rm", "--network", "host", "-h", "goadansible",
        "-v", f"{goad_host_path}:/goad",
        "-w", "/goad/ansible",
        "goadansible",
        "/bin/bash", "-c",
        f"ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i {inventory} {playbook} -v",
    ]

    _scenario_deploy_output.append(f"=== Deploying scenario: {scenario_id} ===")
    _scenario_deploy_output.append(playbook_result["summary"])
    _scenario_deploy_output.append("")

    try:
        async for line in stream_cmd(cmd):
            _scenario_deploy_output.append(line)
        _scenario_deploy_output.append("\n=== Scenario deployment complete ===")
    except Exception as exc:
        _scenario_deploy_output.append(f"ERROR: {exc}")
    finally:
        _scenario_deploy_running = False


async def ws_scenario_deploy(websocket: WebSocket, token: str):
    """Stream scenario deployment output via WebSocket."""
    from .main import AUTH_TOKEN

    if token != AUTH_TOKEN:
        await websocket.close(code=4001)
        return

    await websocket.accept()
    last_idx = 0
    try:
        while True:
            if last_idx < len(_scenario_deploy_output):
                for line in _scenario_deploy_output[last_idx:]:
                    await websocket.send_json({"type": "output", "data": line})
                last_idx = len(_scenario_deploy_output)

            if not _scenario_deploy_running and last_idx >= len(_scenario_deploy_output):
                await websocket.send_json({"type": "status", "data": "complete"})
                break

            await asyncio.sleep(0.3)
    except WebSocketDisconnect:
        pass


# ── WebSocket Endpoints ──────────────────────────────────────────────────────

# Build state
_build_running = False
_build_output: list[str] = []


@router.get("/build/status")
async def build_status():
    return {"running": _build_running, "output": _build_output[-200:]}


async def ws_build(websocket: WebSocket, token: str):
    """Stream sandbox build output via WebSocket."""
    global _build_running, _build_output
    from .main import AUTH_TOKEN

    if token != AUTH_TOKEN:
        await websocket.close(code=4001)
        return

    await websocket.accept()

    if _build_running:
        await websocket.send_json({"type": "error", "data": "Build already in progress"})
        await websocket.close()
        return

    _build_running = True
    _build_output = []

    try:
        await websocket.send_json({"type": "status", "data": "Build started"})
        async for line in docker_ops.stream_build(SANDBOX_DOCKERFILE, str(AGENT_DIR)):
            _build_output.append(line)
            await websocket.send_json({"type": "output", "data": line})
        await websocket.send_json({"type": "status", "data": "Build complete"})
    except WebSocketDisconnect:
        pass
    except Exception as e:
        await websocket.send_json({"type": "error", "data": str(e)})
    finally:
        _build_running = False


async def ws_logs(websocket: WebSocket, name: str, token: str):
    """Stream container logs via WebSocket."""
    from .main import AUTH_TOKEN

    if token != AUTH_TOKEN:
        await websocket.close(code=4001)
        return

    await websocket.accept()
    try:
        while True:
            logs = await docker_ops.get_logs(name, 50)
            await websocket.send_json({"type": "logs", "data": logs})
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        pass


async def ws_ad_expansion(websocket: WebSocket, token: str):
    """Stream AD expansion deployment output via WebSocket."""
    from .main import AUTH_TOKEN

    if token != AUTH_TOKEN:
        await websocket.close(code=4001)
        return

    await websocket.accept()
    sent = 0
    try:
        while True:
            new_lines = _ad_expansion_output[sent:]
            for line in new_lines:
                await websocket.send_json({"type": "output", "data": line})
                sent += 1
            if not _ad_expansion_running and sent >= len(_ad_expansion_output):
                await websocket.send_json({"type": "status", "data": "done"})
                break
            await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        pass


async def ws_lx01_provision(websocket: WebSocket, token: str):
    """Stream LX01 provisioning output via WebSocket."""
    from .main import AUTH_TOKEN

    if token != AUTH_TOKEN:
        await websocket.close(code=4001)
        return

    await websocket.accept()
    sent = 0
    try:
        while True:
            new_lines = _lx01_provision_output[sent:]
            for line in new_lines:
                await websocket.send_json({"type": "output", "data": line})
                sent += 1
            if not _lx01_provision_running and sent >= len(_lx01_provision_output):
                await websocket.send_json({"type": "status", "data": "done"})
                break
            await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        pass
