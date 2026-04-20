"""Docker container and image operations."""

import re
from dataclasses import dataclass
from typing import AsyncGenerator

from .shell import run_cmd, stream_cmd

_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")


def _valid_name(name: str) -> bool:
    return bool(name) and len(name) <= 128 and _NAME_RE.match(name) is not None


@dataclass
class ContainerInfo:
    name: str
    status: str
    image: str
    ports: str
    healthy: bool


@dataclass
class ImageInfo:
    repository: str
    tag: str
    image_id: str
    size: str
    created: str


async def list_containers(prefix: str = "ia-") -> list[ContainerInfo]:
    rc, out, _ = await run_cmd([
        "docker", "ps", "-a",
        "--filter", f"name={prefix}",
        "--format", "{{.Names}}\t{{.Status}}\t{{.Image}}\t{{.Ports}}",
    ])
    if rc != 0:
        return []
    result = []
    for line in out.strip().splitlines():
        if not line.strip():
            continue
        p = line.split("\t")
        status = p[1] if len(p) > 1 else ""
        result.append(ContainerInfo(
            name=p[0],
            status=status,
            image=p[2] if len(p) > 2 else "",
            ports=p[3] if len(p) > 3 else "",
            healthy="healthy" in status.lower() or ("up" in status.lower() and "unhealthy" not in status.lower()),
        ))
    return result


async def list_images() -> list[ImageInfo]:
    rc, out, _ = await run_cmd([
        "docker", "images",
        "--format", "{{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Size}}\t{{.CreatedSince}}",
    ])
    if rc != 0:
        return []
    keep = ("ia-pentest", "docker-mcp", "docker-agent", "goadansible")
    result = []
    for line in out.strip().splitlines():
        p = line.split("\t")
        repo = p[0] if p else ""
        if not any(k in repo for k in keep):
            continue
        result.append(ImageInfo(
            repository=repo,
            tag=p[1] if len(p) > 1 else "",
            image_id=p[2] if len(p) > 2 else "",
            size=p[3] if len(p) > 3 else "",
            created=p[4] if len(p) > 4 else "",
        ))
    return result


async def container_action(name: str, action: str) -> tuple[bool, str]:
    if not _valid_name(name):
        return False, "Invalid container name"
    if action not in ("start", "stop", "restart"):
        return False, f"Unknown action: {action}"
    rc, out, err = await run_cmd(["docker", action, name], timeout=60)
    return rc == 0, (out + err).strip() or ("OK" if rc == 0 else "Failed")


async def get_logs(name: str, tail: int = 200) -> str:
    if not _valid_name(name):
        return "Invalid container name"
    tail = min(max(tail, 10), 5000)
    rc, out, err = await run_cmd(["docker", "logs", name, "--tail", str(tail)], timeout=15)
    return out + err


async def stream_build(dockerfile: str, context: str) -> AsyncGenerator[str, None]:
    async for line in stream_cmd([
        "docker", "build", "--no-cache",
        "-t", "ia-pentest-sandbox:latest",
        "-f", dockerfile, context,
    ]):
        yield line


async def compose_up(compose_file: str, env: dict[str, str]) -> AsyncGenerator[str, None]:
    import os
    full_env = {**os.environ, **env}
    proc_env_args = []
    for k, v in env.items():
        proc_env_args.extend(["-e", f"{k}={v}"])

    async for line in stream_cmd([
        "docker", "compose", "-f", compose_file, "up", "-d", "--build",
    ]):
        yield line
