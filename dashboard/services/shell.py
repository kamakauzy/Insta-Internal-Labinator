"""Safe subprocess execution — never uses shell=True."""

import asyncio
import subprocess
from typing import AsyncGenerator


async def run_cmd(args: list[str], timeout: int = 60) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return -1, "", "Command timed out"
    return proc.returncode or 0, stdout.decode(errors="replace"), stderr.decode(errors="replace")


async def run_ps(script: str, timeout: int = 60) -> tuple[int, str, str]:
    return await run_cmd([
        "powershell.exe", "-NoProfile", "-NonInteractive",
        "-ExecutionPolicy", "Bypass", "-Command", script,
    ], timeout=timeout)


async def stream_cmd(args: list[str]) -> AsyncGenerator[str, None]:
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    async for line in proc.stdout:
        yield line.decode(errors="replace")
    await proc.wait()


def run_cmd_sync(args: list[str], timeout: int = 30) -> tuple[int, str, str]:
    try:
        r = subprocess.run(args, capture_output=True, timeout=timeout, text=True)
        return r.returncode or 0, r.stdout, r.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return -1, "", str(e)
