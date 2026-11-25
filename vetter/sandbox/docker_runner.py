"""Docker-backed MCP sandbox launcher."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from vetter.config import BASE_DIR
from vetter.mcp_client import ToolInfo
from vetter.registry import ServerEntry
from vetter.sandbox.runner import SandboxReport, run_sandbox


def docker_available() -> bool:
    return shutil.which("docker") is not None and subprocess.run(
        ["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False
    ).returncode == 0


async def run_docker_sandbox(entry: ServerEntry, tools: list[ToolInfo]) -> SandboxReport:
    """Run the server command in a disposable, isolated container.

    The base image follows the detected runtime. Docker's internal network
    blocks direct egress; HTTP proxy configuration points at Vetter's logger.
    """
    image = "node:20-slim" if entry.language == "node" else "python:3.12-slim"
    network = f"vetter-{uuid.uuid4().hex[:10]}"
    with tempfile.TemporaryDirectory(prefix="vetter-docker-") as tmp:
        dockerfile = Path(tmp) / "Dockerfile"
        dockerfile.write_text(f"FROM {image}\nRUN apt-get update && apt-get install -y --no-install-recommends strace && rm -rf /var/lib/apt/lists/*\n")
        tag = f"vetter-sandbox:{uuid.uuid4().hex[:10]}"
        for args in (["docker", "build", "-t", tag, tmp], ["docker", "network", "create", "--internal", network]):
            result = subprocess.run(args, capture_output=True, text=True, timeout=180, check=False)
            if result.returncode:
                return SandboxReport(error=f"Docker sandbox setup failed: {result.stderr[-1000:]}", sandbox_mode="docker")
        command = [
            "docker", "run", "--rm", "-i", "--network", network,
            "--mount", f"type=bind,src={BASE_DIR},dst=/vetter,readonly",
            "--add-host", "host.docker.internal:host-gateway",
            "--mount", "type=bind,src={HOME},dst=/tmp/vetter-home,readonly",
            "--mount", "type=bind,src={AUDIT},dst=/tmp/vetter-audit.ndjson",
            "-w", "/vetter", "-e", "HOME=/tmp/vetter-home", "-e", "VETTER_AUDIT_LOG=/tmp/vetter-audit.ndjson",
            "-e", "PYTHONPATH=/vetter", "-e", "HTTP_PROXY={PROXY}", "-e", "HTTPS_PROXY={PROXY}",
            "-e", "http_proxy={PROXY}", "-e", "https_proxy={PROXY}", "-e", "NO_PROXY=", "-e", "no_proxy=",
            tag, "strace", "-f", "-e", "trace=file,network", *entry.command,
        ]
        try:
            return await run_sandbox(entry, tools, command=command, mode="docker")
        finally:
            subprocess.run(["docker", "network", "rm", network], capture_output=True, check=False)
