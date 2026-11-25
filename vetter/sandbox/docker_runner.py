"""Docker-backed MCP sandbox launcher."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import uuid
from functools import lru_cache
from pathlib import Path

from vetter.config import BASE_DIR
from vetter.mcp_client import ToolInfo
from vetter.registry import ServerEntry
from vetter.sandbox.runner import SandboxReport, run_sandbox


class DockerUnavailable(RuntimeError):
    """Docker cannot be reached or sandbox setup could not be completed."""


@lru_cache(maxsize=1)
def _docker_cli_env() -> dict[str, str]:
    """Use the host's Docker Desktop context, never the sandbox fake HOME."""
    env = dict(os.environ)
    if not env.get("DOCKER_HOST"):
        try:
            result = subprocess.run(
                ["docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
                env=env,
            )
            host = result.stdout.strip()
            if result.returncode == 0 and host:
                env["DOCKER_HOST"] = host
        except (OSError, subprocess.SubprocessError):
            pass
    return env


def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
            env=_docker_cli_env(),
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


async def run_docker_sandbox(entry: ServerEntry, tools: list[ToolInfo]) -> SandboxReport:
    """Run the server command in a disposable, isolated container.

    The base image follows the detected runtime. Docker's internal network
    blocks direct egress; HTTP proxy configuration points at Vetter's logger.
    """
    image = "node:20-slim" if entry.language == "node" else "python:3.12-slim"
    network = f"vetter-{uuid.uuid4().hex[:10]}"
    docker_env = _docker_cli_env()
    with tempfile.TemporaryDirectory(prefix="vetter-docker-") as tmp:
        proxy_script = Path(__file__).with_name("docker_proxy.py")
        Path(tmp, "docker_proxy.py").write_text(proxy_script.read_text())
        dockerfile = Path(tmp) / "Dockerfile"
        install_python_runtime_deps = "RUN pip install --no-cache-dir 'mcp>=1.9,<2' httpx\n" if entry.language == "python" else ""
        dockerfile.write_text(
            f"FROM {image}\n"
            "RUN apt-get update && apt-get install -y --no-install-recommends strace "
            "&& rm -rf /var/lib/apt/lists/*\n"
            f"{install_python_runtime_deps}COPY docker_proxy.py /docker_proxy.py\n"
        )
        tag = f"vetter-sandbox:{uuid.uuid4().hex[:10]}"
        for args in (["docker", "build", "-t", tag, tmp], ["docker", "network", "create", "--internal", network]):
            try:
                result = subprocess.run(args, capture_output=True, text=True, timeout=180, check=False, env=docker_env)
            except (OSError, subprocess.SubprocessError) as exc:
                raise DockerUnavailable(f"Docker sandbox setup failed: {exc}") from exc
            if result.returncode:
                raise DockerUnavailable(f"Docker sandbox setup failed: {result.stderr[-1000:]}")
        proxy_name = f"vetter-proxy-{uuid.uuid4().hex[:10]}"
        proxy_start = subprocess.run(
            [
                "docker", "run", "-d", "--rm", "--name", proxy_name, "--network", network,
                "--network-alias", "vetter-proxy", "--mount", f"type=bind,src={tmp},dst=/vetter-scratch",
                tag, "python3", "/docker_proxy.py",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env=docker_env,
        )
        if proxy_start.returncode:
            subprocess.run(["docker", "network", "rm", network], capture_output=True, check=False, env=docker_env)
            raise DockerUnavailable(f"Docker sandbox proxy failed to start: {proxy_start.stderr[-1000:]}")
        server_command = list(entry.command)
        if entry.language == "python" and server_command:
            server_command[0] = "python3"
        command = [
            "docker", "run", "--rm", "-i", "--network", network,
            "--mount", f"type=bind,src={BASE_DIR},dst=/vetter,readonly",
            "--add-host", "host.docker.internal:host-gateway",
            "--mount", "type=bind,src={HOME},dst=/tmp/vetter-home,readonly",
            "--mount", "type=bind,src={AUDIT},dst=/tmp/vetter-audit.ndjson",
            "--mount", "type=bind,src={SITE},dst=/vetter-sandbox/sitecustomize,readonly",
            "-w", "/vetter", "-e", "HOME=/tmp/vetter-home", "-e", "VETTER_AUDIT_LOG=/tmp/vetter-audit.ndjson",
            "-e", "PYTHONPATH=/vetter-sandbox/sitecustomize:/vetter", "-e", "HTTP_PROXY=http://vetter-proxy:3128", "-e", "HTTPS_PROXY=http://vetter-proxy:3128",
            "-e", "http_proxy=http://vetter-proxy:3128", "-e", "https_proxy=http://vetter-proxy:3128", "-e", "NO_PROXY=", "-e", "no_proxy=",
            tag, "strace", "-f", "-e", "trace=file,network", *server_command,
        ]
        try:
            # Docker's CLI uses the real host settings. The fake HOME and proxy
            # values are injected only with `docker run -e` inside the container.
            host_cli_env = {
                "HOME": docker_env.get("HOME", ""),
                "PATH": docker_env.get("PATH", "/usr/bin:/bin"),
                "DOCKER_HOST": docker_env.get("DOCKER_HOST", ""),
                "DOCKER_CONFIG": docker_env.get("DOCKER_CONFIG", ""),
            }
            host_cli_env = {key: value for key, value in host_cli_env.items() if value}
            report = await run_sandbox(entry, tools, command=command, mode="docker", command_env=host_cli_env)
            proxy_log = Path(tmp) / "proxy.ndjson"
            if proxy_log.exists():
                import json

                records = [json.loads(line) for line in proxy_log.read_text().splitlines() if line.strip()]
                report.network_destinations = sorted(
                    set(report.network_destinations) | {str(row.get("host", "")) for row in records if row.get("host")}
                )
                leaks = [(row, token) for row in records for token in row.get("canary_hits", [])]
                if leaks:
                    leak_row, token = leaks[0]
                    leaked_path = report.canary_paths.get(token)
                    report.canary_leak.leaked = True
                    report.canary_leak.secret = leaked_path or "decoy secret"
                    report.canary_leak.destination = str(leak_row.get("host") or "")
                    if leaked_path:
                        from vetter.sandbox.runner import FileAccess

                        report.files_opened.append(FileAccess(path=f"~/{leaked_path}", is_decoy=True))
            return report
        finally:
            subprocess.run(["docker", "rm", "-f", proxy_name], capture_output=True, check=False, env=docker_env)
            subprocess.run(
                ["docker", "network", "rm", network], capture_output=True, check=False, env=docker_env
            )
