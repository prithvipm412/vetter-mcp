"""The `vetter` console script: scan, sandbox, approve, verify, proxy,
protect, serve and demo, all from the terminal, with rich tables for output.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import Any

from rich.console import Console
from rich.table import Table

from vetter import db, fingerprint
from vetter.config import BACKEND_PORT
from vetter.mcp_client import MCPIntrospectionError, list_server_tools
from vetter.sandbox.runner import run_sandbox
from vetter.scan_service import SANDBOX_NOT_SUPPORTED_MESSAGE, scan_and_store
from vetter.server_lookup import all_entries, get_entry

console = Console()
error_console = Console(stderr=True, style="bold red")


def _resolve_server_ids(ids: list[str]) -> list[str]:
    return ids if ids else sorted(all_entries())


def _verdict_style(verdict: str | None) -> str:
    return {"looks_ok": "green", "review": "yellow", "high_risk": "bold red"}.get(verdict or "", "dim")


def _status_style(status: str | None) -> str:
    return {"approved": "green", "blocked": "red", "paused_changed": "bold yellow"}.get(status or "", "dim")


def cmd_scan(args: argparse.Namespace) -> int:
    db.init_db()
    server_ids = _resolve_server_ids(args.server_ids)

    table = Table(title="vetter scan")
    table.add_column("ID")
    table.add_column("Verdict")
    table.add_column("Status")
    table.add_column("Labels")

    exit_code = 0
    for server_id in server_ids:
        entry = get_entry(server_id)
        if entry is None:
            error_console.print(f"unknown server id: {server_id}")
            exit_code = 1
            continue
        try:
            row = asyncio.run(scan_and_store(entry, with_sandbox=not args.no_sandbox))
        except MCPIntrospectionError as exc:
            error_console.print(f"{server_id}: {exc}")
            exit_code = 1
            continue
        table.add_row(
            server_id,
            f"[{_verdict_style(row['verdict'])}]{row['verdict']}[/]",
            f"[{_status_style(row['status'])}]{row['status']}[/]",
            str(len(row["labels"])),
        )
    console.print(table)
    return exit_code


def cmd_sandbox(args: argparse.Namespace) -> int:
    entry = get_entry(args.server_id)
    if entry is None:
        error_console.print(f"unknown server id: {args.server_id}")
        return 1
    if entry.language != "python":
        console.print(f"[yellow]{SANDBOX_NOT_SUPPORTED_MESSAGE} (language={entry.language})[/]")
        return 0

    async def _run() -> Any:
        tools = await list_server_tools(entry.command, env=entry.env)
        return await run_sandbox(entry, tools)

    try:
        report = asyncio.run(_run())
    except MCPIntrospectionError as exc:
        error_console.print(str(exc))
        return 1

    calls = Table(title=f"{args.server_id}: tool calls")
    calls.add_column("Tool")
    calls.add_column("OK")
    calls.add_column("Error")
    for call in report.tool_calls:
        calls.add_row(call.tool, "[green]yes[/]" if call.ok else "[red]no[/]", call.error or "")
    console.print(calls)

    files = Table(title="files opened")
    files.add_column("Path")
    files.add_column("Decoy?")
    for f in report.files_opened:
        files.add_row(f.path, "[bold red]DECOY[/]" if f.is_decoy else "")
    console.print(files)

    console.print(f"network destinations: {report.network_destinations or '(none)'}")
    if report.canary_leak.leaked:
        console.print(
            f"[bold red]canary_leak: secret from {report.canary_leak.secret} sent to "
            f"{report.canary_leak.destination}[/]"
        )
    else:
        console.print("[green]canary_leak: none detected[/]")
    if report.error:
        error_console.print(report.error)
        return 1
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    entry = get_entry(args.server_id)
    if entry is None:
        error_console.print(f"unknown server id: {args.server_id}")
        return 1
    db.init_db()
    db.ensure_server_row(entry.id, entry.name)
    try:
        tools = asyncio.run(list_server_tools(entry.command, env=entry.env))
    except MCPIntrospectionError as exc:
        error_console.print(str(exc))
        return 1
    fingerprint.approve_server(entry.id, tools)
    db.set_status(entry.id, "approved")
    console.print(f"[green]approved[/] {entry.id} ({len(tools)} tool(s) fingerprinted)")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    entry = get_entry(args.server_id)
    if entry is None:
        error_console.print(f"unknown server id: {args.server_id}")
        return 1
    try:
        tools = asyncio.run(list_server_tools(entry.command, env=entry.env))
    except MCPIntrospectionError as exc:
        error_console.print(str(exc))
        return 1
    result = fingerprint.verify_server(entry.id, tools)

    table = Table(title=f"vetter verify: {entry.id}")
    table.add_column("field")
    table.add_column("value")
    table.add_row("approved", "[green]yes[/]" if result["approved"] else "[red]no[/]")
    table.add_row("changed_tools", str(result["changed_tools"]) or "(none)")
    table.add_row("new_tools", str(result["new_tools"]) or "(none)")
    table.add_row("missing_tools", str(result["missing_tools"]) or "(none)")
    console.print(table)
    return 0 if result["approved"] and not result["changed_tools"] else 1


def cmd_proxy(remaining_args: list[str]) -> int:
    # vetter.proxy owns its own argparse (it must accept `--server X -- cmd
    # args...`, which doesn't nest cleanly inside another parser), so just
    # hand it the raw argv tail.
    from vetter.proxy import main as proxy_main

    sys.argv = ["vetter-proxy", *remaining_args]
    proxy_main()
    return 0


def cmd_protect(args: argparse.Namespace) -> int:
    from vetter import protect as protect_module

    result = protect_module.undo() if args.undo else protect_module.protect()
    console.print(f"status: [bold]{result['status']}[/]")
    if result.get("message"):
        console.print(result["message"])
    changed = result.get("changed")
    if changed:
        table = Table(title="servers wrapped")
        table.add_column("server")
        table.add_column("before")
        table.add_column("after")
        for item in changed:
            table.add_row(
                item["server"],
                " ".join([item["before"]["command"], *item["before"]["args"]]),
                " ".join([item["after"]["command"], *item["after"]["args"]]),
            )
        console.print(table)
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run("vetter.main:app", host=args.host, port=args.port, reload=args.reload)
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    from vetter.demo_runner import run_demo

    steps = asyncio.run(run_demo())

    table = Table(title="vetter demo: 3 scenarios, end to end")
    table.add_column("scenario")
    table.add_column("step")
    table.add_column("expected")
    table.add_column("verdict")
    table.add_column("status")
    table.add_column("result")

    all_passed = True
    for step in steps:
        all_passed = all_passed and step.passed
        table.add_row(
            step.scenario,
            step.step,
            step.expected,
            f"[{_verdict_style(step.verdict)}]{step.verdict}[/]" if step.verdict else "-",
            f"[{_status_style(step.status)}]{step.status}[/]" if step.status else "-",
            "[green]PASS[/]" if step.passed else "[bold red]FAIL[/]",
        )
    console.print(table)
    console.print("[bold green]all scenarios behaved as expected[/]" if all_passed else "[bold red]one or more scenarios did not behave as expected[/]")
    return 0 if all_passed else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vetter", description="App-store review for your MCP servers.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="static-scan (and sandbox) one or more servers")
    p_scan.add_argument("server_ids", nargs="*", help="server ids; default: every known server")
    p_scan.add_argument("--no-sandbox", action="store_true", help="skip the dynamic sandbox run")
    p_scan.set_defaults(func=cmd_scan)

    p_sandbox = sub.add_parser("sandbox", help="run only the lite sandbox for one server")
    p_sandbox.add_argument("server_id")
    p_sandbox.set_defaults(func=cmd_sandbox)

    p_approve = sub.add_parser("approve", help="fingerprint and approve a server's current tools")
    p_approve.add_argument("server_id")
    p_approve.set_defaults(func=cmd_approve)

    p_verify = sub.add_parser("verify", help="compare a server's live tools against its approved baseline")
    p_verify.add_argument("server_id")
    p_verify.set_defaults(func=cmd_verify)

    sub.add_parser(
        "proxy", help="runtime proxy: vetter proxy --server <id> -- <command...>", add_help=False
    )

    p_protect = sub.add_parser("protect", help="wrap every server in the Claude Desktop config")
    p_protect.add_argument("--undo", action="store_true", help="restore the most recent backup instead")
    p_protect.set_defaults(func=cmd_protect)

    p_serve = sub.add_parser("serve", help="run the FastAPI backend")
    p_serve.add_argument("--host", default="0.0.0.0")
    p_serve.add_argument("--port", type=int, default=BACKEND_PORT)
    p_serve.add_argument("--reload", action="store_true")
    p_serve.set_defaults(func=cmd_serve)

    p_demo = sub.add_parser("demo", help="fresh reset, run all 3 demo scenarios, print a summary")
    p_demo.set_defaults(func=cmd_demo)

    return parser


def main() -> None:
    argv = sys.argv[1:]
    if argv and argv[0] == "proxy":
        raise SystemExit(cmd_proxy(argv[1:]))

    parser = build_parser()
    args = parser.parse_args(argv)
    raise SystemExit(args.func(args))


if __name__ == "__main__":
    main()
