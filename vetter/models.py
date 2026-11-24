"""Pydantic response/request models for the vetter API."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel

Verdict = Literal["looks_ok", "review", "high_risk"]
Status = Literal["new", "approved", "blocked", "paused_changed"]


class Finding(BaseModel):
    category: str
    severity: Literal["low", "medium", "high"]
    label: str
    detail: str
    tool_name: str | None = None


class DeclaredTool(BaseModel):
    name: str
    description: str


class Behaviour(BaseModel):
    declared_tools: list[DeclaredTool]
    detected_actions: list[str]
    extra_tools: list[str]


class ClaimVsBehaviour(BaseModel):
    stated_purpose: str
    capability_match: bool
    mismatches: list[str]


class ScanReport(BaseModel):
    static_findings: list[Finding]
    behaviour: Behaviour
    claim_vs_behaviour: ClaimVsBehaviour


class ServerSummary(BaseModel):
    id: str
    name: str
    verdict: Verdict | None
    labels: list[str]
    status: Status


class ServerScanResult(ServerSummary):
    static_findings: list[Finding]
    behaviour: Behaviour
    claim_vs_behaviour: ClaimVsBehaviour
