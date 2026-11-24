from __future__ import annotations

from vetter.fingerprint import (
    approve_server,
    compute_tool_fingerprint,
    revoke_server,
    verify_server,
)
from vetter.mcp_client import ToolInfo


def _tool(name="t", description="d", schema=None) -> ToolInfo:
    return ToolInfo(name=name, description=description, input_schema=schema or {})


def test_fingerprint_is_deterministic():
    a = compute_tool_fingerprint(_tool())
    b = compute_tool_fingerprint(_tool())
    assert a == b
    assert len(a) == 64  # hex sha256


def test_fingerprint_changes_with_description():
    a = compute_tool_fingerprint(_tool(description="d"))
    b = compute_tool_fingerprint(_tool(description="d changed"))
    assert a != b


def test_fingerprint_changes_with_schema():
    a = compute_tool_fingerprint(_tool(schema={"properties": {"x": {}}}))
    b = compute_tool_fingerprint(_tool(schema={"properties": {"y": {}}}))
    assert a != b


def test_verify_before_approve_is_unapproved(isolated_paths):
    result = verify_server("srv", [_tool()], path=isolated_paths["lock"])
    assert result["approved"] is False


def test_approve_then_verify_matches(isolated_paths):
    tools = [_tool(name="a"), _tool(name="b")]
    approve_server("srv", tools, path=isolated_paths["lock"])

    result = verify_server("srv", tools, path=isolated_paths["lock"])
    assert result["approved"] is True
    assert result["changed_tools"] == []
    assert result["new_tools"] == []
    assert result["missing_tools"] == []


def test_verify_detects_description_change(isolated_paths):
    tools = [_tool(name="a", description="original")]
    approve_server("srv", tools, path=isolated_paths["lock"])

    changed_tools = [_tool(name="a", description="original, plus a rug pull")]
    result = verify_server("srv", changed_tools, path=isolated_paths["lock"])

    assert result["approved"] is True
    assert result["changed_tools"] == ["a"]


def test_verify_detects_new_and_missing_tools(isolated_paths):
    approve_server("srv", [_tool(name="a"), _tool(name="b")], path=isolated_paths["lock"])

    result = verify_server("srv", [_tool(name="a"), _tool(name="c")], path=isolated_paths["lock"])

    assert result["new_tools"] == ["c"]
    assert result["missing_tools"] == ["b"]


def test_revoke_removes_approval(isolated_paths):
    tools = [_tool(name="a")]
    approve_server("srv", tools, path=isolated_paths["lock"])
    assert revoke_server("srv", path=isolated_paths["lock"]) is True

    result = verify_server("srv", tools, path=isolated_paths["lock"])
    assert result["approved"] is False


def test_revoke_nonexistent_server_returns_false(isolated_paths):
    assert revoke_server("does-not-exist", path=isolated_paths["lock"]) is False
