import pytest

from src.auth import check_permission, get_role_from_request


class _MockRequest:
    """テスト用の最小限のHTTPリクエストモック。"""
    def __init__(self, role: str | None):
        self.headers = {"X-Role": role} if role else {}


def test_admin_can_call_all_tools():
    req = _MockRequest("admin")
    for tool in ["tool_get_stats_list", "tool_get_stats_data", "tool_get_meta_info"]:
        ok, reason = check_permission(tool, request=req)
        assert ok, f"admin should be allowed to call {tool}: {reason}"


def test_viewer_can_call_read_tools():
    req = _MockRequest("viewer")
    for tool in ["tool_get_stats_list", "tool_get_stats_data", "tool_get_meta_info"]:
        ok, reason = check_permission(tool, request=req)
        assert ok, f"viewer should be allowed to call {tool}: {reason}"


def test_missing_role_is_denied():
    req = _MockRequest(None)
    ok, reason = check_permission("tool_get_stats_list", request=req)
    assert not ok
    assert "missing or invalid" in reason


def test_invalid_role_is_denied():
    req = _MockRequest("superuser")
    ok, reason = check_permission("tool_get_stats_list", request=req)
    assert not ok
    assert "missing or invalid" in reason


def test_no_request_falls_back_to_env_var(monkeypatch):
    """stdio トランスポート時: request=None で ESTAT_ROLE 環境変数を使う。"""
    monkeypatch.setenv("ESTAT_ROLE", "viewer")
    ok, _ = check_permission("tool_get_stats_list", request=None)
    assert ok


def test_no_request_no_env_var_is_denied(monkeypatch):
    monkeypatch.delenv("ESTAT_ROLE", raising=False)
    ok, reason = check_permission("tool_get_stats_list", request=None)
    assert not ok
    assert "missing or invalid" in reason


def test_denied_tool_logs_warning(caplog):
    import logging
    req = _MockRequest(None)
    with caplog.at_level(logging.WARNING, logger="src.auth"):
        ok, _ = check_permission("tool_get_stats_list", request=req)
    assert not ok
    assert "[AUTH]" in caplog.text
