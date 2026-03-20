import pytest

import src.auth as auth_module
from src.auth import check_permission, current_role


def _set_role(role: str | None):
    """テスト用: current_role ContextVar を直接設定する。"""
    current_role.set(role)


def test_admin_can_call_all_tools():
    _set_role("admin")
    for tool in ["tool_get_stats_list", "tool_get_stats_data", "tool_get_meta_info"]:
        ok, reason = check_permission(tool)
        assert ok, f"admin should be allowed to call {tool}: {reason}"


def test_viewer_can_call_read_tools():
    _set_role("viewer")
    for tool in ["tool_get_stats_list", "tool_get_stats_data", "tool_get_meta_info"]:
        ok, reason = check_permission(tool)
        assert ok, f"viewer should be allowed to call {tool}: {reason}"


def test_missing_role_is_denied():
    _set_role(None)
    ok, reason = check_permission("tool_get_stats_list")
    assert not ok
    assert "missing or invalid" in reason


def test_invalid_role_is_denied():
    _set_role("superuser")
    ok, reason = check_permission("tool_get_stats_list")
    assert not ok
    assert "missing or invalid" in reason


def test_env_var_fallback(monkeypatch):
    """X-Role ヘッダーがない場合に ESTAT_ROLE 環境変数で代替できる。"""
    _set_role(None)
    monkeypatch.setenv("ESTAT_ROLE", "viewer")
    # get_current_role が env var を読むかテスト
    role = auth_module.get_current_role()
    assert role == "viewer"


def test_denied_tool_logs_warning(caplog):
    import logging
    _set_role(None)
    with caplog.at_level(logging.WARNING, logger="src.auth"):
        ok, _ = check_permission("tool_get_stats_list")
    assert not ok
    assert "[AUTH]" in caplog.text
