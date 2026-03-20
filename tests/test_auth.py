import pytest

from src.auth import check_permission, get_role_for_request, store_session_role, _session_roles


class _MockRequest:
    """テスト用の最小限のHTTPリクエストモック。"""
    def __init__(self, role: str | None = None, session_id: str | None = None):
        self.headers = {"X-Role": role} if role else {}
        self.query_params = {"session_id": session_id} if session_id else {}


def setup_function():
    """各テスト前にセッションストアをクリア。"""
    _session_roles.clear()


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


# --- セッションベース認証のテスト ---

def test_store_and_get_session_role():
    """store_session_role でロールを保存し、session_id 経由で引き当てられること。"""
    store_session_role("sess-001", "admin")
    req = _MockRequest(session_id="sess-001")
    role = get_role_for_request(req)
    assert role == "admin"


def test_session_role_none_is_stored():
    """ロールなしセッションも保存・引き当てができること。"""
    store_session_role("sess-002", None)
    req = _MockRequest(session_id="sess-002")
    role = get_role_for_request(req)
    assert role is None


def test_session_role_check_permission():
    """セッションID経由でロールを解決し、権限チェックが通ること。"""
    store_session_role("sess-003", "viewer")
    req = _MockRequest(session_id="sess-003")
    ok, reason = check_permission("tool_get_stats_list", request=req)
    assert ok, reason


def test_session_role_denied_without_role():
    """ロールなしセッションでは権限チェックが拒否されること。"""
    store_session_role("sess-004", None)
    req = _MockRequest(session_id="sess-004")
    ok, reason = check_permission("tool_get_stats_list", request=req)
    assert not ok
    assert "missing or invalid" in reason


def test_header_fallback_when_no_session_id():
    """session_id がない場合は X-Role ヘッダーにフォールバックすること。"""
    req = _MockRequest(role="admin")
    role = get_role_for_request(req)
    assert role == "admin"


def test_unknown_session_id_falls_back_to_header():
    """未登録の session_id は X-Role ヘッダーにフォールバックすること。"""
    req = _MockRequest(role="viewer", session_id="unknown-session")
    role = get_role_for_request(req)
    assert role == "viewer"
