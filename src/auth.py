import contextvars
import logging
import os

logger = logging.getLogger(__name__)

# リクエストスコープのロールを保持するコンテキスト変数
current_role: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "current_role", default=None
)

VALID_ROLES = {"admin", "viewer"}

# ツール名 → 許可ロールの対応（将来の書き込み系ツールは admin のみにする想定）
TOOL_PERMISSIONS: dict[str, set[str]] = {
    "tool_get_stats_list": {"admin", "viewer"},
    "tool_get_stats_data": {"admin", "viewer"},
    "tool_get_meta_info": {"admin", "viewer"},
}


def get_current_role() -> str | None:
    """現在のロールを返す。ContextVar未設定時は環境変数 ESTAT_ROLE にフォールバック。"""
    role = current_role.get()
    if role is None:
        role = os.environ.get("ESTAT_ROLE") or None
    return role


def check_permission(tool_name: str) -> tuple[bool, str]:
    """ツール呼び出しの権限を確認する。

    Returns:
        (許可, 拒否理由) のタプル。許可の場合は拒否理由は空文字。
    """
    role = get_current_role()
    if role is None or role not in VALID_ROLES:
        reason = f"Access denied: X-Role header is missing or invalid (got: {role!r})"
        logger.warning("[AUTH] %s | tool=%s", reason, tool_name)
        return False, reason

    allowed = TOOL_PERMISSIONS.get(tool_name, set())
    if role not in allowed:
        reason = f"Access denied: role '{role}' cannot call '{tool_name}'"
        logger.warning("[AUTH] %s", reason)
        return False, reason

    return True, ""
