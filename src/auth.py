import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

VALID_ROLES = {"admin", "viewer"}

# ツール名 → 許可ロールの対応（将来の書き込み系ツールは admin のみにする想定）
TOOL_PERMISSIONS: dict[str, set[str]] = {
    "tool_get_stats_list": {"admin", "viewer"},
    "tool_get_stats_data": {"admin", "viewer"},
    "tool_get_meta_info": {"admin", "viewer"},
}


def get_role_from_request(request: Any) -> str | None:
    """HTTP リクエストの X-Role ヘッダーからロールを取得する。

    request が None（stdio トランスポート）の場合は ESTAT_ROLE 環境変数にフォールバック。
    """
    if request is not None:
        return request.headers.get("X-Role") or None
    return os.environ.get("ESTAT_ROLE") or None


def check_permission(tool_name: str, request: Any = None) -> tuple[bool, str]:
    """ツール呼び出しの権限を確認する。

    Args:
        tool_name: 呼び出し対象のツール名
        request: Starlette Request オブジェクト（SSE トランスポート時）

    Returns:
        (許可, 拒否理由) のタプル。許可の場合は拒否理由は空文字。
    """
    role = get_role_from_request(request)

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
