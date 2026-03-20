import logging
import re
from typing import Any, Callable

from src import auth

logger = logging.getLogger(__name__)


class SessionRoleMiddleware:
    """GET /sse 接続時に X-Role ヘッダーを読み取り、session_id と紐付けるミドルウェア。"""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        path = scope.get("path", "")
        if scope["type"] == "http" and path.rstrip("/") == "/sse":
            headers = {
                k.decode().lower(): v.decode()
                for k, v in scope.get("headers", [])
            }
            role = headers.get("x-role") or None
            logger.debug("[MIDDLEWARE] SSE接続開始 role=%r", role)

            async def capturing_send(message: dict) -> None:
                if message.get("type") == "http.response.body":
                    body = message.get("body", b"").decode(errors="ignore")
                    logger.debug("[MIDDLEWARE] SSEボディチャンク: %r", body[:200])
                    match = re.search(r"session_id=([\w-]+)", body)
                    if match:
                        session_id = match.group(1)
                        auth.store_session_role(session_id, role)
                        logger.info("[MIDDLEWARE] セッション登録 session_id=%s role=%r", session_id, role)
                await send(message)

            await self.app(scope, receive, capturing_send)
        else:
            await self.app(scope, receive, send)
