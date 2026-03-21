import json
import logging
import re
from typing import Any, Callable

import jwt

from src import auth
from src.config import AUTH_MODE
from src.jwt_auth import extract_roles, get_primary_role, verify_token

logger = logging.getLogger(__name__)


class SessionRoleMiddleware:
    """GET /sse 接続時に認証を行い、session_id とロールを紐付けるミドルウェア。

    AUTH_MODE に応じて認証方式を切り替える:
    - "keycloak": Authorization: Bearer <token> を検証（JWT/JWKS）
    - "mock": X-Role ヘッダーをそのまま信頼（開発・テスト用）
    """

    def __init__(self, app: Any) -> None:
        self.app = app
        logger.info("[MIDDLEWARE] 認証モード: %s", AUTH_MODE)

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        path = scope.get("path", "")
        if scope["type"] == "http" and path.rstrip("/") == "/sse":
            headers = {
                k.decode().lower(): v.decode()
                for k, v in scope.get("headers", [])
            }

            if AUTH_MODE == "keycloak":
                await self._handle_keycloak_auth(scope, receive, send, headers)
            else:
                await self._handle_mock_auth(scope, receive, send, headers)
        else:
            await self.app(scope, receive, send)

    async def _handle_keycloak_auth(
        self, scope: dict, receive: Callable, send: Callable, headers: dict[str, str]
    ) -> None:
        """Keycloak JWT認証でSSE接続を処理する。"""
        auth_header = headers.get("authorization", "")

        if not auth_header.startswith("Bearer "):
            logger.warning("[MIDDLEWARE] Bearerトークンなし")
            await self._send_401(send, "Missing or invalid Authorization header")
            return

        token = auth_header[7:]  # "Bearer " を除去

        try:
            payload = verify_token(token)
        except jwt.ExpiredSignatureError:
            logger.warning("[MIDDLEWARE] トークン期限切れ")
            await self._send_401(send, "Token has expired")
            return
        except jwt.InvalidAudienceError:
            logger.warning("[MIDDLEWARE] 不正なaudience")
            await self._send_401(send, "Invalid token audience")
            return
        except jwt.InvalidIssuerError:
            logger.warning("[MIDDLEWARE] 不正なissuer")
            await self._send_401(send, "Invalid token issuer")
            return
        except jwt.InvalidTokenError as e:
            logger.warning("[MIDDLEWARE] 不正なトークン: %s", e)
            await self._send_401(send, f"Invalid token: {e}")
            return

        role = get_primary_role(payload)
        logger.info(
            "[MIDDLEWARE] JWT認証成功 sub=%s role=%r roles=%s",
            payload.get("sub"),
            role,
            extract_roles(payload),
        )

        await self._capture_session_and_bind_role(scope, receive, send, role)

    async def _handle_mock_auth(
        self, scope: dict, receive: Callable, send: Callable, headers: dict[str, str]
    ) -> None:
        """モック認証（X-Roleヘッダー）でSSE接続を処理する。"""
        role = headers.get("x-role") or None
        logger.debug("[MIDDLEWARE] モック認証 role=%r", role)
        await self._capture_session_and_bind_role(scope, receive, send, role)

    async def _capture_session_and_bind_role(
        self, scope: dict, receive: Callable, send: Callable, role: str | None
    ) -> None:
        """レスポンスボディからsession_idを抽出し、ロールと紐付ける。"""

        async def capturing_send(message: dict) -> None:
            if message.get("type") == "http.response.body":
                body = message.get("body", b"").decode(errors="ignore")
                logger.debug("[MIDDLEWARE] SSEボディチャンク: %r", body[:200])
                match = re.search(r"session_id=([\w-]+)", body)
                if match:
                    session_id = match.group(1)
                    auth.store_session_role(session_id, role)
                    logger.info(
                        "[MIDDLEWARE] セッション登録 session_id=%s role=%r",
                        session_id,
                        role,
                    )
            await send(message)

        await self.app(scope, receive, capturing_send)

    @staticmethod
    async def _send_401(send: Callable, detail: str) -> None:
        """401 Unauthorizedレスポンスを送信する。"""
        body = json.dumps({"error": "Unauthorized", "detail": detail}).encode()
        await send({
            "type": "http.response.start",
            "status": 401,
            "headers": [
                [b"content-type", b"application/json"],
                [b"content-length", str(len(body)).encode()],
                [b"www-authenticate", b"Bearer"],
            ],
        })
        await send({
            "type": "http.response.body",
            "body": body,
        })
