"""ミドルウェアのテスト（Keycloakモード / mockモード切り替え含む）。"""

import json
import time
from unittest.mock import AsyncMock, patch, MagicMock

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from src import auth
from src.middleware import SessionRoleMiddleware


# --- テスト用ヘルパー ---


def _generate_rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


def _create_jwks_from_public_key(public_key, kid="test-kid"):
    from jwt.algorithms import RSAAlgorithm

    jwk_dict = RSAAlgorithm.to_jwk(public_key, as_dict=True)
    jwk_dict["kid"] = kid
    jwk_dict["use"] = "sig"
    jwk_dict["alg"] = "RS256"
    return {"keys": [jwk_dict]}


def _create_test_token(private_key, kid="test-kid", roles=None, exp_offset=3600):
    now = int(time.time())
    payload = {
        "sub": "test-user-id",
        "iss": "http://localhost:8080/realms/estat",
        "aud": "estat-mcp-client",
        "exp": now + exp_offset,
        "iat": now,
    }
    if roles is not None:
        payload["realm_roles"] = roles
    return pyjwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})


def _make_sse_scope(headers: dict[str, str] | None = None) -> dict:
    raw_headers = []
    if headers:
        for k, v in headers.items():
            raw_headers.append([k.lower().encode(), v.encode()])
    return {
        "type": "http",
        "path": "/sse",
        "headers": raw_headers,
    }


# --- テスト ---


@pytest.fixture(autouse=True)
def clear_session_store():
    auth._session_roles.clear()
    yield
    auth._session_roles.clear()


@pytest.fixture
def rsa_keys():
    return _generate_rsa_key_pair()


@pytest.fixture
def jwks_data(rsa_keys):
    _, public_key = rsa_keys
    return _create_jwks_from_public_key(public_key)


class TestMockMode:
    """AUTH_MODE=mock のテスト。"""

    @pytest.mark.asyncio
    @patch("src.middleware.AUTH_MODE", "mock")
    async def test_mock_mode_reads_x_role_header(self):
        """mockモードでX-Roleヘッダーからロールを読み取ること。"""
        captured_role = {}

        async def fake_app(scope, receive, send):
            # session_idを含むSSEボディを送信
            await send({
                "type": "http.response.body",
                "body": b"event: endpoint\ndata: /messages?session_id=sess-mock-001\n\n",
            })

        middleware = SessionRoleMiddleware(fake_app)
        scope = _make_sse_scope({"X-Role": "viewer"})
        await middleware(scope, AsyncMock(), AsyncMock())

        assert "sess-mock-001" in auth._session_roles
        assert auth._session_roles["sess-mock-001"] == "viewer"

    @pytest.mark.asyncio
    @patch("src.middleware.AUTH_MODE", "mock")
    async def test_mock_mode_no_role_header(self):
        """mockモードでX-Roleヘッダーなしでもリクエストが通ること。"""

        async def fake_app(scope, receive, send):
            await send({
                "type": "http.response.body",
                "body": b"event: endpoint\ndata: /messages?session_id=sess-mock-002\n\n",
            })

        middleware = SessionRoleMiddleware(fake_app)
        scope = _make_sse_scope()
        await middleware(scope, AsyncMock(), AsyncMock())

        assert auth._session_roles.get("sess-mock-002") is None


class TestKeycloakMode:
    """AUTH_MODE=keycloak のテスト。"""

    @pytest.mark.asyncio
    @patch("src.middleware.AUTH_MODE", "keycloak")
    @patch("src.jwt_auth._fetch_jwks")
    async def test_valid_bearer_token(self, mock_fetch, rsa_keys, jwks_data):
        """有効なBearerトークンでSSE接続が成功すること。"""
        private_key, _ = rsa_keys
        mock_fetch.return_value = jwks_data
        token = _create_test_token(private_key, roles=["admin"])

        async def fake_app(scope, receive, send):
            await send({
                "type": "http.response.body",
                "body": b"event: endpoint\ndata: /messages?session_id=sess-kc-001\n\n",
            })

        middleware = SessionRoleMiddleware(fake_app)
        scope = _make_sse_scope({"Authorization": f"Bearer {token}"})
        await middleware(scope, AsyncMock(), AsyncMock())

        assert auth._session_roles.get("sess-kc-001") == "admin"

    @pytest.mark.asyncio
    @patch("src.middleware.AUTH_MODE", "keycloak")
    async def test_missing_authorization_header(self):
        """Authorizationヘッダーなしで401が返ること。"""
        sent_messages = []

        async def capture_send(message):
            sent_messages.append(message)

        async def fake_app(scope, receive, send):
            pytest.fail("App should not be called without auth")

        middleware = SessionRoleMiddleware(fake_app)
        scope = _make_sse_scope()
        await middleware(scope, AsyncMock(), capture_send)

        assert sent_messages[0]["status"] == 401
        body = json.loads(sent_messages[1]["body"])
        assert body["error"] == "Unauthorized"

    @pytest.mark.asyncio
    @patch("src.middleware.AUTH_MODE", "keycloak")
    async def test_invalid_bearer_prefix(self):
        """Bearer以外のprefixで401が返ること。"""
        sent_messages = []

        async def capture_send(message):
            sent_messages.append(message)

        async def fake_app(scope, receive, send):
            pytest.fail("App should not be called")

        middleware = SessionRoleMiddleware(fake_app)
        scope = _make_sse_scope({"Authorization": "Basic abc123"})
        await middleware(scope, AsyncMock(), capture_send)

        assert sent_messages[0]["status"] == 401

    @pytest.mark.asyncio
    @patch("src.middleware.AUTH_MODE", "keycloak")
    @patch("src.jwt_auth._fetch_jwks")
    async def test_expired_token_returns_401(self, mock_fetch, rsa_keys, jwks_data):
        """期限切れトークンで401が返ること。"""
        private_key, _ = rsa_keys
        mock_fetch.return_value = jwks_data
        token = _create_test_token(private_key, exp_offset=-3600)

        sent_messages = []

        async def capture_send(message):
            sent_messages.append(message)

        async def fake_app(scope, receive, send):
            pytest.fail("App should not be called")

        middleware = SessionRoleMiddleware(fake_app)
        scope = _make_sse_scope({"Authorization": f"Bearer {token}"})
        await middleware(scope, AsyncMock(), capture_send)

        assert sent_messages[0]["status"] == 401
        body = json.loads(sent_messages[1]["body"])
        assert "expired" in body["detail"].lower()

    @pytest.mark.asyncio
    @patch("src.middleware.AUTH_MODE", "keycloak")
    @patch("src.jwt_auth._fetch_jwks")
    async def test_viewer_role_from_jwt(self, mock_fetch, rsa_keys, jwks_data):
        """viewerロールのトークンでセッションにviewerが紐付くこと。"""
        private_key, _ = rsa_keys
        mock_fetch.return_value = jwks_data
        token = _create_test_token(private_key, roles=["viewer"])

        async def fake_app(scope, receive, send):
            await send({
                "type": "http.response.body",
                "body": b"event: endpoint\ndata: /messages?session_id=sess-kc-viewer\n\n",
            })

        middleware = SessionRoleMiddleware(fake_app)
        scope = _make_sse_scope({"Authorization": f"Bearer {token}"})
        await middleware(scope, AsyncMock(), AsyncMock())

        assert auth._session_roles.get("sess-kc-viewer") == "viewer"

    @pytest.mark.asyncio
    @patch("src.middleware.AUTH_MODE", "keycloak")
    @patch("src.jwt_auth._fetch_jwks")
    async def test_invalid_signature_returns_401(self, mock_fetch, jwks_data):
        """異なる鍵で署名したトークンで401が返ること。"""
        other_private_key, _ = _generate_rsa_key_pair()
        mock_fetch.return_value = jwks_data
        token = _create_test_token(other_private_key)

        sent_messages = []

        async def capture_send(message):
            sent_messages.append(message)

        async def fake_app(scope, receive, send):
            pytest.fail("App should not be called")

        middleware = SessionRoleMiddleware(fake_app)
        scope = _make_sse_scope({"Authorization": f"Bearer {token}"})
        await middleware(scope, AsyncMock(), capture_send)

        assert sent_messages[0]["status"] == 401


class TestNonSseRequests:
    """SSE以外のリクエストのテスト。"""

    @pytest.mark.asyncio
    @patch("src.middleware.AUTH_MODE", "keycloak")
    async def test_non_sse_path_passes_through(self):
        """SSE以外のパスはそのまま通過すること。"""
        app_called = False

        async def fake_app(scope, receive, send):
            nonlocal app_called
            app_called = True

        middleware = SessionRoleMiddleware(fake_app)
        scope = {"type": "http", "path": "/messages", "headers": []}
        await middleware(scope, AsyncMock(), AsyncMock())

        assert app_called
