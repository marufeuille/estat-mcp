"""JWT認証モジュールのテスト。"""

import time
from unittest.mock import MagicMock, patch

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from src.jwt_auth import (
    extract_roles,
    get_primary_role,
    invalidate_jwks_cache,
    verify_token,
    _fetch_jwks,
    _jwks_cache,
)


# --- テスト用RSA鍵ペアの生成 ---


def _generate_rsa_key_pair():
    """テスト用のRSA鍵ペアを生成する。"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def _create_jwks_from_public_key(public_key, kid="test-kid"):
    """公開鍵からJWKS形式のデータを生成する。"""
    from jwt.algorithms import RSAAlgorithm

    jwk_dict = RSAAlgorithm.to_jwk(public_key, as_dict=True)
    jwk_dict["kid"] = kid
    jwk_dict["use"] = "sig"
    jwk_dict["alg"] = "RS256"
    return {"keys": [jwk_dict]}


def _create_test_token(
    private_key,
    kid="test-kid",
    issuer="http://localhost:8080/realms/estat",
    audience="estat-mcp-client",
    roles=None,
    exp_offset=3600,
    extra_claims=None,
):
    """テスト用JWTトークンを生成する。"""
    now = int(time.time())
    payload = {
        "sub": "test-user-id",
        "iss": issuer,
        "aud": audience,
        "exp": now + exp_offset,
        "iat": now,
    }
    if roles is not None:
        payload["realm_roles"] = roles
    if extra_claims:
        payload.update(extra_claims)

    return pyjwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={"kid": kid},
    )


# --- フィクスチャ ---


@pytest.fixture(autouse=True)
def clear_jwks_cache():
    """各テスト前にJWKSキャッシュをクリアする。"""
    invalidate_jwks_cache()
    yield
    invalidate_jwks_cache()


@pytest.fixture
def rsa_keys():
    """テスト用RSA鍵ペアを提供する。"""
    return _generate_rsa_key_pair()


@pytest.fixture
def jwks_data(rsa_keys):
    """テスト用JWKSデータを提供する。"""
    _, public_key = rsa_keys
    return _create_jwks_from_public_key(public_key)


# --- extract_roles テスト ---


class TestExtractRoles:
    def test_realm_roles_list(self):
        payload = {"realm_roles": ["admin", "viewer"]}
        assert extract_roles(payload) == ["admin", "viewer"]

    def test_realm_roles_string(self):
        payload = {"realm_roles": "admin"}
        assert extract_roles(payload) == ["admin"]

    def test_realm_access_fallback(self):
        payload = {"realm_access": {"roles": ["admin", "viewer"]}}
        assert extract_roles(payload) == ["admin", "viewer"]

    def test_no_roles(self):
        payload = {"sub": "test"}
        assert extract_roles(payload) == []

    def test_empty_realm_roles(self):
        payload = {"realm_roles": []}
        assert extract_roles(payload) == []


# --- get_primary_role テスト ---


class TestGetPrimaryRole:
    def test_admin_takes_priority(self):
        payload = {"realm_roles": ["viewer", "admin"]}
        assert get_primary_role(payload) == "admin"

    def test_viewer_only(self):
        payload = {"realm_roles": ["viewer"]}
        assert get_primary_role(payload) == "viewer"

    def test_admin_only(self):
        payload = {"realm_roles": ["admin"]}
        assert get_primary_role(payload) == "admin"

    def test_no_known_roles(self):
        payload = {"realm_roles": ["unknown"]}
        assert get_primary_role(payload) is None

    def test_empty_payload(self):
        assert get_primary_role({}) is None


# --- verify_token テスト ---


class TestVerifyToken:
    @patch("src.jwt_auth._fetch_jwks")
    def test_valid_token(self, mock_fetch, rsa_keys, jwks_data):
        """有効なトークンで検証が成功すること。"""
        private_key, _ = rsa_keys
        mock_fetch.return_value = jwks_data
        token = _create_test_token(private_key, roles=["admin"])

        payload = verify_token(token)

        assert payload["sub"] == "test-user-id"
        assert payload["realm_roles"] == ["admin"]

    @patch("src.jwt_auth._fetch_jwks")
    def test_expired_token(self, mock_fetch, rsa_keys, jwks_data):
        """期限切れトークンでExpiredSignatureErrorが発生すること。"""
        private_key, _ = rsa_keys
        mock_fetch.return_value = jwks_data
        token = _create_test_token(private_key, exp_offset=-3600)

        with pytest.raises(pyjwt.ExpiredSignatureError):
            verify_token(token)

    @patch("src.jwt_auth._fetch_jwks")
    def test_invalid_audience(self, mock_fetch, rsa_keys, jwks_data):
        """不正なaudienceでInvalidAudienceErrorが発生すること。"""
        private_key, _ = rsa_keys
        mock_fetch.return_value = jwks_data
        token = _create_test_token(private_key, audience="wrong-client")

        with pytest.raises(pyjwt.InvalidAudienceError):
            verify_token(token)

    @patch("src.jwt_auth._fetch_jwks")
    def test_invalid_issuer(self, mock_fetch, rsa_keys, jwks_data):
        """不正なissuerでInvalidIssuerErrorが発生すること。"""
        private_key, _ = rsa_keys
        mock_fetch.return_value = jwks_data
        token = _create_test_token(private_key, issuer="http://evil.example.com/realms/fake")

        with pytest.raises(pyjwt.InvalidIssuerError):
            verify_token(token)

    @patch("src.jwt_auth._fetch_jwks")
    def test_wrong_signature(self, mock_fetch, jwks_data):
        """異なる鍵で署名したトークンで検証が失敗すること。"""
        other_private_key, _ = _generate_rsa_key_pair()
        mock_fetch.return_value = jwks_data
        token = _create_test_token(other_private_key)

        with pytest.raises(pyjwt.InvalidTokenError):
            verify_token(token)

    def test_malformed_token(self):
        """不正な形式のトークンでエラーが発生すること。"""
        with pytest.raises(pyjwt.InvalidTokenError):
            verify_token("not-a-valid-jwt")

    @patch("src.jwt_auth._fetch_jwks")
    def test_missing_kid_in_header(self, mock_fetch, rsa_keys, jwks_data):
        """kidがないトークンでエラーが発生すること。"""
        private_key, _ = rsa_keys
        mock_fetch.return_value = jwks_data

        now = int(time.time())
        token = pyjwt.encode(
            {"sub": "test", "iss": "http://localhost:8080/realms/estat",
             "aud": "estat-mcp-client", "exp": now + 3600, "iat": now},
            private_key,
            algorithm="RS256",
            # headers に kid を設定しない
        )

        with pytest.raises(pyjwt.InvalidTokenError, match="kid"):
            verify_token(token)

    @patch("src.jwt_auth._fetch_jwks")
    def test_unknown_kid_triggers_cache_refresh(self, mock_fetch, rsa_keys, jwks_data):
        """未知のkidの場合にJWKSを再取得すること。"""
        private_key, public_key = rsa_keys
        # 最初のフェッチは空、再取得で正しいJWKSを返す
        empty_jwks = {"keys": []}
        new_jwks = _create_jwks_from_public_key(public_key, kid="new-kid")
        mock_fetch.side_effect = [empty_jwks, new_jwks]

        token = _create_test_token(private_key, kid="new-kid")
        payload = verify_token(token)
        assert payload["sub"] == "test-user-id"
        assert mock_fetch.call_count == 2


# --- JWKSキャッシュのテスト ---


class TestJwksCache:
    @patch("src.jwt_auth.httpx.get")
    def test_cache_prevents_repeated_fetches(self, mock_get, jwks_data):
        """キャッシュが有効な間はHTTPリクエストが1回のみであること。"""
        mock_response = MagicMock()
        mock_response.json.return_value = jwks_data
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        _fetch_jwks()
        _fetch_jwks()
        _fetch_jwks()

        assert mock_get.call_count == 1

    @patch("src.jwt_auth.httpx.get")
    def test_cache_expiry_triggers_refetch(self, mock_get, jwks_data):
        """キャッシュTTL超過後に再取得されること。"""
        mock_response = MagicMock()
        mock_response.json.return_value = jwks_data
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        import src.jwt_auth as jwt_auth_module

        _fetch_jwks()
        # キャッシュタイムスタンプを過去に設定
        jwt_auth_module._jwks_cache_timestamp = time.time() - 600

        _fetch_jwks()

        assert mock_get.call_count == 2

    @patch("src.jwt_auth.httpx.get")
    def test_fetch_failure_uses_stale_cache(self, mock_get, jwks_data):
        """JWKS取得失敗時に期限切れキャッシュを使用すること。"""
        import httpx as httpx_module
        import src.jwt_auth as jwt_auth_module

        mock_response = MagicMock()
        mock_response.json.return_value = jwks_data
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        _fetch_jwks()

        # キャッシュを期限切れにして、次のフェッチを失敗させる
        jwt_auth_module._jwks_cache_timestamp = time.time() - 600
        mock_get.side_effect = httpx_module.ConnectError("Connection refused")

        result = _fetch_jwks()
        assert "keys" in result
