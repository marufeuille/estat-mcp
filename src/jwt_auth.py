"""KeycloakのJWKSエンドポイントからJWTトークンを検証するモジュール。"""

import logging
import time
from typing import Any

import httpx
import jwt

from src.config import KEYCLOAK_AUDIENCE, KEYCLOAK_REALM, KEYCLOAK_URL, JWKS_CACHE_TTL

logger = logging.getLogger(__name__)

# JWKSキャッシュ
_jwks_cache: dict[str, Any] = {}
_jwks_cache_timestamp: float = 0.0


def _get_issuer_url() -> str:
    """KeycloakのIssuer URLを構築する。"""
    return f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}"


def _get_jwks_url() -> str:
    """KeycloakのJWKS URLを構築する。"""
    return f"{_get_issuer_url()}/protocol/openid-connect/certs"


def _fetch_jwks() -> dict[str, Any]:
    """KeycloakのJWKSエンドポイントから公開鍵を取得する（キャッシュ付き）。"""
    global _jwks_cache, _jwks_cache_timestamp

    now = time.time()
    if _jwks_cache and (now - _jwks_cache_timestamp) < JWKS_CACHE_TTL:
        logger.debug("[JWT] JWKSキャッシュヒット (age=%.0fs)", now - _jwks_cache_timestamp)
        return _jwks_cache

    jwks_url = _get_jwks_url()
    logger.info("[JWT] JWKSエンドポイントから公開鍵を取得: %s", jwks_url)
    try:
        response = httpx.get(jwks_url, timeout=10.0)
        response.raise_for_status()
        _jwks_cache = response.json()
        _jwks_cache_timestamp = now
        logger.info("[JWT] JWKS取得成功 (keys=%d)", len(_jwks_cache.get("keys", [])))
        return _jwks_cache
    except httpx.HTTPError as e:
        logger.error("[JWT] JWKS取得失敗: %s", e)
        # キャッシュが残っていれば返す（graceful degradation）
        if _jwks_cache:
            logger.warning("[JWT] 期限切れのJWKSキャッシュを使用")
            return _jwks_cache
        raise


def invalidate_jwks_cache() -> None:
    """JWKSキャッシュを無効化する（テスト用）。"""
    global _jwks_cache, _jwks_cache_timestamp
    _jwks_cache = {}
    _jwks_cache_timestamp = 0.0


def _find_key_by_kid(jwks_data: dict[str, Any], kid: str) -> Any | None:
    """JWKSデータからkidに一致する鍵を検索する。"""
    keys = jwks_data.get("keys", [])
    if not keys:
        return None
    jwk_set = jwt.PyJWKSet.from_dict(jwks_data)
    for key in jwk_set.keys:
        if key.key_id == kid:
            return key
    return None


def verify_token(token: str) -> dict[str, Any]:
    """JWTトークンを検証し、ペイロードを返す。

    検証項目:
    - 署名（KeycloakのJWKS公開鍵で検証）
    - 有効期限（exp クレーム）
    - 発行者（iss クレーム）
    - 対象者（aud クレーム）

    Args:
        token: Bearer トークン文字列

    Returns:
        検証済みのJWTペイロード（dict）

    Raises:
        jwt.InvalidTokenError: トークンが無効な場合
    """
    # トークンのヘッダーからkidを取得（不正なトークンはここでDecodeErrorになる）
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.DecodeError as e:
        raise jwt.InvalidTokenError(f"Malformed token: {e}") from e

    kid = unverified_header.get("kid")

    if not kid:
        raise jwt.InvalidTokenError("Token header missing 'kid'")

    jwks_data = _fetch_jwks()

    # kidに対応する鍵を検索
    signing_key = _find_key_by_kid(jwks_data, kid)

    if signing_key is None:
        # kidが見つからない場合、JWKSを再取得して再試行
        logger.info("[JWT] kid=%s が見つからないためJWKSを再取得", kid)
        invalidate_jwks_cache()
        jwks_data = _fetch_jwks()
        signing_key = _find_key_by_kid(jwks_data, kid)
        if signing_key is None:
            raise jwt.InvalidTokenError(f"No matching key found for kid: {kid}")

    issuer = _get_issuer_url()

    payload = jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=KEYCLOAK_AUDIENCE,
        issuer=issuer,
        options={
            "verify_exp": True,
            "verify_iss": True,
            "verify_aud": True,
        },
    )

    logger.debug("[JWT] トークン検証成功: sub=%s", payload.get("sub"))
    return payload


def extract_roles(payload: dict[str, Any]) -> list[str]:
    """JWTペイロードからレルムロールを抽出する。

    KeycloakのprotocolMapperで設定した `realm_roles` クレームからロールを取得する。
    フォールバックとして `realm_access.roles` も確認する。

    Args:
        payload: 検証済みのJWTペイロード

    Returns:
        ロール名のリスト
    """
    # カスタムクレーム（realm-roles-mapper で設定済み）
    roles = payload.get("realm_roles")
    if isinstance(roles, list):
        return roles
    if isinstance(roles, str):
        return [roles]

    # フォールバック: Keycloak標準の realm_access.roles
    realm_access = payload.get("realm_access", {})
    if isinstance(realm_access, dict):
        roles = realm_access.get("roles", [])
        if isinstance(roles, list):
            return roles

    return []


def get_primary_role(payload: dict[str, Any]) -> str | None:
    """JWTペイロードからプライマリロール（admin > viewer）を取得する。

    Args:
        payload: 検証済みのJWTペイロード

    Returns:
        "admin", "viewer", or None
    """
    roles = extract_roles(payload)
    # 優先順位: admin > viewer
    if "admin" in roles:
        return "admin"
    if "viewer" in roles:
        return "viewer"
    return None
