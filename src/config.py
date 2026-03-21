import os
from dotenv import load_dotenv

load_dotenv()

ESTAT_APP_ID = os.environ.get("ESTAT_APP_ID", "")

# 認証モード: "keycloak" (JWT検証) or "mock" (X-Roleヘッダー)
AUTH_MODE = os.environ.get("AUTH_MODE", "mock")

# Keycloak設定
KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://localhost:8080")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "estat")
KEYCLOAK_AUDIENCE = os.environ.get("KEYCLOAK_AUDIENCE", "estat-mcp-client")

# JWKS公開鍵キャッシュTTL（秒）
JWKS_CACHE_TTL = int(os.environ.get("JWKS_CACHE_TTL", "300"))
