# estat-mcp

e-Stat API MCP server with Keycloak JWT authentication.

## Prerequisites

- Python 3.11+
- Docker & Docker Compose

## Keycloak Setup

### 起動

```bash
make keycloak-up
```

初回起動時に以下が自動作成されます:

- Realm: `estat`
- Client: `estat-mcp-client` (secret: `estat-mcp-secret`)
- Realm Roles: `admin`, `viewer`
- Test Users:
  - `test-admin` (password: `password`, role: `admin`)
  - `test-viewer` (password: `password`, role: `viewer`)

### 管理コンソール

http://localhost:8080 にアクセス（admin / admin）

### トークン取得

```bash
# test-admin ユーザーでトークン取得
make keycloak-token-admin

# test-viewer ユーザーでトークン取得
make keycloak-token-viewer

# curl で直接取得
curl -s -X POST http://localhost:8080/realms/estat/protocol/openid-connect/token \
  -d "client_id=estat-mcp-client" \
  -d "client_secret=estat-mcp-secret" \
  -d "grant_type=password" \
  -d "username=test-admin" \
  -d "password=password" | python3 -m json.tool
```

### 停止

```bash
make keycloak-down
```
