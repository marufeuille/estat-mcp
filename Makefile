.PHONY: keycloak-up keycloak-down keycloak-logs keycloak-token-admin keycloak-token-viewer

# ========== Keycloak ==========

## Keycloak + PostgreSQL を起動
keycloak-up:
	docker compose up -d

## Keycloak + PostgreSQL を停止
keycloak-down:
	docker compose down

## Keycloak のログを表示
keycloak-logs:
	docker compose logs -f keycloak

## test-admin ユーザーで JWT トークンを取得
keycloak-token-admin:
	@curl -s -X POST http://localhost:8080/realms/estat/protocol/openid-connect/token \
		-d "client_id=estat-mcp-client" \
		-d "client_secret=estat-mcp-secret" \
		-d "grant_type=password" \
		-d "username=test-admin" \
		-d "password=password" | python3 -m json.tool

## test-viewer ユーザーで JWT トークンを取得
keycloak-token-viewer:
	@curl -s -X POST http://localhost:8080/realms/estat/protocol/openid-connect/token \
		-d "client_id=estat-mcp-client" \
		-d "client_secret=estat-mcp-secret" \
		-d "grant_type=password" \
		-d "username=test-viewer" \
		-d "password=password" | python3 -m json.tool
