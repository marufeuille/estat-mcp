from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from src.auth import current_role


class RoleMiddleware(BaseHTTPMiddleware):
    """X-Role ヘッダーを current_role ContextVar に設定するミドルウェア。"""

    async def dispatch(self, request: Request, call_next):
        role = request.headers.get("X-Role")
        token = current_role.set(role)
        try:
            return await call_next(request)
        finally:
            current_role.reset(token)
