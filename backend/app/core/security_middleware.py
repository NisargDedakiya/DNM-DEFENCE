"""
Cross-cutting security middleware: response headers and the rate limiter
instance shared across routers. Kept separate from main.py so it's easy
to unit test and reason about independently of route wiring.
"""
from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings

limiter = Limiter(key_func=get_remote_address, default_limits=[settings.RATE_LIMIT_DEFAULT])


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Adds standard defensive headers to every response. This is an API
    backend (JSON responses, no server-rendered HTML), so the CSP is
    intentionally locked down to default-src 'none' -- there's nothing
    here for a browser to execute or render.
    """

    async def dispatch(self, request, call_next):
        response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        )
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"

        if settings.FORCE_HTTPS:
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"

        return response
