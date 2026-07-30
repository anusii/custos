"""
MCP-client -> broker authentication: validates Bearer tokens presented by MCP
clients (Claude, MCP Inspector, ...) calling the broker over streamable-HTTP.

This is the other half of the OAuth story from solid_auth_client.py: that
module gets the *broker* a token to present to the *POD*; this module checks
tokens *other callers* present to the *broker*. Both reuse the same
Authorization Server (CSS, via solid_auth_client.discover()).

Validates tokens by verifying their signature locally against CSS's published
JWKS (RFC 9068 JWT access tokens) rather than calling CSS's token
introspection endpoint. Introspection was tried first, but empirically CSS's
introspection endpoint is scoped to the introspecting client's own tokens: a
token freshly issued to a *different* (dynamically-registered) client came
back `{"active": false}` even though valid. That's a policy of the shared dev
instance, not something we administer or can fix here. JWKS-based signature
verification has no such restriction — it only needs the AS's public signing
keys, which are public by definition, so it works for any client's token and
also avoids a network round-trip to the AS on every call.

Bearer tokens only, no DPoP: Claude's MCP client does not implement DPoP, so
a DPoP requirement on this leg would break the primary test/target client
(broker -> POD keeps DPoP, since CSS and solid_auth_client both speak it —
that is a separate, unrelated leg).

Known limitation (accepted for this phase): CSS does not bind the token's
`aud` claim to the `resource` parameter we request (RFC 8707) — empirically,
`aud` is always the fixed string "solid" regardless of what resource was
requested. So this verifier checks signature validity and expiry, but not
audience match. Fails closed: any missing config, network error, signature
failure, or expired token results in verify_token() returning None, which the
mcp SDK's RequireAuthMiddleware treats as an invalid token (401).
"""

from __future__ import annotations

import json
from typing import Any

import httpx
from jwcrypto.jwk import JWKSet
from jwcrypto.jwt import JWT

from mcp.server.auth.provider import AccessToken, TokenVerifier

import solid_auth_client

_jwks_cache: JWKSet | None = None


def _get_jwks() -> JWKSet | None:
    """Fetch and cache the Authorization Server's public signing keys (once
    per process — a key rotation on CSS's side would need a broker restart,
    an accepted limitation for this phase)."""
    global _jwks_cache
    if _jwks_cache is not None:
        return _jwks_cache
    doc = solid_auth_client.discover()
    jwks_uri = doc.get("jwks_uri") if doc else None
    if not jwks_uri:
        return None
    try:
        resp = httpx.get(jwks_uri, timeout=10.0)
        resp.raise_for_status()
        _jwks_cache = JWKSet.from_json(resp.text)
    except (httpx.HTTPError, ValueError):
        return None
    return _jwks_cache


class CustosTokenVerifier(TokenVerifier):
    """Validates MCP-client Bearer tokens by verifying their JWT signature
    locally against CSS's JWKS."""

    async def verify_token(self, token: str) -> AccessToken | None:
        jwks = _get_jwks()
        if jwks is None:
            return None

        try:
            verified = JWT(jwt=token, key=jwks)
            claims: dict[str, Any] = json.loads(verified.claims)
        except Exception:
            # Fail closed on any signature/expiry/format problem — a
            # prototype-appropriate catch-all, matching _load_grants()'s
            # posture in server.py of failing closed on malformed input.
            return None

        scope = claims.get("scope", "")
        return AccessToken(
            token=token,
            client_id=claims.get("client_id", "unknown"),
            scopes=scope.split() if scope else [],
            expires_at=claims.get("exp"),
            resource=claims.get("aud"),
            subject=claims.get("webid") or claims.get("sub"),
            claims=claims,
        )
