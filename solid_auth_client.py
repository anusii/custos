"""
Solid-OIDC client-credentials + DPoP support for the Custos broker.

Gives the broker its *own* authenticated identity so it can read a POD that is
no longer public-read, instead of relying solely on the grants.json consent
gate to protect world-readable data. Talks to Community Solid Server's
Client Credentials grant (https://communitysolidserver.github.io/CommunitySolidServer/latest/usage/client-credentials/),
binding the issued access token to a DPoP keypair per RFC 9449.

Entirely optional: if POD_OIDC_CLIENT_ID / POD_OIDC_CLIENT_SECRET are not set,
get_access_token() returns None and server.py falls back to today's
unauthenticated GET.

Config (environment variables):
    POD_OIDC_CLIENT_ID       id half of a CSS client-credentials pair.
    POD_OIDC_CLIENT_SECRET   secret half of a CSS client-credentials pair.
    POD_OIDC_TOKEN_ENDPOINT  Optional override. If unset, discovered from
                             <origin of POD_BASE_URL>/.well-known/openid-configuration.

discover() fetches and caches that same discovery document;
broker_token_verifier.py reuses it to find the JWKS endpoint for validating
*incoming* MCP-client tokens' signatures locally — a separate concern from
this module's job of acquiring the broker's own outgoing token.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT

CLIENT_ID = os.environ.get("POD_OIDC_CLIENT_ID")
CLIENT_SECRET = os.environ.get("POD_OIDC_CLIENT_SECRET")
TOKEN_ENDPOINT_OVERRIDE = os.environ.get("POD_OIDC_TOKEN_ENDPOINT")
POD_BASE_URL = os.environ.get("POD_BASE_URL")

HOME = Path(os.environ.get("SOLIDMCP_HOME", Path(__file__).parent)).resolve()
DPOP_KEY_PATH = HOME / "dpop_key.json"

# Refresh proactively once fewer than this many seconds of validity remain.
TOKEN_REFRESH_MARGIN = 60

_dpop_key: JWK | None = None
_token_cache: dict[str, Any] = {"access_token": None, "expires_at": 0.0}
_discovery_doc_cache: dict[str, Any] | None = None


def _configured() -> bool:
    return bool(CLIENT_ID and CLIENT_SECRET)


# --------------------------------------------------------------------------- #
# DPoP key management (RFC 9449)
# --------------------------------------------------------------------------- #

def _get_or_create_dpop_key() -> JWK:
    global _dpop_key
    if _dpop_key is not None:
        return _dpop_key
    if DPOP_KEY_PATH.exists():
        _dpop_key = JWK.from_json(DPOP_KEY_PATH.read_text(encoding="utf-8"))
        return _dpop_key
    key = JWK.generate(kty="RSA", size=2048, alg="RS256", use="sig")
    try:
        DPOP_KEY_PATH.write_text(key.export_private(), encoding="utf-8")
        try:
            os.chmod(DPOP_KEY_PATH, 0o600)
        except OSError:
            pass  # no-op on Windows; real protection there needs icacls.
    except OSError:
        pass  # Key still works for this run even if it can't be persisted.
    _dpop_key = key
    return key


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _build_dpop_proof(htu: str, htm: str, access_token: str | None = None) -> str:
    """Build and sign one DPoP proof JWT. Proofs are single-use — call this
    fresh for every request, never reuse one."""
    key = _get_or_create_dpop_key()
    claims = {
        "htu": urlunsplit(urlsplit(htu)._replace(query="", fragment="")),
        "htm": htm,
        "jti": secrets.token_urlsafe(16),
        "iat": int(time.time()),
    }
    if access_token is not None:
        # ath is only present on resource requests, never on the token-endpoint
        # request that mints the token in the first place.
        claims["ath"] = _b64url(hashlib.sha256(access_token.encode("ascii")).digest())
    header = {
        "typ": "dpop+jwt",
        "alg": "RS256",
        "jwk": key.export_public(as_dict=True),
    }
    token = JWT(header=header, claims=claims)
    token.make_signed_token(key)
    return token.serialize()


# --------------------------------------------------------------------------- #
# Token-endpoint discovery + acquisition
# --------------------------------------------------------------------------- #

def discover(pod_base_url: str | None = None) -> dict[str, Any] | None:
    """Fetch and cache the issuer's OIDC discovery document (once per process).
    Used for both the token endpoint (this module) and the JWKS endpoint
    (broker_token_verifier.py) — one shared cache, one HTTP call."""
    global _discovery_doc_cache
    if _discovery_doc_cache is not None:
        return _discovery_doc_cache
    base = pod_base_url or POD_BASE_URL
    if not base:
        return None
    origin = urlsplit(base)
    discovery_url = f"{origin.scheme}://{origin.netloc}/.well-known/openid-configuration"
    try:
        resp = httpx.get(discovery_url, timeout=10.0)
        resp.raise_for_status()
        _discovery_doc_cache = resp.json()
    except (httpx.HTTPError, ValueError):
        return None
    return _discovery_doc_cache


def _discover_token_endpoint() -> str | None:
    if TOKEN_ENDPOINT_OVERRIDE:
        return TOKEN_ENDPOINT_OVERRIDE
    doc = discover()
    return doc.get("token_endpoint") if doc else None


def _request_access_token() -> dict[str, Any] | None:
    token_endpoint = _discover_token_endpoint()
    if not token_endpoint:
        return None
    proof = _build_dpop_proof(htu=token_endpoint, htm="POST")
    try:
        resp = httpx.post(
            token_endpoint,
            data={"grant_type": "client_credentials"},
            auth=(CLIENT_ID, CLIENT_SECRET),
            headers={"DPoP": proof},
            timeout=10.0,
        )
        resp.raise_for_status()
        payload = resp.json()
    except (httpx.HTTPError, ValueError):
        return None
    if not payload.get("access_token") or payload.get("token_type", "").lower() != "dpop":
        return None
    return payload


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def get_access_token() -> str | None:
    """Return a cached-or-fresh DPoP-bound access token, or None if broker
    auth isn't configured (or acquisition failed) — callers must treat None
    as "fall back to unauthenticated"."""
    if not _configured():
        return None
    if _token_cache["access_token"] and _token_cache["expires_at"] - time.time() > TOKEN_REFRESH_MARGIN:
        return _token_cache["access_token"]
    payload = _request_access_token()
    if payload is None:
        return None
    _token_cache["access_token"] = payload["access_token"]
    _token_cache["expires_at"] = time.time() + float(payload.get("expires_in", 0))
    return _token_cache["access_token"]


def build_resource_dpop_proof(url: str, method: str, access_token: str) -> str:
    """Proof for an authenticated resource request (includes ath)."""
    return _build_dpop_proof(htu=url, htm=method, access_token=access_token)


def invalidate_token() -> None:
    """Drop the cached token, e.g. after a 401 from the POD."""
    _token_cache["access_token"] = None
    _token_cache["expires_at"] = 0.0
