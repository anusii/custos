"""
Solid-OIDC auth for the Custos broker's own outgoing identity (broker -> POD),
DPoP-bound per RFC 9449. Two ways to get an access token, tried in this order:

    1. Refresh-token grant, using a token obtained via login_with_pkce() (a
       real interactive Authorization Code + PKCE login, done once by
       setup_gui.py) and stored in the OS keyring. This is the primary path
       for the local-background-service model: a real user login, not a
       standing machine credential.
    2. Client-credentials grant (POD_OIDC_CLIENT_ID/SECRET env vars) --
       Community Solid Server's Client Credentials extension
       (https://communitysolidserver.github.io/CommunitySolidServer/latest/usage/client-credentials/).
       Kept as a fallback for automation/testing where an interactive login
       isn't practical; unaffected by the addition above.

If neither is available, get_access_token() returns None and server.py falls
back to an unauthenticated GET.

Config:
    POD_BASE_URL             Env var, or falls back to ~/.custos/config.json's
                             "pod_base_url" (written by setup_gui.py).
    POD_OIDC_CLIENT_ID       Client-credentials fallback (path 2 above).
    POD_OIDC_CLIENT_SECRET
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
import http.server
import json
import os
import secrets
import socket
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlsplit, urlunsplit

import httpx
import keyring
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT
from rdflib import Graph, URIRef

CLIENT_ID = os.environ.get("POD_OIDC_CLIENT_ID")
CLIENT_SECRET = os.environ.get("POD_OIDC_CLIENT_SECRET")
TOKEN_ENDPOINT_OVERRIDE = os.environ.get("POD_OIDC_TOKEN_ENDPOINT")

CONFIG_PATH = Path.home() / ".custos" / "config.json"


def _load_local_config() -> dict[str, Any]:
    if not CONFIG_PATH.exists():
        return {}
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


_local_config = _load_local_config()
POD_BASE_URL = os.environ.get("POD_BASE_URL") or _local_config.get("pod_base_url")
ENCRYPTION_BASE_URL = os.environ.get("POD_ENCRYPTION_BASE_URL") or _local_config.get("encryption_base_url")


def pod_root_url() -> str | None:
    """The POD's own root container (e.g. https://pod/username/), used to
    compute the POD-relative resource paths solidpod's ind-keys.ttl indexes
    by. Falls back to origin + first path segment of POD_BASE_URL if not
    explicitly configured -- a CSS-shaped heuristic (<origin>/<username>/),
    override with POD_ROOT_URL if a different provider lays pods out
    differently."""
    override = os.environ.get("POD_ROOT_URL") or _local_config.get("pod_root_url")
    if override:
        return override
    if not POD_BASE_URL:
        return None
    parts = urlsplit(POD_BASE_URL)
    segments = [s for s in parts.path.split("/") if s]
    if not segments:
        return f"{parts.scheme}://{parts.netloc}/"
    return f"{parts.scheme}://{parts.netloc}/{segments[0]}/"


HOME = Path(os.environ.get("SOLIDMCP_HOME", Path(__file__).parent)).resolve()
DPOP_KEY_PATH = HOME / "dpop_key.json"

KEYRING_SERVICE = "custos-broker"
KEYRING_REFRESH_TOKEN = "refresh_token"
KEYRING_LOGIN_CLIENT_ID = "login_client_id"

# Refresh proactively once fewer than this many seconds of validity remain.
TOKEN_REFRESH_MARGIN = 60

_dpop_key: JWK | None = None
_token_cache: dict[str, Any] = {"access_token": None, "expires_at": 0.0}
_discovery_doc_cache: dict[str, Any] | None = None


def _configured() -> bool:
    return bool(CLIENT_ID and CLIENT_SECRET)


def _get_stored_refresh_token() -> str | None:
    return keyring.get_password(KEYRING_SERVICE, KEYRING_REFRESH_TOKEN)


def _store_refresh_token(refresh_token: str) -> None:
    keyring.set_password(KEYRING_SERVICE, KEYRING_REFRESH_TOKEN, refresh_token)


def _get_stored_login_client_id() -> str | None:
    return keyring.get_password(KEYRING_SERVICE, KEYRING_LOGIN_CLIENT_ID)


def _store_login_client_id(client_id: str) -> None:
    keyring.set_password(KEYRING_SERVICE, KEYRING_LOGIN_CLIENT_ID, client_id)


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
# WebID -> issuer discovery (used by setup_gui.py before login)
# --------------------------------------------------------------------------- #

SOLID_OIDC_ISSUER_PRED = URIRef("http://www.w3.org/ns/solid/terms#oidcIssuer")


def discover_issuer_from_webid(webid_url: str) -> str | None:
    """Fetch a WebID profile document and return its solid:oidcIssuer, or
    None if unreachable/not found."""
    try:
        resp = httpx.get(webid_url, headers={"Accept": "text/turtle"}, timeout=10.0)
        resp.raise_for_status()
    except httpx.HTTPError:
        return None
    g = Graph()
    try:
        g.parse(data=resp.text, format="turtle", publicID=webid_url)
    except Exception:
        return None
    for _, _, obj in g.triples((URIRef(webid_url), SOLID_OIDC_ISSUER_PRED, None)):
        return str(obj)
    return None


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


def _request_access_token_via_refresh(refresh_token: str, client_id: str, token_endpoint: str) -> dict[str, Any] | None:
    # client_id is required in the body here even though there's no secret:
    # this is a public client (token_endpoint_auth_method=none), and RFC 6749
    # still requires client_id to identify which registered client is
    # refreshing -- omitting it is silently rejected by CSS's oidc-provider.
    proof = _build_dpop_proof(htu=token_endpoint, htm="POST")
    try:
        resp = httpx.post(
            token_endpoint,
            data={"grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": client_id},
            headers={"DPoP": proof},
            timeout=10.0,
        )
        resp.raise_for_status()
        payload = resp.json()
    except (httpx.HTTPError, ValueError):
        return None
    if not payload.get("access_token"):
        return None
    return payload


# --------------------------------------------------------------------------- #
# Interactive login (Authorization Code + PKCE + dynamic client registration)
#
# Used once by setup_gui.py to obtain the broker's own persistent identity
# for the user's POD -- a real login, not a standing machine credential. The
# resulting refresh token is stored via keyring; ongoing access-token
# acquisition (get_access_token(), below) uses it without any further
# interaction. This is the same PKCE+DCR+loopback-redirect pattern already
# proven end-to-end in oauth_test_client.py, repurposed: there, Claude was
# the client logging into the broker; here, the broker is the client logging
# into the user's own POD.
# --------------------------------------------------------------------------- #

def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def login_with_pkce(issuer_url: str, timeout: float = 180.0) -> dict[str, Any] | None:
    """Blocking. Opens the system browser for the user to log into
    `issuer_url` and approve; waits for the redirect on a local loopback
    listener. Returns the full token payload (including refresh_token, since
    offline_access is requested) or None on any failure. Never raises for
    expected failure modes (network errors, user denial, timeout) -- callers
    should treat None as "login didn't succeed" and surface that plainly."""
    doc = discover(issuer_url)
    if not doc:
        return None
    authorization_endpoint = doc.get("authorization_endpoint")
    token_endpoint = doc.get("token_endpoint")
    registration_endpoint = doc.get("registration_endpoint")
    if not (authorization_endpoint and token_endpoint and registration_endpoint):
        return None

    port = _find_free_port()
    redirect_uri = f"http://127.0.0.1:{port}/callback"

    try:
        resp = httpx.post(
            registration_endpoint,
            json={
                "client_name": "custos-broker",
                "redirect_uris": [redirect_uri],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            },
            timeout=10.0,
        )
        resp.raise_for_status()
        client_id = resp.json()["client_id"]
    except (httpx.HTTPError, ValueError, KeyError):
        return None

    code_verifier = secrets.token_urlsafe(64)
    code_challenge = _b64url(hashlib.sha256(code_verifier.encode()).digest())
    state = secrets.token_urlsafe(16)

    auth_url = f"{authorization_endpoint}?" + urlencode(
        {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid webid offline_access",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            # CSS's oidc-provider only issues a refresh token for
            # offline_access when consent is explicitly (re-)prompted, not
            # just requested -- confirmed by the same behavior in solid_auth's
            # Dart reference (SolidOidcManagerFactory forces this too).
            "prompt": "consent",
        }
    )

    result: dict[str, Any] = {}
    done = threading.Event()

    class _CallbackHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            params = parse_qs(urlparse(self.path).query)
            result["code"] = params.get("code", [None])[0]
            result["state"] = params.get("state", [None])[0]
            result["error"] = params.get("error", [None])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>Login complete. You can close this tab.</body></html>")
            done.set()

        def log_message(self, format, *args):
            pass  # keep stdout clean

    httpd = http.server.HTTPServer(("127.0.0.1", port), _CallbackHandler)
    threading.Thread(target=httpd.handle_request, daemon=True).start()
    webbrowser.open(auth_url)

    if not done.wait(timeout=timeout):
        return None
    if result.get("error") or result.get("state") != state:
        return None
    code = result.get("code")
    if not code:
        return None

    proof = _build_dpop_proof(htu=token_endpoint, htm="POST")
    try:
        resp = httpx.post(
            token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "code_verifier": code_verifier,
            },
            headers={"DPoP": proof},
            timeout=10.0,
        )
        resp.raise_for_status()
        payload = resp.json()
    except (httpx.HTTPError, ValueError):
        return None
    if not payload.get("access_token"):
        return None
    # Dynamic registration mints a fresh client_id every login; callers need
    # it to make later refresh_token requests (a public client's refresh
    # request must still identify itself). Not a normal token-response
    # field, so it isn't overwritten by anything the AS returns.
    payload["client_id"] = client_id
    return payload


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def get_access_token() -> str | None:
    """Return a cached-or-fresh DPoP-bound access token, or None if broker
    auth isn't configured (or acquisition failed) — callers must treat None
    as "fall back to unauthenticated". Tries, in order: (1) a refresh token
    from a prior login_with_pkce() login, stored via keyring; (2) the
    client-credentials fallback (POD_OIDC_CLIENT_ID/SECRET)."""
    if _token_cache["access_token"] and _token_cache["expires_at"] - time.time() > TOKEN_REFRESH_MARGIN:
        return _token_cache["access_token"]

    refresh_token = _get_stored_refresh_token()
    login_client_id = _get_stored_login_client_id()
    if refresh_token and login_client_id:
        token_endpoint = _discover_token_endpoint()
        if token_endpoint:
            payload = _request_access_token_via_refresh(refresh_token, login_client_id, token_endpoint)
            if payload is not None:
                if payload.get("refresh_token"):
                    # Some ASes rotate the refresh token on each use.
                    _store_refresh_token(payload["refresh_token"])
                _token_cache["access_token"] = payload["access_token"]
                _token_cache["expires_at"] = time.time() + float(payload.get("expires_in", 0))
                return _token_cache["access_token"]

    if not _configured():
        return None
    payload = _request_access_token()
    if payload is None:
        return None
    _token_cache["access_token"] = payload["access_token"]
    _token_cache["expires_at"] = time.time() + float(payload.get("expires_in", 0))
    return _token_cache["access_token"]


def build_resource_dpop_proof(url: str, method: str, access_token: str) -> str:
    """Proof for an authenticated resource request (includes ath)."""
    return _build_dpop_proof(htu=url, htm=method, access_token=access_token)


def authenticated_headers(url: str, token: str) -> dict[str, str]:
    """Headers for one authenticated GET, DPoP-bound to this exact token.
    Shared by server.py's _fetch_graph() and setup_gui.py's key-file reads."""
    return {
        "Accept": "text/turtle",
        "Authorization": f"DPoP {token}",
        "DPoP": build_resource_dpop_proof(url, "GET", token),
    }


def invalidate_token() -> None:
    """Drop the cached token, e.g. after a 401 from the POD."""
    _token_cache["access_token"] = None
    _token_cache["expires_at"] = 0.0
