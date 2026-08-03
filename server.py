"""
Custos broker — walking-skeleton prototype (Phase 0).

An MCP server that fronts a Solid POD and exposes a *deliberately tiny* tool
surface to an AI agent (Claude Desktop, over stdio). Two tools only:

    - list_purposes()               -> the categories of context available
    - search_context(query, purpose) -> minimal facts, gated by consent

The one thing that makes this the product and not a generic file reader is the
CONSENT GATE: before any data leaves the vault, we check a grants file. No
grant -> "access denied, consent required for purpose X". Every call — allowed
or denied — is written to an append-only audit log. Flip a grant off and the
next call is refused, live. That revoke moment is the whole demo.

Deliberately deferred (see BasicSteps.md): TNO encryption, embeddings /
semantic retrieval, and fine-grained per-purpose OAuth scopes. Two auth legs
now exist: broker -> POD (DPoP-bound, see solid_auth_client.py) and, when run
over streamable-HTTP, MCP-client -> broker (plain Bearer tokens validated
against the same CSS instance via broker_token_verifier.py — no DPoP here,
since Claude's MCP client doesn't implement it). Data is plaintext, consent
is a stub JSON file (grants.json still does all purpose-level gating; OAuth
adds real caller identity and a network auth boundary on top of it, not a
replacement for it).

Config (all optional, via environment variables):
    POD_BASE_URL           Base URL of the POD, e.g. http://localhost:3000/alice/
                           Context containers are expected at <POD_BASE_URL>context/<purpose>/
    LOCAL_CONTEXT_DIR      Instead of a live POD, read Turtle files from a local
                           directory: <LOCAL_CONTEXT_DIR>/<purpose>/*.ttl
                           (lets you run the whole loop before CSS is up).
    SOLIDMCP_HOME          Where grants.json, audit.log, and dpop_key.json live.
                           Defaults to this file's directory.
    POD_OIDC_CLIENT_ID     CSS client-credentials id. If set (with the secret
    POD_OIDC_CLIENT_SECRET below), the broker authenticates to the POD with a
                           DPoP-bound access token instead of a plain GET —
                           see solid_auth_client.py. Omit both to keep today's
                           unauthenticated behaviour (works against public-read
                           containers only).
    POD_OIDC_TOKEN_ENDPOINT  Optional override; otherwise discovered from
                           <origin of POD_BASE_URL>/.well-known/openid-configuration.
    MCP_TRANSPORT          "stdio" (default, unchanged Claude Desktop setup) or
                           "streamable-http" to require MCP-client Bearer-token
                           auth — see broker_token_verifier.py. Ignored, and
                           always stdio, when this file is imported rather than
                           run directly.
    MCP_HTTP_HOST          Host to bind when MCP_TRANSPORT=streamable-http.
                           Default 127.0.0.1.
    MCP_HTTP_PORT          Port to bind when MCP_TRANSPORT=streamable-http.
                           Default 8000.
    MCP_RESOURCE_URL       This broker's own resource identifier (RFC 8707),
                           e.g. http://127.0.0.1:8000/mcp. Defaults to
                           http://<MCP_HTTP_HOST>:<MCP_HTTP_PORT>/mcp.
    MCP_OIDC_ISSUER        The Authorization Server MCP-client tokens must come
                           from. Defaults to the origin of POD_BASE_URL (the
                           same CSS instance already used for broker -> POD
                           auth) — only needed as an override, or if
                           POD_BASE_URL isn't set but streamable-http is used.

Exactly one of POD_BASE_URL / LOCAL_CONTEXT_DIR should be set. If neither is,
we fall back to LOCAL_CONTEXT_DIR = <SOLIDMCP_HOME>/data so the server still
runs against the seed data shipped alongside it.

Any of the above can also be set in a `.env` file next to this script instead
of the shell — see .env.example. Values already set in the real environment
(e.g. Claude Desktop's `env` config block) take priority over the .env file.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# Must run before importing solid_auth_client/broker_token_verifier below —
# both read their own env vars at module-import time, so .env has to be
# loaded first. override=False (the default) means anything already set in
# the real environment wins over the .env file.
load_dotenv(Path(__file__).parent / ".env")

import json
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

import httpx
from rdflib import Graph
from rdflib.namespace import RDF

from mcp.server.auth.middleware.auth_context import get_access_token as _get_caller_access_token
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

import pod_decryption
import solid_auth_client
from broker_token_verifier import REQUIRED_SCOPES, CustosTokenVerifier

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

HOME = Path(os.environ.get("SOLIDMCP_HOME", Path(__file__).parent)).resolve()
GRANTS_PATH = HOME / "grants.json"
AUDIT_PATH = HOME / "audit.log"

POD_BASE_URL = os.environ.get("POD_BASE_URL")  # e.g. http://localhost:3000/alice/
LOCAL_CONTEXT_DIR = os.environ.get("LOCAL_CONTEXT_DIR")

# If nothing is configured, run against the bundled seed data so the loop still
# walks with zero external setup.
if not POD_BASE_URL and not LOCAL_CONTEXT_DIR:
    LOCAL_CONTEXT_DIR = str(HOME / "data")

# The container inside the POD (or local dir) that holds purpose sub-containers.
CONTEXT_ROOT = "context"

# Cap how many facts we ever hand back in one call. The invariant from the
# report: the agent receives the *smallest* consented slice, never a bulk dump.
MAX_FACTS = 10

MCP_TRANSPORT = os.environ.get("MCP_TRANSPORT", "stdio")
MCP_HTTP_HOST = os.environ.get("MCP_HTTP_HOST", "127.0.0.1")
MCP_HTTP_PORT = int(os.environ.get("MCP_HTTP_PORT", "8000"))

if MCP_TRANSPORT == "streamable-http":
    _resource_url = os.environ.get("MCP_RESOURCE_URL", f"http://{MCP_HTTP_HOST}:{MCP_HTTP_PORT}/mcp")
    _issuer_url = os.environ.get("MCP_OIDC_ISSUER")
    if not _issuer_url and POD_BASE_URL:
        _origin = urlsplit(POD_BASE_URL)
        _issuer_url = f"{_origin.scheme}://{_origin.netloc}/"
    if not _issuer_url:
        raise RuntimeError(
            "MCP_TRANSPORT=streamable-http requires POD_BASE_URL or MCP_OIDC_ISSUER "
            "to be set, so MCP-client tokens can be validated against an Authorization Server."
        )
    # FastMCP auto-enables DNS-rebinding protection when host is loopback,
    # allowlisting only 127.0.0.1/localhost Host headers. A tunnel (ngrok etc.)
    # forwards requests with the public hostname in the Host header, which
    # that default allowlist rejects with 421. Explicitly allow whatever
    # MCP_RESOURCE_URL's host is, alongside the usual loopback entries.
    _resource_host = urlsplit(_resource_url).netloc
    _transport_security = TransportSecuritySettings(
        allowed_hosts=["127.0.0.1:*", "localhost:*", "[::1]:*", _resource_host, f"{_resource_host}:*"],
    )
    mcp = FastMCP(
        "custos-broker",
        host=MCP_HTTP_HOST,
        port=MCP_HTTP_PORT,
        token_verifier=CustosTokenVerifier(),
        transport_security=_transport_security,
        auth=AuthSettings(
            issuer_url=_issuer_url,
            resource_server_url=_resource_url,
            # CSS needs at least these to issue a Solid-OIDC token (the webid
            # claim is how we identify the caller). Advertised here so a
            # spec-compliant MCP client reads them from our Protected
            # Resource Metadata and includes them in its authorization
            # request — our own oauth_test_client.py already does this
            # explicitly; this is what makes an MCP client that reads PRM's
            # scopes_supported do the same without being told separately.
            required_scopes=REQUIRED_SCOPES,
        ),
    )
else:
    mcp = FastMCP("custos-broker")


# --------------------------------------------------------------------------- #
# Consent + audit — the two plain files the "console" will toggle
# --------------------------------------------------------------------------- #

def _load_grants() -> dict[str, Any]:
    """Read grants.json. Shape:

        {
          "grants": {
            "travel": { "read": true }
          }
        }

    Missing file / purpose / action all mean "not granted".
    """
    if not GRANTS_PATH.exists():
        return {"grants": {}}
    try:
        return json.loads(GRANTS_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        # A malformed grants file must fail closed, not open.
        return {"grants": {}}


def _is_granted(purpose: str, action: str = "read") -> bool:
    grants = _load_grants().get("grants", {})
    return bool(grants.get(purpose, {}).get(action, False))


def _purpose_container_url(purpose: str) -> str | None:
    """Full URL of a purpose's data container. A purpose must have an entry
    in grants.json to be recognized at all (explicit opt-in — consent and
    "this purpose exists" share one registry, no separate app allowlist).
    Resolution order, first candidate that actually fetches wins:

      1. grants.json's explicit "path" (relative to the POD root, or a full
         URL) — for cases the two conventions below don't fit.
      2. <POD root>/<purpose>/data/ — the convention real solidpod apps use
         (each app owns a top-level folder with its own data/, encryption/,
         sharing/ siblings, e.g. notepod/data/, papertrail/data/).
      3. <POD_BASE_URL>context/<purpose>/ — the original convention, kept
         for backward compatibility with purposes that pre-date it.
    """
    grants = _load_grants().get("grants", {})
    if purpose not in grants:
        return None
    custom_path = grants[purpose].get("path")
    root = solid_auth_client.pod_root_url()

    candidates: list[str] = []
    if custom_path:
        if custom_path.startswith(("http://", "https://")):
            candidates.append(custom_path.rstrip("/") + "/")
        elif root:
            candidates.append(root.rstrip("/") + "/" + custom_path.strip("/") + "/")
    else:
        if root:
            candidates.append(root.rstrip("/") + "/" + purpose + "/data/")
        if POD_BASE_URL:
            candidates.append(POD_BASE_URL.rstrip("/") + "/" + CONTEXT_ROOT + "/" + purpose + "/")

    for url in candidates:
        if _fetch_graph(url) is not None:
            return url
    return None


def _caller_id() -> str | None:
    """The authenticated MCP-client's subject (WebID), if this call arrived
    over streamable-HTTP with a valid Bearer token. None under stdio, or when
    auth isn't configured — the audit log simply omits the field then, same
    as it always has."""
    token = _get_caller_access_token()
    return token.subject if token else None


def _audit(event: dict[str, Any]) -> None:
    """Append one JSON line to the audit log. Never throws — a failure to log
    should not crash the broker, but we prefix the record with a UTC timestamp
    and the tool that produced it."""
    record = {"ts": datetime.now(timezone.utc).isoformat(), **event}
    caller = _caller_id()
    if caller:
        record["caller"] = caller
    try:
        with AUDIT_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# Vault access — read plaintext Turtle from a POD (HTTP) or a local directory
# --------------------------------------------------------------------------- #

def _list_local_purposes() -> list[str]:
    root = Path(LOCAL_CONTEXT_DIR) / CONTEXT_ROOT
    if not root.is_dir():
        # Allow LOCAL_CONTEXT_DIR to point straight at the context root too.
        root = Path(LOCAL_CONTEXT_DIR)
    if not root.is_dir():
        return []
    return sorted(p.name for p in root.iterdir() if p.is_dir())


def _list_pod_purposes() -> list[str]:
    """Every purpose registered in grants.json (explicit opt-in — this is
    the "what exists" registry, regardless of whether read is currently
    granted), plus sub-containers of <POD_BASE_URL>context/ via LDP
    containment (the original auto-discovery, kept for anything not yet
    added to grants.json)."""
    from rdflib import URIRef

    purposes: set[str] = set(_load_grants().get("grants", {}).keys())
    url = POD_BASE_URL.rstrip("/") + "/" + CONTEXT_ROOT + "/"
    g = _fetch_graph(url)
    if g is not None:
        ldp_contains = URIRef("http://www.w3.org/ns/ldp#contains")
        for _, _, obj in g.triples((None, ldp_contains, None)):
            name = str(obj).rstrip("/").rsplit("/", 1)[-1]
            if name:
                purposes.add(name)
    return sorted(purposes)


def _fetch_graph(url: str) -> Graph | None:
    token = solid_auth_client.get_access_token()
    headers = solid_auth_client.authenticated_headers(url, token) if token else {"Accept": "text/turtle"}
    try:
        resp = httpx.get(url, headers=headers, timeout=10.0)
        if resp.status_code == 401 and token:
            # Token may have been revoked/expired server-side; refresh once.
            solid_auth_client.invalidate_token()
            token = solid_auth_client.get_access_token()
            if token:
                resp = httpx.get(url, headers=solid_auth_client.authenticated_headers(url, token), timeout=10.0)
        resp.raise_for_status()
    except (httpx.HTTPError, httpx.InvalidURL):
        return None
    g = Graph()
    try:
        g.parse(data=resp.text, format="turtle", publicID=url)
    except Exception:
        return None
    return _maybe_decrypt(g, url)


def _maybe_decrypt(g: Graph, url: str) -> Graph:
    """No-op passthrough unless `g` is a solidpod-encrypted whole-document
    replacement (see pod_decryption.py) and decryption is configured. Also
    reverses NotePod's own inner noteContent cipher (see
    pod_decryption.notepod_decrypt_content) -- unconditional and harmless to
    call on any graph, since it's a no-op unless a noteContent/
    createdDateTime pair is actually present."""
    if pod_decryption.is_encrypted_resource(g, url):
        root = solid_auth_client.pod_root_url()
        if root and url.startswith(root):
            resource_path = url[len(root):]
            g = pod_decryption.maybe_decrypt_resource(
                g, url, resource_path, _fetch_graph, solid_auth_client.ENCRYPTION_BASE_URL
            )
    return pod_decryption.notepod_decrypt_content(g)


def _load_local_facts(purpose: str) -> list[dict[str, str]]:
    base = Path(LOCAL_CONTEXT_DIR) / CONTEXT_ROOT / purpose
    if not base.is_dir():
        base = Path(LOCAL_CONTEXT_DIR) / purpose
    if not base.is_dir():
        return []
    facts: list[dict[str, str]] = []
    for ttl in sorted(base.glob("*.ttl")):
        g = Graph()
        try:
            g.parse(str(ttl), format="turtle")
        except Exception:
            continue
        facts.extend(_facts_from_graph(g, source=ttl.name))
    return facts


def _load_pod_facts(purpose: str) -> list[dict[str, str]]:
    """Fetch the purpose container, then each contained resource, and flatten
    literal objects into facts."""
    container = _purpose_container_url(purpose)
    if not container:
        return []
    cg = _fetch_graph(container)
    if cg is None:
        return []

    from rdflib import URIRef

    ldp_contains = URIRef("http://www.w3.org/ns/ldp#contains")
    resource_urls = [str(o) for _, _, o in cg.triples((None, ldp_contains, None))]

    facts: list[dict[str, str]] = []
    # Facts stated directly on the container resource itself, too.
    facts.extend(_facts_from_graph(cg, source=container))
    for url in resource_urls:
        if url.rstrip("/") == container.rstrip("/"):
            continue
        rg = _fetch_graph(url)
        if rg is not None:
            facts.extend(_facts_from_graph(rg, source=url))
    return facts


def _facts_from_graph(g: Graph, source: str) -> list[dict[str, str]]:
    """Turn a graph's literal triples into flat, human-readable facts. Each fact
    keeps its source and the predicate's local name so the agent (and the audit)
    can see where it came from."""
    facts: list[dict[str, str]] = []
    for subj, pred, obj in g:
        if pred == RDF.type:
            continue
        if getattr(obj, "language", None) is not None or hasattr(obj, "datatype"):
            # Literal-ish: rdflib Literals expose .datatype / .language
            text = str(obj)
        else:
            continue
        # Skip blank/URI objects — only surface literal values as facts.
        from rdflib import Literal

        if not isinstance(obj, Literal):
            continue
        pred_name = str(pred).rstrip("/#").rsplit("/", 1)[-1].rsplit("#", 1)[-1]
        facts.append(
            {
                "text": text,
                "predicate": pred_name,
                "subject": str(subj),
                "source": source,
            }
        )
    return facts


def _load_facts(purpose: str) -> list[dict[str, str]]:
    if POD_BASE_URL:
        return _load_pod_facts(purpose)
    return _load_local_facts(purpose)


def _list_purposes_impl() -> list[str]:
    if POD_BASE_URL:
        return _list_pod_purposes()
    return _list_local_purposes()


# --------------------------------------------------------------------------- #
# Dumb keyword retrieval — no embeddings yet (Phase 1 swaps this out)
# --------------------------------------------------------------------------- #

def _keyword_match(query: str, facts: list[dict[str, str]]) -> list[dict[str, str]]:
    terms = [t for t in query.lower().split() if t]
    if not terms:
        return facts[:MAX_FACTS]
    scored = []
    for fact in facts:
        hay = (fact["text"] + " " + fact["predicate"]).lower()
        score = sum(1 for t in terms if t in hay)
        if score:
            scored.append((score, fact))
    scored.sort(key=lambda s: s[0], reverse=True)
    return [f for _, f in scored[:MAX_FACTS]]


# --------------------------------------------------------------------------- #
# MCP tools
# --------------------------------------------------------------------------- #

@mcp.tool()
def list_purposes() -> dict[str, Any]:
    """List the *categories* of personal context available in the vault.

    This returns only the purpose names (e.g. "travel", "health") — never the
    underlying data. Use it to discover what exists, then call search_context
    with a specific purpose. Access to the data itself still requires consent.
    """
    purposes = _list_purposes_impl()
    _audit({"tool": "list_purposes", "decision": "allow", "result_count": len(purposes)})
    return {
        "purposes": purposes,
        "note": "These are categories only. search_context(query, purpose) "
        "requires an active consent grant for that purpose.",
    }


@mcp.tool()
def search_context(query: str, purpose: str) -> dict[str, Any]:
    """Retrieve the minimal relevant facts for a purpose from the user's vault.

    Args:
        query:   what you are looking for (free text; keyword-matched for now).
        purpose: the context category to search, e.g. "travel". Must have an
                 active consent grant or the request is refused.

    Consent is checked first. If the user has not granted read access for this
    purpose, nothing is returned and the denial is logged. Every call — allowed
    or denied — is recorded in the audit log the user controls.
    """
    if not _is_granted(purpose, "read"):
        _audit(
            {
                "tool": "search_context",
                "purpose": purpose,
                "query": query,
                "decision": "deny",
                "reason": "no_grant",
            }
        )
        return {
            "status": "denied",
            "message": f"Access denied: consent required for purpose '{purpose}'. "
            f"Ask the user to grant read access in their Custos console.",
        }

    facts = _load_facts(purpose)
    matched = _keyword_match(query, facts)
    _audit(
        {
            "tool": "search_context",
            "purpose": purpose,
            "query": query,
            "decision": "allow",
            "result_count": len(matched),
        }
    )
    return {
        "status": "ok",
        "purpose": purpose,
        "query": query,
        "facts": matched,
        "note": f"Returned {len(matched)} fact(s), capped at {MAX_FACTS}. "
        "This is the minimal consented slice, not a bulk export.",
    }


if __name__ == "__main__":
    # stdio (default) — what Claude Desktop launches, unauthenticated by
    # design (the process boundary is the trust boundary). streamable-http
    # requires a valid Bearer token per broker_token_verifier.py.
    mcp.run(transport=MCP_TRANSPORT)
