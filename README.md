# Custos broker

An MCP server that lets Claude read your personal context from a Solid POD —
gated by consent, authenticated at two layers, and fully audited.

## What's here

- **Two MCP tools**: `list_purposes` (what categories of context exist) and
  `search_context` (retrieve facts for a purpose).
- **Consent gate**: `grants.json` decides what's readable per purpose. Revoke
  a grant and the next call is refused, live — no restart.
- **Audit log**: every call, allowed or denied, appended to `audit.log` with
  a timestamp and (when authenticated) the caller's identity.
- **Broker → POD auth**: the broker authenticates to your POD with its own
  Solid-OIDC identity (DPoP-bound, via Community Solid Server's Client
  Credentials grant), so your data doesn't need to be public-read.
- **MCP-client → broker auth** (optional): the broker can also run as an
  OAuth 2.1 Resource Server over streamable-HTTP, requiring a real Bearer
  token from your POD's Authorization Server before any tool call is
  honored — proven end-to-end with PKCE and dynamic client registration.

## Quick start

See [SETUP.md](SETUP.md) — install, point it at your own POD, wire it into
Claude Desktop, run the demo.

## What's not here yet

Semantic search (currently a dumb keyword match), fine-grained per-purpose
OAuth scopes, end-to-end encryption, and a real console app for managing
consent (today `grants.json` is hand-edited).

## Background

The product vision and commercialisation analysis this prototype was scoped
from live in [PLAN.md](PLAN.md).
