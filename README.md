# Custos broker

An MCP server that runs entirely on your own machine and lets Claude read
your personal context from a Solid POD — gated by consent, authenticated at
two layers, and fully audited.

## What's here

- **Two MCP tools**: `list_purposes` (what categories of context exist) and
  `search_context` (retrieve facts for a purpose).
- **Consent gate**: `grants.json` decides what's readable per purpose. Revoke
  a grant and the next call is refused, live — no restart. Editable by hand
  or from `setup_gui.py`'s own grants table (toggle/add/remove purposes).
- **Audit log**: every call, allowed or denied, appended to `audit.log` with
  a timestamp and (when authenticated) the caller's identity.
- **Broker → POD auth**: a one-time interactive login (`setup_gui.py`) —
  Authorization Code + PKCE, DPoP-bound, the broker logging into *your* POD
  as its own Solid-OIDC client — with the refresh token and (if your data is
  TNO-encrypted) derived master key persisted via your OS's secure
  credential store (`keyring`). A manually-created CSS Client Credentials
  pair still works as a fallback, useful for automation.
- **Local TNO decryption**: matches `solidpod`'s own key-derivation and
  content-cipher scheme (Argon2id, HKDF, AES-256-CTR) byte-for-byte, plus
  NotePod's additional inner field cipher — decryption happens locally in
  this process and the security key/derived master key never leaves it.
- **Runs entirely over stdio** — one broker per user, spawned locally by
  Claude Desktop or Claude Code, no hosting required; the process-spawn
  boundary is the trust model. An MCP-client → broker OAuth layer over
  streamable-HTTP also exists (proven end-to-end with PKCE and dynamic
  client registration) but is a secondary/advanced mode, not the primary
  story — see SETUP.md.

## Quick start

See [SETUP.md](SETUP.md) — install, log into your own POD (`setup_gui.py`),
wire it into Claude Desktop or Claude Code, run the demo.

## What's not here yet

Semantic search (currently a dumb keyword match), fine-grained per-purpose
OAuth scopes, legacy (v1) POD key-derivation support, and RSA private-key
decryption / cross-user resource sharing.

## Background

The product vision and commercialisation analysis this prototype was scoped
from live in [PLAN.md](PLAN.md).
