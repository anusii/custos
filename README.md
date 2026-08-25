# Custos broker (MCP server)

[![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)](https://www.python.org/)

An MCP server that runs entirely on your own machine and lets an AI agent 
(tested with Claude) read your personal context from a Solid POD. Context 
is gated by consent, authenticated at two layers, and fully audited.

## What's here

- **Six MCP tools**: `list_purposes` (what categories of context exist),
  `search_context` (keyword-matched facts for a purpose), `get_document`
  (one specific resource by name/path), `describe_purpose` (field names +
  one example each, to sharpen a search), `request_access` (records a
  request for the user to review, never self-grants), and `get_audit`
  (recent audit-log entries, ungated). All but `get_audit` are gated by the
  same consent check as `search_context`.
- **Consent gate**: `grants.json` decides what's readable per purpose. Revoke
  a grant and the next call is refused, live and no restart required. Editable by hand
  or from `setup_gui.py`'s own grants table (toggle/add/remove purposes).
- **Audit log**: every call, allowed or denied, appended to `audit.log` with
  a timestamp and (when authenticated) the caller's identity.
- **Broker → POD auth**: a one-time interactive login (`setup_gui.py`).
  Authorization Code + PKCE, DPoP-bound, the broker logging into *your* POD
  as its own Solid-OIDC client with the refresh token and (if your data is
  TNO-encrypted) derived master key persisted via your OS's secure
  credential store (`keyring`). A manually-created CSS Client Credentials
  pair still works as a fallback, useful for automation.

<img width="615" height="1132" alt="custos-mcp" src="https://github.com/user-attachments/assets/4a6849f7-c4b2-491d-940b-888bbeb6045a" />

- **Local TNO decryption**: matches `solidpod`'s own key-derivation and
  content-cipher scheme (Argon2id, HKDF, AES-256-CTR) byte-for-byte, plus
  NotePod's additional inner field cipher. Decryption happens locally in
  this process and the security key/derived master key never leaves it.
- **Runs entirely over stdio**. One broker per user, spawned locally by
  Claude Desktop or Claude Code, no hosting required; the process-spawn
  boundary is the trust model. An MCP-client → broker OAuth layer over
  streamable-HTTP also exists (proven end-to-end with PKCE and dynamic
  client registration) but is a secondary/advanced mode, not the primary
  story. See SETUP.md.

## Quick start

See [SETUP.md](SETUP.md) - install, log into your own POD (`setup_gui.py`),
wire it into Claude Desktop or Claude Code, run the demo.

## What's not here yet

`append_memory` (the only planned tool that would make the broker write
back to the POD, needs its own write-side consent flag, so it's a
deliberate scope decision, not yet started), semantic search (currently a
dumb keyword match), fine-grained per-purpose OAuth scopes, legacy (v1) POD
key-derivation support, and RSA private-key decryption / cross-user resource
sharing.
