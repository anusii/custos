# Custos broker (MCP server)

[![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)](https://www.python.org/)

**A consent-governed context broker for LLM agents.**

Custos is a Python [MCP](https://modelcontextprotocol.io) server that sits 
between an LLM agent and a user's personal data. Agents don't get a filesystem.
They get a narrow, purpose-scoped API, and every request is checked against a 
consent grant the user controls and written to an audit log the user can read.

Custos runs entirely on your own machine and lets an AI agent 
(tested with Claude) read your personal context from a Solid POD.

---

## Why this exists

Agentic assistants are converging on the same pattern: give the model broad 
read access to your data and trust the prompt to keep it honest. That works until 
it doesn't. The failure modes aren't exotic; an agent pulls your medical notes 
into a travel booking context, or a summarisation step quietly copies something 
into a transcript that outlives the session.

The interesting problems in agentic systems aren't in the prompts. They're in 
**what the agent is allowed to see, why it was allowed to see it, and whether you can prove afterwards what happened.**

**Custos** treats that as an information-flow control problem rather than a prompt 
engineering one. The design uses [Solid](https://solidproject.org) PODs with ACL policies 
as the storage and policy substrate, so the vault is user-owned infrastructure, 
not another vendor's database.

---

## Architecture: two doors

Access requires passing two independent gates. Neither one alone is sufficient, and they fail for different reasons.

```
   Agent (Claude, GPT, …)
        │
        │  MCP  ─ purpose-scoped calls only
        ▼
┌───────────────────────────────────────────┐
│              CUSTOS BROKER                │
│                                           │
│   ┌─────────────────────────────────┐     │
│   │  DOOR 1 — Consent               │     │
│   │  Is `purpose` granted for read? │     │
│   │  grants.json, user-controlled   │     │
│   └────────────┬────────────────────┘     │
│                │ allow          deny ─────┼──▶ logged, refused
│                ▼                          │
│   ┌─────────────────────────────────┐     │
│   │  DOOR 2 — Vault                 │     │
│   │  Session key from OS keychain   │     │
│   │  Argon2id-derived, in-memory    │     │
│   └────────────┬────────────────────┘     │
│                │                          │
│                ▼                          │
│        Minimal relevant facts             │
│        (not the whole container)          │
│                │                          │
│         ┌──────▼──────┐                   │
│         │ AUDIT LOG   │  every call,      │
│         │             │  allowed or not   │
│         └─────────────┘                   │
└───────────────────────────────────────────┘
        │
        ▼
   Solid POD (ACL-enforced containers, one per app)
```

**Door 1 is policy.** Data is partitioned by *purpose* (`travel`, `healthpod`, `notepod`, …), 
not by file or folder. An agent asks for context by purpose; the broker checks `grants.json` 
for an active read grant. No grant, no data — and the denial is recorded.

**Door 2 is cryptographic.** The vault key is derived once, with Argon2id, from your security 
key during setup, then persisted in the OS keychain, never re-derived or re-entered on later 
launches. At runtime it's read from the keychain and held in memory only for as long as the 
broker process itself is running. A grant that says "yes" gets you nothing without that key 
already unlocked.

The separation matters because the two doors answer different questions. Door 1 answers 
*should this agent see this?* Door 2 answers *is the user actually present?* Collapsing them 
into a single check is the mistake most designs in this space make.

---

## What's here

- **Six MCP tools**, deliberately. The shape of the API is most of the security model. An agent can't ask for something the interface doesn't express.

| Tool | Consent required | What it does |
|---|---|---|
| `list_purposes` | No | Returns purpose *names* only — never underlying data. Discovery without disclosure. |
| `describe_purpose` | Yes | Field names plus one example value each, so the agent can write a sharper query instead of guessing keywords blind. |
| `search_context` | Yes | Returns the minimal relevant facts for a purpose. Keyword-matched. |
| `get_document` | Yes | Fetches one specific resource. Anything resolving outside that purpose's own container is refused. |
| `request_access` | No | Records a request for the user to review later. Explicitly cannot grant anything. |
| `get_audit` | No | Reads the broker's own log, including denials. |

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

---

## Quick start

See [SETUP.md](SETUP.md) for full guide - install, log into your own 
POD (`setup_gui.py`), wire it into Claude Desktop or Claude Code, 
run the demo.

---

## What this doesn't do yet

Listed because the gaps are the interesting part, and because a security tool whose README only lists strengths should not be trusted.

- **No transitive disclosure tracking.** Custos governs what crosses the boundary once. It does not follow a fact after the agent has it; if the model pulls a `healthpod` fact and then writes it into a `travel` document, nothing catches that. The fix is a taint log that tracks provenance across purposes, and it's the largest open item.
- **No trust ontology for MCP servers.** The broker treats the calling agent as a single opaque principal. In a real deployment with several MCP servers in one client, they are not equally trustworthy, and there's currently no way to express that.
- **Retrieval is keyword matching.** `search_context` does not use embeddings. Fine for a small vault, wrong at scale — and "minimal relevant facts" is only as good as relevance ranking.
- **Consent is per-purpose, not per-field.** Coarser than the design intends.
- **Single-user, local-first.** No multi-tenancy, no remote deployment story.

---

<!-- 
## What's not here yet

`append_memory` (the only planned tool that would make the broker write
back to the POD, needs its own write-side consent flag, so it's a
deliberate scope decision, not yet started), semantic search (currently a
dumb keyword match), fine-grained per-purpose OAuth scopes, legacy (v1) POD
key-derivation support, and RSA private-key decryption / cross-user resource
sharing. -->
