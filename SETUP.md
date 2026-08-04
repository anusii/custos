# Custos broker (MCP server) - setup guide

An MCP server ("broker") that runs entirely on your own machine, fronts your
Solid POD, and lets Claude read your personal context, but only through a
consent gate, with every access logged, revocation that takes effect on the
next call, and (if your data is TNO-encrypted) decryption that happens
locally, in this process, never sent anywhere.

**What you'll see working, end to end:**
1. Claude reads a fact/data from your vault (POD), but only because a grant exists.
2. Every access (allowed or denied) lands in an append-only audit log.
3. Flip the grant off, and the *next* call is refusede, no restart.

## Prerequisites

- **Python 3.11+** (with Tkinter - bundled with the standard python.org
  installer on Windows/macOS; on Linux you may need e.g. `python3-tk`)
- **Claude Desktop or the Claude Code CLI** installed
- **A Solid POD**, ideally Community Solid Server (CSS)-based (e.g. any
  `solidcommunity.au` pod) for the full login-based setup below. Any Solid
  POD works with the simpler, alternative public-read approach (§A).

## 1. Install

```bash
cd custos
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt   # Windows
# source .venv/bin/activate && pip install -r requirements.txt  # macOS/Linux
```

## 2. Sanity-check the wiring with bundled sample data (no POD needed yet)

Before touching your real POD, confirm Claude Desktop can talk to the broker
at all, using the sample data shipped in `data/context/travel/`.

Edit `claude_desktop_config.json`:
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "custos": {
      "command": "<path-to-custos>/.venv/Scripts/python.exe",
      "args": ["<path-to-custos>/server.py"]
    }
  }
}
```

Replace `<path-to-custos>` with wherever you cloned this repo (on
macOS/Linux, `command` is `<path-to-custos>/.venv/bin/python`). No `env`
block - with nothing configured, the broker reads `data/context/<purpose>/*.ttl`
directly. Restart Claude Desktop, then run **[6. The demo](#6-the-demo)**
below against this sample data. Once that works, come back here.

Using Claude Code instead of Desktop? See **§4b** below for the `claude mcp
add` equivalent of this same config, come back to this sanity check with
that instead.

## 3. Run the one-time setup (login + security key)

```powershell
.venv\Scripts\python.exe setup_gui.py
```

A small window opens with the steps below (plus a fourth, **Manage access
grants**, covered in §5, same window, just a different section of it).

**Step 1 - Log into your POD.** Enter your WebID; it opens your browser for
a real login (Authorization Code + PKCE, the same OAuth flow already proven
in this project, just with the broker as the client logging into *your*
POD instead of Claude logging into the broker). On success this stores a
refresh token via your OS's secure credential store (`keyring` - Windows
Credential Manager / macOS Keychain / Linux Secret Service) and your POD's
base URL in `~/.custos/config.json`. No client credentials to create by
hand, no `.acl` files to write for this step.

**Step 2 - Verify your security key** (only if your POD data is
TNO-encrypted, i.e. written by a `solidpod`-based app like NotePod). Enter
the app directory where the data lives (e.g. `notepod` - the container
holding that app's `encryption/` subfolder) and your security key. The
broker fetches `encryption/enc-keys.ttl`, derives your master key
(Argon2id + HKDF, matching the Flutter app's own algorithm exactly), and
checks it against the stored verification value *before* saving anything -
a wrong key is rejected here, not silently later. On success, the derived
master key is stored via `keyring` too. If your data isn't encrypted, skip
this step entirely.

Once both steps are done, **the ongoing broker needs no further
interaction** - every later launch (including Claude Desktop spawning it
silently over stdio) just reads what's already stored.

**Step 3 (optional) - Test the broker.** Start/Stop buttons and
a live log view let you launch `server.py` standalone and confirm it starts
cleanly. Catches config/import errors before you wire it into Claude. Once
running it just waits quietly (normal for stdio, only a real MCP client
talking to it produces visible activity), so this is a smoke test, not a way
to interactively query it.

## 4. Wire into Claude

### 4a. Claude Desktop

```json
{
  "mcpServers": {
    "custos": {
      "command": "<path-to-custos>/.venv/Scripts/python.exe",
      "args": ["<path-to-custos>/server.py"]
    }
  }
}
```

No `env` block needed, POD base URL, auth, and (if set up) the decryption
key all come from what `setup_gui.py` already stored. Restart Claude
Desktop.

### 4b. Claude Code

Same command/args as above, added via the CLI instead of a config file:

```bash
claude mcp add custos --scope user -- "<path-to-custos>/.venv/bin/python" "<path-to-custos>/server.py"
```

```powershell
claude mcp add custos --scope user -- "<path-to-custos>\.venv\Scripts\python.exe" "<path-to-custos>\server.py"
```

- **`--scope user` matters** - the default scope (`local`) ties the server
  to whichever directory you happened to run `claude mcp add` from; it won't
  show up in a Claude Code session started elsewhere unless you use `user`
  scope (available everywhere) or always launch `claude` from that same
  directory.
- Verify it's registered with `claude mcp list`, then start (or restart)
  `claude` and run `/mcp` inside a session to confirm `custos` is connected.
- No `env` block/flag needed here either, same reasoning as 4a.

## 5. Set up `grants.json`

`grants.json` is the consent gate - the thing that decides whether a purpose
is readable at all, independent of everything above. You can hand-edit the
file directly (e.g. for the revoke demo below), or use `setup_gui.py`'s
**Step 4 - Manage access grants** table (Toggle Read / Add / Remove /
Save) - both write the exact same file, so pick whichever's convenient:

```json
{
  "grants": {
    "travel": { "read": true }
  }
}
```

A purpose just needs an entry here to be recognized at all - that's the
opt-in. The actual data location is then resolved automatically, first
candidate that exists wins:

1. An explicit `"path"` field in the grants entry (relative to your POD
   root, or a full URL) - for anything that doesn't fit the two conventions
   below.
2. `<your POD root>/<purpose>/data/` - the convention real Solid apps
   actually use (each app owns a top-level folder with its own `data/`,
   `encryption/`, `sharing/` as siblings - e.g. `notepod/data/`,
   `papertrail/data/`). Just add the app's own name as the purpose and this
   is tried automatically, no `"path"` needed:
   ```json
   { "grants": { "notepod": { "read": true }, "papertrail": { "read": true } } }
   ```
3. `<POD_BASE_URL>context/<purpose>/` - the original convention this broker
   started with, kept for backward compatibility.

Data format doesn't matter here either - `search_context` extracts every
literal value from whatever Turtle it finds, regardless of which
app/vocabulary wrote it (notes, receipts, anything else).

## 6. The demo

1. Ensure `grants.json` has the relevant purpose set to `"read": true`.
2. Ask Claude something that would use that context - e.g. for `travel`:
   *"Plan me a long weekend. Check my travel context first."*
3. Open `grants.json`, set that purpose's `read` to `false`, save.
4. Ask Claude to search again. It is **refused**: *"Access denied: consent
   required for purpose '...'."*
5. Open `audit.log` - every call, allow and deny, is there with a UTC
   timestamp.

That revoke → refuse → audited sequence is the whole point.

---

## Alternative / advanced setups

### §A. Public-read container (works on any Solid POD, not just CSS)

If you'd rather not do the login flow (or your POD isn't CSS-based), make
the container public-read instead:

```turtle
@prefix acl: <http://www.w3.org/ns/auth/acl#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .

<#owner>
    a acl:Authorization ;
    acl:agent    <https://your-pod-provider/your-username/profile/card#me> ;
    acl:accessTo <./> ;
    acl:default  <./> ;
    acl:mode     acl:Read, acl:Write, acl:Control .

<#public>
    a acl:Authorization ;
    acl:agentClass foaf:Agent ;
    acl:accessTo <./> ;
    acl:default  <./> ;
    acl:mode     acl:Read .
```

Set `POD_BASE_URL` via `claude_desktop_config.json`'s `env` block (or
`.env`, see below) and skip `setup_gui.py` entirely. **Honest limitation:**
`grants.json` is then the *only* thing protecting the data - the POD's own
ACL isn't.

### §B. Static CSS client credentials (instead of the login flow)

The broker also still supports authenticating via a manually-created CSS
client-credentials pair (`POD_OIDC_CLIENT_ID`/`SECRET` env vars) rather than
`setup_gui.py`'s interactive login - useful for automation/testing where an
interactive browser login isn't practical. Create one at
`<your-pod-provider>/.account/account/` ("Client credentials" control) and
set both env vars; this is tried as a fallback if no login-flow refresh
token is found in `keyring`.

### Command-line testing (`.env`)

Copy `.env.example` to `.env` and fill in values - `server.py` loads it
automatically. Values already set in your shell take priority. Never commit
`.env` (it's gitignored).

### MCP-client → broker OAuth (streamable-HTTP)

Everything above uses stdio - the OS process-spawn boundary is the trust
model, appropriate for one broker per user run entirely locally (the
architecture this project actually targets). The broker also supports
running as an HTTP server requiring its own OAuth 2.1 Bearer-token layer on
*top* of stdio's trust model (`MCP_TRANSPORT=streamable-http`) - proven to
work end-to-end, but solves a problem (distinguishing multiple *networked*
callers) that doesn't apply to the local-broker-per-user model, so it's a
secondary/advanced mode, not the primary story. See `LessonsLearned.md` for
what that involved.

## Encrypted POD data - current limitations

Decryption (via `setup_gui.py`'s security-key step) currently supports:
current (v2, Argon2id) key derivation, AES-256-CTR content decryption,
reading a resource's own per-file "individual key", and NotePod's
additional inner `noteContent` field cipher (its own extra layer on top of
`solidpod`'s scheme, reversed separately). Not yet supported: legacy (v1,
SHA-256) key derivation, RSA private-key decryption / cross-user resource
sharing, and large-file chunking / notification encryption. See
`LessonsLearned.md` and `PLAN.md` for the reasoning if any of these need
adding.

## What's next

- Keyword match → local embedding index (`search_context` retrieval swap).
- `grants.json` → real per-purpose OAuth scopes - blocked on CSS's fixed
  scope list; would need either extending CSS or a dedicated Authorization
  Server. `grants.json` remains the real purpose-level gate for now.
- Remaining tools from the original design: `request_access`, `get_document`,
  `append_memory`, `get_audit`.
