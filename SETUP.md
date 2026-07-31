# Custos broker — setup guide

An MCP server ("broker") that fronts a Solid POD and lets Claude read your
personal context — but only through a consent gate, with every access
logged, and revocation that takes effect on the next call. This guide gets
it running against your own POD, wired into your own Claude Desktop.

**What you'll see working, end to end:**
1. Claude reads a fact from your vault — but only because a grant exists.
2. Every access (allowed or denied) lands in an append-only audit log.
3. Flip the grant off, and the *next* call is refused — live, no restart.

That revoke → refuse → audited sequence is the whole point.

## Prerequisites

- **Python 3.11+**
- **Claude Desktop** installed
- **A Solid POD.** Community Solid Server (CSS) is assumed for the
  broker's-own-identity auth step (§3b) — if your POD is on CSS (e.g. any
  `solidcommunity.au` pod), you get the full story. Any Solid POD works if
  you're fine using a public-read container instead (§3a).

## 1. Install

```bash
cd solidmcp
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
      "command": "<path-to-solidmcp>/.venv/Scripts/python.exe",
      "args": ["<path-to-solidmcp>/server.py"]
    }
  }
}
```

Replace `<path-to-solidmcp>` with wherever you cloned this repo (on
macOS/Linux, `command` is `<path-to-solidmcp>/.venv/bin/python`). No `env`
block — with nothing configured, the broker reads `data/context/<purpose>/*.ttl`
directly, which includes a bundled `travel` purpose.

Restart Claude Desktop. The two tools (`list_purposes`, `search_context`)
appear under the 🔌 icon. Now run **[6. The demo](#6-the-demo)** below against
this sample data. Once that works, come back here and move on to your own POD.

## 3. Point it at your own POD

The broker expects purpose containers at `<POD_BASE_URL>context/<purpose>/`
(e.g. `travel`, `health`, whatever categories you want to expose). Pick one
of the two options below.

### 3a. Simplest: a public-read container

Any Solid POD works this way, CSS or not. Create a container (e.g.
`context/travel/`) with a Turtle file of facts, and an ACL making it
public-read:

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

Replace the WebID with your own. Put this `.acl` file at (or above, with
`acl:default` propagating down) the container you want readable.

**Honest limitation:** with a public container, `grants.json` (§5) is the
*only* thing actually protecting the data — the POD's own ACL isn't. Fine
for a first test; §3b removes this limitation.

### 3b. Recommended (CSS pods): a private container + the broker's own identity

The broker authenticates to your POD as its own Solid-OIDC identity (DPoP-bound,
via Community Solid Server's Client Credentials grant), so the container can
stay owner-only.

**One-time setup, in your browser:**

1. Log into `<your-pod-provider>/.account/login/password/` with your pod
   account's username/password.
2. Find the **Client credentials** control in the account dashboard (or
   `<your-pod-provider>/.account/account/` once logged in, which lists the
   controls available to your session) and create a named credential, e.g.
   `solidmcp-broker`.
3. Copy the returned `id` and `secret` immediately — CSS shows the secret
   only once. Never commit these; treat them like a password.

Then create your container with an **owner-only** ACL (no public block at all):

```turtle
@prefix acl: <http://www.w3.org/ns/auth/acl#> .

<#owner>
    a acl:Authorization ;
    acl:agent    <https://your-pod-provider/your-username/profile/card#me> ;
    acl:accessTo <./> ;
    acl:default  <./> ;
    acl:mode     acl:Read, acl:Write, acl:Control .
```

Implementation lives in `solid_auth_client.py` — a DPoP RSA keypair is
generated once and persisted to `dpop_key.json` (gitignored — never commit
it), and `server.py`'s `_fetch_graph()` attaches `Authorization: DPoP <token>`
+ a fresh `DPoP: <proof>` header per request, refreshing the token once on a
401 before giving up.

## 4. Configure environment variables

| Var | Meaning |
|---|---|
| `POD_BASE_URL` | Your POD base, e.g. `https://your-pod-provider/your-username/`. |
| `POD_OIDC_CLIENT_ID` / `POD_OIDC_CLIENT_SECRET` | From §3b. Omit both for §3a's public-read approach. |
| `POD_OIDC_TOKEN_ENDPOINT` | Optional override; otherwise discovered from `<origin of POD_BASE_URL>/.well-known/openid-configuration`. |
| `LOCAL_CONTEXT_DIR` | Read from `<dir>/context/<purpose>/*.ttl` instead of a POD (what §2 uses by default). |
| `SOLIDMCP_HOME` | Where `grants.json` / `audit.log` / `dpop_key.json` live. Defaults to this folder. |

**Running from the command line (e.g. testing streamable-HTTP, §2c):** copy
`.env.example` to `.env` and fill in the values you need — `server.py` loads
it automatically, so you don't have to retype `$env:` lines every restart.
Values already set in your shell still take priority over the file. Never
commit `.env` (it's gitignored).

**Running via Claude Desktop (stdio, the default):** update
`claude_desktop_config.json`'s `env` block (from §2) with `POD_BASE_URL`
and, if you did §3b, `POD_OIDC_CLIENT_ID`/`SECRET`:

```json
{
  "mcpServers": {
    "custos": {
      "command": "<path-to-solidmcp>/.venv/Scripts/python.exe",
      "args": ["<path-to-solidmcp>/server.py"],
      "env": {
        "POD_BASE_URL": "https://your-pod-provider/your-username/",
        "POD_OIDC_CLIENT_ID": "<id from §3b, omit if using §3a>",
        "POD_OIDC_CLIENT_SECRET": "<secret from §3b, omit if using §3a>"
      }
    }
  }
}
```

## 5. Set up `grants.json`

`grants.json` is the consent gate — the *only* thing the demo uses to decide
whether a purpose is readable (§3a) or the extra layer on top of your POD's
own ACL (§3b). Edit it so the purpose name matches your container:

```json
{
  "grants": {
    "travel": { "read": true }
  }
}
```

The purpose key (`travel` here) must match your container name — if you
called it `health`, use `{"health": {"read": true}}` instead.

Restart Claude Desktop after any `env` block change (env vars are only read
at process start).

## 6. The demo

1. Ensure `grants.json` has the relevant purpose set to `"read": true`.
2. Ask Claude something that would use that context — e.g. for `travel`:
   *"Plan me a long weekend. Check my travel context first."* Claude calls
   `list_purposes`, then `search_context("...", "travel")` and gets back the
   facts from your POD (or the bundled sample, if you're still on §2).
3. Open `grants.json`, set that purpose's `read` to `false`, save. (A real
   console app would do this with a toggle; hand-editing stands in for now.)
4. Ask Claude to search again. It is **refused**: *"Access denied: consent
   required for purpose '...'."*
5. Open `audit.log` — every call, allow and deny, is there with a UTC
   timestamp.

That revoke → refuse → audited sequence is the whole point.

---

## Advanced / optional: MCP-client → broker authentication

Everything above uses Claude Desktop's default **stdio** transport — a local
subprocess with no auth of its own, because the OS process boundary is the
trust boundary (only whoever controls `claude_desktop_config.json` can call
it). That's enough for one user, one local app, and **is not needed for the
demo above.**

It stops being enough the moment the broker is reachable by more than one
caller or over a network. The broker also supports running as an HTTP server
requiring a real OAuth 2.1 Bearer token (validated against your POD's
Authorization Server via JWKS, no DPoP on this leg since Claude's MCP client
doesn't implement it) — set `MCP_TRANSPORT=streamable-http`. This has been
proven to work end-to-end (PKCE, dynamic client registration, real login),
but testing it requires either a custom OAuth test client or a tool like MCP
Inspector, and using it from Claude Desktop's Connectors UI requires the
broker be reachable over public HTTPS (Anthropic's cloud, not your machine,
initiates that connection) — e.g. via a tunnel. That's a separate, bigger
step beyond this guide; ask if you want to go there next.

## What's next

- Broker → POD Solid-OIDC + DPoP auth (§3b) and MCP-client → broker OAuth
  (above) are both done and proven, independently of each other.
- Keyword match → local embedding index (`search_context` retrieval swap).
- `grants.json` → real per-purpose OAuth scopes (`read:travel`, etc.) —
  blocked on CSS's fixed scope list; would need either extending CSS or a
  dedicated Authorization Server. `grants.json` remains the real
  purpose-level gate for now.
- TNO encryption last.
- Remaining tools from the original design: `request_access`, `get_document`,
  `append_memory`, `get_audit`.
