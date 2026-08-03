"""
One-time interactive setup for the Custos broker.

Logs the broker into your POD (Authorization Code + PKCE, DPoP-bound) and
verifies your security key for TNO decryption, storing what's needed
(refresh token, derived master key via `keyring`; POD base URL and
encryption-key-file location via a plain local config file) so the ongoing
broker (server.py, run by Claude Desktop over stdio) needs no further
interaction -- no terminal, no prompts, on every later launch.

Run once, yourself:
    .venv\\Scripts\\python.exe setup_gui.py
"""

from __future__ import annotations

import base64
import json
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk
from urllib.parse import urlsplit

import httpx
import keyring
from rdflib import Graph

import pod_decryption
import solid_auth_client

CONFIG_PATH = Path.home() / ".custos" / "config.json"
SERVER_PATH = Path(__file__).parent / "server.py"

# Same resolution as server.py's HOME/GRANTS_PATH -- must stay in lockstep so
# the GUI edits the exact file whatever broker instance is actually reading,
# including under a SOLIDMCP_HOME override.
HOME = Path(os.environ.get("SOLIDMCP_HOME", Path(__file__).parent)).resolve()
GRANTS_PATH = HOME / "grants.json"


def _guess_pod_root_url(webid: str) -> str:
    """<origin>/<first-path-segment>/ -- matches CSS's <origin>/<username>/
    layout. Editable in the UI if a different provider lays pods out
    differently."""
    parts = urlsplit(webid)
    segments = [s for s in parts.path.split("/") if s]
    if segments:
        return f"{parts.scheme}://{parts.netloc}/{segments[0]}/"
    return f"{parts.scheme}://{parts.netloc}/"


def _save_config(**kwargs) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    existing: dict = {}
    if CONFIG_PATH.exists():
        try:
            existing = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            existing = {}
    existing.update({k: v for k, v in kwargs.items() if v})
    CONFIG_PATH.write_text(json.dumps(existing, indent=2), encoding="utf-8")


def _fetch_graph(url: str) -> Graph | None:
    """Same shape as server.py's _fetch_graph, using the broker's own token
    (already obtained via step 1's login) -- used here only to read the
    encryption key files for step 2's verification."""
    token = solid_auth_client.get_access_token()
    print(f"[setup_gui] DEBUG: token acquired: {bool(token)}")
    headers = solid_auth_client.authenticated_headers(url, token) if token else {"Accept": "text/turtle"}
    try:
        resp = httpx.get(url, headers=headers, timeout=10.0)
        print(f"[setup_gui] DEBUG: GET {url} -> {resp.status_code}")
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        print(f"[setup_gui] DEBUG: request failed: {exc!r}")
        return None
    g = Graph()
    try:
        g.parse(data=resp.text, format="turtle", publicID=url)
    except Exception:
        return None
    return g


class SetupWindow(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Custos broker setup")
        self.resizable(False, True)
        self._pod_root_url: str | None = None
        self._broker_process: subprocess.Popen | None = None
        self._broker_log_queue: queue.Queue[str] = queue.Queue()
        self._grants_data: dict = self._load_grants_file()
        self._grants_dirty: bool = False
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        pad = {"padx": 16, "pady": 4}

        tk.Label(self, text="Step 1 - Log into your POD", font=("", 11, "bold")).pack(pady=(16, 4))
        tk.Label(self, text="Your WebID (e.g. https://pods.example.org/alice/profile/card#me)").pack(**pad)
        self.webid_entry = tk.Entry(self, width=55)
        self.webid_entry.pack(**pad)
        self.login_button = tk.Button(self, text="Login", command=self._on_login_clicked)
        self.login_button.pack(**pad)
        self.login_status = tk.Label(self, text="Not logged in yet.", fg="gray")
        self.login_status.pack(pady=(0, 12))

        ttk.Separator(self, orient="horizontal").pack(fill="x", padx=20)

        tk.Label(self, text="Step 2 - Verify your security key", font=("", 11, "bold")).pack(pady=(16, 4))
        tk.Label(self, text="App directory where encryption/ keys live (e.g. notepod)").pack(**pad)
        self.app_dir_entry = tk.Entry(self, width=55)
        self.app_dir_entry.pack(**pad)
        tk.Label(self, text="Security key").pack(**pad)
        self.security_key_entry = tk.Entry(self, width=55, show="*")
        self.security_key_entry.pack(**pad)
        self.verify_button = tk.Button(
            self, text="Verify & Save", command=self._on_verify_clicked, state="disabled"
        )
        self.verify_button.pack(**pad)
        self.verify_status = tk.Label(self, text="Log in first.", fg="gray")
        self.verify_status.pack(pady=(0, 16))

        ttk.Separator(self, orient="horizontal").pack(fill="x", padx=20)

        tk.Label(self, text="Step 3 (Optional) - Test the broker", font=("", 11, "bold")).pack(pady=(16, 4))
        tk.Label(
            self,
            text="Launches server.py standalone (stdio) so you can confirm it starts\n"
            "cleanly before wiring it into Claude. It just waits quietly once up which\n"
            "is normal; only a real MCP client (Claude) actually talks to it.",
            justify="center",
            fg="gray",
        ).pack(**pad)
        broker_buttons = tk.Frame(self)
        broker_buttons.pack(**pad)
        self.start_broker_button = tk.Button(broker_buttons, text="Start", command=self._on_start_broker_clicked)
        self.start_broker_button.pack(side="left", padx=4)
        self.stop_broker_button = tk.Button(
            broker_buttons, text="Stop", command=self._on_stop_broker_clicked, state="disabled"
        )
        self.stop_broker_button.pack(side="left", padx=4)
        self.broker_status = tk.Label(self, text="Not running.", fg="gray")
        self.broker_status.pack(pady=(0, 4))
        self.broker_log = scrolledtext.ScrolledText(self, width=70, height=10, state="disabled")
        self.broker_log.pack(padx=16, pady=(0, 16))

        ttk.Separator(self, orient="horizontal").pack(fill="x", padx=20)

        tk.Label(self, text="Step 4 - Manage access grants", font=("", 11, "bold")).pack(pady=(16, 4))
        tk.Label(
            self,
            text="Each purpose needs Read on to be readable at all. This is the\n"
            "consent gate itself (grants.json). Changes save immediately to the\n"
            "same file the broker reads, and take effect on the very next call.",
            justify="center",
            fg="gray",
        ).pack(**pad)

        self.grants_tree = ttk.Treeview(
            self, columns=("read", "path"), show="tree headings", height=6, selectmode="browse"
        )
        self.grants_tree.heading("#0", text="Purpose")
        self.grants_tree.heading("read", text="Read")
        self.grants_tree.heading("path", text="Path override")
        self.grants_tree.column("#0", width=140)
        self.grants_tree.column("read", width=60, anchor="center")
        self.grants_tree.column("path", width=220)
        self.grants_tree.pack(padx=16, pady=(0, 4), fill="x")

        grants_row_buttons = tk.Frame(self)
        grants_row_buttons.pack(**pad)
        tk.Button(grants_row_buttons, text="Toggle Read", command=self._on_toggle_read_clicked).pack(
            side="left", padx=4
        )
        tk.Button(grants_row_buttons, text="Remove", command=self._on_remove_purpose_clicked).pack(
            side="left", padx=4
        )
        tk.Label(grants_row_buttons, text="   New purpose:").pack(side="left")
        self.new_purpose_entry = tk.Entry(grants_row_buttons, width=16)
        self.new_purpose_entry.pack(side="left", padx=4)
        tk.Button(grants_row_buttons, text="Add", command=self._on_add_purpose_clicked).pack(side="left", padx=4)

        grants_save_buttons = tk.Frame(self)
        grants_save_buttons.pack(**pad)
        tk.Button(grants_save_buttons, text="Reload from disk", command=self._on_reload_grants_clicked).pack(
            side="left", padx=4
        )
        tk.Button(grants_save_buttons, text="Save changes", command=self._on_save_grants_clicked).pack(
            side="left", padx=4
        )
        self.grants_status = tk.Label(self, text="All changes saved.", fg="gray")
        self.grants_status.pack(pady=(0, 16))

        self._refresh_grants_tree()

    # -- Step 1: login -------------------------------------------------- #

    def _on_login_clicked(self) -> None:
        webid = self.webid_entry.get().strip()
        if not webid:
            messagebox.showerror("Custos setup", "Enter your WebID first.")
            return
        self.login_button.config(state="disabled")
        self.login_status.config(text="Discovering your POD's login provider...", fg="black")
        threading.Thread(target=self._do_login, args=(webid,), daemon=True).start()

    def _do_login(self, webid: str) -> None:
        issuer = solid_auth_client.discover_issuer_from_webid(webid)
        if not issuer:
            self.after(0, self._login_failed, "Couldn't discover a login provider from that WebID.")
            return
        self.after(0, lambda: self.login_status.config(text="Opening your browser to log in..."))
        payload = solid_auth_client.login_with_pkce(issuer)
        if not payload or not payload.get("refresh_token"):
            self.after(
                0,
                self._login_failed,
                "Login didn't complete, or no refresh token was granted (offline_access scope).",
            )
            return
        solid_auth_client._store_refresh_token(payload["refresh_token"])
        solid_auth_client._store_login_client_id(payload["client_id"])
        self._pod_root_url = _guess_pod_root_url(webid)
        _save_config(pod_base_url=self._pod_root_url, pod_root_url=self._pod_root_url, webid=webid)
        self.after(0, self._login_succeeded)

    def _login_failed(self, message: str) -> None:
        self.login_status.config(text=f"Login failed: {message}", fg="red")
        self.login_button.config(state="normal")

    def _login_succeeded(self) -> None:
        self.login_status.config(text=f"Logged in. POD root: {self._pod_root_url}", fg="green")
        self.verify_button.config(state="normal")
        self.verify_status.config(text="Ready to verify your security key.", fg="gray")

    # -- Step 2: security key -------------------------------------------- #

    def _on_verify_clicked(self) -> None:
        app_dir = self.app_dir_entry.get().strip()
        security_key = self.security_key_entry.get()
        if not app_dir or not security_key:
            messagebox.showerror("Custos setup", "Enter both the app directory and your security key.")
            return
        self.verify_button.config(state="disabled")
        self.verify_status.config(text="Verifying...", fg="black")
        threading.Thread(target=self._do_verify, args=(app_dir, security_key), daemon=True).start()

    def _do_verify(self, app_dir: str, security_key: str) -> None:
        encryption_base = self._pod_root_url.rstrip("/") + "/" + app_dir.strip("/") + "/"
        enc_keys = pod_decryption.read_enc_keys(_fetch_graph, encryption_base)
        if enc_keys is None:
            self.after(
                0,
                self._verify_failed,
                "Couldn't find/read encryption/enc-keys.ttl there — check the app directory name.",
            )
            return
        master_key, verification = pod_decryption.derive_keys(security_key, enc_keys["salt"])
        if verification != enc_keys["verification"]:
            self.after(0, self._verify_failed, "That security key doesn't match this POD's stored verification value.")
            return
        keyring.set_password(
            pod_decryption.KEYRING_SERVICE,
            pod_decryption.KEYRING_MASTER_KEY,
            base64.b64encode(master_key).decode(),
        )
        _save_config(encryption_base_url=encryption_base)
        self.after(0, self._verify_succeeded)

    def _verify_failed(self, message: str) -> None:
        self.verify_status.config(text=message, fg="red")
        self.verify_button.config(state="normal")

    def _verify_succeeded(self) -> None:
        self.verify_status.config(text="Security key verified and saved. Setup complete!", fg="green")

    # -- Step 3: run the broker ------------------------------------------ #

    def _on_start_broker_clicked(self) -> None:
        if self._broker_process is not None:
            return
        self._append_log(f"Starting {SERVER_PATH} ...\n")
        self._broker_process = subprocess.Popen(
            [sys.executable, str(SERVER_PATH)],
            cwd=str(SERVER_PATH.parent),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        self.start_broker_button.config(state="disabled")
        self.stop_broker_button.config(state="normal")
        self.broker_status.config(text=f"Running (pid {self._broker_process.pid}).", fg="green")
        threading.Thread(target=self._read_broker_output, daemon=True).start()
        self.after(200, self._poll_broker_log)

    def _read_broker_output(self) -> None:
        proc = self._broker_process
        if proc is None or proc.stdout is None:
            return
        for line in proc.stdout:
            self._broker_log_queue.put(line)
        self._broker_log_queue.put("__PROCESS_EXITED__\n")

    def _poll_broker_log(self) -> None:
        try:
            while True:
                line = self._broker_log_queue.get_nowait()
                if line == "__PROCESS_EXITED__\n":
                    self._on_broker_exited()
                    return
                self._append_log(line)
        except queue.Empty:
            pass
        if self._broker_process is not None:
            self.after(200, self._poll_broker_log)

    def _append_log(self, text: str) -> None:
        self.broker_log.config(state="normal")
        self.broker_log.insert("end", text)
        self.broker_log.see("end")
        self.broker_log.config(state="disabled")

    def _on_stop_broker_clicked(self) -> None:
        if self._broker_process is None:
            return
        self._broker_process.terminate()

    def _on_broker_exited(self) -> None:
        code = self._broker_process.poll() if self._broker_process else None
        self._append_log(f"\n[broker process exited, code {code}]\n")
        self._broker_process = None
        self.start_broker_button.config(state="normal")
        self.stop_broker_button.config(state="disabled")
        self.broker_status.config(text="Not running.", fg="gray")

    def _on_close(self) -> None:
        if self._broker_process is not None:
            self._broker_process.terminate()
        self.destroy()

    # -- Step 4: manage grants.json --------------------------------------- #

    def _load_grants_file(self) -> dict:
        if not GRANTS_PATH.exists():
            return {"grants": {}}
        try:
            return json.loads(GRANTS_PATH.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {"grants": {}}

    def _refresh_grants_tree(self) -> None:
        self.grants_tree.delete(*self.grants_tree.get_children())
        for purpose, entry in self._grants_data.get("grants", {}).items():
            read_on = bool(entry.get("read"))
            path = entry.get("path") or "(default)"
            self.grants_tree.insert("", "end", iid=purpose, text=purpose, values=("On" if read_on else "Off", path))

    def _mark_grants_dirty(self) -> None:
        self._grants_dirty = True
        self.grants_status.config(text="Unsaved changes — click Save to apply.", fg="black")

    def _on_reload_grants_clicked(self) -> None:
        if self._grants_dirty and not messagebox.askyesno(
            "Custos setup", "Discard unsaved grant changes and reload from disk?"
        ):
            return
        self._grants_data = self._load_grants_file()
        self._grants_dirty = False
        self._refresh_grants_tree()
        self.grants_status.config(text="Reloaded from disk.", fg="gray")

    def _on_toggle_read_clicked(self) -> None:
        selected = self.grants_tree.selection()
        if not selected:
            messagebox.showinfo("Custos setup", "Select a purpose first.")
            return
        purpose = selected[0]
        entry = self._grants_data.setdefault("grants", {}).setdefault(purpose, {})
        entry["read"] = not bool(entry.get("read"))
        self._mark_grants_dirty()
        self._refresh_grants_tree()
        self.grants_tree.selection_set(purpose)

    def _on_add_purpose_clicked(self) -> None:
        purpose = self.new_purpose_entry.get().strip()
        if not purpose:
            messagebox.showerror("Custos setup", "Enter a purpose name first.")
            return
        grants = self._grants_data.setdefault("grants", {})
        if purpose in grants:
            messagebox.showerror("Custos setup", f"'{purpose}' is already in grants.json.")
            return
        grants[purpose] = {"read": True}
        self.new_purpose_entry.delete(0, "end")
        self._mark_grants_dirty()
        self._refresh_grants_tree()
        self.grants_tree.selection_set(purpose)

    def _on_remove_purpose_clicked(self) -> None:
        selected = self.grants_tree.selection()
        if not selected:
            messagebox.showinfo("Custos setup", "Select a purpose first.")
            return
        purpose = selected[0]
        if not messagebox.askyesno("Custos setup", f"Remove '{purpose}' from grants.json?"):
            return
        self._grants_data.get("grants", {}).pop(purpose, None)
        self._mark_grants_dirty()
        self._refresh_grants_tree()

    def _on_save_grants_clicked(self) -> None:
        try:
            GRANTS_PATH.write_text(json.dumps(self._grants_data, indent=2), encoding="utf-8")
        except OSError as exc:
            messagebox.showerror("Custos setup", f"Couldn't save grants.json: {exc}")
            return
        self._grants_dirty = False
        self.grants_status.config(text="Saved — takes effect on the next call, no restart needed.", fg="green")


if __name__ == "__main__":
    SetupWindow().mainloop()
