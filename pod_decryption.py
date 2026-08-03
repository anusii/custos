"""
TNO (Trust No One) decryption for data written by the solidpod Flutter
library. The POD server (and, by default, this broker) only ever sees
ciphertext — this module reverses that, entirely client-side, exactly like
the Flutter app already does. Nothing in this module ever sends key
material anywhere; decryption happens in this process's memory only.

Algorithm confirmed against the actual solidpod/notepod Dart source (not
docs), including the exact library calls PointyCastle/encrypter_plus make:

    key_helper.dart, data_encryption.dart, individual_key_manager.dart
    (solidpod/lib/src/solid/utils/ -- see LessonsLearned.md for full paths)

Two things worth knowing before touching this file:

1. Data content and the wrapped "individual key" are both AES-256-CTR
   ("SIC" in PointyCastle's naming) with PKCS7 padding -- unusual, since CTR
   is a stream cipher and doesn't normally need padding, but encrypter_plus's
   AES class defaults to PKCS7 even in CTR mode. Only the RSA private-key
   wrap (not implemented here -- see module docstring bottom) uses CBC.
2. The wrapped "individual key" is doubly-encoded: decrypting it yields the
   *base64 string* of the key, not the raw key bytes. Base64-decode again to
   get the actual 32-byte AES key. Skipping this silently produces a
   wrong-length key instead of an error.

get_master_key() reads a key already derived and verified by setup_gui.py
and stored via `keyring` -- this module itself never prompts for anything.
If no master key is available (setup hasn't been run yet), decryption is
simply skipped and plaintext-looking resources pass through unaffected.

NotePod additionally applies its own inner cipher to just the noteContent
field (see notepod_decrypt_content() below) -- confirmed against notepod's
own source (encryption.dart), not guessed: its real purpose is working
around a Turtle-parser limitation with special characters in note text, not
secrecy (the key is derived from the note's own createdDateTime, itself
stored in plaintext in the same document).

Deliberately out of scope (see PLAN.md / LessonsLearned.md for the reasoning
if this changes): legacy v1 (SHA-256) key derivation, RSA private-key
decryption and cross-user resource sharing, large-file chunking /
notification encryption.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any, Callable

import keyring
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from rdflib import Graph, Literal, URIRef

KEYRING_SERVICE = "custos-broker"
KEYRING_MASTER_KEY = "master_key"

# solidTerms: https://solidcommunity.au/predicates/terms#
SOLID_TERMS = "https://solidcommunity.au/predicates/terms#"
PRED_IV = URIRef(SOLID_TERMS + "iv")
PRED_ENC_DATA = URIRef(SOLID_TERMS + "encData")
PRED_SALT = URIRef(SOLID_TERMS + "salt")
PRED_ENC_KEY = URIRef(SOLID_TERMS + "encKey")
PRED_SESSION_KEY = URIRef(SOLID_TERMS + "sessionKey")
PRED_PATH = URIRef(SOLID_TERMS + "path")

# NotePod's own predicates -- same solidTerms namespace, confirmed against
# notepod/lib/constants/turtle_structures.dart.
PRED_NOTE_CONTENT = URIRef(SOLID_TERMS + "noteContent")
PRED_CREATED_DATETIME = URIRef(SOLID_TERMS + "createdDateTime")
_NOTEPOD_FIXED_IV = bytes(range(1, 17))

ENC_KEYS_PATH = "encryption/enc-keys.ttl"
IND_KEYS_PATH = "encryption/ind-keys.ttl"


# --------------------------------------------------------------------------- #
# Crypto primitives
# --------------------------------------------------------------------------- #

def derive_keys(security_key: str, salt: bytes) -> tuple[bytes, bytes]:
    """Argon2id -> two HKDF-SHA256 calls -> (master_key, verification_value),
    each 32 bytes. Matches solidpod's key_helper.dart:deriveKeys exactly."""
    argon2_raw = hash_secret_raw(
        secret=security_key.encode("utf-8"),
        salt=salt,
        time_cost=1,
        memory_cost=10000,
        parallelism=4,
        hash_len=32,
        type=Type.ID,
        version=19,
    )
    master_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"solidpod/v2/master-key").derive(
        argon2_raw
    )
    verification = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt, info=b"solidpod/v2/verification"
    ).derive(argon2_raw)
    return master_key, verification


def _pkcs7_unpad(padded: bytes) -> bytes:
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _pkcs7_pad(data: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()


def aes_ctr_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-256-CTR + PKCS7-unpad -- the scheme encrypter_plus actually uses
    for data content and for wrapping individual/session keys."""
    decryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return _pkcs7_unpad(padded)


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-256-CBC + PKCS7 -- only used for the RSA private-key wrap, which
    this module doesn't implement yet (no sharing support). Kept here since
    it's a two-line function and the natural place for it when that's added."""
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return _pkcs7_unpad(padded)


# --------------------------------------------------------------------------- #
# Master key (from keyring, set by setup_gui.py -- never prompted here)
# --------------------------------------------------------------------------- #

_master_key_cache: bytes | None = None


def get_master_key() -> bytes | None:
    """Read the already-derived-and-verified master key set by setup_gui.py.
    Returns None (not an error) if setup hasn't been run -- callers should
    treat encrypted resources as unreadable rather than crash."""
    global _master_key_cache
    if _master_key_cache is not None:
        return _master_key_cache
    stored = keyring.get_password(KEYRING_SERVICE, KEYRING_MASTER_KEY)
    if not stored:
        return None
    _master_key_cache = base64.b64decode(stored)
    return _master_key_cache


# --------------------------------------------------------------------------- #
# Key-management files (enc-keys.ttl / ind-keys.ttl)
# --------------------------------------------------------------------------- #

def _literal(g: Graph, subject: URIRef | None, predicate: URIRef) -> str | None:
    for s, p, o in g.triples((subject, predicate, None)):
        return str(o)
    return None


def read_enc_keys(fetch_graph: Callable[[str], Graph | None], encryption_base_url: str) -> dict[str, Any] | None:
    """Parse <encryption_base_url>enc-keys.ttl: salt, keyVersion, verification
    value. Returns None if the resource can't be fetched/parsed."""
    url = encryption_base_url.rstrip("/") + "/" + ENC_KEYS_PATH
    print(f"[pod_decryption] DEBUG: fetching {url}")
    g = fetch_graph(url)
    if g is None:
        print("[pod_decryption] DEBUG: fetch_graph returned None (request failed or didn't parse as Turtle)")
        return None
    print(f"[pod_decryption] DEBUG: fetched graph has {len(g)} triples:")
    for s, p, o in g:
        print(f"[pod_decryption] DEBUG:   {s} {p} {o!r}")
    salt_b64 = _literal(g, None, PRED_SALT)
    enc_key_b64 = _literal(g, None, PRED_ENC_KEY)
    if not salt_b64 or not enc_key_b64:
        print(f"[pod_decryption] DEBUG: salt={salt_b64!r} encKey={enc_key_b64!r} (expected predicates {PRED_SALT} / {PRED_ENC_KEY})")
        return None
    return {"salt": base64.b64decode(salt_b64), "verification": base64.b64decode(enc_key_b64)}


def read_ind_key_for_path(
    fetch_graph: Callable[[str], Graph | None], encryption_base_url: str, resource_path: str
) -> tuple[str, str] | None:
    """Parse <encryption_base_url>ind-keys.ttl and return the (sessionKey,
    iv) base64 pair for the given POD-relative resource_path, or None."""
    url = encryption_base_url.rstrip("/") + "/" + IND_KEYS_PATH
    g = fetch_graph(url)
    if g is None:
        return None
    # Compare by string value, not by Literal equality/hashing: the stored
    # path literal carries an explicit datatype=xsd:string, and rdflib's
    # graph.subjects() index lookup does not reliably treat that as equal to
    # a plain (implicit-xsd:string) Literal("...") even though RDF 1.1 says
    # they're the same value -- confirmed empirically, not assumed.
    for subj, _, obj in g.triples((None, PRED_PATH, None)):
        if str(obj) != resource_path:
            continue
        session_key_b64 = _literal(g, subj, PRED_SESSION_KEY)
        iv_b64 = _literal(g, subj, PRED_IV)
        if session_key_b64 and iv_b64:
            return session_key_b64, iv_b64
    return None


def unwrap_individual_key(session_key_b64: str, iv_b64: str, master_key: bytes) -> bytes:
    """The wrapped individual key is doubly-encoded: AES-CTR-decrypting it
    yields the *base64 string* of the key, not the raw bytes -- decode again."""
    iv = base64.b64decode(iv_b64)
    padded_plain = aes_ctr_decrypt(base64.b64decode(session_key_b64), master_key, iv)
    inner_b64_str = padded_plain.decode("utf-8")
    return base64.b64decode(inner_b64_str)


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #

def is_encrypted_resource(g: Graph, resource_url: str) -> bool:
    subj = URIRef(resource_url)
    return _literal(g, subj, PRED_IV) is not None and _literal(g, subj, PRED_ENC_DATA) is not None


def maybe_decrypt_resource(
    g: Graph,
    resource_url: str,
    resource_path: str,
    fetch_graph: Callable[[str], Graph | None],
    encryption_base_url: str | None,
) -> Graph:
    """If `g` is a solidpod-encrypted whole-document replacement for
    resource_url, decrypt and re-parse the recovered plaintext as a new
    Graph. Otherwise return `g` unchanged -- a no-op for plaintext PODs."""
    if not is_encrypted_resource(g, resource_url):
        return g
    if not encryption_base_url:
        return g  # decryption not configured; caller sees the raw (ciphertext) graph

    master_key = get_master_key()
    if master_key is None:
        return g  # setup_gui.py hasn't been run yet

    ind_key = read_ind_key_for_path(fetch_graph, encryption_base_url, resource_path)
    if ind_key is None:
        return g
    individual_key = unwrap_individual_key(ind_key[0], ind_key[1], master_key)

    subj = URIRef(resource_url)
    iv_b64 = _literal(g, subj, PRED_IV)
    enc_data_b64 = _literal(g, subj, PRED_ENC_DATA)
    plaintext = aes_ctr_decrypt(base64.b64decode(enc_data_b64), individual_key, base64.b64decode(iv_b64))

    inner = Graph()
    try:
        inner.parse(data=plaintext.decode("utf-8"), format="turtle", publicID=resource_url)
    except Exception:
        return g
    return inner


def notepod_decrypt_content(g: Graph) -> Graph:
    """Reverse NotePod's own inner cipher on noteContent (separate from, and
    applied on top of, solidpod's whole-document encryption already handled
    by maybe_decrypt_resource above). AES-256-CBC+PKCS7, key = first 32 hex
    characters of SHA-256(createdDateTime) used as raw ASCII bytes (not
    hex-decoded), fixed IV = bytes 1..16 -- confirmed against notepod's own
    encryption.dart. No-op if the graph has no noteContent/createdDateTime
    pair (e.g. non-NotePod data), or if decryption fails for any reason —
    fails closed, leaving the original value rather than guessing."""
    created = _literal(g, None, PRED_CREATED_DATETIME)
    content = _literal(g, None, PRED_NOTE_CONTENT)
    if not created or not content:
        return g
    key = hashlib.sha256(created.encode("utf-8")).hexdigest()[:32].encode("ascii")
    try:
        plaintext = aes_cbc_decrypt(base64.b64decode(content), key, _NOTEPOD_FIXED_IV).decode("utf-8")
    except Exception:
        return g
    for subj in list(g.subjects(PRED_NOTE_CONTENT, None)):
        g.remove((subj, PRED_NOTE_CONTENT, None))
        g.add((subj, PRED_NOTE_CONTENT, Literal(plaintext)))
    return g
