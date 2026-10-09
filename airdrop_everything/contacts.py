"""Decide whether an AirDrop sender is someone this machine knows.

Portable port of omdrop's contacts.py. Apple's "Contacts Only" is not a name
check: a sender proves identity with (1) an Apple ID *validation record* -- a
CMS blob signed by Apple carrying SHA-256 hashes of the account's verified
emails and phone numbers -- and (2) an Apple-issued client TLS certificate
whose CN is ``com.apple.idms.appleid.prd.<altDsID>`` matching the record's
altDsID. Verification needs only Apple's public root, vendored in certs/.

Three checks, all three matter:
  1. the record's signature verifies to Apple Root CA;
  2. the certificate is Apple-issued AND its CN ends with the record's altDsID
     (otherwise a replayed record would suffice to impersonate a contact);
  3. a hashed identifier in the record matches our known-senders list.
"""
import hashlib
import os
import plistlib
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

APPLE_ISSUER_CN = "Apple Application Integration Certification Authority"
CN_PREFIX = "com.apple.idms.appleid.prd."

CERTS_DIR = Path(__file__).resolve().parent / "certs"
APPLE_ROOT_CA = CERTS_DIR / "apple_root_ca.pem"

ACCEPT = "accept"
REJECT_NO_RECORD = "no-record"
REJECT_BAD_RECORD = "bad-record"
REJECT_NO_CERT = "no-certificate"
REJECT_UNBOUND = "record-not-bound-to-certificate"
REJECT_UNKNOWN = "not-a-known-sender"

WHY = {
    ACCEPT: "sender is a known contact",
    REJECT_NO_RECORD: "sender sent no Apple ID validation record",
    REJECT_BAD_RECORD: "the validation record is not signed by Apple, or has expired",
    REJECT_NO_CERT: "sender presented no client certificate",
    REJECT_UNBOUND: "the validation record does not belong to the presented certificate",
    REJECT_UNKNOWN: "sender is not in the known-senders list",
}


def config_dir():
    base = os.environ.get("A4E_CONFIG")
    if base:
        return Path(base)
    if os.name == "nt":
        return Path(os.environ.get("APPDATA", Path.home() / ".config")) / "airdrop-everything"
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "airdrop-everything"


def known_senders_path():
    return config_dir() / "known-senders"


def apple_root_ca():
    return str(APPLE_ROOT_CA) if APPLE_ROOT_CA.is_file() else None


def apple_intermediates():
    if CERTS_DIR.is_dir():
        return sorted(str(p) for p in CERTS_DIR.glob("apple-aai*.pem"))
    return []


def normalize(entry):
    """Normalize an address-book entry the way AirDrop does before hashing:
    phone numbers hash digits-only, emails hash lowercased."""
    entry = entry.strip()
    if not entry or entry.startswith("#"):
        return None
    if "@" in entry:
        return entry.lower()
    digits = re.sub(r"\D", "", entry)
    return digits or None


def hash_identifier(entry):
    return hashlib.sha256(entry.encode()).hexdigest().lower()


def known_hashes(path=None):
    path = Path(path or known_senders_path())
    if not path.exists():
        return set()
    out = set()
    for line in path.read_text(errors="replace").splitlines():
        entry = normalize(line)
        if entry:
            out.add(hash_identifier(entry))
    return out


def _openssl():
    import shutil
    return shutil.which("openssl")


def verify_record(record, ca_file=None):
    """Verify Apple's CMS signature over a validation record; None if invalid.

    Uses the openssl CLI (present on macOS, virtually every Linux, and Git /
    package-manager installs of Windows). Returns None when openssl is absent
    too -- callers treat that as "cannot judge", never as "accept".
    """
    ca = ca_file or apple_root_ca()
    openssl = _openssl()
    if not ca or not record or not openssl:
        return None
    with tempfile.NamedTemporaryFile(suffix=".bin") as out:
        proc = subprocess.run(
            [openssl, "cms", "-verify", "-inform", "DER", "-CAfile", ca,
             "-purpose", "any", "-out", out.name],
            input=record, capture_output=True)
        if proc.returncode != 0:
            return None
        payload = Path(out.name).read_bytes()
    try:
        plist = plistlib.loads(payload)
    except Exception:
        return None
    valid_as_of = plist.get("ValidAsOf")
    duration = plist.get("SuggestValidDuration")
    expires = None
    if isinstance(valid_as_of, datetime) and isinstance(duration, (int, float)):
        base = valid_as_of if valid_as_of.tzinfo else valid_as_of.replace(tzinfo=timezone.utc)
        expires = base.timestamp() + duration
    hashes = {h.lower() for h in
              (plist.get("ValidatedEmailHashes") or []) +
              (plist.get("ValidatedPhoneHashes") or [])
              if isinstance(h, str)}
    return {
        "account": plist.get("altDsID", ""),
        "hashes": hashes,
        "expires": expires,
        "expired": bool(expires and expires < datetime.now(timezone.utc).timestamp()),
    }


def certificate_account(der, ca_file=None, untrusted=None):
    """The Apple ID a client certificate belongs to, or "" if not Apple-issued.

    The leaf must verify to Apple's root (with the vendored intermediates as
    untrusted chain input); the CN must carry the com.apple.idms prefix.
    """
    if not der:
        return ""
    openssl = _openssl()
    ca = ca_file or apple_root_ca()
    if not ca or not openssl:
        return ""          # fail closed: without the root we cannot judge
    chain = list(untrusted) if untrusted is not None else apple_intermediates()
    with tempfile.TemporaryDirectory() as tmp:
        leaf = Path(tmp) / "leaf.pem"
        pem = subprocess.run([openssl, "x509", "-inform", "DER", "-out", str(leaf)],
                             input=der, capture_output=True)
        if pem.returncode != 0:
            return ""
        args = [openssl, "verify", "-CAfile", ca, "-purpose", "any"]
        if chain:
            bundle = Path(tmp) / "chain.pem"
            bundle.write_bytes(b"".join(Path(c).read_bytes() for c in chain))
            args += ["-untrusted", str(bundle)]
        verified = subprocess.run([*args, str(leaf)], capture_output=True)
        if verified.returncode != 0:
            return ""
        subject = subprocess.run(
            [openssl, "x509", "-in", str(leaf), "-noout", "-subject"],
            capture_output=True).stdout.decode(errors="replace")
    if "CN=" not in subject:
        return ""
    cn = subject.split("CN=", 1)[1].strip()
    return cn[len(CN_PREFIX):] if cn.startswith(CN_PREFIX) else ""


def decide(record, peer_cert, known=None, ca_file=None, untrusted=None):
    """Should we accept a transfer from this sender? -> (outcome, detail)."""
    known = known_hashes() if known is None else known
    if not record:
        return REJECT_NO_RECORD, {}
    info = verify_record(record, ca_file)
    if info is None or info["expired"]:
        return REJECT_BAD_RECORD, {"expired": bool(info and info["expired"])}
    if not peer_cert:
        return REJECT_NO_CERT, {}
    account = certificate_account(peer_cert, ca_file, untrusted)
    if not account or account != info["account"]:
        return REJECT_UNBOUND, {"apple_issued_certificate": bool(account)}
    if not known:
        return REJECT_UNKNOWN, {"known_senders": 0}
    if info["hashes"] & known:
        return ACCEPT, {"known_senders": len(known)}
    return REJECT_UNKNOWN, {"known_senders": len(known)}


def decide_discovery(record, known=None, ca_file=None):
    """May this sender even see us? Weaker than decide(); discovery only.

    A sender presents its client certificate on /Ask, never on /Discover, so
    at discovery time a record cannot be bound to the connection. A replayed
    record is therefore accepted here -- this only controls whether a tile
    appears in a stranger's share sheet, never whether a transfer proceeds.
    Fails open for unparseable/missing records.
    """
    known = known_hashes() if known is None else known
    if not record:
        return ACCEPT, {"identified": False}
    info = verify_record(record, ca_file)
    if info is None or info["expired"]:
        return ACCEPT, {"identified": False}
    if known and info["hashes"] & known:
        return ACCEPT, {"identified": True}
    return REJECT_UNKNOWN, {"known_senders": len(known)}


def visibility(path=None):
    """'everyone' (default) or 'contacts', from the config file."""
    path = Path(path) if path else config_dir() / "visibility"
    try:
        value = path.read_text().strip().lower()
    except OSError:
        return "everyone"
    return "contacts" if value == "contacts" else "everyone"
