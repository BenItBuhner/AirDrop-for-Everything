"""AirDrop identity: the TLS certificate + optional Apple ID record we present.

Follows the same contract as omdrop's identity docs, minus their 1Password /
kernel-keyring plumbing (that machinery is Linux-specific):

  * ``<keys>/certificate.pem`` + ``key.pem`` + ``validation_record.cms``:
    an Apple-issued identity, used when all three exist (Contacts Only peers
    need it). ``validation_record.cms`` is presented only with this pair.
  * ``<keys>/certificate.self-signed.pem`` + ``key.self-signed.pem``:
    the fallback, generated here when missing. Everyone-mode peers accept it.

Keys are searched in ``--keys DIR``, then ``~/.airdrop-everything/keys``,
then ``~/.omdrop/keys`` so a machine that also runs omdrop shares its
identity with it.
"""
import contextlib
import os
import ssl
import subprocess
import sys
from pathlib import Path


class IdentityError(RuntimeError):
    """A named identity-selection or loading failure (never secret material)."""


class Identity:
    """Selected TLS material and the optional Apple ID validation record."""

    def __init__(self, kind, certificate, key, record_data=None):
        self.kind = kind                      # 'apple' or 'self-signed'
        self.certificate = str(certificate)
        self.key = str(key)
        self.record_data = record_data
        self.warnings = []

    def load_cert_chain(self, ctx):
        try:
            ctx.load_cert_chain(self.certificate, self.key)
        except (OSError, ValueError, ssl.SSLError) as e:
            raise IdentityError(f"identity-tls-load-failed: {e}") from None


def default_keys_dir():
    """Where our keys live; falls back to omdrop's directory when present."""
    ours = Path.home() / ".airdrop-everything" / "keys"
    if ours.is_dir() or not (Path.home() / ".omdrop" / "keys").is_dir():
        return ours
    return Path.home() / ".omdrop" / "keys"


def create_self_signed(directory, computer_name):
    """Generate the self-signed pair (RSA-2048, CN=<name>, 365 days)."""
    directory = Path(directory)
    certificate = directory / "certificate.self-signed.pem"
    key = directory / "key.self-signed.pem"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        _gen_with_cryptography(certificate, key, computer_name)
        return
    except ImportError:
        pass
    except Exception as e:
        raise IdentityError(f"self-signed-create-failed: {e}") from None
    _gen_with_openssl(certificate, key, computer_name)


def _gen_with_cryptography(certificate, key, computer_name):
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, computer_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(k.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(k, hashes.SHA256()))
    key.write_bytes(k.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    certificate.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    _chmod600(key)
    _chmod600(certificate)


def _gen_with_openssl(certificate, key, computer_name):
    import tempfile
    name = computer_name.replace("\\", "\\\\").replace("/", "\\/")
    with tempfile.TemporaryDirectory(dir=str(certificate.parent)) as tmp_s:
        tmp = Path(tmp_s)
        result = subprocess.run(
            ["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-x509",
             "-days", "365", "-subj", f"/CN={name}",
             "-keyout", str(tmp / "key.pem"),
             "-out", str(tmp / "certificate.pem")],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        if result.returncode:
            raise IdentityError("self-signed-create-failed (no cryptography "
                                "package and openssl failed)")
        os.replace(tmp / "key.pem", key)
        os.replace(tmp / "certificate.pem", certificate)
        _chmod600(key)
        _chmod600(certificate)


def _chmod600(path):
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)


def resolve(keys=None, computer_name="airdrop", create=True):
    """Pick an identity. Returns Identity; raises IdentityError."""
    directory = Path(keys) if keys else default_keys_dir()
    cert = directory / "certificate.pem"
    key = directory / "key.pem"
    record = directory / "validation_record.cms"
    if cert.is_file() and key.is_file():
        record_data = record.read_bytes() if record.is_file() else None
        return Identity("apple", cert, key, record_data)

    scert = directory / "certificate.self-signed.pem"
    skey = directory / "key.self-signed.pem"
    if not (scert.is_file() and skey.is_file()):
        if not create:
            raise IdentityError("self-signed-missing")
        create_self_signed(directory, computer_name)
    return Identity("self-signed", scert, skey)


def import_apple_identity(keys, certificate, key, record=None):
    """Copy an Apple-issued cert/key (+ optional validation record) into keys dir."""
    directory = Path(keys) if keys else default_keys_dir()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    for src, dst in ((certificate, "certificate.pem"), (key, "key.pem"),
                     (record, "validation_record.cms")):
        if src:
            data = Path(src).read_bytes()
            (directory / dst).write_bytes(data)
            _chmod600(directory / dst)


def extract_macos_identity(outdir):
    """On macOS, pull the local Apple ID certificate+key out of the keychain.

    sharingd keeps `com.apple.idms.appleid.prd.<altDsID>` items in the login
    keychain; `security` can export them when the user unlocks it. Returns the
    cert path written, or raises IdentityError with what failed.
    """
    if sys.platform != "darwin":
        raise IdentityError("keychain extraction only exists on macOS")
    outdir = Path(outdir)
    outdir.mkdir(mode=0o700, parents=True, exist_ok=True)
    cert_pem = outdir / "certificate.pem"
    proc = subprocess.run(
        ["security", "find-certificate", "-c",
         "com.apple.idms.appleid.prd", "-a", "-p"],
        capture_output=True)
    if proc.returncode or b"BEGIN CERTIFICATE" not in proc.stdout:
        raise IdentityError("no Apple ID certificate in the login keychain "
                            "(is this Mac signed in to an Apple Account?)")
    # There may be several; the AirDrop one is issued by the Application
    # Integration CA. Take the first match as a starting point.
    cert_pem.write_bytes(proc.stdout)
    raise IdentityError(
        f"certificate written to {cert_pem}; export the matching private "
        "key from Keychain Access as key.pem beside it")
