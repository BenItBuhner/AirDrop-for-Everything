"""airdrop-everything -- the command line.

  a4e receive        become an AirDrop receiver (advertise + serve + store)
  a4e send FILE..    send files to a receiver
  a4e peers          list receivers in range
  a4e wake           emit the BLE AirDrop advert that wakes Apple receivers
  a4e identity       show / generate / import our AirDrop identity
  a4e doctor         report platform capabilities and what stands in the way
  a4e radio ...      Linux AWDL helper: start|stop|status|peers|probe (root)
  a4e af-listen      dump AWDL action frames (Linux, monitor interface, root)
"""
import argparse
import contextlib
import logging
import os
import sys
import threading
import time

from . import __version__, ble, const, contacts, discovery, identity, transport
from .util import platform_name, short_hostname

log = logging.getLogger("airdrop")

DEFAULT_MODEL = "MacBookPro18,3"
DEFAULT_NAME = None          # resolved to short hostname at use


def _cfg_dir():
    return contacts.config_dir()


def _load_config(path=None):
    import tomllib
    path = path or (_cfg_dir() / "config.toml")
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except FileNotFoundError:
        return {}
    except tomllib.TOMLDecodeError as e:
        raise SystemExit(f"{path}: {e}") from e


def _resolve_identity(args):
    try:
        return identity.resolve(keys=getattr(args, "keys", None),
                                computer_name=_sender_name(args))
    except identity.IdentityError as e:
        raise SystemExit(f"identity error: {e}") from e


def _receiver_name(args, cfg):
    n = getattr(args, "name", None) or cfg.get("name") or short_hostname()
    import re as _re
    if _re.search(r"[/\\\x00-\x1f]", n) or not 1 <= len(n) <= 63:
        raise SystemExit(f"name {n!r}: 1-63 chars, no path separators/controls")
    return n


def _model(args, cfg):
    import re
    m = getattr(args, "model", None) or cfg.get("model", DEFAULT_MODEL)
    if not re.match(r"^[A-Za-z]+[0-9]+,[0-9]+$", m):
        raise SystemExit(f"model {m!r}: must look like MacBookPro18,3")
    return m


def _sender_name(args):
    return getattr(args, "name", None) or short_hostname()


def _dest(args, cfg):
    d = getattr(args, "outdir", None) or cfg.get("download_dir") \
        or os.path.join(os.path.expanduser("~"), "Downloads")
    d = os.path.realpath(os.path.expanduser(d))
    if not os.path.isdir(d):
        raise SystemExit(f"download dir {d}: not a directory")
    return d


# ------------------------------------------------------------------- receive

def cmd_receive(args):
    from . import server
    cfg_file = _load_config(getattr(args, "config", None))
    name = _receiver_name(args, cfg_file)
    model = _model(args, cfg_file)
    dest = _dest(args, cfg_file)
    visibility = "contacts" if getattr(args, "contacts", False) else "everyone"
    max_pct = getattr(args, "max_receive_percent", None) \
        or cfg_file.get("max_receive_percent", 30)

    ident = _resolve_identity(args)
    for w in ident.warnings:
        log.warning("identity: %s", w)
    log.info("identity: %s%s", ident.kind,
             f", Apple ID record {len(ident.record_data)} B"
             if ident.record_data else "")

    trans = transport.pick(args.iface)
    service_id = args.service_id or trans.service_id
    host_label = (name.lower().replace(" ", "-") or "a4e") \
        if trans.mode == "lan" else _awdl_host(name)

    threading.Event()

    def on_ask(ask):
        if not getattr(args, "ask", False):
            return True
        sender = ask.get("SenderComputerName") or "someone"
        files = ask.get("Files") or []
        desc = ", ".join(f.get("FileName", "?") for f in files[:4]) or \
            str(len(ask.get("Items") or [])) + " item(s)"
        print(f"\nAirDrop: {sender} wants to send {desc}. Accept? [Y/n] ",
              end="", flush=True)
        try:
            return input().strip().lower() not in ("n", "no")
        except EOFError:
            return False

    cfg = {
        "name": name, "model": model, "dest": dest,
        "visibility": visibility, "max_receive_percent": max_pct,
        "record_data": ident.record_data,
        "on_ask": on_ask if getattr(args, "ask", False) else None,
        "on_upload": lambda tid, files: print(
            f"received: {', '.join(files)}") or (args.quiet and None),
    }

    srv = server.serve(cfg, ident, host=trans.bind_addr, port=args.port)

    announcers = []
    raw_announcer = None
    if trans.mode == "awdl" and trans.raw_ok and not args.no_raw:
        # AF_PACKET bursts are what reliably reach the air over AWDL.
        raw_announcer = discovery.RawAnnouncer(
            trans.iface, trans.mac, service_id, host_label, args.port,
            args.flags, interval=3.0)
        responder = discovery.RawResponder(
            trans.iface, trans.mac, service_id, host_label, args.port,
            args.flags)
        raw_announcer.start()
        responder.start()
        announcers.extend([raw_announcer, responder])
    zc = discovery.ZeroconfAnnouncer(
        host_label=host_label, service_id=service_id, port=args.port,
        flags=args.flags,
        interfaces=([str(a).split("%")[0] for a in trans.addrs]
                    if trans.mode == "awdl" else None),
        reannounce=(3.0 if trans.mode == "awdl" and not trans.raw_ok else 0))
    zc.start(trans.addrs)
    announcers.append(zc)

    print(f"AirDrop receiver {name!r} ({model})")
    print(f"  service:  {service_id}._airdrop._tcp.local :{args.port}")
    print(f"  via:      {trans.describe()}")
    print(f"  saving:   {dest}")
    print(f"  policy:   {visibility}"
          + (" (prompting per transfer)" if getattr(args, "ask", False) else ""))

    stop = threading.Event()

    def on_sig(*_):
        stop.set()
    try:
        import signal
        signal.signal(signal.SIGINT, on_sig)
        signal.signal(signal.SIGTERM, on_sig)
    except (ValueError, OSError):
        pass

    deadline = time.time() + args.duration if args.duration else None
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        while not stop.is_set():
            if deadline and time.time() >= deadline:
                break
            time.sleep(0.25)
    finally:
        for a in announcers:
            with contextlib.suppress(Exception):
                a.stop()
        srv.shutdown()          # stop serve_forever's loop first
        t.join(timeout=5)
        srv.reset_sessions()
        srv.server_close()
    return 0


def _awdl_host(name):
    label = "".join(c for c in name.lower()
                    if c in "abcdefghijklmnopqrstuvwxyz0123456789-").strip("-")
    return f"{label}-awdl.local" if label else "a4e-awdl.local"


# ---------------------------------------------------------------------- send

def cmd_send(args):
    files = args.files
    names = [os.path.basename(f) for f in files]
    if len(set(names)) != len(names):
        raise SystemExit("two of the files have the same name; the receiver "
                         "would keep only one")
    for f in files:
        if not os.path.isfile(f):
            raise SystemExit(f"{f}: not a file")
    ident = _resolve_identity(args)
    trans = transport.pick(args.iface) if not args.direct else None
    service_id = (trans.service_id if trans else None) or "000000000000"

    advertiser = None
    auth_tag = args.auth_tag
    if not args.no_wake and not args.direct:
        try:
            advertiser = ble.Advertiser(
                adapter=args.ble_adapter)
            advertiser.start()
            auth_tag = auth_tag or advertiser.tag.hex()
        except Exception as e:
            log.warning("BLE wake unavailable: %s", e)
            advertiser = None

    def progress(stage, name):
        print(f"[{stage}] {name or ''}")

    try:
        if args.direct:
            host, _, port = args.direct.rpartition(":")
            host = host.strip("[]")
            from .client import AirDropClient
            c = AirDropClient(ident, (host, int(port)),
                              computer_name=_sender_name(args),
                              computer_model=_model(args, {}),
                              service_id=service_id)
            name = c.send_discover()
            if args.discover_only:
                if name:
                    print(name)
                return 0
            c.reconnect(timeout=args.ask_timeout)
            if not c.send_ask(files, auth_tag=auth_tag):
                return 3
            return 0 if c.send_upload(files) else 4

        # Discovery path: AF log first (Linux/awdl), then mDNS browse.
        chosen = None
        if trans and trans.mode == "awdl" and args.af_log:
            chosen = _try_af_log(args, ident, trans, service_id)
        if not chosen:
            from .client import Finder
            interfaces = None
            ip_version = None
            if trans and trans.mode == "awdl":
                interfaces = [str(a).split("%")[0] for a in trans.addrs]
                from zeroconf import IPVersion
                ip_version = IPVersion.V6Only
            elif trans and trans.iface:
                interfaces = [str(a).split("%")[0] for a in trans.addrs]
            finder = Finder(
                ident, interfaces=interfaces,
                interface_name=trans.iface if trans else None,
                ip_version=ip_version, want=args.to,
                computer_name=_sender_name(args),
                computer_model=_model(args, {}), service_id=service_id,
                on_peer=lambda i, n, a, p:
                    print(f"  peer {i} {n or '(anonymous)'} [{a}]:{p}"))
            deadline = time.time() + args.timeout
            while True:
                chosen = finder.run(max(1, min(10, deadline - time.time())))
                if chosen or not args.wait or time.time() >= deadline:
                    break
        if not chosen:
            print(f"no receiver found in {args.timeout:.0f}s", file=sys.stderr)
            return 2
        client = chosen["client"]
        client.computer_name = _sender_name(args)
        client.computer_model = _model(args, {})
        client.service_id = service_id
        print(f"receiver: {chosen.get('name')!r} ({chosen['ident']}) "
              f"at [{chosen['addr']}]:{chosen['port']} - asking")
        client.reconnect(timeout=args.ask_timeout)
        if not client.send_ask(files, auth_tag=auth_tag):
            print("declined")
            return 3
        ok = client.send_upload(files)
        what = names[0] if len(names) == 1 else f"{len(names)} files"
        print(f"{'sent' if ok else 'upload failed'}: {what}")
        return 0 if ok else 4
    finally:
        if advertiser:
            advertiser.stop()


def _try_af_log(args, ident, trans, service_id):
    """Take a receiver from the newest AirDrop TLVs in an AF capture log."""
    from . import aframes
    from .client import AirDropClient
    from .util import eui64_linklocal
    eps = aframes.endpoints_from_log(args.af_log, want=args.to)
    for ep in eps:
        addr = eui64_linklocal(ep["sa"])
        c = AirDropClient(ident, (addr, ep["port"]),
                          interface_name=trans.iface,
                          computer_name=_sender_name(args),
                          computer_model=_model(args, {}),
                          service_id=service_id)
        try:
            name = c.send_discover()
        except Exception as e:
            log.info("AF endpoint %s DISCOVER failed: %r", ep["id"], e)
            continue
        if name is None:
            c.close()
            continue
        if args.to and len(args.to) != 12 and ":" not in args.to \
                and args.to.lower() not in name.lower():
            c.close()
            continue
        return {"ident": ep["id"], "name": name, "client": c,
                "addr": addr, "port": ep["port"]}
    return None


# --------------------------------------------------------------------- peers

def cmd_peers(args):
    ident = _resolve_identity(args)
    trans = transport.pick(args.iface)
    advertiser = None
    if not args.no_wake:
        try:
            advertiser = ble.Advertiser(adapter=args.ble_adapter)
            advertiser.start()
        except Exception as e:
            log.warning("BLE wake unavailable: %s", e)
    try:
        from .client import Finder
        interfaces = None
        ip_version = None
        if trans.mode == "awdl":
            interfaces = [str(a).split("%")[0] for a in trans.addrs]
            from zeroconf import IPVersion
            ip_version = IPVersion.V6Only
        elif trans.iface:
            interfaces = [str(a).split("%")[0] for a in trans.addrs]
        finder = Finder(
            ident, interfaces=interfaces,
            interface_name=trans.iface, ip_version=ip_version,
            want=args.to, computer_name=_sender_name(args),
            service_id=trans.service_id,
            on_peer=lambda i, n, a, p: print(
                f"{i}  {n or '(anonymous)'}  [{a}]:{p}"))
        finder.run(args.timeout)
        if not finder.seen:
            print("no peers heard", file=sys.stderr)
            return 2
        return 0
    finally:
        if advertiser:
            advertiser.stop()


# ---------------------------------------------------------------------- wake

def cmd_wake(args):
    hashes = bytes.fromhex(args.hashes) if args.hashes else b"\x00" * 8
    if not args.hashes:
        try:
            ident = identity.resolve(keys=args.keys, create=False)
            if ident.record_data:
                hashes, n = ble.hashes_from_record(ident.record_data)
                log.info("contact hashes from record (%d identifiers)", n)
        except Exception:
            pass
    adv = ble.Advertiser(arm=args.arm, hashes=hashes,
                         tag=bytes.fromhex(args.tag) if args.tag else None,
                         adapter=args.ble_adapter,
                         interval_ms=args.interval_ms)
    adv.start()
    print(f"advertising AirDrop presence for {args.seconds}s "
          f"(arm={args.arm} tag={adv.tag.hex()} backend={adv.backend.name})")
    try:
        time.sleep(args.seconds)
    except KeyboardInterrupt:
        pass
    finally:
        adv.stop()
    return 0


# ------------------------------------------------------------------ identity

def cmd_identity(args):
    if args.import_cert:
        identity.import_apple_identity(args.keys, args.import_cert[0],
                                       args.import_cert[1],
                                       args.import_cert[2] if
                                       len(args.import_cert) > 2 else None)
        print(f"imported Apple identity into {identity.default_keys_dir()}")
        return 0
    try:
        ident = identity.resolve(keys=args.keys, create=False)
        identity.default_keys_dir()
        print(f"identity: {ident.kind}")
        print(f"  certificate: {ident.certificate}")
        print(f"  key:         {ident.key}")
        print(f"  record:      {len(ident.record_data)} bytes"
              if ident.record_data else "  record:      none (Everyone only)")
        return 0
    except identity.IdentityError as e:
        print(f"no identity yet: {e}", file=sys.stderr)
        print("one will be self-signed on first use, or import an Apple ID "
              "pair with --import CERT KEY [RECORD]")
        return 1


# -------------------------------------------------------------------- doctor

def cmd_doctor(args):
    import importlib.util
    plat = platform_name()
    print(f"platform:       {plat} ({sys.platform}), python {sys.version.split()[0]}")
    for mod, label in (("zeroconf", "mDNS"), ("cryptography", "cert gen"),
                       ("PIL", "thumbnails"), ("dbus", "BlueZ BLE"),
                       ("winsdk", "WinRT BLE"), ("winrt", "WinRT BLE (alt)"),
                       ("psutil", "iface/MAC lookup")):
        print(f"  {label:22} {'yes' if importlib.util.find_spec(mod) else 'no'}")
    import shutil
    for tool in ("openssl", "iw", "hcitool", "avahi-resolve"):
        print(f"  tool {tool:17} {'yes' if shutil.which(tool) else 'no'}")
    print(f"AWDL interface: {'awdl0 present' if transport.awdl_available() else 'none'}")
    if plat == "linux":
        owl = os.environ.get("A4E_OWL", "/usr/lib/airdrop-everything/owl")
        print(f"OWL binary:     {'found' if os.access(owl, os.X_OK) else 'missing'} ({owl})")
        sta = None
        with contextlib.suppress(OSError):
            sta = os.listdir("/sys/class/net")
        if sta:
            import re
            import subprocess
            for name in sta:
                if name in ("awdl0", "mon0", "lo"):
                    continue
                out = subprocess.run(["iw", "dev", name, "link"],
                                     capture_output=True, text=True).stdout
                m = re.search(r"freq:\s*(\d+)", out)
                if m:
                    ok = int(m.group(1)) in (2437, 5220, 5745)
                    print(f"  wifi {name}: AP {m.group(1)} MHz "
                          f"({'AWDL-shareable' if ok else 'NOT ch6/44/149'})")
    print(f"BLE backend:    {ble.pick_backend().name}")
    print(f"config dir:     {_cfg_dir()}")
    print(f"keys dir:       {identity.default_keys_dir()}")
    if plat in ("windows", "android"):
        print()
        print("note: this platform has no AWDL driver path, so Apple devices")
        print("cannot be discovered; LAN transport talks to other devices")
        print("running AirDrop-for-Everything (or Macs with BrowseAllInterfaces).")
    return 0


# -------------------------------------------------------------- linux extras

def cmd_radio(args):
    if platform_name() != "linux":
        raise SystemExit("the OWL radio backend exists on Linux only; "
                         "on this OS use --iface lan (or awdl0 on macOS)")
    from . import radio_owl
    return radio_owl.main(args.radio_args)


def cmd_af_listen(args):
    if platform_name() != "linux":
        raise SystemExit("AF_PACKET capture is Linux-only")
    from . import aframes
    aframes.listen(args.iface, print_lines=True)
    return 0


# --------------------------------------------------------------------- parse

def build_parser():
    p = argparse.ArgumentParser(
        prog="airdrop-everything",
        description="AirDrop for every platform: send and receive over "
                    "AWDL (macOS/Linux+OWL) or plain LAN.")
    p.add_argument("--version", action="version",
                   version=f"%(prog)s {__version__}")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--iface", default="auto",
                        help="auto|lan|awdl0|<interface> (default: awdl0 when "
                             "it exists, else LAN)")
        sp.add_argument("--keys", default=None,
                        help="identity directory (default ~/.airdrop-everything/keys)")
        sp.add_argument("--name", default=None)
        sp.add_argument("--model", default=None)

    r = sub.add_parser("receive", help="become discoverable and receive files")
    common(r)
    r.add_argument("--port", type=int, default=const.AIRDROP_PORT)
    r.add_argument("--flags", type=lambda x: int(x, 0), default=const.FLAGS_DEFAULT)
    r.add_argument("--outdir", default=None)
    r.add_argument("--contacts", action="store_true",
                   help="Contacts Only: verify Apple-issued identity + known-senders")
    r.add_argument("--ask", action="store_true",
                   help="prompt before accepting each transfer")
    r.add_argument("--duration", type=float, default=0,
                   help="seconds to stay discoverable (0 = until stopped)")
    r.add_argument("--service-id", default=None, help="12-hex mDNS instance id")
    r.add_argument("--no-raw", action="store_true",
                   help="no AF_PACKET announcer/responder on awdl0")
    r.add_argument("--max-receive-percent", type=int, default=None)
    r.add_argument("--config", default=None)
    r.add_argument("--quiet", action="store_true")
    r.set_defaults(fn=cmd_receive)

    s = sub.add_parser("send", help="send files to a receiver")
    common(s)
    s.add_argument("files", nargs="+", metavar="FILE")
    s.add_argument("--to", default=None,
                   help="receiver: name substring, 12-hex service id, or MAC")
    s.add_argument("--timeout", type=float, default=60)
    s.add_argument("--wait", action="store_true",
                   help="keep browsing until timeout instead of first-found")
    s.add_argument("--ask-timeout", type=float, default=90,
                   help="seconds for the receiver's user to accept")
    s.add_argument("--direct", default=None, metavar="HOST:PORT",
                   help="skip discovery; send to this endpoint")
    s.add_argument("--discover-only", action="store_true",
                   help="with --direct: print the peer's name and send nothing")
    s.add_argument("--auth-tag", default=None,
                   help="3 bytes hex: SenderIdentityAuthTag (matches BLE advert)")
    s.add_argument("--no-wake", action="store_true",
                   help="don't emit the BLE AirDrop advert while discovering")
    s.add_argument("--ble-adapter", default="hci0")
    s.add_argument("--af-log", default=None,
                   help="aflisten output: resolve endpoints from action frames")
    s.set_defaults(fn=cmd_send)

    pe = sub.add_parser("peers", help="list discoverable receivers")
    common(pe)
    pe.add_argument("--to", default=None)
    pe.add_argument("--timeout", type=float, default=10)
    pe.add_argument("--no-wake", action="store_true")
    pe.add_argument("--ble-adapter", default="hci0")
    pe.set_defaults(fn=cmd_peers)

    w = sub.add_parser("wake", help="emit the BLE AirDrop advert")
    w.add_argument("--arm", choices=["A", "V2", "B"], default="A")
    w.add_argument("--seconds", type=int, default=120)
    w.add_argument("--interval-ms", type=int, default=100)
    w.add_argument("--tag", default=None, help="3 bytes hex (default random)")
    w.add_argument("--hashes", default=None, help="8 bytes hex contact hashes")
    w.add_argument("--ble-adapter", default="hci0")
    w.add_argument("--keys", default=None)
    w.set_defaults(fn=cmd_wake)

    i = sub.add_parser("identity", help="show or import our AirDrop identity")
    i.add_argument("--keys", default=None)
    i.add_argument("--import", dest="import_cert", nargs="+",
                   metavar="PATH", help="CERT KEY [RECORD] file paths")
    i.set_defaults(fn=cmd_identity)

    d = sub.add_parser("doctor", help="report platform capabilities")
    d.set_defaults(fn=cmd_doctor)

    ra = sub.add_parser("radio", help="Linux AWDL helper (root): "
                        "start|stop|status|peers|probe")
    ra.add_argument("radio_args", nargs=argparse.REMAINDER)
    ra.set_defaults(fn=cmd_radio)

    af = sub.add_parser("af-listen", help="dump AWDL action frames (Linux root)")
    af.add_argument("--iface", default="mon0")
    af.set_defaults(fn=cmd_af_listen)

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stdout)
    logging.getLogger("zeroconf").setLevel(logging.WARNING)
    logging.getLogger("PIL").setLevel(logging.WARNING)
    try:
        return args.fn(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
