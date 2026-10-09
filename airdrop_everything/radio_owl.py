"""Linux AWDL radio helper -- a Python port of omdrop-owl's omdrop-discoverable.

Same contract, same exit codes, same behaviour:

  radio-owl start <seconds>    become discoverable for N seconds (0 = until stopped)
  radio-owl stop               tear down
  radio-owl status [--json]    {"visible":bool,"remaining":int|null,"reason":str,"rx_proven":bool}
  radio-owl peers              "<mac> rssi=?" per AWDL peer
  radio-owl probe [--json]     what this backend is and what blocks it

How (omdrop-owl README): the Wi-Fi station stays associated and AWDL shares
the AP's channel, which must be 6, 44 or 149. A monitor vif carries the
station's MAC; OWL runs on it with ``-S intersect``; OWL creates awdl0;
announcements go out as plain frames (OWL adds AWDL encapsulation itself).

Exit codes: 0 ok | 2 usage/not root | 3 can't become discoverable now
(AP channel) | 4 no AWDL radio | 5 already discoverable (window extended).
"""
import json
import os
import re
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

from . import const, discovery
from .util import eui64_linklocal, platform_name

RUN = Path(os.environ.get("A4E_RUN", "/run/airdrop-everything"))
CONF = Path(os.environ.get("A4E_CONF", "/etc/airdrop-everything"))
OWL_BIN = os.environ.get("A4E_OWL", "/usr/lib/airdrop-everything/owl")
IF_AWD = "awdl0"
IF_MON = "mon0"
PROFILES_PATH = Path(__file__).resolve().parent / "owl-profiles"

ADV_FLAGS = const.FLAGS_DEFAULT       # 0x89
ADV_INTERVAL = 3.0
VERSION = "0.1.0"
CONTRACT = "omdrop-owl-compatible"

AWDL_FREQS = {2437: 6, 5220: 44, 5745: 149}


def _log(msg):
    try:
        RUN.mkdir(parents=True, exist_ok=True)
        with open(RUN / "log", "a") as f:
            f.write(f"{time.strftime('%H:%M:%SZ', time.gmtime())} {msg}\n")
    except OSError:
        pass


def die(msg, code=2):
    _log(f"error: {msg}")
    print(f"radio-owl: {msg}", file=sys.stderr)
    sys.exit(code)


def knob(name):
    try:
        return (CONF / name).read_text().splitlines()[0].strip()
    except (OSError, IndexError):
        return ""


def alive(pid, pattern=None):
    """/proc check so unprivileged status works (kill -0 fails EPERM)."""
    if not pid:
        return False
    try:
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ")
    except OSError:
        return False
    return pattern is None or pattern.encode() in cmdline


def pid_of(name):
    try:
        return int((RUN / f"{name}.pid").read_text().strip())
    except (OSError, ValueError):
        return None


def station_iface():
    """The Wi-Fi station interface: $CONF/infra-iface, else first managed."""
    forced = os.environ.get("A4E_INFRA_IFACE") or knob("infra-iface")
    if forced:
        return forced
    try:
        names = sorted(os.listdir("/sys/class/net"))
    except OSError:
        return None
    for name in names:
        if name in (IF_AWD, IF_MON):
            continue
        if not os.path.isdir(f"/sys/class/net/{name}/phy80211"):
            continue
        out = subprocess.run(["iw", "dev", name, "info"],
                             capture_output=True, text=True)
        if "type managed" in out.stdout:
            return name
    return None


def driver_of(iface):
    try:
        return os.path.basename(os.path.realpath(f"/sys/class/net/{iface}/device/driver"))
    except OSError:
        return ""


def load_profile(driver):
    """Driver's owl-profiles line -> dict, else the '*' line."""
    tables = []
    if (CONF / "owl-profiles").is_file():
        tables.append(CONF / "owl-profiles")
    if PROFILES_PATH.is_file():
        tables.append(PROFILES_PATH)
    for table in tables:
        fallback = None
        for line in table.read_text().splitlines():
            if line.startswith("#") or len(line.split()) < 6:
                continue
            parts = line.split()
            if parts[0] == driver:
                keys = ("driver", "status", "mode", "mon_mac", "reconnect", "mt76_pm")
                d = dict(zip(keys, parts[:6]))
                d["notes"] = " ".join(parts[6:])
                return d
            if parts[0] == "*":
                keys = ("driver", "status", "mode", "mon_mac", "reconnect", "mt76_pm")
                fallback = dict(zip(keys, parts[:6]))
                fallback["notes"] = " ".join(parts[6:])
        if fallback:
            return fallback
    return None


def untested_hint(drv):
    return (f"AirDrop-over-OWL hasn't been tested on this computer's Wi-Fi "
            f"({drv or 'unknown driver'}). To try anyway, put 1 in "
            f"{CONF}/allow-untested.")


def mt76_dir(iface):
    try:
        phy = os.path.basename(os.path.realpath(f"/sys/class/net/{iface}/phy80211"))
    except OSError:
        return None
    d = f"/sys/kernel/debug/ieee80211/{phy}/mt76"
    return d if os.path.isdir(d) else None


# ------------------------------------------------------------------ commands

def visible():
    return (alive(pid_of("supervisor"), "supervise")
            and alive(pid_of("owl"), "owl")
            and _awdl_link_local())


def _awdl_link_local():
    out = subprocess.run(["ip", "-6", "addr", "show", "dev", IF_AWD, "scope", "link"],
                         capture_output=True, text=True)
    return "inet6" in out.stdout and "tentative" not in out.stdout


def cmd_status(as_json=False):
    vis = visible()
    remaining = None
    reason = ""
    try:
        reason = (RUN / "reason").read_text().strip()
    except OSError:
        pass
    if vis:
        try:
            until = int((RUN / "until").read_text().strip() or 0)
        except (OSError, ValueError):
            until = 0
        if until > 0:
            remaining = max(0, until - int(time.time()))
    rx = False
    if vis:
        try:
            rx = "add peer" in (RUN / "owl.log").read_text()
        except OSError:
            pass
    if as_json:
        print(json.dumps({"visible": vis, "remaining": remaining,
                          "reason": reason.replace('"', ""), "rx_proven": rx,
                          "peer_op": ""}))
    else:
        print(f"visible={str(vis).lower()} remaining={remaining} "
              f"reason={reason} rx_proven={str(rx).lower()}")
    return 0


def cmd_peers():
    """AWDL peers from OWL's log ('add peer <mac>' / 'remove peer <mac>')."""
    try:
        text = (RUN / "owl.log").read_text()
    except OSError:
        die(f"no OWL log at {RUN / 'owl.log'}; is the radio up?", 4)
    seen = {}
    for m in re.finditer(r"(add|remove) peer ([0-9a-f:]+)", text):
        mac = ":".join(p.zfill(2) for p in m.group(2).split(":"))
        if m.group(1) == "add":
            seen[mac] = True
        else:
            seen.pop(mac, None)
    for mac in seen:
        print(f"{mac} rssi=?")
    return 0


def cmd_probe(as_json=False):
    missing = []
    sta = station_iface()
    hw = True
    if not sta:
        hw = False
        missing.append(("hardware", "This computer has no Wi-Fi interface "
                        "this backend can use."))
    else:
        drv = driver_of(sta)
        prof = load_profile(drv)
        if prof is None:
            hw = False
            missing.append(("backend", f"hardware profiles missing "
                           f"({PROFILES_PATH}); reinstall."))
        elif prof["status"] != "tested" and knob("allow-untested") != "1":
            hw = False
            missing.append(("hardware", untested_hint(drv)))
        else:
            if not os.path.isfile(OWL_BIN) or not os.access(OWL_BIN, os.X_OK):
                missing.append(("backend", f"OWL is not installed at "
                               f"{OWL_BIN}."))
            if prof["mode"] != "shared":
                missing.append(("backend", f"profile asks for "
                               f"\"{prof['mode']}\" mode, not implemented."))
            out = subprocess.run(["iw", "dev", sta, "link"],
                                 capture_output=True, text=True).stdout
            m = re.search(r"freq:\s*(\d+)", out)
            ap = int(m.group(1)) if m else None
            if ap is None:
                missing.append(("radio", "Wi-Fi isn't connected, and AirDrop "
                               "shares its channel. Connect to Wi-Fi first."))
            elif ap not in AWDL_FREQS:
                missing.append(("radio", f"Your Wi-Fi network is on {ap} MHz, "
                               "but AirDrop can only share channel 6, 44 or "
                               "149 with it. Move the router to one of those."))
    if not as_json:
        for _id, say in missing:
            print(say)
        if not missing:
            print("ready")
        return 0
    print(json.dumps({
        "backend": "owl", "version": VERSION, "contract": CONTRACT,
        "hardware": hw,
        "missing": [{"id": i, "say": s} for i, s in missing]}))
    return 0


def cmd_stop(why="stopped"):
    if os.geteuid() != 0:
        die("must run as root", 2)
    sup = pid_of("supervisor")
    if sup and sup not in (os.getpid(), os.getppid()):
        try:
            os.kill(sup, signal.SIGTERM)
        except OSError:
            pass
    owl = pid_of("owl")
    if owl:
        try:
            os.kill(owl, signal.SIGTERM)
        except OSError:
            pass
    subprocess.run(["ip", "link", "set", IF_MON, "down"],
                   capture_output=True)
    subprocess.run(["iw", "dev", IF_MON, "del"], capture_output=True)
    try:
        sta = (RUN / "station").read_text().strip()
        pm = (RUN / "pm").read_text().strip()
    except OSError:
        sta, pm = "", ""
    if sta and pm:
        d = mt76_dir(sta)
        if d:
            a, _, b = pm.partition(" ")
            for fname, val in (("runtime-pm", a), ("deep-sleep", b)):
                try:
                    Path(d, fname).write_text(val)
                except OSError:
                    pass
    reconnect = knob("reconnect-after")
    if reconnect == "0":
        reconnect = "no"
    elif reconnect == "1":
        reconnect = "yes"
    else:
        try:
            reconnect = (RUN / "profile").read_text().split()[3]
        except (OSError, IndexError):
            reconnect = "no"
    if sta and reconnect == "yes":
        time.sleep(1)
        # A fresh association right after the monitor vif is deleted keeps
        # drivers that wedge on vif deletion (mt7925e) healthy.
        r = subprocess.run(["nmcli", "-w", "20", "device", "connect", sta],
                           capture_output=True)
        if r.returncode:
            subprocess.run(["iw", "dev", sta, "disconnect"], capture_output=True)
    for f in ("supervisor.pid", "owl.pid", "until"):
        try:
            (RUN / f).unlink()
        except OSError:
            pass
    try:
        (RUN / "reason").write_text(why)
    except OSError:
        pass
    _log(f"stopped ({why})")
    return 0


def supervise_loop():
    """Background half of a window: announce, watch OWL, end at expiry."""
    import threading
    from .util import iface_mac
    mac = iface_mac(IF_AWD)
    if mac:
        from . import discovery as _d
        host = _awdl_hostname()
        ann = _d.RawAnnouncer(IF_AWD, mac, mac.hex(), host, 8771, ADV_FLAGS,
                              interval=ADV_INTERVAL)
        ann.start()
    else:
        ann = None
    try:
        while True:
            try:
                until = int((RUN / "until").read_text().strip() or 0)
            except (OSError, ValueError):
                until = 0
            if until > 0 and time.time() >= until:
                _log("window expired")
                cmd_stop("expired")
                return
            owl = pid_of("owl")
            if owl and not alive(owl, "owl"):
                _log("OWL exited")
                cmd_stop("owl-exited")
                return
            time.sleep(1)
    finally:
        if ann:
            ann.stop()


def _awdl_hostname():
    forced = os.environ.get("A4E_AWDL_HOST") or knob("awdl-host")
    if forced:
        return forced.rstrip(".").removesuffix(".local")
    short = socket.gethostname().split(".")[0].lower()
    label = "".join(c for c in short if c in "abcdefghijklmnopqrstuvwxyz0123456789-").strip("-")
    return f"{label}-awdl.local" if label else "a4e-awdl.local"


def cmd_start(secs):
    if os.geteuid() != 0:
        die("must run as root", 2)
    if platform_name() != "linux":
        die("the OWL radio backend is Linux-only", 4)
    RUN.mkdir(parents=True, exist_ok=True)
    if alive(pid_of("supervisor"), "supervise"):
        (RUN / "until").write_text(
            str(int(time.time()) + secs) if secs > 0 else "0")
        _log(f"already discoverable; window now {secs}s")
        return 5
    for f in ("log", "announce.log"):
        (RUN / f).write_text("")
    try:
        (RUN / "reason").unlink()
    except OSError:
        pass

    sta = station_iface()
    if not sta:
        die("no Wi-Fi interface to run AWDL on", 4)
    drv = driver_of(sta)
    prof = load_profile(drv)
    if prof is None:
        die(f"no hardware profile at {PROFILES_PATH}; reinstall", 4)
    if prof["status"] != "tested" and knob("allow-untested") != "1":
        die(untested_hint(drv), 4)
    if prof["mode"] != "shared":
        die(f"profile asks for \"{prof['mode']}\" mode, not implemented", 4)
    if not (os.path.isfile(OWL_BIN) and os.access(OWL_BIN, os.X_OK)):
        die(f"OWL is not installed at {OWL_BIN}", 4)

    # Wi-Fi takes a few seconds after a driver reload to associate; wait for
    # a default route before judging the link.
    gw = ""
    for _ in range(15):
        out = subprocess.run(["ip", "-4", "route", "show", "default", "dev", sta],
                             capture_output=True, text=True).stdout
        parts = out.split()
        if len(parts) > 2:
            gw = parts[2]
            r = subprocess.run(["ping", "-c1", "-W1", "-I", sta, gw],
                               capture_output=True)
            if r.returncode == 0:
                break
            gw = ""
        time.sleep(1)
    if not gw:
        die("Wi-Fi isn't connected (or isn't passing traffic), and AirDrop "
            "shares its channel. Connect to Wi-Fi and try again.", 3)
    out = subprocess.run(["iw", "dev", sta, "link"], capture_output=True,
                         text=True).stdout
    m = re.search(r"freq:\s*(\d+)", out)
    ap = int(m.group(1)) if m else None
    if ap not in AWDL_FREQS:
        die(f"your Wi-Fi network is on {ap or 'an unknown'} MHz, but AirDrop "
            "can only share channel 6, 44 or 149 with it. Move the router to "
            "one of those.", 3)
    chan = AWDL_FREQS[ap]
    stamac = Path(f"/sys/class/net/{sta}/address").read_text().strip()
    (RUN / "station").write_text(sta)
    (RUN / "profile").write_text(
        f"{drv} {prof['mode']} {prof['mon_mac']} {prof['reconnect']} {prof['mt76_pm']}")
    _log(f"station {sta} ({stamac}, {drv}) on ch{chan}, gateway {gw}; "
         f"profile: mode={prof['mode']} mon_mac={prof['mon_mac']} "
         f"reconnect={prof['reconnect']} mt76_pm={prof['mt76_pm']}")

    subprocess.run(["iw", "dev", IF_MON, "del"], capture_output=True)
    phy = os.path.basename(os.path.realpath(f"/sys/class/net/{sta}/phy80211"))
    r = subprocess.run(["iw", "phy", phy, "interface", "add", IF_MON,
                        "type", "monitor"], capture_output=True, text=True)
    if r.returncode:
        die(f"could not create the monitor interface {IF_MON}: "
            f"{r.stderr.strip()}", 4)
    owl_extra = []
    if prof["mon_mac"] == "own":
        monmac = "02:" + stamac.split(":", 1)[1]
        owl_extra = ["-m", stamac]
    else:
        monmac = stamac
    subprocess.run(["ip", "link", "set", IF_MON, "address", monmac],
                   capture_output=True)
    r = subprocess.run(["ip", "link", "set", IF_MON, "up"],
                       capture_output=True, text=True)
    if r.returncode:
        die(f"could not bring {IF_MON} up: {r.stderr.strip()}", 4)

    subprocess.run(["mount", "-t", "debugfs", "none", "/sys/kernel/debug"],
                   capture_output=True)
    mt76 = mt76_dir(sta)
    if prof["mt76_pm"] == "yes" and mt76:
        try:
            pm = (Path(mt76, "runtime-pm").read_text().strip() + " " +
                  Path(mt76, "deep-sleep").read_text().strip())
            (RUN / "pm").write_text(pm)
            Path(mt76, "runtime-pm").write_text("0")
            Path(mt76, "deep-sleep").write_text("0")
        except OSError:
            pass

    (RUN / "until").write_text(str(int(time.time()) + secs) if secs > 0 else "0")
    owl_log = open(RUN / "owl.log", "wb")
    owl = subprocess.Popen(
        [OWL_BIN, "-i", IF_MON, "-c", str(chan), "-N", "-S", "intersect",
         *owl_extra, "-v"],
        stdout=owl_log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
        start_new_session=True)
    (RUN / "owl.pid").write_text(str(owl.pid))
    for _ in range(40):
        r = subprocess.run(["ip", "link", "show", IF_AWD], capture_output=True)
        if r.returncode == 0:
            break
        time.sleep(0.5)
    else:
        tail = ""
        try:
            tail = (RUN / "owl.log").read_text().strip().splitlines()[-1]
        except (OSError, IndexError):
            pass
        cmd_stop("owl-failed")
        die(f"AWDL didn't come up: {tail or 'OWL exited'}", 4)
    subprocess.run(["nmcli", "device", "set", IF_AWD, "managed", "no"],
                   capture_output=True)
    subprocess.run(["ip", "link", "set", IF_AWD, "up"], capture_output=True)
    for _ in range(40):
        if _awdl_link_local():
            break
        time.sleep(0.5)
    sup = subprocess.Popen([sys.executable, "-m",
                            "airdrop_everything.radio_owl", "supervise"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           stdin=subprocess.DEVNULL, start_new_session=True)
    (RUN / "supervisor.pid").write_text(str(sup.pid))
    _log(f"discoverable for {secs}s (0 = until stopped)")
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        die("usage: radio-owl start <seconds> | stop | status [--json] | "
            "peers | probe [--json]", 2)
    cmd, args = argv[0], argv[1:]
    if cmd == "start":
        if not args or not args[0].isdigit():
            die("usage: radio-owl start <seconds>", 2)
        return cmd_start(int(args[0]))
    if cmd == "stop":
        return cmd_stop(args[1] if len(args) > 1 else "stopped")
    if cmd == "status":
        return cmd_status("--json" in args)
    if cmd == "peers":
        return cmd_peers()
    if cmd == "probe":
        return cmd_probe("--json" in args)
    if cmd == "supervise":
        if os.geteuid() != 0:
            return 2
        supervise_loop()
        return 0
    die("usage: radio-owl start <seconds> | stop | status [--json] | "
        "peers | probe [--json]", 2)


if __name__ == "__main__":
    sys.exit(main())
