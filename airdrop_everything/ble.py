"""Apple Continuity AirDrop BLE advertisement -- the sender-side wake.

Measured behaviour (omdrop-awdl's ble-airdrop-adv.py): a Mac with Finder >
AirDrop open publishes no `_airdrop._tcp` until a sender's BLE AirDrop advert
appears -- the advert is the gate on a receiver's AirDrop publication.

ON-AIR VALUE. Manufacturer Specific Data, company 0x004C (Apple), value =
one Continuity TLV ``05 12 <18 bytes>``. Three observed arms:

  A   (OS 26 shape, current Apple devices)  40 <tag3> 00 00 00 00 03 <4x2-byte hashes> 00
  V2  (iPhone, Aug 2025 report)             00x8                      02 <hashes> 00
  B   (published 2019/2020 shape)           00x8                      01 <hashes> 00

The 3 `tag` bytes correlate the BLE presence with the /Ask's
SenderIdentityAuthTag. The eight hash bytes are four truncated SHA-256
prefixes of the sender's contact identifiers; zeros = "no contact match",
which an Everyone-mode receiver accepts (Contacts Only cannot match them).

Backends, best-first per OS:
  linux   -> dbus+BlueZ LEAdvertisement1 when dbus is importable, else raw
             HCI via hcitool/hcitool-equivalent (needs root)
  windows -> WinRT BluetoothLEAdvertisementPublisher (winsdk/winrt package)
  macos   -> not possible: CBPeripheralManager cannot emit manufacturer data
  android -> raw HCI path under Termux-with-root, otherwise unavailable
"""
import contextlib
import logging
import os
import plistlib
import subprocess
import time

from . import const
from .util import platform_name

log = logging.getLogger("airdrop.ble")


def build_payload(arm="A", tlv_type=const.BLE_TYPE_AIRDROP,
                  hashes=b"\x00" * 8, tag=None):
    """The ManufacturerData value: [type][len][18-byte body]."""
    if tag is None:
        tag = os.urandom(3)
    if len(hashes) != 8:
        raise ValueError("hashes must be 8 bytes (four 2-byte hashes)")
    if len(tag) != 3:
        raise ValueError("tag must be 3 bytes")
    if arm == "A":        # OS 26 shape: 40 <tag> 00000000 03 hashes 00
        body = bytes([0x40]) + tag + bytes(4) + bytes([0x03]) + hashes + bytes(1)
    elif arm == "V2":     # iPhone Aug-2025 shape: 00x8 02 hashes 00
        body = bytes(8) + bytes([0x02]) + hashes + bytes(1)
    else:                 # published 2019/2020 shape: 00x8 01 hashes 00
        body = bytes(8) + bytes([0x01]) + hashes + bytes(1)
    assert len(body) == 18
    return bytes([tlv_type, len(body)]) + body, tag


def hashes_from_record(record):
    """The four 2-byte contact hashes from our own Apple ID validation record.

    Zeros mean "no contact match" (Everyone-mode receivers only). The record's
    ValidatedEmailHashes/ValidatedPhoneHashes are full SHA-256 of identifiers
    Apple verified; the advert carries the first two bytes of each. Slot order
    mirrors a genuine advert: email, phone, second email, third email, with
    spare identifiers filling empty slots.
    """
    openssl = _openssl()
    if not openssl:
        raise RuntimeError("openssl not found; cannot read validation record")
    proc = subprocess.run(
        [openssl, "cms", "-verify", "-noverify", "-inform", "DER"],
        input=record, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"cannot read validation record: {proc.stderr.decode(errors='replace').strip()}")
    plist = plistlib.loads(proc.stdout)
    emails = [h.lower()[:4] for h in (plist.get("ValidatedEmailHashes") or [])
              if isinstance(h, str)]
    phones = [h.lower()[:4] for h in (plist.get("ValidatedPhoneHashes") or [])
              if isinstance(h, str)]
    if not emails and not phones:
        raise RuntimeError("validation record validates no identifiers")
    slots = [emails[0:1], phones[0:1], emails[1:2], emails[2:3]]
    spare = [h for h in emails[3:] + phones[1:]]
    out = []
    for slot in slots:
        if slot:
            out.append(slot[0])
        elif spare:
            out.append(spare.pop(0))
        else:
            out.append("0000")
    return bytes.fromhex("".join(out)), len(emails) + len(phones)


def _openssl():
    import shutil
    return shutil.which("openssl")


# ------------------------------------------------------------------ backends

class Backend:
    name = "none"

    def start(self, value, interval_ms):  # pragma: no cover - platform code
        raise NotImplementedError

    def stop(self):
        pass


class HciToolBackend(Backend):
    """Raw HCI commands through hcitool/btmgmt on Linux (root required).

    Uses the legacy-but-universal trio: LE Set Advertising Parameters,
    LE Set Advertising Data, LE Set Advertise Enable. No D-Bus needed, so it
    also works on stripped-down systems and Android/Termux with root.
    """

    name = "hcitool"

    def __init__(self, adapter="hci0"):
        self.adapter = adapter
        self._on = False

    def _cmd(self, *args):
        proc = subprocess.run(["hcitool", "-i", self.adapter, "cmd", *args],
                              capture_output=True, timeout=10)
        if proc.returncode != 0:
            raise RuntimeError(
                f"hcitool failed: {proc.stderr.decode(errors='replace').strip()}")

    def start(self, value, interval_ms):
        import shutil
        if not shutil.which("hcitool"):
            raise RuntimeError("hcitool not found (install bluez tools "
                               "or use the dbus backend)")
        interval = max(32, min(16384, int(interval_ms / 0.625)))
        iv = interval.to_bytes(2, "little")
        # LE Set Advertising Parameters: non-connectable broadcast undirected
        self._cmd("0x08", "0x0006",
                  f"0x{iv[0]:02x}", f"0x{iv[1]:02x}",
                  f"0x{iv[0]:02x}", f"0x{iv[1]:02x}",
                  "0x03", "0x00", "0x00",
                  "0x00", "0x00", "0x00", "0x00", "0x00", "0x00",
                  "0x07", "0x00")
        # LE Set Advertising Data: [len=31 cap] [flags AD] [mfr AD]
        flags = bytes([0x02, 0x01, 0x06])
        mfr = bytes([len(value) + 3, 0xFF]) + \
            const.APPLE_COMPANY_ID.to_bytes(2, "little") + value
        adv = (flags + mfr)[:31]
        data = bytes([len(adv)]) + adv + bytes(31 - len(adv))
        self._cmd("0x08", "0x0008", *[f"0x{b:02x}" for b in data])
        self._cmd("0x08", "0x000a", "0x01")
        self._on = True
        log.info("BLE advert on %s via hcitool (%d B AD)", self.adapter, len(adv))

    def stop(self):
        if self._on:
            with contextlib.suppress(Exception):
                self._cmd("0x08", "0x000a", "0x00")
            self._on = False


class BlueZDBusBackend(Backend):
    """BlueZ LEAdvertisement1 over D-Bus (needs python dbus + GLib)."""

    name = "bluez-dbus"

    def __init__(self, adapter="hci0"):
        self.adapter = adapter
        self._bus = None
        self._loop = None
        self._mgr = None
        self._adv = None

    def start(self, value, interval_ms):
        import threading

        import dbus
        import dbus.mainloop.glib
        import dbus.service
        from gi.repository import GLib

        AD_IFACE = "org.bluez.LEAdvertisement1"
        ADM_IFACE = "org.bluez.LEAdvertisingManager1"
        PATH = "/org/airdrop4e/adv0"
        done = threading.Event()
        state = {}

        class Adv(dbus.service.Object):
            def __init__(self, bus):
                super().__init__(bus, PATH)
                self.props = {
                    "Type": "peripheral",
                    "ManufacturerData": dbus.Dictionary(
                        {dbus.UInt16(const.APPLE_COMPANY_ID):
                         dbus.Array(value, signature="y")}, signature="qv"),
                    "Includes": dbus.Array([], signature="s"),
                    "MinInterval": dbus.UInt32(interval_ms),
                    "MaxInterval": dbus.UInt32(interval_ms),
                }

            @dbus.service.method("org.freedesktop.DBus.Properties",
                                 in_signature="ss", out_signature="v")
            def Get(self, iface, name_):
                return self.props[name_]

            @dbus.service.method("org.freedesktop.DBus.Properties",
                                 in_signature="s", out_signature="a{sv}")
            def GetAll(self, iface):
                if iface != AD_IFACE:
                    raise dbus.exceptions.DBusException(
                        "org.freedesktop.DBus.Error.InvalidArgs")
                return self.props

            @dbus.service.method(AD_IFACE, in_signature="", out_signature="")
            def Release(self):
                pass

        def run():
            dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
            self._bus = dbus.SystemBus()
            adapter_obj = self._bus.get_object(
                "org.bluez", f"/org/bluez/{self.adapter}")
            props = dbus.Interface(adapter_obj, "org.freedesktop.DBus.Properties")
            if not bool(props.Get("org.bluez.Adapter1", "Powered")):
                props.Set("org.bluez.Adapter1", "Powered", dbus.Boolean(True))
            self._mgr = dbus.Interface(adapter_obj, ADM_IFACE)
            self._adv = Adv(self._bus)
            self._loop = GLib.MainLoop()

            def ok():
                state["ok"] = True
                done.set()

            def fail(e):
                state["err"] = str(e)
                done.set()

            self._mgr.RegisterAdvertisement(PATH, {}, reply_handler=ok,
                                            error_handler=fail)
            self._loop.run()

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()
        if not done.wait(timeout=10):
            raise RuntimeError("BlueZ advertisement registration timed out")
        if "err" in state:
            raise RuntimeError(f"BlueZ advertisement failed: {state['err']}")
        log.info("BLE advert on %s via BlueZ D-Bus", self.adapter)

    def stop(self):
        try:
            if self._mgr and self._adv:
                self._mgr.UnregisterAdvertisement("/org/airdrop4e/adv0")
        except Exception:
            pass
        try:
            if self._loop:
                self._loop.quit()
        except Exception:
            pass


class WinRTBackend(Backend):
    """Windows WinRT BluetoothLEAdvertisementPublisher (winsdk package)."""

    name = "winrt"

    def __init__(self):
        self.publisher = None

    def start(self, value, interval_ms):
        try:
            from winsdk.windows.devices.bluetooth.advertisement import (
                BluetoothLEAdvertisementPublisher,
                BluetoothLEManufacturerData,
            )
            from winsdk.windows.storage.streams import DataWriter
        except ImportError:
            try:
                from winrt.windows.devices.bluetooth.advertisement import (
                    BluetoothLEAdvertisementPublisher,
                    BluetoothLEManufacturerData,
                )
                from winrt.windows.storage.streams import DataWriter
            except ImportError as e:
                raise RuntimeError(
                    "Windows BLE advertising needs the `winsdk` package "
                    "(pip install winsdk)") from e
        writer = DataWriter()
        writer.write_bytes(bytes(value))
        mfr = BluetoothLEManufacturerData()
        mfr.company_id = const.APPLE_COMPANY_ID
        mfr.data = writer.detach_buffer()
        self.publisher = BluetoothLEAdvertisementPublisher()
        self.publisher.advertisement.manufacturer_data.append(mfr)
        # Apple's AirDrop adverts are connectable; non-connectable broadcast
        # is what most Apple wake adverts use, but Windows' publisher defaults
        # are fine either way.
        self.publisher.start()
        log.info("BLE advert via WinRT (status=%s)", self.publisher.status)

    def stop(self):
        if self.publisher:
            with contextlib.suppress(Exception):
                self.publisher.stop()


class UnsupportedBackend(Backend):
    name = "unsupported"

    def start(self, value, interval_ms):
        plat = platform_name()
        why = {
            "macos": "CoreBluetooth cannot emit manufacturer data (Apple's "
                     "own Continuity adverts are not exposable)",
            "android": "no BLE advertiser API without root; try hcitool "
                       "under a rooted shell",
        }.get(plat, "no BLE advertisement backend for this platform")
        raise RuntimeError(why)


def pick_backend(adapter="hci0"):
    plat = platform_name()
    if plat == "linux" or plat == "android":
        try:
            import dbus  # noqa: F401
            return BlueZDBusBackend(adapter)
        except ImportError:
            return HciToolBackend(adapter)
    if plat == "windows":
        return WinRTBackend()
    return UnsupportedBackend()


class Advertiser:
    """Publish the AirDrop BLE advert for a duration, in the background."""

    def __init__(self, arm="A", hashes=b"\x00" * 8, tag=None, adapter="hci0",
                 interval_ms=100):
        self.value, self.tag = build_payload(arm=arm, hashes=hashes, tag=tag)
        self.interval_ms = interval_ms
        self.backend = pick_backend(adapter)
        self.started = False

    def start(self):
        self.backend.start(self.value, self.interval_ms)
        self.started = True
        log.info("BLE AirDrop advert up (backend=%s tag=%s)",
                 self.backend.name, self.tag.hex())
        return self

    def stop(self):
        if self.started:
            self.backend.stop()
            self.started = False
            log.info("BLE AirDrop advert down")

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()

    def run_for(self, seconds):
        self.start()
        try:
            time.sleep(seconds)
        finally:
            self.stop()
