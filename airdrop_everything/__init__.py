"""AirDrop-for-Everything: a portable AirDrop implementation.

Re-implementation of the AirDrop protocol stack (mDNS discovery + HTTPS
/Discover /Ask /Upload + DVZip/cpio payload) with pluggable link layers:

  * LAN transport -- any IPv4/IPv6 network, works on every OS
  * native AWDL   -- macOS's own awdl0 interface
  * OWL transport -- userspace AWDL on Linux via the OWL daemon
  * BLE wake      -- Apple Continuity AirDrop advertisements

Inspired by and interoperable with:
  * omdrop-owl   (https://github.com/t4t5/omdrop-owl)          by t4t5
  * omdrop       (https://github.com/brentkearney/omdrop-plugin) by Brent Kearney
  * omdrop-awdl  (https://github.com/brentkearney/omdrop-awdl)  by Brent Kearney
  * OpenDrop     (https://github.com/seemoo-lab/opendrop)       by SEEMOO
  * OWL          (https://github.com/seemoo-lab/owl)            by SEEMOO
"""

__version__ = "0.1.0"
