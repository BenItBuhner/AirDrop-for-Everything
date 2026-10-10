package tech.airdrop4e

import android.content.Context
import android.net.wifi.WifiManager

/**
 * Holds the WifiManager.MulticastLock required for mDNS (224.0.0.251:5353)
 * traffic. Without it, Android drops inbound multicast packets even though
 * sending works — a receiver would be invisible and a browse would see
 * nothing.
 *
 * Reference-counted: acquiring while already held is fine, so the receiver
 * and a concurrent browse can both hold it. Requires
 * CHANGE_WIFI_MULTICAST_STATE in the manifest.
 */
class MulticastLockHolder(context: Context) {

    private val lock: WifiManager.MulticastLock =
        (context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager)
            .createMulticastLock("airdrop4e-mdns")
            .apply { setReferenceCounted(true) }

    fun acquire() {
        lock.acquire()
    }

    fun release() {
        if (lock.isHeld) lock.release()
    }
}
