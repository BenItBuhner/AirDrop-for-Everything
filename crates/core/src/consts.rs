//! AirDrop wire constants (as reverse-engineered by the omdrop projects).

/// HTTPS port sharingd uses.
pub const AIRDROP_PORT: u16 = 8771;
/// mDNS service type.
pub const SERVICE_TYPE: &str = "_airdrop._tcp.local.";
/// Bonjour domain suffix.
pub const LOCAL_DOMAIN: &str = "local.";

// TXT `flags` capability bits.
pub const SUPPORTS_URL: u32 = 0x01;
pub const SUPPORTS_DVZIP: u32 = 0x02;
pub const SUPPORTS_PIPELINING: u32 = 0x04;
pub const SUPPORTS_MIXED_TYPES: u32 = 0x08;
pub const SUPPORTS_IRIS: u32 = 0x40;
pub const SUPPORTS_DISCOVER_MAYBE: u32 = 0x80;
pub const SUPPORTS_ASSET_BUNDLE: u32 = 0x200;
/// What we advertise (Discover + DVZip + URL, matching omdrop's 0x88|0x09).
pub const FLAGS_DEFAULT: u32 = 137;

/// DeviceSupportFlags sent in /Discover.
pub const DEVICE_SUPPORT_FLAGS: u64 = 0x7ff;
/// BundleID sent in /Ask.
pub const BUNDLE_ID: &str = "com.apple.finder";

/// Content-Type of the upload body.
pub const UPLOAD_CONTENT_TYPE: &str = "application/x-dvzip";

/// Apple BLE company id and the AirDrop Continuity TLV type.
pub const APPLE_COMPANY_ID: u16 = 0x004C;
pub const BLE_TYPE_AIRDROP: u8 = 0x05;

/// AWDL action-frame vendor magic (Apple OUI + type).
pub const AF_VENDOR_MAGIC: [u8; 4] = [0x00, 0x17, 0xf2, 0x00]; // context: parse starts at OUI

/// Default receiver model string.
pub const DEFAULT_MODEL: &str = "MacBookPro18,3";

/// Map a file extension to a UTI for the /Ask Files[] entries.
pub fn uti_for_ext(ext: &str) -> &'static str {
    match ext.to_ascii_lowercase().as_str() {
        ".jpg" | ".jpeg" => "public.jpeg",
        ".png" => "public.png",
        ".gif" => "public.gif",
        ".heic" => "public.heic",
        ".mp4" | ".mov" | ".m4v" => "public.movie",
        ".mp3" | ".m4a" | ".aac" => "public.audio",
        ".wav" => "com.microsoft.waveform-audio",
        ".pdf" => "com.adobe.pdf",
        ".txt" | ".md" | ".log" => "public.plain-text",
        ".html" | ".htm" => "public.html",
        ".zip" => "public.zip-archive",
        ".json" => "public.json",
        ".csv" => "public.comma-separated-values-text",
        _ => "public.data",
    }
}
