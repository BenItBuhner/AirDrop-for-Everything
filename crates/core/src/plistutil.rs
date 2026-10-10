//! Binary-plist helpers for the /Discover and /Ask payloads.

use crate::Result;
use plist::Value;

/// Serialize a dictionary to binary plist bytes.
pub fn to_binary(v: &Value) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    v.to_writer_binary(&mut buf)?;
    Ok(buf)
}

/// Parse a binary plist body.
pub fn from_binary(bytes: &[u8]) -> Result<Value> {
    Ok(plist::from_bytes::<Value>(bytes)?)
}

/// Convenience constructors matching plist::Value shapes.
pub fn dict() -> plist::Dictionary {
    plist::Dictionary::new()
}
