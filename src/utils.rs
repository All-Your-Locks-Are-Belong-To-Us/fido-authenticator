use ctap_types::serde::Error;
use serde::Serialize;
use trussed::types::Message;

// EWW.. this is a bit unsafe isn't it
pub(crate) fn format_hex(data: &[u8], mut buffer: &mut [u8]) {
    const HEX_CHARS: &[u8] = b"0123456789abcdef";
    for byte in data.iter() {
        buffer[0] = HEX_CHARS[(byte >> 4) as usize];
        buffer[1] = HEX_CHARS[(byte & 0xf) as usize];
        buffer = &mut buffer[2..];
    }
}

pub(crate) fn cbor_serialize_message<T: Serialize>(
    object: &T,
) -> core::result::Result<Message, Error> {
    Ok(trussed::cbor_serialize_bytes(object)?)
}
