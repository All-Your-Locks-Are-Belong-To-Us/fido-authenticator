use ctap_types::{authenticator::ctap2, Bytes, String, Vec};
use trussed::client;

use crate::authenticator::{Authenticator, UserPresence};
#[cfg(feature = "enable-fido-2-1-pre")]
use crate::state::MAX_SERIALIZED_LARGE_BLOB_ARRAY;

impl<UP, T> Authenticator<UP, T>
where
    UP: UserPresence,
    T: client::Client
        + client::P256
        + client::Chacha8Poly1305
        + client::Aes256Cbc
        + client::Sha256
        + client::HmacSha256
        + client::Ed255,
{
    pub(super) fn get_info(&mut self) -> ctap2::get_info::Response {
        use core::str::FromStr;
        let mut versions = Vec::new();
        versions.push(String::from_str("U2F_V2").unwrap()).unwrap();
        versions
            .push(String::from_str("FIDO_2_0").unwrap())
            .unwrap();
        #[cfg(feature = "enable-fido-2-1-pre")]
        versions
            .push(String::from_str("FIDO_2_1_PRE").unwrap())
            .unwrap();

        let mut extensions = Vec::new();
        // extensions.push(String::from_str("credProtect").unwrap()).unwrap();
        extensions
            .push(String::from_str("credProtect").unwrap())
            .unwrap();
        extensions
            .push(String::from_str("hmac-secret").unwrap())
            .unwrap();

        let mut pin_protocols = Vec::<u8, 1>::new();
        pin_protocols.push(1).unwrap();

        let mut options = ctap2::get_info::CtapOptions::default();
        options.rk = true;
        options.up = true;
        options.uv = None; // "uv" here refers to "in itself", e.g. biometric
                           // options.plat = false;
        options.cred_mgmt = Some(true);
        // options.client_pin = None; // not capable of PIN
        options.client_pin = match self.state.persistent.pin_is_set() {
            true => Some(true),
            false => Some(false),
        };
        #[cfg(feature = "enable-fido-2-1-pre")]
        {
            options.large_blobs = Some(true);
        }

        let (_, aaguid) = self.state.identity.attestation(&mut self.trussed);

        ctap2::get_info::Response {
            versions,
            extensions: Some(extensions),
            aaguid: Bytes::from_slice(&aaguid).unwrap(),
            options: Some(options),
            max_msg_size: Some(ctap_types::sizes::MESSAGE_SIZE),
            pin_protocols: Some(pin_protocols),
            max_creds_in_list: Some(ctap_types::sizes::MAX_CREDENTIAL_COUNT_IN_LIST),
            max_cred_id_length: Some(ctap_types::sizes::MAX_CREDENTIAL_ID_LENGTH),
            #[cfg(feature = "enable-fido-2-1-pre")]
            max_serialized_large_blob_array: Some(MAX_SERIALIZED_LARGE_BLOB_ARRAY),
            ..ctap2::get_info::Response::default()
        }
    }
}
