use ctap_types::authenticator::ctap2;
use trussed::client;

use super::{Authenticator, UserPresence};
use crate::Result;

impl<UP, T> Authenticator<UP, T>
where
    UP: UserPresence,
    T: client::Client
        + client::P256
        + client::Chacha8Poly1305
        + client::Aes256Cbc
        + client::Sha256
        + client::HmacSha256
        + client::Ed255
        + client::Totp, // + TrussedClient
{
    pub(super) fn large_blobs(
        &mut self,
        _parameters: &ctap2::large_blobs::Parameters,
    ) -> Result<ctap2::large_blobs::Response> {
        Err(ctap_types::authenticator::Error::InvalidParameter)
    }
}
