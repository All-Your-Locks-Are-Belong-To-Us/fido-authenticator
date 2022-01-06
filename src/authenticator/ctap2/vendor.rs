use ctap_types::{authenticator::Error, operation::VendorOperation};
use trussed::{client, syscall};

use crate::authenticator::{Authenticator, UserPresence};
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
    pub(super) fn vendor(&mut self, op: VendorOperation) -> Result<()> {
        info!("hello VO {:?}", &op);
        match op.into() {
            0x79 => syscall!(self.trussed.debug_dump_store()),
            _ => return Err(Error::InvalidCommand),
        };

        Ok(())
    }
}
