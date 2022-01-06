use ctap_types::authenticator::Error;
use littlefs2::path::PathBuf;
use trussed::{client, syscall, types::Location};

use crate::authenticator::{Authenticator, UserPresence};
use crate::{constants, Result};

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
    pub(super) fn reset(&mut self) -> Result<()> {
        // 1. >10s after bootup -> NotAllowed
        let uptime = syscall!(self.trussed.uptime()).uptime;
        if uptime.as_secs() > 10 {
            #[cfg(not(feature = "disable-reset-time-window"))]
            return Err(Error::NotAllowed);
        }
        // 2. check for user presence
        // denied -> OperationDenied
        // timeout -> UserActionTimeout
        self.up
            .user_present(&mut self.trussed, constants::FIDO2_UP_TIMEOUT)?;

        // Delete resident keys
        syscall!(self.trussed.delete_all(Location::Internal));
        syscall!(self
            .trussed
            .remove_dir_all(Location::Internal, PathBuf::from("rk"),));

        // b. delete persistent state
        self.state.persistent.reset(&mut self.trussed)?;

        // c. Reset runtime state
        self.state.runtime.reset(&mut self.trussed);

        Ok(())
    }
}
