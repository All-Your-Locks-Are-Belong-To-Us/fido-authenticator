#![cfg_attr(not(test), no_std)]

#[macro_use]
extern crate delog;
generate_macros!();

use ctap_types::authenticator::Error;
use trussed::{syscall, Client as TrussedClient};

mod authenticator;
pub mod constants;
pub mod state;
mod utils;

pub use authenticator::Authenticator;

pub type Result<T> = core::result::Result<T, Error>;

/// Idea is to maybe send a request over a queue,
/// and return upon button press.
/// TODO: Do we need a timeout?
pub trait UserPresence: Copy {
    fn user_present<T: TrussedClient>(
        self,
        trussed: &mut T,
        timeout_milliseconds: u32,
    ) -> Result<()>;
}

#[derive(Copy, Clone)]
pub struct SilentAuthenticator {}

impl UserPresence for SilentAuthenticator {
    fn user_present<T: TrussedClient>(self, _: &mut T, _: u32) -> Result<()> {
        Ok(())
    }
}

#[derive(Copy, Clone)]
pub struct NonSilentAuthenticator {}

impl UserPresence for NonSilentAuthenticator {
    fn user_present<T: TrussedClient>(
        self,
        trussed: &mut T,
        timeout_milliseconds: u32,
    ) -> Result<()> {
        let result = syscall!(trussed.confirm_user_present(timeout_milliseconds)).result;
        result.map_err(|err| match err {
            trussed::types::consent::Error::TimedOut => Error::KeepaliveCancel,
            _ => Error::OperationDenied,
        })
    }
}

#[cfg(test)]
mod test {}
