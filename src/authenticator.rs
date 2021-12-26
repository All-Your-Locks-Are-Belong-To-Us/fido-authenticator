mod credential;
mod credential_management;
mod ctap1;
mod ctap2;

use core::convert::TryFrom;

pub(crate) use credential::Credential;
use ctap_types::{authenticator::Error, Bytes32};
use trussed::{client, syscall};

use crate::{
    state::{self},
    utils::format_hex,
    Result,
    UserPresence,
};

pub struct Authenticator<UP, T>
where
    UP: UserPresence,
{
    trussed: T,
    state: state::State,
    up: UP,
}

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
    pub fn new(trussed: T, up: UP) -> Self {
        let state = state::State::new();
        Self { trussed, state, up }
    }

    /// Hash data.
    fn hash(&mut self, data: &[u8]) -> Bytes32 {
        let hash = syscall!(self.trussed.hash_sha256(data)).hash;
        hash.to_bytes().expect("hash should fit")
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum SupportedAlgorithm {
    P256 = -7,
    Ed25519 = -8,
    Totp = -9,
}

impl TryFrom<i32> for SupportedAlgorithm {
    type Error = Error;
    fn try_from(alg: i32) -> Result<Self> {
        Ok(match alg {
            -7 => SupportedAlgorithm::P256,
            -8 => SupportedAlgorithm::Ed25519,
            -9 => SupportedAlgorithm::Totp,
            _ => return Err(Error::UnsupportedAlgorithm),
        })
    }
}
