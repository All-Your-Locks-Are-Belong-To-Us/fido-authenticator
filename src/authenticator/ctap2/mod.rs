use core::convert::TryInto;

use ctap_types::{
    authenticator::{ctap2, Error, Request, Response},
    Bytes,
};
use littlefs2::path::PathBuf;
use trussed::{client, syscall, types::KeyId};

use super::{Authenticator, UserPresence};
use crate::{constants, utils::format_hex, Result};

mod client_pin;
mod credential_mgmt;
mod get_assertion;
mod get_info;
mod make_credential;
mod reset;
mod vendor;

#[cfg(feature = "enable-fido-2-1-pre")]
mod large_blobs;

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
    pub fn call(&mut self, request: &Request) -> Result<Response> {
        // if let Some(request) = self.interchange.take_request() {
        // debug!("request: {:?}", &request);
        self.state
            .persistent
            .load_if_not_initialised(&mut self.trussed);

        match request {
            Request::Ctap2(request) => {
                match request {
                    // 0x4
                    ctap2::Request::GetInfo => {
                        debug!("GI");
                        let response = self.get_info();
                        Ok(Response::Ctap2(ctap2::Response::GetInfo(response)))
                    }

                    // 0x2
                    ctap2::Request::MakeCredential(parameters) => {
                        debug!("MC request");
                        let response = self.make_credential(parameters);
                        match response {
                            Ok(response) => {
                                Ok(Response::Ctap2(ctap2::Response::MakeCredential(response)))
                            }
                            Err(error) => Err(error),
                        }
                    }

                    // 0x1
                    ctap2::Request::GetAssertion(parameters) => {
                        debug!("GA request");
                        let response = self.get_assertion(parameters);
                        match response {
                            Ok(response) => {
                                Ok(Response::Ctap2(ctap2::Response::GetAssertion(response)))
                            }
                            Err(error) => Err(error),
                        }
                    }

                    // 0x8
                    ctap2::Request::GetNextAssertion => {
                        debug!("GNA request");
                        let response = self.get_next_assertion();
                        match response {
                            Ok(response) => {
                                Ok(Response::Ctap2(ctap2::Response::GetNextAssertion(response)))
                            }
                            Err(error) => Err(error),
                        }
                    }

                    // 0x7
                    ctap2::Request::Reset => {
                        debug!("Reset request");
                        let response = self.reset();
                        match response {
                            Ok(()) => Ok(Response::Ctap2(ctap2::Response::Reset)),
                            Err(error) => Err(error),
                        }
                    }

                    // 0x6
                    ctap2::Request::ClientPin(parameters) => {
                        debug!("CP request");
                        let response = self.client_pin(parameters);
                        match response {
                            Ok(response) => {
                                Ok(Response::Ctap2(ctap2::Response::ClientPin(response)))
                            }
                            Err(error) => Err(error),
                        }
                    }

                    // 0xA
                    ctap2::Request::CredentialManagement(parameters) => {
                        debug!("CM request");
                        let response = self.credential_management(parameters);
                        match response {
                            Ok(response) => {
                                // let mut buf = [0u8; 512];
                                // info!("{:?}", ctap_types::serde::cbor_serialize(&response, &mut buf));
                                Ok(Response::Ctap2(ctap2::Response::CredentialManagement(
                                    response,
                                )))
                            }
                            Err(error) => Err(error),
                        }
                    }

                    // 0xC
                    ctap2::Request::LargeBlobs(parameters) => {
                        #[cfg(feature = "enable-fido-2-1-pre")]
                        {
                            debug!("LargeBlobs request");
                            let response = self.large_blobs(parameters);
                            match response {
                                Ok(response) => {
                                    Ok(Response::Ctap2(ctap2::Response::LargeBlobs(response)))
                                }
                                Err(error) => Err(error),
                            }
                        }
                        #[cfg(not(feature = "enable-fido-2-1-pre"))]
                        {
                            // to silence clippy.
                            let _parameters = parameters;
                            Err(Error::InvalidCommand)
                        }
                    }

                    ctap2::Request::Vendor(op) => {
                        debug!("Vendor request");
                        let response = self.vendor(*op);
                        match response {
                            Ok(()) => Ok(Response::Ctap2(ctap2::Response::Vendor)),
                            Err(error) => Err(error),
                        }
                    } // _ => {
                      //     // debug!("not implemented: {:?}", &request);
                      //     debug!("request not implemented");
                      //     self.interchange.respond(Err(Error::InvalidCommand)).expect("internal error");
                      // }
                }
            }
            Request::Ctap1(_request) => {
                debug!("ctap1 not implemented: {:?}", &_request);
                Err(Error::InvalidCommand)
            }
        }
        // }
    }

    // fn verify_pin(&mut self, pin_auth: &Bytes<16>, client_data_hash: &Bytes<32>) -> bool {
    fn verify_pin(&mut self, pin_auth: &[u8; 16], data: &[u8]) -> Result<()> {
        let key = self.state.runtime.pin_token(&mut self.trussed);
        let tag = syscall!(self.trussed.sign_hmacsha256(key, data)).signature;
        if pin_auth == &tag[..16] {
            Ok(())
        } else {
            Err(Error::PinAuthInvalid)
        }
    }

    fn verify_pin_auth(
        &mut self,
        shared_secret: KeyId,
        data: &[u8],
        pin_auth: &Bytes<16>,
    ) -> Result<()> {
        let expected_pin_auth =
            syscall!(self.trussed.sign_hmacsha256(shared_secret, data)).signature;

        if expected_pin_auth[..16] == pin_auth[..] {
            Ok(())
        } else {
            Err(Error::PinAuthInvalid)
        }
    }

    // fn verify_pin_auth_using_token(&mut self, data: &[u8], pin_auth: &Bytes<16>)
    fn verify_pin_auth_using_token(
        &mut self,
        parameters: &ctap2::credential_management::Parameters,
    ) -> Result<()> {
        // info!("CM params: {:?}", parameters);
        use ctap2::credential_management::Subcommand;
        match parameters.sub_command {
            // are we Haskell yet lol
            sub_command @ Subcommand::GetCredsMetadata
            | sub_command @ Subcommand::EnumerateRpsBegin
            | sub_command @ Subcommand::EnumerateCredentialsBegin
            | sub_command @ Subcommand::DeleteCredential => {
                // check pinProtocol
                let pin_protocol = parameters
                    // .sub_command_params.as_ref().ok_or(Error::MissingParameter)?
                    .pin_protocol
                    .ok_or(Error::MissingParameter)?;
                if pin_protocol != 1 {
                    return Err(Error::InvalidParameter);
                }

                // check pinAuth
                let pin_token = self.state.runtime.pin_token(&mut self.trussed);
                let mut data: Bytes<{ ctap_types::sizes::MAX_CREDENTIAL_ID_LENGTH_PLUS_256 }> =
                    Bytes::from_slice(&[sub_command as u8]).unwrap();
                let len = 1 + match sub_command {
                    Subcommand::EnumerateCredentialsBegin | Subcommand::DeleteCredential => {
                        data.resize_to_capacity();
                        // ble, need to reserialize
                        ctap_types::serde::cbor_serialize(
                            &parameters
                                .sub_command_params
                                .as_ref()
                                .ok_or(Error::MissingParameter)?,
                            &mut data[1..],
                        )
                        .map_err(|_| Error::LimitExceeded)?
                        .len()
                    }
                    _ => 0,
                };

                // info!("input to hmacsha256: {:?}", &data[..len]);
                let expected_pin_auth =
                    syscall!(self.trussed.sign_hmacsha256(pin_token, &data[..len],)).signature;

                let pin_auth = parameters
                    .pin_auth
                    .as_ref()
                    .ok_or(Error::MissingParameter)?;

                if expected_pin_auth[..16] == pin_auth[..] {
                    info!("passed pinauth");
                    Ok(())
                } else {
                    info!("failed pinauth!");
                    self.state.decrement_retries(&mut self.trussed)?;
                    let maybe_blocked = self.state.pin_blocked();
                    if maybe_blocked.is_err() {
                        info!("blocked");
                        maybe_blocked
                    } else {
                        info!("pinAuthInvalid");
                        Err(Error::PinAuthInvalid)
                    }
                }
            }

            _ => Ok(()),
        }
    }

    /// Returns whether UV was performed.
    fn pin_prechecks(
        &mut self,
        options: &Option<ctap2::AuthenticatorOptions>,
        pin_auth: &Option<ctap2::PinAuth>,
        pin_protocol: &Option<u32>,
        data: &[u8],
    ) -> Result<bool> {
        // 1. pinAuth zero length -> wait for user touch, then
        // return PinNotSet if not set, PinInvalid if set
        //
        // the idea is for multi-authnr scenario where platform
        // wants to enforce PIN and needs to figure out which authnrs support PIN
        if let Some(pin_auth) = pin_auth.as_ref() {
            if pin_auth.len() == 0 {
                self.up
                    .user_present(&mut self.trussed, constants::FIDO2_UP_TIMEOUT)?;
                if !self.state.persistent.pin_is_set() {
                    return Err(Error::PinNotSet);
                } else {
                    return Err(Error::PinAuthInvalid);
                }
            }
        }

        // 2. check PIN protocol is 1 if pinAuth was sent
        if let Some(ref _pin_auth) = pin_auth {
            if let Some(1) = pin_protocol {
            } else {
                return Err(Error::PinAuthInvalid);
            }
        }

        // 3. if no PIN is set (we have no other form of UV),
        // and platform sent `uv` or `pinAuth`, return InvalidOption
        if !self.state.persistent.pin_is_set() {
            if let Some(ref options) = &options {
                if Some(true) == options.uv {
                    return Err(Error::InvalidOption);
                }
            }
            if pin_auth.is_some() {
                return Err(Error::InvalidOption);
            }
        }

        // 4. If authenticator is protected by som form of user verification, do it
        //
        // TODO: Should we should fail if `uv` is passed?
        // Current thinking: no
        if self.state.persistent.pin_is_set() {
            // let mut uv_performed = false;
            if let Some(ref pin_auth) = pin_auth {
                if pin_auth.len() != 16 {
                    return Err(Error::InvalidParameter);
                }
                // seems a bit redundant to check here in light of 2.
                // I guess the CTAP spec writers aren't implementers :D
                if let Some(1) = pin_protocol {
                    // 5. if pinAuth is present and pinProtocol = 1, verify
                    // success --> set uv = 1
                    // error --> PinAuthInvalid
                    self.verify_pin(
                        // unwrap panic ruled out above
                        pin_auth.as_slice().try_into().unwrap(),
                        data,
                    )?;

                    return Ok(true);
                } else {
                    // 7. pinAuth present + pinProtocol != 1 --> error PinAuthInvalid
                    return Err(Error::PinAuthInvalid);
                }
            } else {
                // 6. pinAuth not present + clientPin set --> error PinRequired
                if self.state.persistent.pin_is_set() {
                    return Err(Error::PinRequired);
                }
            }
        }

        Ok(false)
    }
}

/// Directory for resident keys for a given relying party.
fn rp_rk_dir(rp_id_hash: &Bytes<32>) -> PathBuf {
    // uses only first 8 bytes of hash, which should be "good enough"
    let mut hex = [b'0'; 16];
    format_hex(&rp_id_hash[..8], &mut hex);

    let mut dir = PathBuf::from(b"rk");
    dir.push(&PathBuf::from(&hex));

    dir
}

/// Path to a resident key.
fn rk_path(rp_id_hash: &Bytes<32>, credential_id_hash: &Bytes<32>) -> PathBuf {
    let mut path = rp_rk_dir(rp_id_hash);

    let mut hex = [0u8; 16];
    format_hex(&credential_id_hash[..8], &mut hex);
    path.push(&PathBuf::from(&hex));

    path
}
