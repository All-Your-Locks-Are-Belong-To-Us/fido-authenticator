use core::convert::TryInto;

use ctap_types::{
    authenticator::{ctap2, Error},
    Bytes,
};
use trussed::{
    client,
    syscall,
    types::{KeyId, KeySerialization, Location, Mechanism, MediumData, Message},
};

use crate::{
    authenticator::{Authenticator, UserPresence},
    Result,
};

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
    pub(super) fn client_pin(
        &mut self,
        parameters: &ctap2::client_pin::Parameters,
    ) -> Result<ctap2::client_pin::Response> {
        use ctap2::client_pin::PinV1Subcommand as Subcommand;
        debug!("processing CP");
        // info!("{:?}", parameters);

        if parameters.pin_protocol != 1 {
            return Err(Error::InvalidParameter);
        }

        Ok(match parameters.sub_command {
            Subcommand::GetRetries => {
                debug!("processing CP.GR");

                ctap2::client_pin::Response {
                    key_agreement: None,
                    pin_token: None,
                    retries: Some(self.state.persistent.retries()),
                }
            }

            Subcommand::GetKeyAgreement => {
                debug!("processing CP.GKA");

                let private_key = self.state.runtime.key_agreement_key(&mut self.trussed);
                let public_key = syscall!(self
                    .trussed
                    .derive_p256_public_key(private_key, Location::Volatile))
                .key;
                let serialized_cose_key = syscall!(self.trussed.serialize_key(
                    Mechanism::P256,
                    public_key,
                    KeySerialization::EcdhEsHkdf256
                ))
                .serialized_key;
                let cose_key = trussed::cbor_deserialize(&serialized_cose_key).unwrap();

                syscall!(self.trussed.delete(public_key));

                ctap2::client_pin::Response {
                    key_agreement: cose_key,
                    pin_token: None,
                    retries: None,
                }
            }

            Subcommand::SetPin => {
                debug!("processing CP.SP");
                // 1. check mandatory parameters
                let platform_kek = match parameters.key_agreement.as_ref() {
                    Some(key) => key,
                    None => {
                        return Err(Error::MissingParameter);
                    }
                };
                let new_pin_enc = match parameters.new_pin_enc.as_ref() {
                    Some(pin) => pin,
                    None => {
                        return Err(Error::MissingParameter);
                    }
                };
                let pin_auth = match parameters.pin_auth.as_ref() {
                    Some(auth) => auth,
                    None => {
                        return Err(Error::MissingParameter);
                    }
                };

                // 2. is pin already set
                if self.state.persistent.pin_is_set() {
                    return Err(Error::NotAllowed);
                }

                // 3. generate shared secret
                let shared_secret = self
                    .state
                    .runtime
                    .generate_shared_secret(&mut self.trussed, platform_kek)?;

                // TODO: there are moar early returns!!
                // - implement Drop?
                // - do garbage collection outside of this?

                // 4. verify pinAuth
                self.verify_pin_auth(shared_secret, new_pin_enc, pin_auth)?;

                // 5. decrypt and verify new PIN
                let new_pin = self.decrypt_pin_check_length(shared_secret, new_pin_enc)?;

                syscall!(self.trussed.delete(shared_secret));

                // 6. store LEFT(SHA-256(newPin), 16), set retries to 8
                self.hash_store_pin(&new_pin)?;
                self.state
                    .reset_retries(&mut self.trussed)
                    .map_err(|_| Error::Other)?;

                ctap2::client_pin::Response {
                    key_agreement: None,
                    pin_token: None,
                    retries: None,
                }
            }

            Subcommand::ChangePin => {
                debug!("processing CP.CP");

                // 1. check mandatory parameters
                let platform_kek = match parameters.key_agreement.as_ref() {
                    Some(key) => key,
                    None => {
                        return Err(Error::MissingParameter);
                    }
                };
                let pin_hash_enc = match parameters.pin_hash_enc.as_ref() {
                    Some(hash) => hash,
                    None => {
                        return Err(Error::MissingParameter);
                    }
                };
                let new_pin_enc = match parameters.new_pin_enc.as_ref() {
                    Some(pin) => pin,
                    None => {
                        return Err(Error::MissingParameter);
                    }
                };
                let pin_auth = match parameters.pin_auth.as_ref() {
                    Some(auth) => auth,
                    None => {
                        return Err(Error::MissingParameter);
                    }
                };

                // 2. fail if no retries left
                self.state.pin_blocked()?;

                // 3. generate shared secret
                let shared_secret = self
                    .state
                    .runtime
                    .generate_shared_secret(&mut self.trussed, platform_kek)?;

                // 4. verify pinAuth
                let mut data = MediumData::new();
                data.extend_from_slice(new_pin_enc)
                    .map_err(|_| Error::InvalidParameter)?;
                data.extend_from_slice(pin_hash_enc)
                    .map_err(|_| Error::InvalidParameter)?;
                self.verify_pin_auth(shared_secret, &data, pin_auth)?;

                // 5. decrement retries
                self.state.decrement_retries(&mut self.trussed)?;

                // 6. decrypt pinHashEnc, compare with stored
                self.decrypt_pin_hash_and_maybe_escalate(shared_secret, pin_hash_enc)?;

                // 7. reset retries
                self.state.reset_retries(&mut self.trussed)?;

                // 8. decrypt and verify new PIN
                let new_pin = self.decrypt_pin_check_length(shared_secret, new_pin_enc)?;

                syscall!(self.trussed.delete(shared_secret));

                // 9. store hashed PIN
                self.hash_store_pin(&new_pin)?;

                ctap2::client_pin::Response {
                    key_agreement: None,
                    pin_token: None,
                    retries: None,
                }
            }

            Subcommand::GetPinToken => {
                debug!("processing CP.GPT");

                // 1. check mandatory parameters
                let platform_kek = match parameters.key_agreement.as_ref() {
                    Some(key) => key,
                    None => {
                        return Err(Error::MissingParameter);
                    }
                };
                let pin_hash_enc = match parameters.pin_hash_enc.as_ref() {
                    Some(hash) => hash,
                    None => {
                        return Err(Error::MissingParameter);
                    }
                };

                // 2. fail if no retries left
                self.state.pin_blocked()?;

                // 3. generate shared secret
                let shared_secret = self
                    .state
                    .runtime
                    .generate_shared_secret(&mut self.trussed, platform_kek)?;

                // 4. decrement retires
                self.state.decrement_retries(&mut self.trussed)?;

                // 5. decrypt and verify pinHashEnc
                self.decrypt_pin_hash_and_maybe_escalate(shared_secret, pin_hash_enc)?;

                // 6. reset retries
                self.state.reset_retries(&mut self.trussed)?;

                // 7. return encrypted pinToken
                let pin_token = self.state.runtime.pin_token(&mut self.trussed);
                debug!("wrapping pin token");
                // info!("exists? {}", syscall!(self.trussed.exists(shared_secret)).exists);
                let pin_token_enc =
                    syscall!(self.trussed.wrap_key_aes256cbc(shared_secret, pin_token)).wrapped_key;

                syscall!(self.trussed.delete(shared_secret));

                // ble...
                if pin_token_enc.len() != 16 {
                    return Err(Error::Other);
                }
                let pin_token_enc_32 = Bytes::from_slice(&pin_token_enc).unwrap();

                ctap2::client_pin::Response {
                    key_agreement: None,
                    pin_token: Some(pin_token_enc_32),
                    retries: None,
                }
            }
            _ => {
                unimplemented!()
            }
        })
    }

    fn decrypt_pin_hash_and_maybe_escalate(
        &mut self,
        shared_secret: KeyId,
        pin_hash_enc: &Bytes<64>,
    ) -> Result<()> {
        let pin_hash = syscall!(self.trussed.decrypt_aes256cbc(shared_secret, pin_hash_enc))
            .plaintext
            .ok_or(Error::Other)?;

        let stored_pin_hash = match self.state.persistent.pin_hash() {
            Some(hash) => hash,
            None => {
                return Err(Error::PinNotSet);
            }
        };

        if pin_hash != stored_pin_hash {
            // I) generate new KEK
            self.state
                .runtime
                .rotate_key_agreement_key(&mut self.trussed);
            if self.state.persistent.retries() == 0 {
                return Err(Error::PinBlocked);
            }
            if self.state.persistent.pin_blocked() {
                return Err(Error::PinAuthBlocked);
            }
            return Err(Error::PinInvalid);
        }

        Ok(())
    }

    fn hash_store_pin(&mut self, pin: &Message) -> Result<()> {
        let pin_hash_32 = syscall!(self.trussed.hash_sha256(pin)).hash;
        let pin_hash: [u8; 16] = pin_hash_32[..16].try_into().unwrap();
        self.state
            .persistent
            .set_pin_hash(&mut self.trussed, pin_hash)
            .unwrap();

        Ok(())
    }

    fn decrypt_pin_check_length(
        &mut self,
        shared_secret: KeyId,
        pin_enc: &[u8],
    ) -> Result<Message> {
        // pin is expected to be filled with null bytes to length at least 64
        if pin_enc.len() < 64 {
            // correct error?
            return Err(Error::PinPolicyViolation);
        }

        let mut pin = syscall!(self.trussed.decrypt_aes256cbc(shared_secret, pin_enc))
            .plaintext
            .ok_or(Error::Other)?;

        // // temp
        // let pin_length = pin.iter().position(|&b| b == b'\0').unwrap_or(pin.len());
        // info!("pin.len() = {}, pin_length = {}, = {:?}",
        //           pin.len(), pin_length, &pin);
        // chop off null bytes
        let pin_length = pin
            .iter()
            .position(|&b| b == b'\0')
            .unwrap_or_else(|| pin.len());
        if !(4..64).contains(&pin_length) {
            return Err(Error::PinPolicyViolation);
        }

        pin.resize_default(pin_length).unwrap();

        Ok(pin)
    }
}
