use core::convert::TryInto;

use ctap_types::{
    ctap1::{
        self as U2f,
        Command as U2fCommand,
        Error as U2fError,
        Response as U2fResponse,
        Result as U2fResult,
    },
    Bytes,
};
use trussed::{
    client,
    syscall,
    types::{KeySerialization, Location, Mechanism, SignatureSerialization},
};

use super::{
    credential::{Credential, CtapVersion, Key},
    Authenticator,
    SupportedAlgorithm,
    UserPresence,
};
use crate::constants;

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
    pub fn call_u2f(&mut self, request: &U2fCommand) -> U2fResult<U2fResponse> {
        info!("called u2f");
        self.state
            .persistent
            .load_if_not_initialised(&mut self.trussed);

        let mut commitment = Bytes::<324>::new();

        match request {
            U2fCommand::Register(reg) => {
                self.up
                    .user_present(&mut self.trussed, constants::U2F_UP_TIMEOUT)
                    .map_err(|_| U2fError::ConditionsOfUseNotSatisfied)?;

                // Generate a new P256 key pair.
                let private_key =
                    syscall!(self.trussed.generate_p256_private_key(Location::Volatile)).key;
                let public_key = syscall!(self
                    .trussed
                    .derive_p256_public_key(private_key, Location::Volatile))
                .key;

                let serialized_cose_public_key = syscall!(self
                    .trussed
                    .serialize_p256_key(public_key, KeySerialization::EcdhEsHkdf256))
                .serialized_key;
                let cose_key: ctap_types::cose::EcdhEsHkdf256PublicKey =
                    trussed::cbor_deserialize(&serialized_cose_public_key).unwrap();

                let wrapping_key = self
                    .state
                    .persistent
                    .key_wrapping_key(&mut self.trussed)
                    .map_err(|_| U2fError::UnspecifiedCheckingError)?;
                debug!("wrapping u2f private key");
                let wrapped_key = syscall!(self.trussed.wrap_key_chacha8poly1305(
                    wrapping_key,
                    private_key,
                    &reg.app_id,
                ))
                .wrapped_key;
                // debug!("wrapped_key = {:?}", &wrapped_key);

                let key = Key::WrappedKey(
                    wrapped_key
                        .to_bytes()
                        .map_err(|_| U2fError::UnspecifiedCheckingError)?,
                );
                let nonce = syscall!(self.trussed.random_bytes(12))
                    .bytes
                    .as_slice()
                    .try_into()
                    .unwrap();

                let mut rp_id = heapless::String::new();

                // We do not know the rpId string in U2F.  Just using placeholder.
                rp_id.push_str("u2f").ok();
                let rp = ctap_types::webauthn::PublicKeyCredentialRpEntity {
                    id: rp_id,
                    name: None,
                    url: None,
                };

                let user = ctap_types::webauthn::PublicKeyCredentialUserEntity {
                    id: Bytes::from_slice(&[0u8; 8]).unwrap(),
                    icon: None,
                    name: None,
                    display_name: None,
                };

                let credential = Credential::new(
                    CtapVersion::U2fV2,
                    &rp,
                    &user,
                    SupportedAlgorithm::P256 as i32,
                    key,
                    self.state
                        .persistent
                        .timestamp(&mut self.trussed)
                        .map_err(|_| U2fError::NotEnoughMemory)?,
                    None,
                    None,
                    #[cfg(feature = "enable-fido-2-1")]
                    None,
                    nonce,
                );

                // info!("made credential {:?}", &credential);

                // 12.b generate credential ID { = AEAD(Serialize(Credential)) }
                let kek = self
                    .state
                    .persistent
                    .key_encryption_key(&mut self.trussed)
                    .map_err(|_| U2fError::NotEnoughMemory)?;
                let credential_id = credential
                    .id_using_hash(&mut self.trussed, kek, &reg.app_id)
                    .map_err(|_| U2fError::NotEnoughMemory)?;
                syscall!(self.trussed.delete(public_key));
                syscall!(self.trussed.delete(private_key));

                commitment.push(0).unwrap(); // reserve byte
                commitment.extend_from_slice(&reg.app_id).unwrap();
                commitment.extend_from_slice(&reg.challenge).unwrap();

                commitment.extend_from_slice(&credential_id.0).unwrap();

                commitment.push(0x04).unwrap(); // public key uncompressed byte
                commitment.extend_from_slice(&cose_key.x).unwrap();
                commitment.extend_from_slice(&cose_key.y).unwrap();

                let attestation = self.state.identity.attestation(&mut self.trussed);

                let (signature, cert) = match attestation {
                    (Some((key, cert)), _aaguid) => {
                        info!("aaguid: {}", hex_str!(&_aaguid));
                        (
                            syscall!(self.trussed.sign(
                                Mechanism::P256,
                                key,
                                &commitment,
                                SignatureSerialization::Asn1Der
                            ))
                            .signature
                            .to_bytes()
                            .unwrap(),
                            cert,
                        )
                    }
                    _ => {
                        info!("Not provisioned with attestation key!");
                        return Err(U2fError::KeyReferenceNotFound);
                    }
                };

                Ok(U2fResponse::Register(U2f::RegisterResponse::new(
                    0x05,
                    &cose_key,
                    &credential_id.0,
                    signature,
                    &cert,
                )))
            }
            U2fCommand::Authenticate(auth) => {
                let cred = Credential::try_from_bytes(self, &auth.app_id, &auth.key_handle);

                let user_presence_byte = match auth.control_byte {
                    U2f::ControlByte::CheckOnly => {
                        // if the control byte is set to 0x07 by the FIDO Client,
                        // the U2F token is supposed to simply check whether the
                        // provided key handle was originally created by this token
                        return if cred.is_ok() {
                            Err(U2fError::ConditionsOfUseNotSatisfied)
                        } else {
                            Err(U2fError::IncorrectDataParameter)
                        };
                    }
                    U2f::ControlByte::EnforceUserPresenceAndSign => {
                        self.up
                            .user_present(&mut self.trussed, constants::U2F_UP_TIMEOUT)
                            .map_err(|_| U2fError::ConditionsOfUseNotSatisfied)?;
                        0x01
                    }
                    U2f::ControlByte::DontEnforceUserPresenceAndSign => 0x00,
                };

                let cred = cred.map_err(|_| U2fError::IncorrectDataParameter)?;

                let key = match &cred.key {
                    Key::WrappedKey(bytes) => {
                        let wrapping_key = self
                            .state
                            .persistent
                            .key_wrapping_key(&mut self.trussed)
                            .map_err(|_| U2fError::IncorrectDataParameter)?;
                        let key_result = syscall!(self.trussed.unwrap_key_chacha8poly1305(
                            wrapping_key,
                            bytes,
                            b"",
                            Location::Volatile,
                        ))
                        .key;
                        match key_result {
                            Some(key) => {
                                info!("loaded u2f key!");
                                key
                            }
                            None => {
                                info!("issue with unwrapping credential id key");
                                return Err(U2fError::IncorrectDataParameter);
                            }
                        }
                    }
                    _ => return Err(U2fError::IncorrectDataParameter),
                };

                if cred.algorithm != -7 {
                    info!("Unexpected mechanism for u2f");
                    return Err(U2fError::IncorrectDataParameter);
                }

                let sig_count = self
                    .state
                    .persistent
                    .timestamp(&mut self.trussed)
                    .map_err(|_| U2fError::UnspecifiedNonpersistentExecutionError)?;

                commitment.extend_from_slice(&auth.app_id).unwrap();
                commitment.push(user_presence_byte).unwrap();
                commitment
                    .extend_from_slice(&sig_count.to_be_bytes())
                    .unwrap();
                commitment.extend_from_slice(&auth.challenge).unwrap();

                let signature = syscall!(self.trussed.sign(
                    Mechanism::P256,
                    key,
                    &commitment,
                    SignatureSerialization::Asn1Der
                ))
                .signature
                .to_bytes()
                .unwrap();

                Ok(U2fResponse::Authenticate(U2f::AuthenticateResponse::new(
                    user_presence_byte,
                    sig_count,
                    signature,
                )))
            }
            U2fCommand::Version => {
                // "U2F_V2"
                Ok(U2fResponse::Version([0x55, 0x32, 0x46, 0x5f, 0x56, 0x32]))
            }
        }
    }
}
