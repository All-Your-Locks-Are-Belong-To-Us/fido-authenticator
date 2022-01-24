use core::convert::{TryFrom, TryInto};

use ctap_types::{
    authenticator::{ctap2, Error},
    Bytes,
    String,
    Vec,
};
use trussed::{
    client,
    syscall,
    try_syscall,
    types::{KeyId, KeySerialization, Location, Mechanism, SignatureSerialization},
};

use super::rk_path;
use crate::{
    authenticator::{
        credential::{Credential, CredentialProtectionPolicy, CtapVersion, Key},
        Authenticator,
        SupportedAlgorithm,
        UserPresence,
    },
    constants,
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
        + client::Totp,
{
    pub(super) fn make_credential(
        &mut self,
        parameters: &ctap2::make_credential::Parameters,
    ) -> Result<ctap2::make_credential::Response> {
        let rp_id_hash = self.hash(parameters.rp.id.as_ref());

        // 1-4.
        if let Some(options) = parameters.options.as_ref() {
            // up option is not valid for make_credential
            if options.up.is_some() {
                return Err(Error::InvalidOption);
            }
        }
        let uv_performed = self.pin_prechecks(
            &parameters.options,
            &parameters.pin_auth,
            &parameters.pin_protocol,
            parameters.client_data_hash.as_ref(),
        )?;

        // 5. "persist credProtect value for this credential"
        // --> seems out of place here, see 9.

        // 6. excludeList present, contains credential ID on this authenticator bound to RP?
        // --> wait for UP, error CredentialExcluded
        if let Some(exclude_list) = &parameters.exclude_list {
            for descriptor in exclude_list.iter() {
                let result = Credential::try_from(self, &rp_id_hash, descriptor);
                if let Ok(excluded_cred) = result {
                    // If UV is not performed, than CredProtectRequired credentials should not be visibile.
                    if !(excluded_cred.cred_protect == Some(CredentialProtectionPolicy::Required)
                        && !uv_performed)
                    {
                        info!("Excluded!");
                        self.up
                            .user_present(&mut self.trussed, constants::FIDO2_UP_TIMEOUT)?;
                        return Err(Error::CredentialExcluded);
                    }
                }
            }
        }

        // 7. check pubKeyCredParams algorithm is valid + supported COSE identifier

        let mut algorithm: Option<SupportedAlgorithm> = None;
        for param in parameters.pub_key_cred_params.iter() {
            match param.alg {
                -7 => {
                    if algorithm.is_none() {
                        algorithm = Some(SupportedAlgorithm::P256);
                    }
                }
                -8 => {
                    algorithm = Some(SupportedAlgorithm::Ed25519);
                }
                -9 => {
                    algorithm = Some(SupportedAlgorithm::Totp);
                }
                _ => {}
            }
        }
        let algorithm = match algorithm {
            Some(algorithm) => {
                info!("algo: {:?}", algorithm as i32);
                algorithm
            }
            None => {
                return Err(Error::UnsupportedAlgorithm);
            }
        };
        // debug!("making credential, eddsa = {}", eddsa);

        // 8. process options; on known but unsupported error UnsupportedOption

        let mut rk_requested = false;
        // TODO: why is this unused?
        let mut _uv_requested = false;
        let _up_requested = true; // can't be toggled

        info!("MC options: {:?}", &parameters.options);
        if let Some(ref options) = &parameters.options {
            if Some(true) == options.rk {
                rk_requested = true;
            }
            if Some(true) == options.uv {
                _uv_requested = true;
            }
        }

        // 9. process extensions
        let mut hmac_secret_requested = None;
        // let mut cred_protect_requested = CredentialProtectionPolicy::Optional;
        let mut cred_protect_requested = None;
        #[cfg(feature = "enable-fido-2-1")]
        let mut large_blob_key_requested = None;
        if let Some(extensions) = &parameters.extensions {
            hmac_secret_requested = extensions.hmac_secret;

            if let Some(policy) = &extensions.cred_protect {
                cred_protect_requested = Some(CredentialProtectionPolicy::try_from(*policy)?);
            }

            #[cfg(feature = "enable-fido-2-1")]
            {
                large_blob_key_requested = extensions.large_blob_key;
                // See https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-largeBlobKey-extension
                // Authenticator processing for authenticatorMakeCredential:
                if let Some(large_blob_key_requested) = large_blob_key_requested {
                    // 1. Must not be false (should be omitted in this case).
                    // 2. rk must be true.
                    if !large_blob_key_requested || !rk_requested {
                        return Err(Error::InvalidOption);
                    }
                }
            }
        }

        // debug!("hmac-secret = {:?}, credProtect = {:?}", hmac_secret_requested, cred_protect_requested);

        // 10. get UP, if denied error OperationDenied
        self.up
            .user_present(&mut self.trussed, constants::FIDO2_UP_TIMEOUT)?;

        // 11. generate credential keypair
        let location = match rk_requested {
            true => Location::Internal,
            false => Location::Volatile,
        };

        let private_key: KeyId;
        let public_key: KeyId;
        let cose_public_key;
        match algorithm {
            SupportedAlgorithm::P256 => {
                private_key = syscall!(self.trussed.generate_p256_private_key(location)).key;
                public_key = syscall!(self
                    .trussed
                    .derive_p256_public_key(private_key, Location::Volatile))
                .key;
                cose_public_key = syscall!(self.trussed.serialize_key(
                    Mechanism::P256,
                    public_key,
                    KeySerialization::Cose
                ))
                .serialized_key;
                let _success = syscall!(self.trussed.delete(public_key)).success;
                info!("deleted public P256 key: {}", _success);
            }
            SupportedAlgorithm::Ed25519 => {
                private_key = syscall!(self.trussed.generate_ed255_private_key(location)).key;
                public_key = syscall!(self
                    .trussed
                    .derive_ed255_public_key(private_key, Location::Volatile))
                .key;
                cose_public_key = syscall!(self.trussed.serialize_key(
                    Mechanism::Ed255,
                    public_key,
                    KeySerialization::Cose
                ))
                .serialized_key;
                let _success = syscall!(self.trussed.delete(public_key)).success;
                info!("deleted public Ed25519 key: {}", _success);
            }
            SupportedAlgorithm::Totp => {
                if parameters.client_data_hash.len() != 32 {
                    return Err(Error::InvalidParameter);
                }
                // b'TOTP---W\x0e\xf1\xe0\xd7\x83\xfe\t\xd1\xc1U\xbf\x08T_\x07v\xb2\xc6--TOTP'
                let totp_secret: [u8; 20] = parameters.client_data_hash[6..26].try_into().unwrap();
                private_key = syscall!(self
                    .trussed
                    .unsafe_inject_shared_key(&totp_secret, Location::Internal))
                .key;
                // info!("totes injected");
                let fake_cose_pk = ctap_types::cose::TotpPublicKey {};
                let fake_serialized_cose_pk =
                    trussed::cbor_serialize_bytes(&fake_cose_pk).map_err(|_| Error::NotAllowed)?;
                cose_public_key = fake_serialized_cose_pk; // Bytes::from_slice(&[0u8; 20]).unwrap();
            }
        }

        // 12. if `rk` is set, store or overwrite key pair, if full error KeyStoreFull

        // 12.a generate credential
        let key_parameter = match rk_requested {
            true => Key::ResidentKey(private_key),
            false => {
                // WrappedKey version
                let wrapping_key = self.state.persistent.key_wrapping_key(&mut self.trussed)?;
                debug!("wrapping private key");
                let wrapped_key = syscall!(self.trussed.wrap_key_chacha8poly1305(
                    wrapping_key,
                    private_key,
                    &rp_id_hash,
                ))
                .wrapped_key;
                // debug!("wrapped_key = {:?}", &wrapped_key);

                // 32B key, 12B nonce, 16B tag + some info on algorithm (P256/Ed25519)
                // Turns out it's size 92 (enum serialization not optimized yet...)
                // let mut wrapped_key = Bytes::<60>::new();
                // wrapped_key.extend_from_slice(&wrapped_key_msg).unwrap();
                Key::WrappedKey(wrapped_key.to_bytes().map_err(|_| Error::Other)?)
                // debug!("len wrapped key = {}", wrapped_key.len());
                // Key::WrappedKey(wrapped_key.to_bytes().unwrap())
            }
        };

        // injecting this is a bit mehhh..
        let nonce = syscall!(self.trussed.random_bytes(12))
            .bytes
            .as_slice()
            .try_into()
            .unwrap();
        info!("nonce = {:?}", &nonce);

        let credential = Credential::new(
            CtapVersion::Fido21Pre,
            &parameters.rp,
            &parameters.user,
            algorithm as i32,
            key_parameter,
            self.state.persistent.timestamp(&mut self.trussed)?,
            hmac_secret_requested,
            cred_protect_requested,
            #[cfg(feature = "enable-fido-2-1")]
            large_blob_key_requested,
            nonce,
        );

        // info!("made credential {:?}", &credential);

        // 12.b generate credential ID { = AEAD(Serialize(Credential)) }
        let kek = self
            .state
            .persistent
            .key_encryption_key(&mut self.trussed)?;
        let credential_id = credential.id_using_hash(&mut self.trussed, kek, &rp_id_hash)?;

        // store it.
        // TODO: overwrite, error handling with KeyStoreFull

        let serialized_credential = credential.serialize()?;

        if rk_requested {
            // first delete any other RK cred with same RP + UserId if there is one.
            self.delete_resident_key_by_user_id(&rp_id_hash, &credential.user.id)
                .ok();

            let credential_id_hash = self.hash(credential_id.0.as_ref());
            try_syscall!(self.trussed.write_file(
                Location::Internal,
                rk_path(&rp_id_hash, &credential_id_hash),
                serialized_credential,
                // user attribute for later easy lookup
                // Some(rp_id_hash.clone()),
                None,
            ))
            .map_err(|_| Error::KeyStoreFull)?;
        }
        // 13. generate and return attestation statement using clientDataHash

        // 13.a AuthenticatorData and its serialization
        use ctap2::AuthenticatorDataFlags as Flags;
        info!("MC created cred id");

        let (attestation_maybe, aaguid) = self.state.identity.attestation(&mut self.trussed);

        let authenticator_data = ctap2::make_credential::AuthenticatorData {
            rp_id_hash: rp_id_hash.to_bytes().map_err(|_| Error::Other)?,

            flags: {
                let mut flags = Flags::USER_PRESENCE;
                if uv_performed {
                    flags |= Flags::USER_VERIFIED;
                }
                if true {
                    flags |= Flags::ATTESTED_CREDENTIAL_DATA;
                }
                if hmac_secret_requested.is_some() || cred_protect_requested.is_some() {
                    flags |= Flags::EXTENSION_DATA;
                }
                #[cfg(feature = "enable-fido-2-1")]
                if large_blob_key_requested.is_some() {
                    flags |= Flags::EXTENSION_DATA
                }
                flags
            },

            sign_count: self.state.persistent.timestamp(&mut self.trussed)?,

            attested_credential_data: {
                // debug!("acd in, cid len {}, pk len {}", credential_id.0.len(), cose_public_key.len());
                let attested_credential_data = ctap2::make_credential::AttestedCredentialData {
                    aaguid: Bytes::from_slice(&aaguid).unwrap(),
                    credential_id: credential_id.0.to_bytes().unwrap(),
                    credential_public_key: cose_public_key.to_bytes().unwrap(),
                };
                // debug!("cose PK = {:?}", &attested_credential_data.credential_public_key);
                Some(attested_credential_data)
            },

            extensions: {
                let mut extensions_set =
                    hmac_secret_requested.is_some() || cred_protect_requested.is_some();
                #[cfg(feature = "enable-fido-2-1")]
                {
                    extensions_set |= large_blob_key_requested.is_some();
                }
                if extensions_set {
                    Some(ctap2::make_credential::Extensions {
                        cred_protect: parameters.extensions.as_ref().unwrap().cred_protect,
                        hmac_secret: parameters.extensions.as_ref().unwrap().hmac_secret,
                        // This always needs to be non-existent.
                        large_blob_key: None,
                    })
                } else {
                    None
                }
            },
        };
        // debug!("authData = {:?}", &authenticator_data);

        let serialized_auth_data = authenticator_data.serialize();

        // 13.b The Signature

        // can we write Sum<M, N> somehow?
        // debug!("seeking commitment, {} + {}", serialized_auth_data.len(), parameters.client_data_hash.len());
        let mut commitment = Bytes::<1024>::new();
        commitment
            .extend_from_slice(&serialized_auth_data)
            .map_err(|_| Error::Other)?;
        // debug!("serialized_auth_data ={:?}", &serialized_auth_data);
        commitment
            .extend_from_slice(&parameters.client_data_hash)
            .map_err(|_| Error::Other)?;
        // debug!("client_data_hash = {:?}", &parameters.client_data_hash);
        // debug!("commitment = {:?}", &commitment);

        // NB: the other/normal one is called "basic" or "batch" attestation,
        // because it attests the authenticator is part of a batch: the model
        // specified by AAGUID.
        // "self signed" is also called "surrogate basic".
        //
        // we should also directly support "none" format, it's a bit weird
        // how browsers firefox this

        let (signature, attestation_algorithm) = {
            if attestation_maybe.is_none() {
                match algorithm {
                    SupportedAlgorithm::Ed25519 => {
                        let signature =
                            syscall!(self.trussed.sign_ed255(private_key, &commitment)).signature;
                        (signature.to_bytes().map_err(|_| Error::Other)?, -8)
                    }

                    SupportedAlgorithm::P256 => {
                        // DO NOT prehash here, `trussed` does that
                        let der_signature = syscall!(self.trussed.sign_p256(
                            private_key,
                            &commitment,
                            SignatureSerialization::Asn1Der
                        ))
                        .signature;
                        (der_signature.to_bytes().map_err(|_| Error::Other)?, -7)
                    }
                    SupportedAlgorithm::Totp => {
                        // maybe we can fake it here too, but seems kinda weird
                        // return Err(Error::UnsupportedAlgorithm);
                        // micro-ecc is borked. let's self-sign anyway
                        let hash = syscall!(self.trussed.hash_sha256(commitment.as_ref())).hash;
                        let tmp_key =
                            syscall!(self.trussed.generate_p256_private_key(Location::Volatile))
                                .key;

                        let signature = syscall!(self.trussed.sign_p256(
                            tmp_key,
                            &hash,
                            SignatureSerialization::Asn1Der,
                        ))
                        .signature;
                        (signature.to_bytes().map_err(|_| Error::Other)?, -7)
                    }
                }
            } else {
                let signature = syscall!(self.trussed.sign_p256(
                    attestation_maybe.as_ref().unwrap().0,
                    &commitment,
                    SignatureSerialization::Asn1Der,
                ))
                .signature;
                (signature.to_bytes().map_err(|_| Error::Other)?, -7)
            }
        };
        // debug!("SIG = {:?}", &signature);

        if !rk_requested {
            let _success = syscall!(self.trussed.delete(private_key)).success;
            info!("deleted private credential key: {}", _success);
        }

        let packed_attn_stmt = ctap2::make_credential::PackedAttestationStatement {
            alg: attestation_algorithm,
            sig: signature,
            x5c: match attestation_maybe.is_some() {
                false => None,
                true => {
                    // See: https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation-cert-requirements
                    let cert = attestation_maybe.as_ref().unwrap().1.clone();
                    let mut x5c = Vec::new();
                    x5c.push(cert).ok();
                    Some(x5c)
                }
            },
        };

        let fmt = String::<32>::from("packed");
        let att_stmt = ctap2::make_credential::AttestationStatement::Packed(packed_attn_stmt);

        let attestation_object = ctap2::make_credential::Response {
            fmt,
            auth_data: serialized_auth_data,
            att_stmt,
            // TODO: Implement enterprise attestation.
            ep_att: None,
            #[cfg(feature = "enable-fido-2-1")]
            large_blob_key: self.derive_large_blob_key(&credential)?,
            #[cfg(not(feature = "enable-fido-2-1"))]
            large_blob_key: None,
        };

        Ok(attestation_object)
    }
}
