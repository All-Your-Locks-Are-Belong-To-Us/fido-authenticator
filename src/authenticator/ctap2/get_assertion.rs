use core::convert::TryInto;

use ctap_types::{
    authenticator::{ctap2, Error},
    Bytes,
    Bytes32,
};
use littlefs2::path::PathBuf;
use trussed::{
    client,
    syscall,
    try_syscall,
    types::{KeyId, Location, Mechanism, SignatureSerialization},
};

use super::{rk_path, rp_rk_dir};
use crate::{
    authenticator::{
        credential::{CredentialList, CredentialProtectionPolicy, Key},
        Authenticator,
        Credential,
        UserPresence,
    },
    constants,
    state,
    state::{MinCredentialHeap, TimestampPath},
    utils::format_hex,
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
    pub(super) fn get_assertion(
        &mut self,
        parameters: &ctap2::get_assertion::Parameters,
    ) -> Result<ctap2::get_assertion::Response> {
        let rp_id_hash = self.hash(parameters.rp_id.as_ref());

        // 1-4.
        let uv_performed = match self.pin_prechecks(
            &parameters.options,
            &parameters.pin_auth,
            &parameters.pin_protocol,
            parameters.client_data_hash.as_ref(),
        ) {
            Ok(b) => b,
            Err(Error::PinRequired) => {
                // UV is optional for get_assertion
                false
            }
            Err(err) => return Err(err),
        };

        // 5. Locate eligible credentials
        //
        // Note: If allowList is passed, credential is Some(credential)
        // If no allowList is passed, credential is None and the retrieved credentials
        // are stored in state.runtime.credential_heap
        self.locate_credentials(&rp_id_hash, &parameters.allow_list, uv_performed)?;

        let credential = self
            .state
            .runtime
            .pop_credential_from_heap(&mut self.trussed);
        let num_credentials = match self.state.runtime.credential_heap().len() {
            0 => None,
            n => Some(n as u32 + 1),
        };
        info!("FIRST cred: {:?}", &credential);
        info!("FIRST NUM creds: {:?}", num_credentials);

        // NB: misleading, if we have "1" we return "None"
        let human_num_credentials = match num_credentials {
            Some(n) => n,
            None => 1,
        };
        info!("found {:?} applicable credentials", human_num_credentials);

        // 6. process any options present

        // UP occurs by default, but option could specify not to.
        let do_up = if parameters.options.is_some() {
            parameters.options.as_ref().unwrap().up.unwrap_or(true)
        } else {
            true
        };

        // 7. collect user presence
        let up_performed = if do_up {
            info!("asking for up");
            self.up
                .user_present(&mut self.trussed, constants::FIDO2_UP_TIMEOUT)?;
            true
        } else {
            info!("not asking for up");
            false
        };

        let multiple_credentials = human_num_credentials > 1;
        self.state.runtime.active_get_assertion = Some(state::ActiveGetAssertionData {
            rp_id_hash: {
                let mut buf = [0u8; 32];
                buf.copy_from_slice(&rp_id_hash);
                buf
            },
            client_data_hash: {
                let mut buf = [0u8; 32];
                buf.copy_from_slice(&parameters.client_data_hash);
                buf
            },
            uv_performed,
            up_performed,
            multiple_credentials,
            extensions: parameters.extensions.clone(),
        });

        self.assert_with_credential(num_credentials, credential)
    }

    pub(super) fn get_next_assertion(&mut self) -> Result<ctap2::get_assertion::Response> {
        // 1./2. don't remember / don't have left any credentials
        if self.state.runtime.credential_heap().is_empty() {
            return Err(Error::NotAllowed);
        }

        // 3. previous GA/GNA >30s ago -> discard stat
        // this is optional over NFC
        if false {
            self.state.runtime.free_credential_heap(&mut self.trussed);
            return Err(Error::NotAllowed);
        }

        // 4. select credential
        // let data = syscall!(self.trussed.read_file(
        //     timestamp_hash.location,
        //     timestamp_hash.path,
        // )).data;
        let credential = self
            .state
            .runtime
            .pop_credential_from_heap(&mut self.trussed);
        // Credential::deserialize(&data).unwrap();

        // 5. suppress PII if no UV was performed in original GA

        // 6. sign
        // 7. reset timer
        // 8. increment credential counter (not applicable)

        self.assert_with_credential(None, credential)
    }

    #[inline(never)]
    fn assert_with_credential(
        &mut self,
        num_credentials: Option<u32>,
        credential: Credential,
    ) -> Result<ctap2::get_assertion::Response> {
        let data = self.state.runtime.active_get_assertion.clone().unwrap();
        let rp_id_hash = Bytes::from_slice(&data.rp_id_hash).unwrap();

        let (key, is_rk) = match credential.key.clone() {
            Key::ResidentKey(key) => (key, true),
            Key::WrappedKey(bytes) => {
                let wrapping_key = self.state.persistent.key_wrapping_key(&mut self.trussed)?;
                // info!("unwrapping {:?} with wrapping key {:?}", &bytes, &wrapping_key);
                let key_result = syscall!(self.trussed.unwrap_key_chacha8poly1305(
                    wrapping_key,
                    &bytes,
                    b"",
                    // &rp_id_hash,
                    Location::Volatile,
                ))
                .key;
                // debug!("key result: {:?}", &key_result);
                info!("key result");
                match key_result {
                    Some(key) => (key, false),
                    None => {
                        return Err(Error::Other);
                    }
                }
            }
        };

        // 8. process any extensions present
        let mut extensions_output = None;
        #[cfg(feature = "enable-fido-2-1")]
        let mut large_blob_key_output = None;
        if let Some(extensions) = &data.extensions {
            extensions_output =
                self.process_assertion_extensions(&data, extensions, &credential, key)?;

            // Yes, the largeBlobKey is an extension. And yes, the output is not stored in the extension output field :))
            // Hence, we process the largeBlobKeyExtension separately. We could instead return the largeBlobKey as a second return value
            // from the process_assertion_extensions. However, we thought this is not a good design.
            // See https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-largeBlobKey-extension
            #[cfg(feature = "enable-fido-2-1")]
            {
                large_blob_key_output =
                    self.process_large_blob_key_extension(extensions, &credential)?;
            }
        }

        // 9./10. sign clientDataHash || authData with "first" credential

        // info!("signing with credential {:?}", &credential);
        let kek = self
            .state
            .persistent
            .key_encryption_key(&mut self.trussed)?;
        let credential_id = credential.id_using_hash(&mut self.trussed, kek, &rp_id_hash)?;

        use ctap2::AuthenticatorDataFlags as Flags;

        let sig_count = self.state.persistent.timestamp(&mut self.trussed)?;

        let authenticator_data = ctap2::get_assertion::AuthenticatorData {
            rp_id_hash,

            flags: {
                let mut flags = Flags::EMPTY;
                if data.up_performed {
                    flags |= Flags::USER_PRESENCE;
                }
                if data.uv_performed {
                    flags |= Flags::USER_VERIFIED;
                }
                if extensions_output.is_some() {
                    flags |= Flags::EXTENSION_DATA;
                }
                flags
            },

            sign_count: sig_count,
            attested_credential_data: None,
            extensions: extensions_output,
        };

        let serialized_auth_data = authenticator_data.serialize();

        let mut commitment = Bytes::<1024>::new();
        commitment
            .extend_from_slice(&serialized_auth_data)
            .map_err(|_| Error::Other)?;
        commitment
            .extend_from_slice(&data.client_data_hash)
            .map_err(|_| Error::Other)?;

        let (mechanism, serialization) = match credential.algorithm {
            -7 => (Mechanism::P256, SignatureSerialization::Asn1Der),
            -8 => (Mechanism::Ed255, SignatureSerialization::Raw),
            -9 => (Mechanism::Totp, SignatureSerialization::Raw),
            _ => {
                return Err(Error::Other);
            }
        };

        debug!("signing with {:?}, {:?}", &mechanism, &serialization);
        let signature = match mechanism {
            Mechanism::Totp => {
                let timestamp = u64::from_le_bytes(data.client_data_hash[..8].try_into().unwrap());
                info!("TOTP with timestamp {:?}", &timestamp);
                syscall!(self.trussed.sign_totp(key, timestamp))
                    .signature
                    .to_bytes()
                    .unwrap()
            }
            _ => syscall!(self
                .trussed
                .sign(mechanism, key, &commitment, serialization))
            .signature
            .to_bytes()
            .unwrap(),
        };

        if !is_rk {
            syscall!(self.trussed.delete(key));
        }

        let mut response = ctap2::get_assertion::Response {
            credential: Some(credential_id.into()),
            auth_data: Bytes::from_slice(&serialized_auth_data).map_err(|_| Error::Other)?,
            signature,
            user: None,
            number_of_credentials: num_credentials,
            // TODO: implement
            user_selected: None,
            #[cfg(not(feature = "enable-fido-2-1"))]
            large_blob_key: None,
            #[cfg(feature = "enable-fido-2-1")]
            large_blob_key: large_blob_key_output,
        };

        if is_rk {
            let mut user = credential.user.clone();
            // User identifiable information (name, DisplayName, icon) MUST not
            // be returned if user verification is not done by the authenticator.
            // For single account per RP case, authenticator returns "id" field.
            if !data.uv_performed || !data.multiple_credentials {
                user.icon = None;
                user.name = None;
                user.display_name = None;
            }
            response.user = Some(user);
        }

        Ok(response)
    }

    #[inline(never)]
    fn process_assertion_extensions(
        &mut self,
        get_assertion_state: &state::ActiveGetAssertionData,
        extensions: &ctap2::get_assertion::ExtensionsInput,
        _credential: &Credential,
        credential_key: KeyId,
    ) -> Result<Option<ctap2::get_assertion::ExtensionsOutput>> {
        let hmac_secret_output = match &extensions.hmac_secret {
            Some(hmac_secret) => {
                if let Some(pin_protocol) = hmac_secret.pin_protocol {
                    if pin_protocol != 1 {
                        return Err(Error::InvalidParameter);
                    }
                }

                // We derive credRandom as an hmac of the existing private key.
                // UV is used as input data since credRandom should depend UV
                // i.e. credRandom = HMAC(private_key, uv)
                let cred_random = syscall!(self.trussed.derive_key(
                    Mechanism::HmacSha256,
                    credential_key,
                    Some(Bytes::from_slice(&[get_assertion_state.uv_performed as u8]).unwrap()),
                    trussed::types::StorageAttributes::new().set_persistence(Location::Volatile)
                ))
                .key;

                // Verify the auth tag, which uses the same process as the pinAuth
                let kek = self
                    .state
                    .runtime
                    .generate_shared_secret(&mut self.trussed, &hmac_secret.key_agreement)?;
                self.verify_pin_auth(kek, &hmac_secret.salt_enc, &hmac_secret.salt_auth)
                    .map_err(|_| Error::ExtensionFirst)?;

                if hmac_secret.salt_enc.len() != 32 && hmac_secret.salt_enc.len() != 64 {
                    return Err(Error::InvalidLength);
                }

                // decrypt input salt_enc to get salt1 or (salt1 || salt2)
                let salts = syscall!(self.trussed.decrypt(
                    Mechanism::Aes256Cbc,
                    kek,
                    &hmac_secret.salt_enc,
                    b"",
                    b"",
                    b""
                ))
                .plaintext
                .ok_or(Error::InvalidOption)?;

                let mut salt_output: Bytes<64> = Bytes::new();

                // output1 = hmac_sha256(credRandom, salt1)
                let output1 =
                    syscall!(self.trussed.sign_hmacsha256(cred_random, &salts[0..32])).signature;

                salt_output.extend_from_slice(&output1).unwrap();

                if salts.len() == 64 {
                    // output2 = hmac_sha256(credRandom, salt2)
                    let output2 =
                        syscall!(self.trussed.sign_hmacsha256(cred_random, &salts[32..64]))
                            .signature;

                    salt_output.extend_from_slice(&output2).unwrap();
                }

                syscall!(self.trussed.delete(cred_random));

                // output_enc = aes256-cbc(sharedSecret, IV=0, output1 || output2)
                let output_enc = syscall!(self.trussed.encrypt(
                    Mechanism::Aes256Cbc,
                    kek,
                    &salt_output,
                    b"",
                    None
                ))
                .ciphertext;

                Some(Bytes::from_slice(&output_enc).unwrap())
            }
            None => None,
        };
        if hmac_secret_output.is_some() {
            Ok(Some(ctap2::get_assertion::ExtensionsOutput {
                hmac_secret: hmac_secret_output,
            }))
        } else {
            Ok(None)
        }
    }

    #[inline(never)]
    #[cfg(feature = "enable-fido-2-1")]
    fn process_large_blob_key_extension(
        &mut self,
        extensions: &ctap2::get_assertion::ExtensionsInput,
        credential: &Credential,
    ) -> Result<Option<Bytes32>> {
        return match &extensions.large_blob_key {
            Some(true) => Ok(self.derive_large_blob_key(credential)?),
            Some(false) => {
                // See https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-largeBlobKey-extension
                // Authenticator authenticatorGetAssertion extension processing 1.
                return Err(Error::InvalidOption);
            }
            None => Ok(None),
        };
    }

    /// If allow_list is some, select the first one that is usable,
    /// and return some(it).
    ///
    /// If allow_list is none, pull applicable credentials, store
    /// in state's credential_heap, and return none
    #[inline(never)]
    fn locate_credentials(
        &mut self,
        rp_id_hash: &Bytes32,
        allow_list: &Option<ctap2::get_assertion::AllowList>,
        uv_performed: bool,
    ) -> Result<()> {
        // validate allowList
        let mut allow_list_len = 0;
        let allowed_credentials = if let Some(allow_list) = allow_list.as_ref() {
            allow_list_len = allow_list.len();
            allow_list
                .into_iter()
                // discard not properly serialized encrypted credentials
                .filter_map(|credential_descriptor| {
                    info!(
                        "GA try from cred id: {}",
                        hex_str!(&credential_descriptor.id),
                    );
                    let cred_maybe =
                        Credential::try_from(self, rp_id_hash, credential_descriptor).ok();
                    info!("cred_maybe: {:?}", &cred_maybe);
                    cred_maybe
                })
                .collect()
        } else {
            CredentialList::new()
        };

        let mut min_heap = MinCredentialHeap::new();

        let allowed_credentials_passed = !allowed_credentials.is_empty();

        if allowed_credentials_passed {
            // "If an allowList is present and is non-empty,
            // locate all denoted credentials present on this authenticator
            // and bound to the specified rpId."
            debug!(
                "allowedList passed with {} creds",
                allowed_credentials.len()
            );
            let mut rk_count = 0;
            let mut applicable_credentials: CredentialList = allowed_credentials
                .into_iter()
                .filter(|credential| match credential.key.clone() {
                    // TODO: should check if wrapped key is valid AEAD
                    // On the other hand, we already decrypted a valid AEAD
                    Key::WrappedKey(_) => true,
                    Key::ResidentKey(key) => {
                        debug!("checking if ResidentKey {:?} exists", &key);
                        let exists = match credential.algorithm {
                            -7 => syscall!(self.trussed.exists(Mechanism::P256, key)).exists,
                            -8 => syscall!(self.trussed.exists(Mechanism::Ed255, key)).exists,
                            -9 => {
                                let exists =
                                    syscall!(self.trussed.exists(Mechanism::Totp, key)).exists;
                                info!("found it");
                                exists
                            }
                            _ => false,
                        };
                        if exists {
                            rk_count += 1;
                        }
                        exists
                    }
                })
                .filter(|credential| {
                    use CredentialProtectionPolicy as Policy;
                    debug!("CredentialProtectionPolicy {:?}", &credential.cred_protect);
                    match credential.cred_protect {
                        None | Some(Policy::Optional) => true,
                        Some(Policy::OptionalWithCredentialIdList) => {
                            allowed_credentials_passed || uv_performed
                        }
                        Some(Policy::Required) => uv_performed,
                    }
                })
                .collect();
            while !applicable_credentials.is_empty() {
                // Store all other applicable credentials in volatile storage and add to our
                // credential heap.
                let credential = applicable_credentials.pop().unwrap();
                let serialized = credential.serialize()?;

                let mut path = [b'0', b'0'];
                format_hex(&[applicable_credentials.len() as u8], &mut path);
                let path = PathBuf::from(&path);
                // let kek = self.state.persistent.key_encryption_key(&mut self.trussed)?;
                // let id = credential.id_using_hash(&mut self.trussed, kek, rp_id_hash)?;
                // let credential_id_hash = self.hash(&id.0.as_ref());

                // let path = rk_path(&rp_id_hash, &credential_id_hash);
                let timestamp_path = TimestampPath {
                    timestamp: credential.creation_time,
                    path: path.clone(),
                    location: Location::Volatile,
                };

                info!("added volatile cred: {:?}", &timestamp_path);
                info!("{}", hex_str!(&serialized));

                try_syscall!(self.trussed.write_file(
                    Location::Volatile,
                    path.clone(),
                    serialized,
                    None,
                ))
                .map_err(|_| Error::KeyStoreFull)?;

                // attempt to read back
                // let data = syscall!(self.trussed.read_file(
                // Location::Volatile,
                // timestamp_path.path.clone(),
                // )).data;
                // crate::Credential::deserialize(&data).unwrap();

                if min_heap.capacity() > min_heap.len() {
                    min_heap.push(timestamp_path).map_err(drop).unwrap();
                } else if timestamp_path.timestamp > min_heap.peek().unwrap().timestamp {
                    min_heap.pop().unwrap();
                    min_heap.push(timestamp_path).map_err(drop).unwrap();
                }
                // If more than one credential was located in step 1 and allowList is present and not empty,
                // select any applicable credential and proceed to step 12. Otherwise, order the credentials
                // by the time when they were created in reverse order.
                // The first credential is the most recent credential that was created.
                if rk_count > 1 {
                    break;
                }
            }
        } else if allow_list_len == 0 {
            // If an allowList is not present,
            // locate all credentials that are present on this authenticator
            // and bound to the specified rpId; sorted by reverse creation time

            // let rp_id_hash = self.hash(rp_id.as_ref());

            //
            // So here's the idea:
            //
            // - credentials can be pretty big
            // - we declare N := MAX_CREDENTIAL_COUNT_IN_LIST in GetInfo
            // - potentially there are more RKs for a given RP (a bit academic ofc)
            //
            // - first, we use a min-heap to keep only the topN credentials:
            //   if our "next" one is larger/later than the min of the heap,
            //   pop this min and push ours
            //
            // - then, we use a max-heap to sort the remaining <=N credentials
            // - these then go into a CredentialList
            // - (we don't need to keep that around even)
            //
            debug!("no allowedList passed");

            // let mut credentials = CredentialList::new();

            let data = syscall!(self.trussed.read_dir_files_first(
                Location::Internal,
                rp_rk_dir(rp_id_hash),
                None,
            ))
            .data;

            let data = match data {
                Some(data) => data,
                None => return Err(Error::NoCredentials),
            };

            let credential = Credential::deserialize(&data).unwrap();

            use CredentialProtectionPolicy as Policy;
            let keep = match credential.cred_protect {
                None | Some(Policy::Optional) => true,
                Some(Policy::OptionalWithCredentialIdList) => {
                    allowed_credentials_passed || uv_performed
                }
                Some(Policy::Required) => uv_performed,
            };

            let kek = self
                .state
                .persistent
                .key_encryption_key(&mut self.trussed)?;
            if keep {
                let id = credential.id_using_hash(&mut self.trussed, kek, rp_id_hash)?;
                let credential_id_hash = self.hash(id.0.as_ref());

                let timestamp_path = TimestampPath {
                    timestamp: credential.creation_time,
                    path: rk_path(rp_id_hash, &credential_id_hash),
                    location: Location::Internal,
                };

                min_heap.push(timestamp_path).map_err(drop).unwrap();
                // info!("first: {:?}", &self.hash(&id.0));
            }

            loop {
                let data = syscall!(self.trussed.read_dir_files_next()).data;
                let data = match data {
                    Some(data) => data,
                    None => break,
                };

                let credential = Credential::deserialize(&data).unwrap();

                let keep = match credential.cred_protect {
                    None | Some(Policy::Optional) => true,
                    Some(Policy::OptionalWithCredentialIdList) => {
                        allowed_credentials_passed || uv_performed
                    }
                    Some(Policy::Required) => uv_performed,
                };

                if keep {
                    let id = credential.id_using_hash(&mut self.trussed, kek, rp_id_hash)?;
                    let credential_id_hash = self.hash(id.0.as_ref());

                    let timestamp_path = TimestampPath {
                        timestamp: credential.creation_time,
                        path: rk_path(rp_id_hash, &credential_id_hash),
                        location: Location::Internal,
                    };

                    if min_heap.capacity() > min_heap.len() {
                        min_heap.push(timestamp_path).map_err(drop).unwrap();
                    } else if timestamp_path.timestamp > min_heap.peek().unwrap().timestamp {
                        min_heap.pop().unwrap();
                        min_heap.push(timestamp_path).map_err(drop).unwrap();
                    }
                }
            }
        };

        // "If no applicable credentials were found, return CTAP2_ERR_NO_CREDENTIALS"
        if min_heap.is_empty() {
            return Err(Error::NoCredentials);
        }

        // now sort them
        self.state.runtime.free_credential_heap(&mut self.trussed);
        let max_heap = self.state.runtime.credential_heap();
        while !min_heap.is_empty() {
            max_heap
                .push(min_heap.pop().unwrap())
                .map_err(drop)
                .unwrap();
        }

        Ok(())
    }
}
