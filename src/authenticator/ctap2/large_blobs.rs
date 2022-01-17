use core::convert::TryFrom;

use ctap2::large_blobs::{Parameters, Response};
use ctap_types::{
    authenticator::{ctap2, Error},
    Bytes,
    Bytes32,
};
use trussed::{
    client,
    syscall,
    types::{KeySerialization, Location, Mechanism},
};

use super::{Authenticator, UserPresence};
use crate::{
    authenticator::{
        credential::{Credential, Key},
        SupportedAlgorithm,
    },
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
    pub(super) fn large_blobs(&mut self, parameters: &Parameters) -> Result<Response> {
        // Sequence according to https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#largeBlobsRW.

        // 1. Is not handled here, but should be handled by the routine parsing the CBOR map.

        // 2./3. Only one of get or set may be `None` and only one must be set.
        if (parameters.get.is_none() && parameters.set.is_none())
            || (parameters.get.is_some() && parameters.set.is_some())
        {
            return Err(Error::InvalidParameter);
        }

        // 4. get is set.
        if let Some(num_get_bytes) = parameters.get {
            // 4.1. length must not be set.
            // 4.2. pinUvAuthParam and pinUvAuthProtocol must not be set.
            if parameters.length.is_some()
                || parameters.pin_uv_auth_param.is_some()
                || parameters.pin_uv_auth_protocol.is_some()
            {
                return Err(Error::InvalidParameter);
            }

            // 4.3. get <= maxFragmentLength
            if num_get_bytes > ctap_types::sizes::LARGE_BLOB_MAX_FRAGMENT_LENGTH as u32 {
                return Err(Error::InvalidLength);
            }

            // 4.4. offset must be in range of the current large blob size.
            let large_blob = self.state.persistent.large_blob();
            if parameters.offset as usize > large_blob.len() {
                return Err(Error::InvalidParameter);
            }

            // 4.5. return the requested data. Make sure to only return as much data as is available in our large blob.
            // Thus, if offset == large_blob.len() the returned array should be empty.
            let end = core::cmp::min(
                (parameters.offset + num_get_bytes) as usize,
                large_blob.len(),
            );
            let range = (parameters.offset as usize)..end;
            Ok(Response {
                config: Bytes::from_slice(&large_blob[range]).unwrap(),
            })
        } else if let Some(write_bytes) = &parameters.set {
            let byte_len = write_bytes.len();
            // 5.1. length of set <= maxFragmentLength
            if byte_len > ctap_types::sizes::LARGE_BLOB_MAX_FRAGMENT_LENGTH {
                return Err(Error::InvalidLength);
            }

            // 5.2. Writing from the beginning.
            if parameters.offset == 0 {
                // 5.2.1. The length must be transmitted in that case.
                if parameters.length.is_none() {
                    return Err(Error::InvalidParameter);
                }

                let total_len = parameters.length.unwrap() as usize;

                // 5.2.2. check capacity of large blobs
                if total_len > self.state.runtime.large_blob_buffer.capacity() {
                    return Err(Error::LargeBlobStorageFull);
                }
                // 5.2.3. Must be at least 17 bytes for the potentially empty array
                // (1 byte empty CBOR empty array + 128 bit SHA256 truncated hash).
                if total_len < 17 {
                    return Err(Error::InvalidParameter);
                }
                // 5.2.4. The length we are expecting.
                self.state.runtime.large_blob_expected_length = total_len;
                // 5.2.5. The offset of the next write request we are expecting.
                self.state.runtime.large_blob_expected_next_offset = 0;
            } else {
                // 5.3. A consecutive write request.
                // 5.3.1 No length must be set.
                if parameters.length.is_some() {
                    return Err(Error::InvalidParameter);
                }
            }

            // 5.4. The offset must match the expected offset.
            if parameters.offset != self.state.runtime.large_blob_expected_next_offset {
                return Err(Error::InvalidSeq);
            }

            // TODO: 5.5. pin auth

            // 5.6. We do not want to overshoot.
            if byte_len + parameters.offset as usize > self.state.runtime.large_blob_expected_length
            {
                return Err(Error::InvalidParameter);
            }

            let buffer = &mut self.state.runtime.large_blob_buffer;
            // 5.7. prepare a buffer to receive a new buffer if offset == 0.
            if parameters.offset == 0 {
                buffer.clear();
            }
            // 5.8. append to the existing buffer.
            buffer
                .extend_from_slice(&write_bytes[..])
                .map_err(|_| Error::Other)?;
            // 5.9. update the next expected offset to the size of the buffer.
            self.state.runtime.large_blob_expected_next_offset = buffer.len() as u32;

            // 5.10. received all bytes
            if buffer.len() == self.state.runtime.large_blob_expected_length {
                // 5.10.1. check integry with SHA256.
                let truncate_sha256_len = 16;
                let cbor_array_without_hash_len =
                    self.state.runtime.large_blob_expected_length - truncate_sha256_len;
                let cbor_array_without_hash = &buffer[..cbor_array_without_hash_len];
                let hash = &buffer[cbor_array_without_hash_len..];
                let calculated_hash: Bytes32 =
                    syscall!(self.trussed.hash_sha256(cbor_array_without_hash))
                        .hash
                        .to_bytes()
                        .map_err(|_| Error::Other)?;
                if hash != &calculated_hash[..truncate_sha256_len] {
                    return Err(Error::IntegrityFailure);
                }

                // 5.10.2. write the data.
                self.state
                    .persistent
                    .set_large_blob(&mut self.trussed, buffer)?;
                buffer.clear();
            }
            // 5.10.3 and 5.11.2. empty response, conditionally awaiting further writes.
            Ok(Response {
                config: Bytes::new(),
            })
        } else {
            unreachable!();
        }
    }

    /// This function derives a 32 bytes large blob key from a given credential, if large blob key is enabled for that credential.
    ///
    /// *Note:* The key is not stored on the authenticator.
    pub(crate) fn derive_large_blob_key(
        &mut self,
        credential: &Credential,
    ) -> Result<Option<Bytes32>> {
        let is_credential_with_large_blob_key =
            credential.large_blob_key.is_some() && credential.large_blob_key.unwrap() == true;
        match is_credential_with_large_blob_key {
            false => Ok(None),
            true => match credential.key {
                Key::ResidentKey(private_key) => {
                    // Derive a key from the credentials private key.
                    // The standard says, that this key may not be derived in another way (e.g. hmac-secret-extension).
                    // So we chose the HKDF with a input specifically tied to this extension:
                    // HMAC-SHA256(HMAC-SHA256(extraction salt = "largeBlobKey", crendential private key), CTXinfo || [0])
                    let large_blob_key_derived_xtr = syscall!(self.trussed.derive_key(
                        Mechanism::HmacSha256,
                        private_key,
                        Some(Bytes::from_slice("largeBlobKey".as_ref()).unwrap()),
                        trussed::types::StorageAttributes::new()
                            .set_persistence(Location::Volatile)
                    ))
                    .key;

                    // Derive the public key.
                    let algorithm = SupportedAlgorithm::try_from(credential.algorithm)?;
                    let serialized_public_key = match algorithm {
                        SupportedAlgorithm::P256 => {
                            let public_key = syscall!(self
                                .trussed
                                .derive_p256_public_key(private_key, Location::Volatile))
                            .key;
                            let serialized_public_key = syscall!(self.trussed.serialize_key(
                                Mechanism::P256,
                                public_key,
                                KeySerialization::Raw,
                            ))
                            .serialized_key;
                            syscall!(self.trussed.delete(public_key));
                            serialized_public_key
                        }
                        SupportedAlgorithm::Ed25519 => {
                            let public_key = syscall!(self
                                .trussed
                                .derive_ed255_public_key(private_key, Location::Volatile))
                            .key;
                            let serialized_public_key = syscall!(self
                                .trussed
                                .serialize_ed255_key(public_key, KeySerialization::Raw))
                            .serialized_key;
                            syscall!(self.trussed.delete(public_key));
                            serialized_public_key
                        }
                        _ => unimplemented!(),
                    };

                    // Now, sign the context info = public key.
                    let large_blob_key = syscall!(self
                        .trussed
                        .sign_hmacsha256(large_blob_key_derived_xtr, &serialized_public_key))
                    .signature
                    .to_bytes()
                    .unwrap();

                    Ok(Some(large_blob_key))
                }
                // Should never happen, as large_blob_key is only set to true during creation
                // when the key is resident.
                _ => unreachable!(),
            },
        }
    }
}
