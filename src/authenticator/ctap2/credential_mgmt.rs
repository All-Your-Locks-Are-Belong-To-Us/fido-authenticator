use ctap_types::{
    authenticator::{ctap2, Error},
    Bytes,
    Bytes32,
};
use littlefs2::path::{Path, PathBuf};
use trussed::{client, syscall, types::Location};

use super::rp_rk_dir;
use crate::{
    authenticator::{
        credential::{Credential, Key},
        credential_management,
        Authenticator,
        UserPresence,
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
    pub(super) fn credential_management(
        &mut self,
        parameters: &ctap2::credential_management::Parameters,
    ) -> Result<ctap2::credential_management::Response> {
        use credential_management as cm;
        use ctap2::credential_management::Subcommand;

        // TODO: I see "failed pinauth" output, but then still continuation...
        self.verify_pin_auth_using_token(parameters)?;

        let mut cred_mgmt = cm::CredentialManagement::new(self);
        let sub_parameters = &parameters.sub_command_params;
        match parameters.sub_command {
            // 0x1
            Subcommand::GetCredsMetadata => cred_mgmt.get_creds_metadata(),

            // 0x2
            Subcommand::EnumerateRpsBegin => cred_mgmt.first_relying_party(),

            // 0x3
            Subcommand::EnumerateRpsGetNextRp => cred_mgmt.next_relying_party(),

            // 0x4
            Subcommand::EnumerateCredentialsBegin => {
                let sub_parameters = sub_parameters.as_ref().ok_or(Error::MissingParameter)?;

                cred_mgmt.first_credential(
                    sub_parameters
                        .rp_id_hash
                        .as_ref()
                        .ok_or(Error::MissingParameter)?,
                )
            }

            // 0x5
            Subcommand::EnumerateCredentialsGetNextCredential => cred_mgmt.next_credential(),

            // 0x6
            Subcommand::DeleteCredential => {
                let sub_parameters = sub_parameters.as_ref().ok_or(Error::MissingParameter)?;

                cred_mgmt.delete_credential(
                    sub_parameters
                        .credential_id
                        .as_ref()
                        .ok_or(Error::MissingParameter)?,
                )
            } // _ => todo!("not implemented yet"),
        }
    }

    pub fn delete_resident_key_by_user_id(
        &mut self,
        rp_id_hash: &Bytes32,
        user_id: &Bytes<64>,
    ) -> Result<()> {
        // Prepare to iterate over all credentials associated to RP.
        let rp_path = rp_rk_dir(rp_id_hash);
        let mut entry = syscall!(self
            .trussed
            .read_dir_first(Location::Internal, rp_path, None,))
        .entry;

        loop {
            info!("this may be an RK: {:?}", &entry);
            let rk_path = match entry {
                // no more RKs left
                // break breaks inner loop here
                None => break,
                Some(entry) => PathBuf::from(entry.path()),
            };

            info!("checking RK {:?} for userId ", &rk_path);
            let credential_data = syscall!(self
                .trussed
                .read_file(Location::Internal, PathBuf::from(rk_path.clone()),))
            .data;
            let credential_maybe = Credential::deserialize(&credential_data);

            if let Ok(old_credential) = credential_maybe {
                if old_credential.user.id == user_id {
                    match old_credential.key {
                        Key::ResidentKey(key) => {
                            info!(":: deleting resident key");
                            syscall!(self.trussed.delete(key));
                        }
                        _ => {
                            warn!(":: WARNING: unexpected server credential in rk.");
                        }
                    }
                    syscall!(self.trussed.remove_file(Location::Internal, rk_path));

                    info!("Overwriting previous rk tied to this userId.");
                    break;
                }
            } else {
                warn_now!("WARNING: Could not read RK.");
            }

            // prepare for next loop iteration
            entry = syscall!(self.trussed.read_dir_next()).entry;
        }

        Ok(())
    }

    pub fn delete_resident_key_by_path(&mut self, rk_path: &Path) -> Result<()> {
        info!("deleting RK {:?}", &rk_path);
        let credential_data = syscall!(self
            .trussed
            .read_file(Location::Internal, PathBuf::from(rk_path),))
        .data;
        let credential_maybe = Credential::deserialize(&credential_data);
        // info!("deleting credential {:?}", &credential);

        if let Ok(credential) = credential_maybe {
            match credential.key {
                Key::ResidentKey(key) => {
                    info!(":: deleting resident key");
                    syscall!(self.trussed.delete(key));
                }
                Key::WrappedKey(_) => {}
            }
        } else {
            // If for some reason there becomes a corrupt credential,
            // we can still at least orphan the key rather then crash.
            info!("Warning!  Orpaning a key.");
        }

        info!(":: deleting RK file {:?} itself", &rk_path);
        syscall!(self
            .trussed
            .remove_file(Location::Internal, PathBuf::from(rk_path),));

        Ok(())
    }
}
