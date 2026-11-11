//! Deploying the registry through LEE's program loader: the guest's user ELF goes up in segments,
//! then a header at the program account points at them. The header's key is the program's
//! upgrade authority, so whoever holds it can redeploy at the same program account, and every
//! log stays where it is.

use account_registry_methods::{ACCOUNT_REGISTRY_ELF, ACCOUNT_REGISTRY_ID};
use lee::{AccountId, PrivateKey, ProgramShardSelector};
use lee_core::program::{PROGRAM_LOADER_ACCOUNT_ID, PdaSeed, ProgramHeader, ProgramSegment};
use program_loader_core::{Instruction, MAX_PROGRAM_SEGMENTS, MAX_SEGMENT_DATA_LEN};

use crate::{LOADER_GAS_LIMIT, LezAccountRegError, Registry, poll, signer_id};

/// The payer `./run-local-sequencer` funds at genesis. Never use it on a real network.
pub const LOCAL_PAYER_KEY: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";

/// The program account key the example deploys under on a local sequencer.
pub const LOCAL_PROGRAM_KEY: &str =
    "2222222222222222222222222222222222222222222222222222222222222222";

/// [`LOCAL_PAYER_KEY`]'s account, as `./run-local-sequencer` names it in the genesis config.
pub const LOCAL_PAYER_ID: &str = "78Skt7EQTvVwfWVYnA1XMjghv3aUR1V5wgQAfVLKJZG5";

impl Registry {
    /// Deploys the registry program at the program account this registry was connected to, whose
    /// key is `header`. Upgrades it in place if an older build is there, and does nothing if this
    /// build is. The deployment stays upgradable by `header`.
    pub fn deploy(&self, header: &PrivateKey) -> Result<(), LezAccountRegError> {
        if signer_id(header) != self.program {
            return Err(LezAccountRegError::Deploy(
                "the header key does not sign for this registry's program account".into(),
            ));
        }
        let existing = self.deployed()?;
        if existing
            .as_ref()
            .is_some_and(|deployed| deployed.image_id == ACCOUNT_REGISTRY_ID)
        {
            return Ok(());
        }
        if existing.as_ref().is_some_and(|deployed| deployed.immutable) {
            return Err(LezAccountRegError::Deploy(
                "another build is deployed there, immutably".into(),
            ));
        }

        let segments = self.upload_segments()?;
        let instruction = if existing.is_some() {
            Instruction::UpdateHeader {
                first_segment: segments[0],
                immutable: false,
            }
        } else {
            Instruction::CreateHeader {
                first_segment: segments[0],
                immutable: false,
            }
        };
        let selectors = [self.program]
            .into_iter()
            .chain(segments.iter().copied())
            .map(loader_shard)
            .collect();
        self.send(
            PROGRAM_LOADER_ACCOUNT_ID,
            selectors,
            &[header],
            instruction,
            LOADER_GAS_LIMIT,
        )?;

        poll(|| {
            Ok(self
                .deployed()?
                .is_some_and(|deployed| deployed.image_id == ACCOUNT_REGISTRY_ID))
        })
    }

    /// The header at the program account, if anything is deployed there. Fails if the account
    /// holds other loader data, such as a segment: a header can never be created over it.
    fn deployed(&self) -> Result<Option<ProgramHeader>, LezAccountRegError> {
        let account = self.rpc.get_account(self.program)?;
        let shard = account.data.shard(PROGRAM_LOADER_ACCOUNT_ID);
        if shard.is_empty() {
            return Ok(None);
        }
        ProgramHeader::from_bytes(shard.as_ref())
            .map(Some)
            .ok_or_else(|| {
                LezAccountRegError::Deploy(
                    "the program account holds loader data that is not a header".into(),
                )
            })
    }

    /// Writes this build's user ELF as a segment chain, tail first, each waiting for the next to
    /// land, and returns the chain head first. A segment already written with the same contents
    /// is kept, so a deploy that stopped half way resumes; one with other contents is an error.
    fn upload_segments(&self) -> Result<Vec<AccountId>, LezAccountRegError> {
        let binary = risc0_binfmt::ProgramBinary::decode(ACCOUNT_REGISTRY_ELF)
            .map_err(|error| LezAccountRegError::Deploy(error.to_string()))?;
        if binary.kernel_elf != risc0_zkos_v1compat::V1COMPAT_ELF {
            return Err(LezAccountRegError::Deploy(
                "the guest is not built with LEE's default kernel".into(),
            ));
        }
        let chunks: Vec<&[u8]> = binary.user_elf.chunks(MAX_SEGMENT_DATA_LEN).collect();
        if chunks.len() > MAX_PROGRAM_SEGMENTS {
            return Err(LezAccountRegError::Deploy(format!(
                "the guest needs {} segments, the loader takes {MAX_PROGRAM_SEGMENTS}",
                chunks.len()
            )));
        }
        let segments: Vec<AccountId> = (0..chunks.len())
            .map(|index| self.segment_account(index))
            .collect();

        for (index, chunk) in chunks.iter().enumerate().rev() {
            let next_segment = segments.get(index + 1).copied();
            let expected = ProgramSegment {
                bytecode: chunk.to_vec(),
                next_segment,
            };
            if self.check_segment(segments[index], &expected)? {
                continue;
            }
            let mut selectors = vec![loader_shard(segments[index])];
            selectors.extend(next_segment.map(loader_shard));
            let instruction = Instruction::WriteSegment {
                bytecode: expected.bytecode.clone(),
                next_segment,
            };
            self.send(
                PROGRAM_LOADER_ACCOUNT_ID,
                selectors,
                &[],
                instruction,
                LOADER_GAS_LIMIT,
            )?;
            poll(|| self.check_segment(segments[index], &expected))?;
        }
        Ok(segments)
    }

    /// Whether `account` holds `expected`. Fails if it holds any other segment: segments are
    /// immutable and anyone may write one, so a squatted address can never be fixed.
    fn check_segment(
        &self,
        account: AccountId,
        expected: &ProgramSegment,
    ) -> Result<bool, LezAccountRegError> {
        match self.segment(account)? {
            None => Ok(false),
            Some(segment) if &segment == expected => Ok(true),
            Some(_) => Err(LezAccountRegError::Deploy(format!(
                "segment {account} holds another program's bytecode"
            ))),
        }
    }

    fn segment(&self, account: AccountId) -> Result<Option<ProgramSegment>, LezAccountRegError> {
        let account = self.rpc.get_account(account)?;
        Ok(ProgramSegment::from_bytes(
            account.data.shard(PROGRAM_LOADER_ACCOUNT_ID).as_ref(),
        ))
    }

    /// Where segment `index` of this build lives: derived from the program account and the image,
    /// so each build gets fresh segments and a retry finds the ones it already wrote.
    fn segment_account(&self, index: usize) -> AccountId {
        let mut seed = [0u8; 32];
        for (chunk, word) in seed
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip(ACCOUNT_REGISTRY_ID)
        {
            *chunk = word.to_le_bytes();
        }
        seed[31] ^= u8::try_from(index).expect("at most MAX_PROGRAM_SEGMENTS segments");
        AccountId::for_public_pda(&self.program, &PdaSeed::new(seed))
    }
}

fn loader_shard(account: AccountId) -> ProgramShardSelector {
    ProgramShardSelector::new(account, PROGRAM_LOADER_ACCOUNT_ID)
}

#[cfg(test)]
mod tests {
    use lee::PrivateKey;

    use super::*;

    #[test]
    fn the_local_payer_id_matches_its_key() {
        let key: PrivateKey = LOCAL_PAYER_KEY.parse().unwrap();
        assert_eq!(LOCAL_PAYER_ID, signer_id(&key).to_string());
    }
}
