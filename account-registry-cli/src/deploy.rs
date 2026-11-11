//! Deploying the registry through LEE's program loader: the guest's user ELF goes up in segments,
//! then a header at the program account points at them. The header's key is the program's
//! upgrade authority, so whoever holds it can redeploy at the same program account, and every
//! log stays where it is.

use account_registry_client::{AccountId, PrivateKey, ProgramShardSelector, Registry, signer_id};
use account_registry_methods::{ACCOUNT_REGISTRY_ELF, ACCOUNT_REGISTRY_ID};
use lee_core::program::{PROGRAM_LOADER_ACCOUNT_ID, PdaSeed, ProgramHeader, ProgramSegment};
use program_loader_core::{Instruction, MAX_PROGRAM_SEGMENTS, MAX_SEGMENT_DATA_LEN};

use crate::{Error, wait};

/// Execution gas reserved for a program loader transaction, which runs natively and meters none.
const LOADER_GAS_LIMIT: u64 = 1_000_000;

/// Deploys the registry program at the program account `registry` was connected to, whose
/// key is `header`. Upgrades it in place if an older build is there, and does nothing if this
/// build is. The deployment stays upgradable by `header`.
pub fn deploy(registry: &Registry, header: &PrivateKey) -> Result<(), Error> {
    if signer_id(header) != registry.program() {
        return Err(Error::Deploy(
            "the header key does not sign for this registry's program account".into(),
        ));
    }
    let existing = deployed(registry)?;
    if existing
        .as_ref()
        .is_some_and(|deployed| deployed.image_id == ACCOUNT_REGISTRY_ID)
    {
        return Ok(());
    }
    if existing.as_ref().is_some_and(|deployed| deployed.immutable) {
        return Err(Error::Deploy(
            "another build is deployed there, immutably".into(),
        ));
    }

    let segments = upload_segments(registry)?;
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
    let selectors = [registry.program()]
        .into_iter()
        .chain(segments.iter().copied())
        .map(loader_shard)
        .collect();
    registry.send(
        PROGRAM_LOADER_ACCOUNT_ID,
        selectors,
        &[header],
        instruction,
        LOADER_GAS_LIMIT,
    )?;

    wait(
        || Ok(deployed(registry)?.is_some_and(|deployed| deployed.image_id == ACCOUNT_REGISTRY_ID)),
    )
}

/// The header at the program account, if anything is deployed there. Fails if the account
/// holds other loader data, such as a segment: a header can never be created over it.
fn deployed(registry: &Registry) -> Result<Option<ProgramHeader>, Error> {
    let account = registry.account(registry.program())?;
    let shard = account.data.shard(PROGRAM_LOADER_ACCOUNT_ID);
    if shard.is_empty() {
        return Ok(None);
    }
    ProgramHeader::from_bytes(shard.as_ref())
        .map(Some)
        .ok_or_else(|| {
            Error::Deploy("the program account holds loader data that is not a header".into())
        })
}

/// Writes this build's user ELF as a segment chain, tail first, each waiting for the next to
/// land, and returns the chain head first. A segment already written with the same contents
/// is kept, so a deploy that stopped half way resumes; one with other contents is an error.
fn upload_segments(registry: &Registry) -> Result<Vec<AccountId>, Error> {
    let binary = risc0_binfmt::ProgramBinary::decode(ACCOUNT_REGISTRY_ELF)
        .map_err(|error| Error::Deploy(error.to_string()))?;
    if binary.kernel_elf != risc0_zkos_v1compat::V1COMPAT_ELF {
        return Err(Error::Deploy(
            "the guest is not built with LEE's default kernel".into(),
        ));
    }
    let chunks: Vec<&[u8]> = binary.user_elf.chunks(MAX_SEGMENT_DATA_LEN).collect();
    if chunks.len() > MAX_PROGRAM_SEGMENTS {
        return Err(Error::Deploy(format!(
            "the guest needs {} segments, the loader takes {MAX_PROGRAM_SEGMENTS}",
            chunks.len()
        )));
    }
    let segments: Vec<AccountId> = (0..chunks.len())
        .map(|index| segment_account(registry, index))
        .collect();

    for (index, chunk) in chunks.iter().enumerate().rev() {
        let next_segment = segments.get(index + 1).copied();
        let expected = ProgramSegment {
            bytecode: chunk.to_vec(),
            next_segment,
        };
        if check_segment(registry, segments[index], &expected)? {
            continue;
        }
        let mut selectors = vec![loader_shard(segments[index])];
        selectors.extend(next_segment.map(loader_shard));
        let instruction = Instruction::WriteSegment {
            bytecode: expected.bytecode.clone(),
            next_segment,
        };
        registry.send(
            PROGRAM_LOADER_ACCOUNT_ID,
            selectors,
            &[],
            instruction,
            LOADER_GAS_LIMIT,
        )?;
        wait(|| check_segment(registry, segments[index], &expected))?;
    }
    Ok(segments)
}

/// Whether `account` holds `expected`. Fails if it holds any other segment: segments are
/// immutable and anyone may write one, so a squatted address can never be fixed.
fn check_segment(
    registry: &Registry,
    account: AccountId,
    expected: &ProgramSegment,
) -> Result<bool, Error> {
    match segment(registry, account)? {
        None => Ok(false),
        Some(segment) if &segment == expected => Ok(true),
        Some(_) => Err(Error::Deploy(format!(
            "segment {account} holds another program's bytecode"
        ))),
    }
}

fn segment(registry: &Registry, account: AccountId) -> Result<Option<ProgramSegment>, Error> {
    let account = registry.account(account)?;
    Ok(ProgramSegment::from_bytes(
        account.data.shard(PROGRAM_LOADER_ACCOUNT_ID).as_ref(),
    ))
}

/// Where segment `index` of this build lives: derived from the program account and the image,
/// so each build gets fresh segments and a retry finds the ones it already wrote.
fn segment_account(registry: &Registry, index: usize) -> AccountId {
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
    AccountId::for_public_pda(&registry.program(), &PdaSeed::new(seed))
}

fn loader_shard(account: AccountId) -> ProgramShardSelector {
    ProgramShardSelector::new(account, PROGRAM_LOADER_ACCOUNT_ID)
}
