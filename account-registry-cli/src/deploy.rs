//! Deploying the registry through LEE's program loader: the guest's user ELF goes up in segments,
//! then a header at the program account points at them. The header's key is the program's
//! upgrade authority, so whoever holds it can redeploy at the same program account, and every
//! log stays where it is.
//!
//! The loader writes a segment or a header only to an account that signs for it. Segment keys
//! are derived from the header key, so only its holder can write this deployment's segments.

use std::time::Duration;

use account_registry_client::{AccountId, Actor, PrivateKey, Registry, signer_id};
use account_registry_methods::{ACCOUNT_REGISTRY_ELF, ACCOUNT_REGISTRY_ID};
use lee_core::program::{PROGRAM_LOADER_ACCOUNT_ID, ProgramHeader, ProgramSegment};
use program_loader_core::{Message, build_segments, segment_count};
use sha2::{Digest, Sha256};

use crate::{
    Error,
    progress::{Progress, units},
};

/// Execution gas reserved over the size of the user ELF. The loader runs natively and charges
/// one gas per byte of loader state it reads, at most the whole segment chain.
const LOADER_GAS_MARGIN: u64 = 100_000;

const SEGMENT_KEY_DOMAIN: &[u8] = b"account-registry/segment-key/v1";

/// Deploys the registry program at the program account `registry` was connected to, whose
/// key is `header`. Upgrades it in place if an older build is there, and does nothing if this
/// build is. The deployment stays upgradable by `header`.
///
/// Reports each transaction on stderr. `payer` is the account `registry` pays with, and each
/// transaction gets `timeout` to land.
pub fn deploy(
    registry: &Registry,
    header: &PrivateKey,
    payer: AccountId,
    timeout: Duration,
) -> Result<(), Error> {
    if signer_id(header) != registry.program() {
        return Err(Error::Deploy(
            "the header key does not sign for this registry's program account".into(),
        ));
    }
    let balance = registry.balance(payer)?;
    eprintln!("  payer {payer}, balance {}", units(balance));

    let image = image_hex(ACCOUNT_REGISTRY_ID);
    let existing = deployed(registry)?;
    match &existing {
        Some(deployed) if deployed.image_id == ACCOUNT_REGISTRY_ID => {
            eprintln!("  on chain: this build, image {image}; nothing to do");
            return Ok(());
        }
        Some(deployed) if deployed.immutable => {
            return Err(Error::Deploy(
                "another build is deployed there, immutably".into(),
            ));
        }
        Some(deployed) => eprintln!(
            "  on chain: image {}; upgrading to image {image}",
            image_hex(deployed.image_id)
        ),
        None => eprintln!("  on chain: nothing; deploying image {image}"),
    }

    let user_elf = user_elf()?;
    let count = segment_count(&user_elf);
    eprintln!(
        "  this build: {count} segments, {} bytes",
        units(user_elf.len() as u128)
    );
    let gas_limit = u64::try_from(user_elf.len())
        .expect("an ELF's size fits in u64")
        .saturating_add(LOADER_GAS_MARGIN);

    let mut progress = Progress::new(registry, payer, timeout, count + 1)?;
    let first_segment = upload_segments(registry, header, &user_elf, gas_limit, &mut progress)?;
    let message = if existing.is_some() {
        Message::UpdateHeader {
            first_segment,
            immutable: false,
        }
    } else {
        Message::CreateHeader {
            first_segment,
            immutable: false,
        }
    };
    let to = loader_actor(registry.program());
    progress.submit(
        "header",
        || registry.send(to, &[header], vec![], message, gas_limit),
        || Ok(deployed(registry)?.is_some_and(|deployed| deployed.image_id == ACCOUNT_REGISTRY_ID)),
    )?;
    progress.finish()
}

/// The header at the program account, if anything is deployed there. Fails if the account
/// holds other loader data, such as a segment: a header can never be created over it.
fn deployed(registry: &Registry) -> Result<Option<ProgramHeader>, Error> {
    let account = registry.account(registry.program())?;
    let state = account.data.actor_state(PROGRAM_LOADER_ACCOUNT_ID);
    if state.is_empty() {
        return Ok(None);
    }
    ProgramHeader::from_loader_actor_state(state)
        .map(Some)
        .ok_or_else(|| {
            Error::Deploy("the program account holds loader data that is not a header".into())
        })
}

/// This build's user ELF, the part of the guest binary the loader stores.
fn user_elf() -> Result<Vec<u8>, Error> {
    let binary = risc0_binfmt::ProgramBinary::decode(ACCOUNT_REGISTRY_ELF)
        .map_err(|error| Error::Deploy(error.to_string()))?;
    if binary.kernel_elf != risc0_zkos_v1compat::V1COMPAT_ELF {
        return Err(Error::Deploy(
            "the guest is not built with LEE's default kernel".into(),
        ));
    }
    Ok(binary.user_elf.to_vec())
}

/// Writes `user_elf` as a segment chain, tail first, each waiting for the next to land, and
/// returns the first segment's account. A segment already written is kept, so a deploy that
/// stopped half way resumes.
fn upload_segments(
    registry: &Registry,
    header: &PrivateKey,
    user_elf: &[u8],
    gas_limit: u64,
    progress: &mut Progress,
) -> Result<AccountId, Error> {
    let keys = (0..segment_count(user_elf))
        .map(|index| segment_key(header, index))
        .collect::<Result<Vec<_>, _>>()?;
    let accounts: Vec<AccountId> = keys.iter().map(signer_id).collect();
    let segments =
        build_segments(user_elf, &accounts).map_err(|error| Error::Deploy(error.to_string()))?;
    let first = *accounts
        .first()
        .ok_or_else(|| Error::Deploy("the guest's user ELF is empty".into()))?;

    let count = segments.len();
    let chain = keys.iter().zip(accounts).zip(segments).enumerate().rev();
    for (index, ((key, account), segment)) in chain {
        let what = format!(
            "segment {} of {count}, {} bytes",
            index + 1,
            units(segment.bytecode.len() as u128)
        );
        if check_segment(registry, account, &segment)? {
            progress.skip(&what);
            continue;
        }
        let message = Message::WriteSegment {
            bytecode: segment.bytecode.clone(),
            next_segment: segment.next_segment,
        };
        progress.submit(
            &what,
            || registry.send(loader_actor(account), &[key], vec![], message, gas_limit),
            || check_segment(registry, account, &segment),
        )?;
    }
    Ok(first)
}

/// Whether `account` holds `expected`. Fails if it holds any other loader data: segments are
/// immutable, so the account could never hold this one.
fn check_segment(
    registry: &Registry,
    account: AccountId,
    expected: &ProgramSegment,
) -> Result<bool, Error> {
    let stored = registry.account(account)?;
    let state = stored.data.actor_state(PROGRAM_LOADER_ACCOUNT_ID);
    if state.is_empty() {
        return Ok(false);
    }
    if ProgramSegment::from_loader_actor_state(state).as_ref() == Some(expected) {
        return Ok(true);
    }
    Err(Error::Deploy(format!(
        "segment account {account} holds other loader data"
    )))
}

/// The key of segment `index` of this build under `header`: derived from the header key and the
/// image, so each build gets fresh segment accounts and a retry finds the ones it already wrote.
fn segment_key(header: &PrivateKey, index: usize) -> Result<PrivateKey, Error> {
    let mut hasher = Sha256::new();
    hasher.update(SEGMENT_KEY_DOMAIN);
    hasher.update(header.value());
    for word in ACCOUNT_REGISTRY_ID {
        hasher.update(word.to_le_bytes());
    }
    hasher.update(
        u64::try_from(index)
            .expect("an index fits in u64")
            .to_le_bytes(),
    );
    PrivateKey::try_new(hasher.finalize().into())
        .map_err(|_| Error::Deploy(format!("no valid key derives for segment {index}")))
}

fn loader_actor(account: AccountId) -> Actor {
    Actor::new(account, PROGRAM_LOADER_ACCOUNT_ID)
}

/// An image ID as its digest in hex, shortened to tell two builds apart.
fn image_hex(image: [u32; 8]) -> String {
    let hex: String = image
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("{}…{}", &hex[..8], &hex[56..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_keys_differ_by_index_and_header() {
        let header = PrivateKey::try_new([5; 32]).unwrap();
        let other = PrivateKey::try_new([6; 32]).unwrap();
        let key = |header, index| signer_id(&segment_key(header, index).unwrap());

        assert_eq!(key(&header, 0), key(&header, 0));
        assert_ne!(key(&header, 0), key(&header, 1));
        assert_ne!(key(&header, 0), key(&other, 0));
    }

    #[test]
    fn the_guest_splits_into_a_chain_the_loader_takes() {
        let user_elf = user_elf().unwrap();
        let count = segment_count(&user_elf);
        let accounts = vec![AccountId::new([1; 32]); count];
        assert!(build_segments(&user_elf, &accounts).is_ok(), "{count}");
    }
}
