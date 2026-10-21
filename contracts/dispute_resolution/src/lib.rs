#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

mod error;
pub use error::DisputeError;

#[cfg(test)]
mod test_dispute_error;

/// Persistent TTL threshold and extension, in ledgers. Both are below the
/// network maximum entry TTL (`6_311_520` ledgers) so `extend_ttl` is always
/// valid: ~30 days before an entry is a candidate for archival, extended to
/// ~180 days on every create, read and update.
const PERSISTENT_TTL_THRESHOLD: u32 = 518_400;
const PERSISTENT_TTL_EXTEND_TO: u32 = 3_110_400;

/// Instance TTL threshold and extension, in ledgers.
///
/// The instance entry holds the dispute counter only, but once it is archived
/// every call fails — so every entry point extends it.
const INSTANCE_TTL_THRESHOLD: u32 = 518_400;
const INSTANCE_TTL_EXTEND_TO: u32 = 3_110_400;

/// Storage keys.
///
/// Every key is namespaced: dispute records are no longer stored under a raw
/// `u64`, so a dispute id can never collide with another contract key.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    /// Monotonically increasing id of the next dispute.
    DisputeCounter,
    /// A dispute record, keyed by its id.
    Dispute(u64),
}

/// Lifecycle state of a dispute.
///
/// Invariants:
/// - A dispute starts in `Open`.
/// - `Open` → `Resolved` via `resolve()` (resolver only).
/// - `Open` or `Resolved` → `Closed`  via `close()` (resolver only).
/// - Once `Closed` the record is terminal; no further transitions are allowed.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DisputeStatus {
    Open,
    Resolved,
    Closed,
}

/// On-ledger dispute record.
///
/// Stored in persistent storage under [`DataKey::Dispute`]. Fields describing
/// the dispute (`id`, `creator`, `resolver`) are written once at creation and
/// never change; only `status` moves through the guarded entry points.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Dispute {
    pub id: u64,
    pub status: DisputeStatus,
    pub resolver: Address,
    pub creator: Address,
}

fn bump_instance_ttl(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);
}

fn bump_dispute_ttl(env: &Env, id: u64) {
    env.storage().persistent().extend_ttl(
        &DataKey::Dispute(id),
        PERSISTENT_TTL_THRESHOLD,
        PERSISTENT_TTL_EXTEND_TO,
    );
}

fn store_dispute(env: &Env, dispute: &Dispute) {
    env.storage()
        .persistent()
        .set(&DataKey::Dispute(dispute.id), dispute);
    bump_dispute_ttl(env, dispute.id);
}

#[contract]
pub struct DisputeResolutionContract;

#[contractimpl]
impl DisputeResolutionContract {
    // -----------------------------------------------------------------------
    // Write entry points
    // -----------------------------------------------------------------------

    /// Create a new dispute and return its unique `u64` ID.
    ///
    /// `creator` must authorize the call, so disputes are attributable and
    /// spam creation costs the creator a signature. Ids come from a
    /// monotonically increasing counter (0, 1, 2, …) and are therefore
    /// sequential and enumerable.
    ///
    /// The `resolver` is the only address that may subsequently call
    /// `resolve()` or `close()`.
    ///
    /// A record is never overwritten: the counter guarantees a fresh id and a
    /// defensive `has` check rejects an occupied key.
    ///
    /// # Events
    /// Publishes `("created", id)` → `(creator, resolver)` on success.
    pub fn create_dispute(env: Env, creator: Address, resolver: Address) -> u64 {
        bump_instance_ttl(&env);
        creator.require_auth();

        let id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::DisputeCounter)
            .unwrap_or(0);

        // A record is never overwritten: the counter guarantees a fresh id, and
        // the defensive check makes an overwrite impossible even if state were
        // tampered with.
        if env.storage().persistent().has(&DataKey::Dispute(id)) {
            panic!("dispute id already exists");
        }

        let dispute = Dispute {
            id,
            status: DisputeStatus::Open,
            resolver: resolver.clone(),
            creator: creator.clone(),
        };
        store_dispute(&env, &dispute);

        let next_id = id.checked_add(1).expect("dispute id overflow");
        env.storage()
            .instance()
            .set(&DataKey::DisputeCounter, &next_id);

        env.events().publish(
            (symbol_short!("created"), id),
            (creator, resolver),
        );

        id
    }

    /// Mark an `Open` dispute as `Resolved`.
    ///
    /// Only the named `resolver` may call this. A dispute that is already
    /// `Resolved` or `Closed` cannot be re-resolved.
    ///
    /// The resolver check runs *before* the status check, so a stranger always
    /// receives `Unauthorized` — never `AlreadyClosed` — and cannot learn a
    /// dispute's state by probing it.
    ///
    /// # Errors
    /// - `DisputeNotFound`  – no dispute exists with the given `id`.
    /// - `Unauthorized`     – `caller` is not the dispute's resolver.
    /// - `AlreadyClosed`    – the dispute is already in a terminal state
    ///                        (`Resolved` or `Closed`).
    ///
    /// # Events
    /// Publishes `("resolved", id)` → `("by", caller)` on success.
    pub fn resolve(env: Env, caller: Address, id: u64) -> Result<(), DisputeError> {
        bump_instance_ttl(&env);
        caller.require_auth();

        let mut dispute = Self::load(&env, id)?;

        // Authorization before state disclosure.
        if caller != dispute.resolver {
            return Err(DisputeError::Unauthorized);
        }

        // Terminal-state guard: both Resolved and Closed are terminal for this
        // transition.
        if dispute.status != DisputeStatus::Open {
            return Err(DisputeError::AlreadyClosed);
        }

        dispute.status = DisputeStatus::Resolved;
        store_dispute(&env, &dispute);

        env.events().publish(
            (symbol_short!("resolved"), id),
            (symbol_short!("by"), caller),
        );

        Ok(())
    }

    /// Mark a dispute as `Closed` (terminal state).
    ///
    /// Accepts disputes in either `Open` or `Resolved` state so that callers
    /// can skip the intermediate resolve step if needed. Once `Closed` the
    /// record is immutable.
    ///
    /// The resolver check runs *before* the status check, so a stranger always
    /// receives `Unauthorized`.
    ///
    /// # Errors
    /// - `DisputeNotFound`  – no dispute exists with the given `id`.
    /// - `Unauthorized`     – `caller` is not the dispute's resolver.
    /// - `AlreadyClosed`    – the dispute is already `Closed`.
    ///
    /// # Events
    /// Publishes `("closed", id)` → `("by", caller)` on success.
    pub fn close(env: Env, caller: Address, id: u64) -> Result<(), DisputeError> {
        bump_instance_ttl(&env);
        caller.require_auth();

        let mut dispute = Self::load(&env, id)?;

        // Authorization before state disclosure.
        if caller != dispute.resolver {
            return Err(DisputeError::Unauthorized);
        }

        // Invariant: no double-close.
        if dispute.status == DisputeStatus::Closed {
            return Err(DisputeError::AlreadyClosed);
        }

        dispute.status = DisputeStatus::Closed;
        store_dispute(&env, &dispute);

        env.events()
            .publish((symbol_short!("closed"), id), (symbol_short!("by"), caller));

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Read entry points
    // -----------------------------------------------------------------------

    /// Fetch a dispute by ID.
    ///
    /// # Errors
    /// - `DisputeNotFound` – no dispute exists with the given `id`.
    pub fn get_dispute(env: Env, id: u64) -> Result<Dispute, DisputeError> {
        Self::load(&env, id)
    }

    /// Fetch the id that the next `create_dispute` will use.
    pub fn get_dispute_count(env: Env) -> u64 {
        bump_instance_ttl(&env);
        env.storage()
            .instance()
            .get(&DataKey::DisputeCounter)
            .unwrap_or(0)
    }

    /// Load a dispute from persistent storage and extend its TTL.
    fn load(env: &Env, id: u64) -> Result<Dispute, DisputeError> {
        bump_instance_ttl(env);
        let dispute = env
            .storage()
            .persistent()
            .get(&DataKey::Dispute(id))
            .ok_or(DisputeError::DisputeNotFound)?;
        bump_dispute_ttl(env, id);
        Ok(dispute)
    }
}
