//! Typed instance storage accessors (Soroban `#[contracttype]` key pattern).

use soroban_sdk::{Env, IntoVal, TryFromVal, Val};

use crate::StorageKey;

/// Minimum ledgers to extend instance storage TTL when bumped.
pub const MIN_TTL: u32 = 17_280;
/// Maximum target TTL for instance storage (Soroban caps extension at this bound).
pub const MAX_TTL: u32 = 34_560;

/// Bump instance storage TTL so contract state does not expire on Mainnet.
pub fn extend_instance_ttl(env: &Env) {
    env.storage().instance().extend_ttl(MIN_TTL, MAX_TTL);
}

/// Read a value from instance storage.
pub fn instance_get<T>(env: &Env, key: &StorageKey) -> Option<T>
where
    T: TryFromVal<Env, Val> + Clone,
{
    env.storage().instance().get(key)
}

/// Write a value to instance storage.
pub fn instance_set<T>(env: &Env, key: &StorageKey, value: &T)
where
    T: IntoVal<Env, Val> + Clone,
{
    env.storage().instance().set(key, value);
}

/// Returns whether instance storage contains `key`.
pub fn instance_has(env: &Env, key: &StorageKey) -> bool {
    env.storage().instance().has(key)
}
