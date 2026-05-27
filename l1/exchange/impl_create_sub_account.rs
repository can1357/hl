//! CreateSubAccount action handler.
//!
//! Handler EA: `0x27E3140`
//! Key callees:
//!   - `l1_sub_account__derive_next_sub_account_user` (`0x36F3C20`)
//!   - `l1_sub_account__create_sub_account` (`0x36F3610`)
//!   - `hash_user_address` (`0x2840FB0`)
//!   - `get_or_create_user_account` (`0x1F849B0`)
//!   - `hashmap_insert_entry_simd` (`0x1F84B30`)
//!   - `l1_sub_account__validate_new_name` (inlined into `0x36F3610`)
//!   - `l1_sub_account__insert_sub_to_master_mapping` (inlined into `0x36F3610`)

use std::collections::BTreeMap;

/// 20-byte user/address identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Address(pub [u8; 20]);

/// Sub-account entry stored per master address.
#[derive(Clone, Debug)]
pub struct SubAccountEntry {
    /// Name of the sub-account (up to 100 bytes).
    pub name: String,
    /// Derived sub-account address.
    pub sub_account: Address,
    /// Master address that owns this sub-account.
    pub master: Address,
}

/// Per-master sub-account tracking.
#[derive(Clone, Debug, Default)]
pub struct SubAccountUserEntries {
    pub entries: Vec<SubAccountEntry>,
}

/// Sub-account module state, reconstructed from exchange offsets.
///
/// The exchange struct stores this at offset +894*16 (field index 894 in the
/// 16-byte-aligned state array). It contains:
/// - `master_to_sub_count`: HashMap<Address, u64> — tracks how many sub-accounts
///   each master has created (used for the dynamic cap check)
/// - `sub_to_master`: HashMap<Address, Address> — reverse mapping from derived
///   sub-account address back to master
/// - `user_entries`: per-master Vec of SubAccountEntry
pub struct SubAccountState {
    pub master_to_sub_count: hashbrown::HashMap<Address, u64>,
    pub sub_to_master: hashbrown::HashMap<Address, Address>,
    // user_entries is accessed via a separate helper
}

/// Result of the CreateSubAccount action.
#[derive(Clone, Debug)]
pub enum CreateSubAccountResult {
    /// Success: sub-account was created. Contains the derived address.
    Created { sub_account: Address },
    /// The derived sub-account address already exists.
    AlreadyExists { sub_account: Address },
    /// Too many sub-accounts for this master.
    TooManySubs { sub_account: Address },
    /// Insufficient equity to create a sub-account.
    InsufficientEquity { equity_usd: f64 },
    /// Sub-account name validation failed or other error.
    Error { status: u16, message: String },
}

/// Minimum raw equity required to create a sub-account.
///
/// The binary checks `user_equity_raw < 0x989680` (10,000,000 in raw units).
/// At the recovered `/ 100.0` scaling, this corresponds to $100,000 USD equivalent.
pub const MIN_EQUITY_RAW: u64 = 10_000_000;

/// Maximum sub-accounts per master address formula:
///
/// ```text
/// base = min(user_equity_raw / 10_000_000_000, 40)
/// cap  = base + 10
/// ```
///
/// So the cap ranges from 10 (at zero equity above threshold) to 50 (at 400B+ raw equity).
pub const EQUITY_PER_EXTRA_SUB: u64 = 10_000_000_000;
pub const MAX_EXTRA_SUBS: u64 = 40;
pub const BASE_SUB_ALLOWANCE: u64 = 10;

/// Derives the next sub-account address for a master.
///
/// Reconstructed from `l1_sub_account__derive_next_sub_account_user` (`0x36F3C20`).
///
/// The derivation:
/// 1. Looks up how many sub-accounts the master currently has (from the
///    `master_to_sub_count` hashmap).
/// 2. Allocates the literal string `"createSubAccount"` (16 bytes).
/// 3. Builds a buffer containing: the 16-byte label, the 20-byte master address,
///    and the current sub-account count as a u64.
/// 4. Runs a hash function (likely keccak256) over that buffer.
/// 5. Returns the final 20 bytes of the hash output as the derived sub-account address.
pub fn derive_next_sub_account_user(
    master_to_sub_count: &hashbrown::HashMap<Address, u64>,
    master: &Address,
) -> Address {
    let current_count = master_to_sub_count
        .get(master)
        .copied()
        .unwrap_or(0);

    // The binary allocates "createSubAccount" (16 bytes), concatenates master + count,
    // then hashes. The hash function initializes a 208-byte state, processes the input,
    // and finalizes into a 32-byte output. The last 20 bytes become the address.
    let mut preimage = Vec::with_capacity(16 + 20 + 8);
    preimage.extend_from_slice(b"createSubAccount");
    preimage.extend_from_slice(&master.0);
    preimage.extend_from_slice(&current_count.to_le_bytes());

    let hash = keccak256(&preimage);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);
    Address(addr)
}

/// Main CreateSubAccount handler.
///
/// Reconstructed from `0x27E3140` and its callee `l1_sub_account__create_sub_account`
/// (`0x36F3610`).
///
/// Flow:
/// 1. Derive the next sub-account address for the master.
/// 2. Check if the derived address already exists in the `sub_to_master` map.
///    If yes → return `AlreadyExists`.
/// 3. Compute user equity (via helper at `0x275FEE0`).
/// 4. Check minimum equity threshold: `user_equity_raw < 10_000_000` → return
///    `InsufficientEquity` with `equity_usd = raw / 100.0`.
/// 5. Check sub-account count cap:
///    ```text
///    extra = min(user_equity_raw / 10_000_000_000, 40)
///    if current_count >= extra + 10 → TooManySubs
///    ```
/// 6. Validate the sub-account name (must be ≤100 bytes, checked at `0x36F3610`).
/// 7. Check that the derived address is not already in `sub_to_master`.
/// 8. Insert the sub→master mapping.
/// 9. Insert or update the per-master user entries vector.
/// 10. Insert the new sub-account into the global user account table
///     (`get_or_create_user_account` at `0x1F849B0`).
/// 11. Insert into the exchange-level entry hashmap
///     (`hashmap_insert_entry_simd` at `0x1F84B30`).
/// 12. Return `Created { sub_account }`.
///
/// The handler also updates clearinghouse state for both master and sub-account
/// addresses (the double call to `0x3743DF0` with the same clearinghouse offset
/// and both addresses).
pub fn create_sub_account(
    exchange: &mut Exchange,
    master: &Address,
    name: &str,
    user_equity_raw: u64,
) -> CreateSubAccountResult {
    // Step 1: derive next address
    let sub_account = derive_next_sub_account_user(
        &exchange.sub_account_state.master_to_sub_count,
        master,
    );

    // Step 2: check if already exists
    if exchange.sub_account_state.sub_to_master.contains_key(&sub_account) {
        return CreateSubAccountResult::AlreadyExists { sub_account };
    }

    // Step 3-4: equity check
    if user_equity_raw < MIN_EQUITY_RAW {
        return CreateSubAccountResult::InsufficientEquity {
            equity_usd: user_equity_raw as f64 / 100.0,
        };
    }

    // Step 5: sub-account count cap
    let current_count = exchange
        .sub_account_state
        .master_to_sub_count
        .get(master)
        .copied()
        .unwrap_or(0);
    let extra_allowed = (user_equity_raw / EQUITY_PER_EXTRA_SUB).min(MAX_EXTRA_SUBS);
    if current_count >= extra_allowed + BASE_SUB_ALLOWANCE {
        return CreateSubAccountResult::TooManySubs { sub_account };
    }

    // Step 6: derive address again (the binary re-derives inside create_sub_account)
    // and check sub_to_master once more
    if exchange.sub_account_state.sub_to_master.contains_key(&sub_account) {
        return CreateSubAccountResult::AlreadyExists { sub_account };
    }

    // Step 7: validate name length
    if name.len() > 100 {
        return CreateSubAccountResult::Error {
            status: 323,
            message: "Sub-account name too long".to_string(),
        };
    }

    // [INFERENCE] Additional name validation happens in validate_new_name,
    // likely checking for duplicates and allowed characters.

    // Step 8: insert sub→master mapping
    // The binary calls l1_sub_account__insert_sub_to_master_mapping which has
    // an internal assert: `assert!(inserted)` — panics if the key already existed.
    // This is safe because we checked contains_key above.
    exchange.sub_account_state.sub_to_master.insert(sub_account, *master);

    // Step 9: insert into per-master entries
    let entries = exchange.user_entries_mut_or_insert(master);
    entries.entries.push(SubAccountEntry {
        name: name.to_string(),
        sub_account,
        master: *master,
    });

    // Step 10-11: create global user account + exchange entry
    exchange.get_or_create_user_account(&sub_account);
    exchange.insert_entry(&sub_account);

    // Step 12: update clearinghouse state for both addresses
    // The binary calls 0x3743DF0 twice: once with master, once with sub_account.
    // This appears to initialize or copy clearinghouse margin state.
    exchange.init_clearinghouse_state(master);
    exchange.init_clearinghouse_state(&sub_account);

    CreateSubAccountResult::Created { sub_account }
}

// -- Placeholder types referenced above --

/// [INFERENCE] Placeholder for the keccak256 hash used by address derivation.
fn keccak256(input: &[u8]) -> [u8; 32] {
    // The binary uses a 208-byte hash state initialized at the derive helper.
    // This is almost certainly keccak256 based on the state size and Ethereum context.
    todo!("keccak256 — see hash state init in sub_4F59A10 / sub_4F59E40")
}

/// [INFERENCE] Exchange state — only the sub-account-relevant fields shown.
pub struct Exchange {
    pub sub_account_state: SubAccountState,
    // ... many other fields
}

impl Exchange {
    fn get_or_create_user_account(&mut self, _addr: &Address) {
        // Calls get_or_create_user_account at 0x1F849B0
    }
    fn insert_entry(&mut self, _addr: &Address) {
        // Calls hashmap_insert_entry_simd at 0x1F84B30
    }
    fn init_clearinghouse_state(&mut self, _addr: &Address) {
        // Calls 0x3743DF0 with clearinghouse offset
    }
    fn user_entries_mut_or_insert(&mut self, _master: &Address) -> &mut SubAccountUserEntries {
        // Calls l1_sub_account__user_entries_mut_or_insert
        todo!()
    }
}

/// Dummy hashbrown stand-in for the reconstructed types.
pub mod hashbrown {
    pub type HashMap<K, V> = std::collections::HashMap<K, V>;
}
