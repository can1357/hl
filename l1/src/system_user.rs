#![allow(dead_code)]

/// Twenty-byte account identifier used by the recovered L1 state code.
pub type Address = [u8; 20];

pub const NUM_SYSTEM_USERS: u8 = 30;
pub const SYSTEM_USER_END_SENTINEL: u8 = NUM_SYSTEM_USERS;
pub const FIRST_PRIVILEGED_SYSTEM_USER_INDEX: u8 = 7;
pub const PRIVILEGED_SYSTEM_USER_COUNT: u8 = 20;
pub const LAST_PRIVILEGED_SYSTEM_USER_INDEX: u8 =
    FIRST_PRIVILEGED_SYSTEM_USER_INDEX + PRIVILEGED_SYSTEM_USER_COUNT - 1;

pub const VOTE_GLOBAL_VALIDATOR_L1_VOTE_ENABLED_TAG: u8 = 0x53;
pub const VOTE_GLOBAL_SET_USDC_EVM_CONTRACT_TAG: u8 = 0x60;

const fn repeated(byte: u8) -> Address {
    [byte; 20]
}

const fn low_u16_address(value: u16) -> Address {
    let bytes = value.to_be_bytes();
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, bytes[0], bytes[1],
    ]
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemUserPrivilege {
    Reserved,
    PrivilegedLedgerUser,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemUser {
    pub index: u8,
    pub address: Address,
    pub privilege: SystemUserPrivilege,
}

/// Fixed system-user table recovered from the optimized 30-way address jump table.
///
/// Indices `7..=26` are the privileged addresses accepted by the inlined vote-global
/// and ledger-update checks.  The order is not numeric: `0x0813` is index 8, before
/// `0x0801..=0x0812`, exactly as in the table.
pub const SYSTEM_USERS: [SystemUser; NUM_SYSTEM_USERS as usize] = [
    SystemUser { index: 0, address: repeated(0x22), privilege: SystemUserPrivilege::Reserved },
    SystemUser { index: 1, address: repeated(0xff), privilege: SystemUserPrivilege::Reserved },
    SystemUser { index: 2, address: repeated(0xee), privilege: SystemUserPrivilege::Reserved },
    SystemUser { index: 3, address: low_u16_address(0xdead), privilege: SystemUserPrivilege::Reserved },
    SystemUser { index: 4, address: low_u16_address(0x0007), privilege: SystemUserPrivilege::Reserved },
    SystemUser { index: 5, address: repeated(0xdd), privilege: SystemUserPrivilege::Reserved },
    SystemUser { index: 6, address: repeated(0xfe), privilege: SystemUserPrivilege::Reserved },
    SystemUser { index: 7, address: low_u16_address(0x0800), privilege: SystemUserPrivilege::PrivilegedLedgerUser },
    SystemUser { index: 8, address: low_u16_address(0x0813), privilege: SystemUserPrivilege::PrivilegedLedgerUser },
    SystemUser { index: 9, address: low_u16_address(0x0801), privilege: SystemUserPrivilege::PrivilegedLedgerUser },
    SystemUser { index: 10, address: low_u16_address(0x0802), privilege: SystemUserPrivilege::PrivilegedLedgerUser },
    SystemUser { index: 11, address: low_u16_address(0x0803), privilege: SystemUserPrivilege::PrivilegedLedgerUser },
    SystemUser { index: 12, address: low_u16_address(0x0804), privilege: SystemUserPrivilege::PrivilegedLedgerUser },
    SystemUser { index: 13, address: low_u16_address(0x0805), privilege: SystemUserPrivilege::PrivilegedLedgerUser },
    SystemUser { index: 14, address: low_u16_address(0x0806), privilege: SystemUserPrivilege::PrivilegedLedgerUser },
    SystemUser { index: 15, address: low_u16_address(0x0807), privilege: SystemUserPrivilege::PrivilegedLedgerUser },
    SystemUser { index: 16, address: low_u16_address(0x0808), privilege: SystemUserPrivilege::PrivilegedLedgerUser },
    SystemUser { index: 17, address: low_u16_address(0x0809), privilege: SystemUserPrivilege::PrivilegedLedgerUser },
    SystemUser { index: 18, address: low_u16_address(0x080a), privilege: SystemUserPrivilege::PrivilegedLedgerUser },
    SystemUser { index: 19, address: low_u16_address(0x080b), privilege: SystemUserPrivilege::PrivilegedLedgerUser },
    SystemUser { index: 20, address: low_u16_address(0x080c), privilege: SystemUserPrivilege::PrivilegedLedgerUser },
    SystemUser { index: 21, address: low_u16_address(0x080d), privilege: SystemUserPrivilege::PrivilegedLedgerUser },
    SystemUser { index: 22, address: low_u16_address(0x080e), privilege: SystemUserPrivilege::PrivilegedLedgerUser },
    SystemUser { index: 23, address: low_u16_address(0x080f), privilege: SystemUserPrivilege::PrivilegedLedgerUser },
    SystemUser { index: 24, address: low_u16_address(0x0810), privilege: SystemUserPrivilege::PrivilegedLedgerUser },
    SystemUser { index: 25, address: low_u16_address(0x0811), privilege: SystemUserPrivilege::PrivilegedLedgerUser },
    SystemUser { index: 26, address: low_u16_address(0x0812), privilege: SystemUserPrivilege::PrivilegedLedgerUser },
    SystemUser { index: 27, address: repeated(0x33), privilege: SystemUserPrivilege::Reserved },
    SystemUser { index: 28, address: repeated(0x55), privilege: SystemUserPrivilege::Reserved },
    SystemUser { index: 29, address: repeated(0xbb), privilege: SystemUserPrivilege::Reserved },
];

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SystemUserIndexIter {
    cursor: u64,
    tail_allowance: u64,
}

impl SystemUserIndexIter {
    pub const fn new() -> Self {
        Self { cursor: 0, tail_allowance: 0 }
    }

    pub const fn with_tail_allowance(cursor: u64, tail_allowance: u64) -> Self {
        Self { cursor, tail_allowance }
    }

    /// Recovered checked iterator step.
    ///
    /// The compiled helper returns index `30` as the end sentinel.  It checks overflow
    /// for `cursor + offset`, `+ 1`, and `+ tail_allowance` before clamping the cursor
    /// to the sentinel when the table bound is crossed.
    pub fn next_index_with_offset(&mut self, offset: u64) -> u8 {
        let current = self
            .cursor
            .checked_add(offset)
            .expect("system user index overflow");
        let next = current.checked_add(1).expect("system user index overflow");
        let bounded_next = next
            .checked_add(self.tail_allowance)
            .expect("system user index overflow");

        if bounded_next <= NUM_SYSTEM_USERS as u64 {
            self.cursor = next;
            if current < NUM_SYSTEM_USERS as u64 {
                current as u8
            } else {
                SYSTEM_USER_END_SENTINEL
            }
        } else {
            self.cursor = NUM_SYSTEM_USERS as u64;
            SYSTEM_USER_END_SENTINEL
        }
    }
}

impl Iterator for SystemUserIndexIter {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        let index = self.next_index_with_offset(0);
        (index != SYSTEM_USER_END_SENTINEL).then_some(index)
    }
}

#[inline]
pub fn system_user_for_index(index: u8) -> Option<&'static SystemUser> {
    SYSTEM_USERS.get(index as usize)
}

#[inline]
pub fn address_for_index(index: u8) -> Option<Address> {
    system_user_for_index(index).map(|user| user.address)
}

pub fn system_user_index(address: &Address) -> Option<u8> {
    let mut iter = SystemUserIndexIter::new();
    while let Some(index) = iter.next() {
        if address_for_index(index).as_ref() == Some(address) {
            return Some(index);
        }
    }
    None
}

#[inline]
pub const fn is_privileged_system_index(index: u8) -> bool {
    index >= FIRST_PRIVILEGED_SYSTEM_USER_INDEX && index <= LAST_PRIVILEGED_SYSTEM_USER_INDEX
}

pub fn is_privileged_system_address(address: &Address) -> bool {
    match system_user_index(address) {
        Some(index) => is_privileged_system_index(index),
        None => false,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemUserLedgerKind {
    /// Action discriminants `0..=4`.  The helper serializes the action tail and uses
    /// the checked `word6 - word7` delta recovered from the decompilation.
    SystemTxWithTailDelta,
    /// VoteGlobal raw tag `0x53` (`ValidatorL1VoteEnabled`).  This path updates the
    /// system-user ledger entry but skips the secondary emitted ledger record.
    ValidatorL1VoteEnabled,
    /// VoteGlobal raw tag `0x60` (`SetUsdcEvmContract`).
    SetUsdcEvmContract,
    /// Any other high action discriminant seen after the privileged-user check.
    OtherPrivilegedAction,
}

impl SystemUserLedgerKind {
    pub const fn recovered_class(self) -> u8 {
        match self {
            Self::SystemTxWithTailDelta => 0,
            Self::ValidatorL1VoteEnabled => 1,
            Self::SetUsdcEvmContract => 2,
            Self::OtherPrivilegedAction => 3,
        }
    }

    pub const fn emits_secondary_record(self) -> bool {
        !matches!(self, Self::ValidatorL1VoteEnabled)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemUserLedgerEffect {
    pub system_user_index: u8,
    pub kind: SystemUserLedgerKind,
    pub tail_delta: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemUserLedgerError {
    TailUnderflow,
}

/// Classify the special ledger side effect used after a signer has matched the
/// privileged system-user range.
///
/// The recovered helper reads an action byte at offset `+72`.  Values below five
/// take the `SystemTxWithTailDelta` arm and panic if the first length/cursor word is
/// smaller than the second.  Tags `0x53` and `0x60` have dedicated classes; all other
/// high values share class `3`.
pub fn classify_privileged_ledger_kind(
    action_discriminant: u8,
    tail_word_6: u64,
    tail_word_7: u64,
) -> Result<SystemUserLedgerKindWithDelta, SystemUserLedgerError> {
    if action_discriminant < 5 {
        let delta = tail_word_6
            .checked_sub(tail_word_7)
            .ok_or(SystemUserLedgerError::TailUnderflow)?;
        return Ok(SystemUserLedgerKindWithDelta {
            kind: SystemUserLedgerKind::SystemTxWithTailDelta,
            tail_delta: Some(delta),
        });
    }

    let kind = match action_discriminant {
        VOTE_GLOBAL_VALIDATOR_L1_VOTE_ENABLED_TAG => SystemUserLedgerKind::ValidatorL1VoteEnabled,
        VOTE_GLOBAL_SET_USDC_EVM_CONTRACT_TAG => SystemUserLedgerKind::SetUsdcEvmContract,
        _ => SystemUserLedgerKind::OtherPrivilegedAction,
    };
    Ok(SystemUserLedgerKindWithDelta { kind, tail_delta: None })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemUserLedgerKindWithDelta {
    pub kind: SystemUserLedgerKind,
    pub tail_delta: Option<u64>,
}

pub trait SystemUserLedgerSink {
    fn account_exists_for_system_redirect(&self, signer: &Address) -> bool;
    fn ensure_system_user_ledger_entry(&mut self, signer: Address, system_user_index: u8, class: u8);
    fn emit_system_user_ledger_record(&mut self, signer: Address, effect: SystemUserLedgerEffect);
}

/// Apply the recovered system-user ledger gate.
///
/// Return value is `Ok(None)` when the binary would fall through without touching the
/// system-user ledger: either the signer is absent from the account map or it is not
/// one of indices `7..=26`.  On a privileged signer, the function inserts/updates the
/// system-user ledger entry and emits the secondary record for every class except
/// `ValidatorL1VoteEnabled`, matching the observed class-1 fast path.
pub fn maybe_redirect_system_ledger_update<S: SystemUserLedgerSink>(
    sink: &mut S,
    signer: Address,
    action_discriminant: u8,
    tail_word_6: u64,
    tail_word_7: u64,
) -> Result<Option<SystemUserLedgerEffect>, SystemUserLedgerError> {
    if !sink.account_exists_for_system_redirect(&signer) {
        return Ok(None);
    }

    let Some(system_user_index) = system_user_index(&signer) else {
        return Ok(None);
    };
    if !is_privileged_system_index(system_user_index) {
        return Ok(None);
    }

    let classified = classify_privileged_ledger_kind(action_discriminant, tail_word_6, tail_word_7)?;
    let effect = SystemUserLedgerEffect {
        system_user_index,
        kind: classified.kind,
        tail_delta: classified.tail_delta,
    };

    sink.ensure_system_user_ledger_entry(signer, system_user_index, classified.kind.recovered_class());
    if classified.kind.emits_secondary_record() {
        sink.emit_system_user_ledger_record(signer, effect);
    }

    Ok(Some(effect))
}
