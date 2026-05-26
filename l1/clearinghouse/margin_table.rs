use serde::{Deserialize, Serialize};

pub const MAX_MARGIN_TABLE_DESCRIPTION_BYTES: usize = 250;
pub const MAX_MARGIN_TIERS: usize = 3;
pub const MAX_MARGIN_LEVERAGE: u8 = 50;
pub const MAX_WIRE_NTL_RAW: u64 = 0x0ccc_cccc_cccc_cccc;
pub const MAX_MARGIN_TIER_LOWER_BOUND_RAW: u64 = 1_000_000_000_000_000;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawMarginTable {
    pub description: String,
    pub margin_tiers: Vec<RawMarginTier>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawMarginTier {
    pub lower_bound: u64,
    pub max_leverage: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MarginTable {
    pub description: String,
    tiers: Vec<MarginTier>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MarginTier {
    pub lower_bound: u64,
    pub upper_bound: Option<u64>,
    pub prior_contribution: u64,
    pub max_leverage: u8,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MarginTableRelation {
    /// `self` never permits higher leverage than `other` at any tier boundary.
    NoMorePermissive = 0,
    /// `self` permits higher leverage at some boundary and lower leverage at none.
    StrictlyMorePermissive = 1,
    /// The two tier curves cross, so neither table dominates the other.
    Incomparable = 2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MarginTableError {
    DescriptionTooLong { len: usize },
    EmptyTiers,
    TooManyTiers { len: usize },
    LowerBoundTooLarge { lower_bound: u64 },
    LowerBoundShouldStartAtZero,
    LowerBoundShouldIncrease,
    MaxLeverageTooBig { max_leverage: u8 },
    MaxLeverageShouldDecrease,
}

impl TryFrom<RawMarginTable> for MarginTable {
    type Error = MarginTableError;

    fn try_from(raw: RawMarginTable) -> Result<Self, Self::Error> {
        Self::try_from_raw(raw)
    }
}

impl MarginTable {
    pub fn try_from_raw(raw: RawMarginTable) -> Result<Self, MarginTableError> {
        let description_len = raw.description.len();
        if description_len > MAX_MARGIN_TABLE_DESCRIPTION_BYTES {
            return Err(MarginTableError::DescriptionTooLong { len: description_len });
        }

        if raw.margin_tiers.is_empty() {
            return Err(MarginTableError::EmptyTiers);
        }
        if raw.margin_tiers.len() > MAX_MARGIN_TIERS {
            return Err(MarginTableError::TooManyTiers { len: raw.margin_tiers.len() });
        }

        let mut tiers = Vec::with_capacity(raw.margin_tiers.len());
        let mut previous_lower = 0;
        let mut previous_leverage = 0;
        let mut prior_contribution = 0;

        for (index, tier) in raw.margin_tiers.iter().copied().enumerate() {
            validate_tier(index, tier)?;

            if index == 0 {
                if tier.lower_bound != 0 {
                    return Err(MarginTableError::LowerBoundShouldStartAtZero);
                }
            } else {
                if tier.lower_bound <= previous_lower {
                    return Err(MarginTableError::LowerBoundShouldIncrease);
                }
                if tier.max_leverage >= previous_leverage {
                    return Err(MarginTableError::MaxLeverageShouldDecrease);
                }

                let current = tier.lower_bound / (2 * u64::from(tier.max_leverage));
                let previous = tier.lower_bound / (2 * u64::from(previous_leverage));
                prior_contribution = prior_contribution.saturating_add(current.saturating_sub(previous));
            }

            let upper_bound = raw.margin_tiers.get(index + 1).map(|next| next.lower_bound);
            tiers.push(MarginTier {
                lower_bound: tier.lower_bound,
                upper_bound,
                prior_contribution,
                max_leverage: tier.max_leverage,
            });

            previous_lower = tier.lower_bound;
            previous_leverage = tier.max_leverage;
        }

        Ok(Self { description: raw.description, tiers })
    }

    pub fn single_tier(description: String, max_leverage: u8) -> Result<Self, MarginTableError> {
        Self::try_from_raw(RawMarginTable {
            description,
            margin_tiers: vec![RawMarginTier { lower_bound: 0, max_leverage }],
        })
    }

    #[inline]
    pub fn tiers(&self) -> &[MarginTier] {
        &self.tiers
    }

    pub fn to_raw(&self) -> RawMarginTable {
        RawMarginTable {
            description: self.description.clone(),
            margin_tiers: self
                .tiers
                .iter()
                .map(|tier| RawMarginTier {
                    lower_bound: tier.lower_bound,
                    max_leverage: tier.max_leverage,
                })
                .collect(),
        }
    }

    /// Return the last tier whose lower bound is not greater than `notional`.
    ///
    /// The recovered binary stores tiers in a B-tree keyed by `lower_bound`; with at most
    /// three tiers, the source-level equivalent is a short linear scan.
    pub fn tier_for_notional(&self, notional: u64) -> &MarginTier {
        let mut selected = &self.tiers[0];
        for tier in &self.tiers[1..] {
            if notional < tier.lower_bound {
                break;
            }
            selected = tier;
        }
        selected
    }

    #[inline]
    pub fn max_leverage_for_notional(&self, notional: u64) -> u8 {
        self.tier_for_notional(notional).max_leverage
    }

    pub fn max_leverage_for_position(&self, px: u64, signed_sz: i64) -> u8 {
        if self.tiers.is_empty() {
            return MAX_MARGIN_LEVERAGE;
        }
        let abs_sz = signed_sz.unsigned_abs();
        let notional = abs_sz.saturating_mul(px);
        self.max_leverage_for_notional(notional)
    }

    /// Recovered helper used by the mode-2 margin path.
    ///
    /// Formula: `notional / (2 * max_leverage) - prior_contribution`, saturating at zero.
    pub fn ntl_div_2x_leverage_minus_prior_contribution(&self, notional: u64) -> u64 {
        let tier = self.tier_for_notional(notional);
        let divisor = 2 * u64::from(tier.max_leverage);
        (notional / divisor).saturating_sub(tier.prior_contribution)
    }

    /// Recovered helper used by the mode-3 margin path.
    ///
    /// Formula: `(2 * notional - 4 * max_leverage * prior_contribution) / (6 * max_leverage)`,
    /// saturating at zero before the division.
    pub fn margin_after_tier_offset_div_6x_leverage(&self, notional: u64) -> u64 {
        let tier = self.tier_for_notional(notional);
        let leverage = u64::from(tier.max_leverage);
        let lhs = notional.saturating_mul(2);
        let rhs = tier.prior_contribution.saturating_mul(4 * leverage);
        lhs.saturating_sub(rhs) / (6 * leverage)
    }

    pub fn relation_to(&self, other: &MarginTable) -> MarginTableRelation {
        let mut saw_greater = false;
        let mut saw_less = false;

        for tier in &self.tiers {
            match self
                .max_leverage_for_notional(tier.lower_bound)
                .cmp(&other.max_leverage_for_notional(tier.lower_bound))
            {
                core::cmp::Ordering::Greater => saw_greater = true,
                core::cmp::Ordering::Less => saw_less = true,
                core::cmp::Ordering::Equal => {}
            }
        }
        for tier in &other.tiers {
            match self
                .max_leverage_for_notional(tier.lower_bound)
                .cmp(&other.max_leverage_for_notional(tier.lower_bound))
            {
                core::cmp::Ordering::Greater => saw_greater = true,
                core::cmp::Ordering::Less => saw_less = true,
                core::cmp::Ordering::Equal => {}
            }
        }

        match (saw_greater, saw_less) {
            (false, _) => MarginTableRelation::NoMorePermissive,
            (true, false) => MarginTableRelation::StrictlyMorePermissive,
            (true, true) => MarginTableRelation::Incomparable,
        }
    }
}

fn validate_tier(index: usize, tier: RawMarginTier) -> Result<(), MarginTableError> {
    if tier.lower_bound >= MAX_WIRE_NTL_RAW {
        return Err(MarginTableError::LowerBoundTooLarge { lower_bound: tier.lower_bound });
    }
    if index != 0 && tier.lower_bound > MAX_MARGIN_TIER_LOWER_BOUND_RAW {
        return Err(MarginTableError::LowerBoundTooLarge { lower_bound: tier.lower_bound });
    }
    if tier.max_leverage > MAX_MARGIN_LEVERAGE {
        return Err(MarginTableError::MaxLeverageTooBig { max_leverage: tier.max_leverage });
    }
    Ok(())
}
