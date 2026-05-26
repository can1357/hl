pub type U256 = u128;

const MAX_FEE_HISTORY_BLOCKS: u64 = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockNumberOrTag {
    Number(u64),
    Latest,
    Finalized,
    Safe,
    Earliest,
    Pending,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RpcError {
    InvalidRewardPercentiles,
    UnresolvedBlockNumber,
    IncompleteBlockRange { expected: usize, actual: usize },
    MissingLastBlock,
    MissingBlockBody,
}

pub type RpcResult<T> = Result<T, RpcError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BaseFeeParams {
    pub elasticity_multiplier: u64,
    pub max_change_denominator: u64,
    pub minimum_base_fee: U256,
}

#[derive(Clone, Debug, PartialEq)]
pub struct FeeHistory {
    pub oldest_block: u64,
    pub base_fee_per_gas: Vec<U256>,
    pub gas_used_ratio: Vec<f64>,
    pub base_fee_per_blob_gas: Vec<U256>,
    pub blob_gas_used_ratio: Vec<f64>,
    pub reward: Option<Vec<Vec<U256>>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeeHistoryReceipt {
    pub gas_used: u64,
    pub effective_gas_price: U256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeeHistoryTransaction {
    pub gas_price: U256,
    pub max_fee_per_gas: Option<U256>,
    pub max_priority_fee_per_gas: Option<U256>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct FeeHistoryBlock {
    pub number: u64,
    pub base_fee_per_gas: Option<U256>,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub blob_gas_used: Option<u64>,
    pub excess_blob_gas: Option<u64>,
    pub transactions: Vec<FeeHistoryTransaction>,
    pub receipts: Vec<FeeHistoryReceipt>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeeHistoryConfig {
    pub base_fee_params: BaseFeeParams,
}

pub trait FeeHistoryProvider {
    fn resolve_block_number(
        &self,
        block: BlockNumberOrTag,
    ) -> impl core::future::Future<Output = RpcResult<u64>> + Send;
    fn fee_history_blocks(
        &self,
        oldest: u64,
        newest: u64,
    ) -> impl core::future::Future<Output = RpcResult<Vec<FeeHistoryBlock>>> + Send;
    fn fee_history_config_for_next_block(&self, parent: &FeeHistoryBlock) -> FeeHistoryConfig;
}

// [INFERENCE: file placement] The copied helper is reconstructed here because
// the recovered fee-history state machine carries this module's panic location,
// while the same optimized code is also shared with a block-batch reader path.
/// Recover `eth_feeHistory` data from a bounded range of canonical blocks.
///
/// The optimized state machine at `0x27b6540` clamps `block_count` to five,
/// rejects reward-percentile arrays that are not monotonically increasing or
/// contain an interior value greater than `100.0`, fetches exactly the computed
/// block range, then builds base-fee, gas-ratio, blob-fee, blob-ratio, and
/// optional reward vectors.  The binary derives the final base-fee element from
/// the last fetched block and panics with `"is present"` if that last block is
/// absent after the range-length check.
pub async fn fee_history<P>(
    provider: &P,
    block_count: u64,
    newest_block: BlockNumberOrTag,
    reward_percentiles: Option<Vec<f64>>,
) -> RpcResult<FeeHistory>
where
    P: FeeHistoryProvider,
{
    if let Some(percentiles) = reward_percentiles.as_deref() {
        validate_reward_percentiles(percentiles)?;
    }

    let requested = block_count.min(MAX_FEE_HISTORY_BLOCKS);
    if requested == 0 {
        return Ok(FeeHistory {
            oldest_block: 0,
            base_fee_per_gas: Vec::new(),
            gas_used_ratio: Vec::new(),
            base_fee_per_blob_gas: Vec::new(),
            blob_gas_used_ratio: Vec::new(),
            reward: reward_percentiles.as_ref().map(|_| Vec::new()),
        });
    }

    let newest = resolve_newest_block(provider, newest_block).await?;
    let capped = requested.min(newest.saturating_add(1));
    let oldest = newest + 1 - capped;

    let blocks = provider.fee_history_blocks(oldest, newest).await?;
    if blocks.len() != capped as usize {
        return Err(RpcError::IncompleteBlockRange {
            expected: capped as usize,
            actual: blocks.len(),
        });
    }

    let mut base_fee_per_gas = Vec::with_capacity(blocks.len() + 1);
    let mut gas_used_ratio = Vec::with_capacity(blocks.len());
    let mut base_fee_per_blob_gas = Vec::with_capacity(blocks.len() + 1);
    let mut blob_gas_used_ratio = Vec::with_capacity(blocks.len());
    let mut reward = reward_percentiles
        .as_ref()
        .map(|_| Vec::with_capacity(blocks.len()));

    for block in &blocks {
        base_fee_per_gas.push(block.base_fee_per_gas.unwrap_or_default());
        gas_used_ratio.push(compute_gas_used_ratio(block.gas_used, block.gas_limit));

        match block.excess_blob_gas {
            Some(excess_blob_gas) => base_fee_per_blob_gas.push(blob_base_fee(excess_blob_gas)),
            None => base_fee_per_blob_gas.push(0),
        }

        blob_gas_used_ratio.push(compute_blob_gas_used_ratio(block.blob_gas_used));

        if let (Some(reward), Some(percentiles)) = (&mut reward, reward_percentiles.as_deref()) {
            reward.push(block_rewards(block, percentiles)?);
        }
    }

    let last = blocks.last().ok_or(RpcError::MissingLastBlock)?;
    let config = provider.fee_history_config_for_next_block(last);
    base_fee_per_gas.push(next_block_base_fee(last, config.base_fee_params));
    base_fee_per_blob_gas.push(next_block_blob_base_fee(last));

    Ok(FeeHistory {
        oldest_block: oldest,
        base_fee_per_gas,
        gas_used_ratio,
        base_fee_per_blob_gas,
        blob_gas_used_ratio,
        reward,
    })
}

async fn resolve_newest_block<P>(provider: &P, block: BlockNumberOrTag) -> RpcResult<u64>
where
    P: FeeHistoryProvider,
{
    match block {
        BlockNumberOrTag::Number(number) => Ok(number),
        BlockNumberOrTag::Earliest => Ok(0),
        other => provider.resolve_block_number(other).await,
    }
}

fn validate_reward_percentiles(percentiles: &[f64]) -> RpcResult<()> {
    if percentiles.len() < 2 {
        return Ok(());
    }

    for window in percentiles.windows(2) {
        let previous = window[0];
        let next = window[1];
        if !(previous <= 100.0 && previous <= next) {
            return Err(RpcError::InvalidRewardPercentiles);
        }
    }

    Ok(())
}

fn compute_gas_used_ratio(gas_used: u64, gas_limit: u64) -> f64 {
    if gas_limit == 0 {
        return 0.0;
    }

    gas_used as f64 / gas_limit as f64
}

fn compute_blob_gas_used_ratio(blob_gas_used: Option<u64>) -> f64 {
    blob_gas_used.map_or(0.0, |used| used as f64 / 786_432.0)
}

fn block_rewards(block: &FeeHistoryBlock, percentiles: &[f64]) -> RpcResult<Vec<U256>> {

    if block.transactions.len() != block.receipts.len() {
        return Err(RpcError::MissingBlockBody);
    }

    if block.transactions.is_empty() || block.gas_used == 0 {
        return Ok(vec![0; percentiles.len()]);
    }

    let base_fee = block.base_fee_per_gas.unwrap_or_default();
    let mut rewards = Vec::with_capacity(block.transactions.len());
    for (tx, receipt) in block.transactions.iter().zip(block.receipts.iter()) {
        let effective = tx.effective_reward_price(receipt.effective_gas_price, base_fee);
        rewards.push(TransactionReward {
            priority_fee: effective,
            gas_used: receipt.gas_used,
        });
    }

    rewards.sort_unstable_by(|left, right| left.priority_fee.cmp(&right.priority_fee));

    let mut out = Vec::with_capacity(percentiles.len());
    let mut reward_index = 0usize;
    let mut cumulative_gas = rewards[0].gas_used;

    for percentile in percentiles {
        let target_gas = percentile_target_gas(block.gas_used, *percentile);
        while cumulative_gas < target_gas && reward_index + 1 < rewards.len() {
            reward_index += 1;
            cumulative_gas = cumulative_gas.saturating_add(rewards[reward_index].gas_used);
        }
        out.push(rewards[reward_index].priority_fee);
    }

    Ok(out)
}

fn percentile_target_gas(block_gas_used: u64, percentile: f64) -> u64 {
    let target = block_gas_used as f64 * percentile / 100.0;
    if target <= 0.0 {
        0
    } else if target > u64::MAX as f64 {
        u64::MAX
    } else {
        target as u64
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TransactionReward {
    priority_fee: U256,
    gas_used: u64,
}

impl FeeHistoryTransaction {
    fn effective_reward_price(&self, receipt_effective_gas_price: U256, base_fee: U256) -> U256 {
        if receipt_effective_gas_price >= base_fee {
            return receipt_effective_gas_price - base_fee;
        }

        let configured_fee = match (self.max_fee_per_gas, self.max_priority_fee_per_gas) {
            (Some(max_fee), Some(max_priority)) => max_fee
                .saturating_sub(base_fee)
                .min(max_priority),
            _ => self.gas_price.saturating_sub(base_fee),
        };
        configured_fee
    }
}

fn next_block_base_fee(parent: &FeeHistoryBlock, params: BaseFeeParams) -> U256 {
    let Some(parent_base_fee) = parent.base_fee_per_gas else {
        return 0;
    };

    if params.elasticity_multiplier == 0 || params.max_change_denominator == 0 {
        return parent_base_fee;
    }

    let target_gas = parent.gas_limit / params.elasticity_multiplier;
    if target_gas == 0 || parent.gas_used == target_gas {
        return parent_base_fee.max(params.minimum_base_fee);
    }

    if parent.gas_used > target_gas {
        let gas_delta = (parent.gas_used - target_gas) as U256;
        let target = target_gas as U256;
        let denominator = params.max_change_denominator as U256;
        let fee_delta = ((parent_base_fee * gas_delta) / target / denominator).max(1);
        parent_base_fee.saturating_add(fee_delta).max(params.minimum_base_fee)
    } else {
        let gas_delta = (target_gas - parent.gas_used) as U256;
        let target = target_gas as U256;
        let denominator = params.max_change_denominator as U256;
        let fee_delta = (parent_base_fee * gas_delta) / target / denominator;
        parent_base_fee.saturating_sub(fee_delta).max(params.minimum_base_fee)
    }
}

fn next_block_blob_base_fee(parent: &FeeHistoryBlock) -> U256 {
    parent.excess_blob_gas.map_or(0, blob_base_fee)
}

fn blob_base_fee(excess_blob_gas: u64) -> U256 {
    fake_exponential(1, excess_blob_gas as U256, 3_338_477)
}

fn fake_exponential(factor: U256, numerator: U256, denominator: U256) -> U256 {
    let mut output: U256 = 0;
    let mut accumulator = factor.saturating_mul(denominator);
    let mut i = 1;

    while accumulator > 0 {
        output = output.saturating_add(accumulator);
        accumulator = accumulator
            .saturating_mul(numerator)
            .checked_div(denominator.saturating_mul(i))
            .unwrap_or_default();
        i += 1;
    }

    output / denominator
}
