use crate::core_types::*;
use crate::math_utils::*;

pub enum LazyAmountCommitment {
    Closed(AmountCommitment),
    Open(Amount, AmountBlindingKey),
    CleartextOpen(Amount)
}

impl LazyAmountCommitment {
    pub fn calculate(&self) -> AmountCommitment {
        match self {
            Self::Closed(x) => x.clone(),
            Self::Open(a, z) => AmountCommitment(commit(*a, &z.0.0)),
            Self::CleartextOpen(a) => AmountCommitment(zero_commit(*a))
        }
    }
}
