use crate::core_types::*;

////
// CarrotEnoteV1
// - onetime address
// - amount commitment
// - encrypted amount
// - encrypted janus anchor
// - view tag
// - ephemeral pubkey
// - tx first key image
///
pub struct CarrotEnoteV1 {
    /// K_o
    pub onetime_address: OutputPubkey,
    /// C_a
    pub amount_commitment: AmountCommitment,
    /// a_enc
    pub amount_enc: EncryptedAmount,
    /// anchor_enc
    pub anchor_enc: EncryptedJanusAnchor,
    /// view_tag
    pub view_tag: ViewTag,
    /// D_e
    pub enote_ephemeral_pubkey: EnoteEphemeralPubkey,
    /// L_0
    pub tx_first_key_image: KeyImage,
}

////
// CarrotCoinbaseEnoteV1
// - onetime address
// - cleartext amount
// - encrypted janus anchor
// - view tag
// - ephemeral pubkey
// - block index
///
pub struct CarrotCoinbaseEnoteV1 {
    /// K_o
    pub onetime_address: OutputPubkey,
    /// a
    pub amount: Amount,
    /// anchor_enc
    pub anchor_enc: EncryptedJanusAnchor,
    /// view_tag
    pub view_tag: ViewTag,
    /// D_e
    pub enote_ephemeral_pubkey: EnoteEphemeralPubkey,
    /// block_index
    pub block_index: BlockIndex,
}
