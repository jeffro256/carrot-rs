use crate::as_crypto::AsMontgomeryPoint;
use crate::device::ViewIncomingKeyDevice;
use crate::enote::{CarrotCoinbaseEnoteV1, CarrotEnoteV1};
use crate::*;

pub enum LazyAmountCommitment {
    Closed(AmountCommitment),
    CleartextOpen(Amount),
}

impl LazyAmountCommitment {
    pub fn calculate(&self) -> AmountCommitment {
        match self {
            Self::Closed(x) => x.clone(),
            Self::CleartextOpen(a) => AmountCommitment::clear_commit(*a),
        }
    }
}

unsafe fn scan_carrot_dest_info(
    onetime_address: &OutputPubkey,
    amount_commitment: &AmountCommitment,
    encrypted_janus_anchor: &EncryptedJanusAnchor,
    encrypted_payment_id: Option<&EncryptedPaymentId>,
    s_sender_receiver: &SenderReceiverSecret,
) -> Option<(
    OnetimeExtensionG,
    OnetimeExtensionT,
    AddressSpendPubkey,
    PaymentId,
    JanusAnchor,
)> {
    // k^o_g = H_n("..g..", s^ctx_sr, C_a)
    let sender_extension_g = OnetimeExtensionG::derive(s_sender_receiver, amount_commitment);

    // k^o_t = H_n("..t..", s^ctx_sr, C_a)
    let sender_extension_t = OnetimeExtensionT::derive(s_sender_receiver, amount_commitment);

    // K^j_s = Ko - K^o_ext = Ko - (k^o_g G + k^o_t T)
    let address_spend_pubkey = AddressSpendPubkey::recover_from_onetime_address(
        onetime_address,
        s_sender_receiver,
        amount_commitment,
    )?;

    // pid = pid_enc XOR m_pid, if applicable
    let nominal_payment_id = match encrypted_payment_id {
        Some(encrypted_payment_id) => {
            encrypted_payment_id.decrypt(&s_sender_receiver, &onetime_address)
        }
        None => Default::default(),
    };

    // anchor = anchor_enc XOR m_anchor
    let janus_anchor = encrypted_janus_anchor.decrypt(&s_sender_receiver, &onetime_address);

    Some((
        sender_extension_g,
        sender_extension_t,
        address_spend_pubkey,
        nominal_payment_id,
        janus_anchor,
    ))
}

unsafe fn try_scan_carrot_external_noamount(
    onetime_address: &OutputPubkey,
    lazy_amount_commitment: &LazyAmountCommitment,
    encrypted_janus_anchor: &EncryptedJanusAnchor,
    view_tag: &ViewTag,
    enote_ephemeral_pubkey: &EnoteEphemeralPubkey,
    encrypted_payment_id: Option<&EncryptedPaymentId>,
    input_context: &InputContext,
    s_sender_receiver_unctx: &MontgomeryECDH,
) -> Option<(
    SenderReceiverSecret,
    OnetimeExtensionG,
    OnetimeExtensionT,
    AddressSpendPubkey,
    PaymentId,
    JanusAnchor,
)> {
    // if vt' != vt, then FAIL
    if !view_tag.derive_and_test(
        &s_sender_receiver_unctx.as_montgomery_ref().0,
        input_context,
        onetime_address,
    ) {
        return None;
    }

    // s^ctx_sr = H_32(s_sr, D_e, input_context)
    let s_sender_receiver = SenderReceiverSecret::derive(
        &s_sender_receiver_unctx.as_montgomery_ref().0,
        enote_ephemeral_pubkey,
        input_context,
    );

    // get C_a
    let amount_commitment = lazy_amount_commitment.calculate();

    // k^g_o, k^t_o, K^j_s', pid', anchor'
    let (
        sender_extension_g,
        sender_extension_t,
        address_spend_pubkey,
        nominal_payment_id,
        janus_anchor,
    ) = unsafe {
        scan_carrot_dest_info(
            onetime_address,
            &amount_commitment,
            encrypted_janus_anchor,
            encrypted_payment_id,
            &s_sender_receiver,
        )?
    };

    return Some((
        s_sender_receiver,
        sender_extension_g,
        sender_extension_t,
        address_spend_pubkey,
        nominal_payment_id,
        janus_anchor,
    ));
}

pub unsafe fn try_scan_carrot_coinbase_enote_no_janus(
    enote: &CarrotCoinbaseEnoteV1,
    s_sender_receiver_unctx: &MontgomeryECDH,
) -> Option<(
    OnetimeExtensionG,
    OnetimeExtensionT,
    AddressSpendPubkey,
    JanusAnchor,
)> {
    // input_context
    let input_context = InputContext::new_coinbase(enote.block_index);

    // s^ctx_sr, k^g_o, k^g_t, K^j_s, pid, anchor
    let (_, sender_extension_g, sender_extension_t, address_spend_pubkey, _, janus_anchor) = unsafe {
        try_scan_carrot_external_noamount(
            &enote.onetime_address,
            &LazyAmountCommitment::CleartextOpen(enote.amount),
            &enote.anchor_enc,
            &enote.view_tag,
            &enote.enote_ephemeral_pubkey,
            None,
            &input_context,
            s_sender_receiver_unctx,
        )?
    };

    Some((
        sender_extension_g,
        sender_extension_t,
        address_spend_pubkey,
        janus_anchor,
    ))
}

pub unsafe fn try_scan_carrot_enote_external_no_janus(
    enote: &CarrotEnoteV1,
    encrypted_payment_id: Option<&EncryptedPaymentId>,
    s_sender_receiver_unctx: &MontgomeryECDH,
) -> Option<(
    OnetimeExtensionG,
    OnetimeExtensionT,
    AddressSpendPubkey,
    Amount,
    AmountBlindingKey,
    PaymentId,
    CarrotEnoteType,
    JanusAnchor,
)> {
    // input_context
    let input_context = InputContext::new_ringct(&enote.tx_first_key_image);

    // s^ctx_sr, k^g_o, k^g_t, K^j_s, pid, and Janus verification
    let (
        s_sender_receiver,
        sender_extension_g,
        sender_extension_t,
        address_spend_pubkey,
        payment_id,
        janus_anchor,
    ) = unsafe {
        try_scan_carrot_external_noamount(
            &enote.onetime_address,
            &LazyAmountCommitment::Closed(enote.amount_commitment.clone()),
            &enote.anchor_enc,
            &enote.view_tag,
            &enote.enote_ephemeral_pubkey,
            encrypted_payment_id,
            &input_context,
            s_sender_receiver_unctx,
        )?
    };

    // enote_type, a, z
    let (amount, amount_blinding_factor, enote_type) = try_get_carrot_amount(
        &s_sender_receiver,
        &enote.amount_enc,
        &enote.onetime_address,
        &address_spend_pubkey,
        &enote.amount_commitment,
    )?;

    Some((
        sender_extension_g,
        sender_extension_t,
        address_spend_pubkey,
        amount,
        amount_blinding_factor,
        payment_id,
        enote_type,
        janus_anchor,
    ))
}

pub unsafe fn try_scan_carrot_enote_internal_burnt(
    enote: &CarrotEnoteV1,
    s_sender_receiver: &SenderReceiverSecret,
) -> Option<(
    OnetimeExtensionG,
    OnetimeExtensionT,
    AddressSpendPubkey,
    Amount,
    AmountBlindingKey,
    CarrotEnoteType,
    JanusAnchor,
)> {
    // k^g_o, k^t_o, K^j_s', pid', anchor'
    let (sender_extension_g, sender_extension_t, address_spend_pubkey, _, janus_anchor) = unsafe {
        scan_carrot_dest_info(
            &enote.onetime_address,
            &enote.amount_commitment,
            &enote.anchor_enc,
            None,
            &s_sender_receiver,
        )?
    };

    // enote_type, a, z
    let (amount, amount_blinding_factor, enote_type) = try_get_carrot_amount(
        s_sender_receiver,
        &enote.amount_enc,
        &enote.onetime_address,
        &address_spend_pubkey,
        &enote.amount_commitment,
    )?;

    Some((
        sender_extension_g,
        sender_extension_t,
        address_spend_pubkey,
        amount,
        amount_blinding_factor,
        enote_type,
        janus_anchor,
    ))
}

pub unsafe fn verify_carrot_normal_janus_protection_and_confirm_pid(
    input_context: &InputContext,
    nominal_address_spend_pubkey: &AddressSpendPubkey,
    is_subaddress: bool,
    enote_ephemeral_pubkey: &EnoteEphemeralPubkey,
    nominal_janus_anchor: &JanusAnchor,
    nominal_payment_id_inout: &mut PaymentId,
) -> bool {
    // if can recompute D_e with pid', then PASS
    if verify_carrot_normal_janus_protection(
        nominal_janus_anchor,
        input_context,
        nominal_address_spend_pubkey,
        is_subaddress,
        nominal_payment_id_inout,
        enote_ephemeral_pubkey,
    ) {
        return true;
    }

    // if can recompute D_e with null pid, then PASS
    *nominal_payment_id_inout = Default::default();
    verify_carrot_normal_janus_protection(
        nominal_janus_anchor,
        input_context,
        nominal_address_spend_pubkey,
        is_subaddress,
        nominal_payment_id_inout,
        enote_ephemeral_pubkey,
    )
}

pub unsafe fn verify_carrot_special_janus_protection<VI>(
    tx_first_key_image: &KeyImage,
    enote_ephemeral_pubkey: &EnoteEphemeralPubkey,
    onetime_address: &OutputPubkey,
    k_view_dev: &VI,
    nominal_janus_anchor: &JanusAnchor,
) -> bool
where
    VI: ViewIncomingKeyDevice,
{
    // input_context = "R" || KI_1
    let input_context = InputContext::new_ringct(tx_first_key_image);

    // anchor_sp = H_16(D_e, input_context, Ko, k_v)
    let Ok(expected_special_anchor) = k_view_dev.make_janus_anchor_special(
        enote_ephemeral_pubkey,
        &input_context,
        onetime_address,
    ) else {
        return false;
    };

    // attempt special janus check: anchor_sp ?= anchor'
    return &expected_special_anchor == nominal_janus_anchor;
}
