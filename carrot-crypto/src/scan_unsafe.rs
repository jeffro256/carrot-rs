use crate::as_crypto::AsMontgomeryPoint;
use crate::device::ViewIncomingKeyDevice;
use crate::enote::{CarrotCoinbaseEnoteV1, CarrotEnoteV1};
use crate::*;

unsafe fn scan_non_coinbase_dest_info(
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
    // k^g_o = H_n[s^ctx_sr]("..G..", C_a)
    let sender_extension_g = OnetimeExtensionG::derive_ringct(s_sender_receiver, amount_commitment);

    // k^t_o = H_n[s^ctx_sr]("..T..", C_a)
    let sender_extension_t = OnetimeExtensionT::derive_ringct(s_sender_receiver, amount_commitment);

    // K^ext_o = k^g_o G + k^t_o T
    let sender_extension =
        OnetimeExtension::derive_from_scalars(&sender_extension_g, &sender_extension_t);

    // K^j_s = Ko - K^o_ext = Ko - (k^g_o G + k^t_o T)
    let address_spend_pubkey =
        AddressSpendPubkey::recover_from_extension(onetime_address, &sender_extension)?;

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

pub unsafe fn try_scan_carrot_coinbase_enote_no_janus(
    enote: &CarrotCoinbaseEnoteV1,
    s_sender_receiver_unctx: &MontgomeryECDH,
    main_address_spend_pubkeys: &[AddressSpendPubkey],
) -> Option<(
    OnetimeExtensionG,
    OnetimeExtensionT,
    AddressSpendPubkey,
    JanusAnchor,
)> {
    // input_context
    let input_context = InputContext::new_coinbase(enote.block_index);

    // if vt' != vt, then FAIL
    if !enote.view_tag.derive_and_test(
        &s_sender_receiver_unctx.as_montgomery_ref().0,
        &input_context,
        &enote.onetime_address,
    ) {
        return None;
    }

    // s^ctx_sr = H_32(s_sr, D_e, input_context)
    let s_sender_receiver = SenderReceiverSecret::derive(
        &s_sender_receiver_unctx.as_montgomery_ref().0,
        &enote.enote_ephemeral_pubkey,
        &input_context,
    );

    for main_address_spend_pubkey in main_address_spend_pubkeys.iter() {
        // k^g_o = H_n[s^ctx_sr]("..coinbase..G..", a, K^0_s)
        let sender_extension_g = OnetimeExtensionG::derive_coinbase(
            &s_sender_receiver,
            enote.amount,
            main_address_spend_pubkey,
        );

        // k^t_o = H_n[s^ctx_sr]("..coinbase..T..", a, K^0_s)
        let sender_extension_t = OnetimeExtensionT::derive_coinbase(
            &s_sender_receiver,
            enote.amount,
            main_address_spend_pubkey,
        );

        // K^ext_o = k^g_o G + k^t_o T
        let sender_extension =
            OnetimeExtension::derive_from_scalars(&sender_extension_g, &sender_extension_t);

        // K^j_s = Ko - K^o_ext
        let recovered_address_spend_pubkey =
            AddressSpendPubkey::recover_from_extension(&enote.onetime_address, &sender_extension)?;

        // if hit on some K^0_s:
        if &recovered_address_spend_pubkey == main_address_spend_pubkey {
            // anchor = anchor_enc XOR m_anchor
            let janus_anchor = enote
                .anchor_enc
                .decrypt(&s_sender_receiver, &enote.onetime_address);

            return Some((
                sender_extension_g,
                sender_extension_t,
                recovered_address_spend_pubkey,
                janus_anchor,
            ));
        }
    }

    None
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

    // if vt' != vt, then FAIL
    if !enote.view_tag.derive_and_test(
        &s_sender_receiver_unctx.as_montgomery_ref().0,
        &input_context,
        &enote.onetime_address,
    ) {
        return None;
    }

    // s^ctx_sr = H_32(s_sr, D_e, input_context)
    let s_sender_receiver = SenderReceiverSecret::derive(
        &s_sender_receiver_unctx.as_montgomery_ref().0,
        &enote.enote_ephemeral_pubkey,
        &input_context,
    );

    // k^g_o, k^t_o, K^j_s', pid', anchor'
    let (
        sender_extension_g,
        sender_extension_t,
        address_spend_pubkey,
        nominal_payment_id,
        janus_anchor,
    ) = unsafe {
        scan_non_coinbase_dest_info(
            &enote.onetime_address,
            &enote.amount_commitment,
            &enote.anchor_enc,
            encrypted_payment_id,
            &s_sender_receiver,
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
        nominal_payment_id,
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
        scan_non_coinbase_dest_info(
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
