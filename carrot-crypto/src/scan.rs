use crate::destination::CarrotDestinationV1;
use crate::device::ViewIncomingKeyDevice;
use crate::device::{self, ViewBalanceSecretDevice};
use crate::enote::*;
use crate::scan_unsafe::*;
use crate::*;

fn is_main_address_spend_pubkey(
    address_spend_pubkey: &AddressSpendPubkey,
    main_address_spend_pubkeys: &[AddressSpendPubkey],
) -> bool {
    for main_address_spend_pubkey in main_address_spend_pubkeys.iter() {
        if address_spend_pubkey == main_address_spend_pubkey {
            return true;
        }
    }
    false
}

fn try_scan_carrot_coinbase_enote_checked(
    enote: &CarrotCoinbaseEnoteV1,
    s_sender_receiver_unctx: &MontgomeryECDH,
    main_address_spend_pubkeys: &[AddressSpendPubkey],
) -> Option<(OnetimeExtensionG, OnetimeExtensionT, AddressSpendPubkey)> {
    // s^ctx_sr, k^g_o, k^g_t, K^j_s, pid, anchor
    let (sender_extension_g, sender_extension_t, address_spend_pubkey, nominal_janus_anchor) =
        unsafe { try_scan_carrot_coinbase_enote_no_janus(enote, s_sender_receiver_unctx) }?;

    if !is_main_address_spend_pubkey(&address_spend_pubkey, main_address_spend_pubkeys) {
        return None;
    }

    if !verify_carrot_normal_janus_protection(
        &nominal_janus_anchor,
        &InputContext::new_coinbase(enote.block_index),
        &address_spend_pubkey,
        /*is_subaddress=*/ false,
        &Default::default(),
        &enote.enote_ephemeral_pubkey,
    ) {
        return None;
    }

    Some((sender_extension_g, sender_extension_t, address_spend_pubkey))
}

fn try_scan_carrot_enote_external_normal_checked(
    enote: &CarrotEnoteV1,
    encrypted_payment_id: Option<&EncryptedPaymentId>,
    s_sender_receiver_unctx: &MontgomeryECDH,
    main_address_spend_pubkeys: &[AddressSpendPubkey],
) -> Option<(
    OnetimeExtensionG,
    OnetimeExtensionT,
    AddressSpendPubkey,
    Amount,
    AmountBlindingKey,
    PaymentId,
    CarrotEnoteType,
    JanusAnchor,
    bool,
)> {
    let (
        sender_extension_g,
        sender_extension_t,
        address_spend_pubkey,
        amount,
        amount_blinding_factor,
        mut payment_id,
        enote_type,
        janus_anchor,
    ) = unsafe {
        try_scan_carrot_enote_external_no_janus(
            enote,
            encrypted_payment_id,
            s_sender_receiver_unctx,
        )
    }?;

    let verified_normal_janus = unsafe {
        verify_carrot_normal_janus_protection_and_confirm_pid(
            &&&InputContext::new_ringct(&enote.tx_first_key_image),
            &address_spend_pubkey,
            !is_main_address_spend_pubkey(&address_spend_pubkey, main_address_spend_pubkeys),
            &enote.enote_ephemeral_pubkey,
            &janus_anchor,
            &mut payment_id,
        )
    };

    Some((
        sender_extension_g,
        sender_extension_t,
        address_spend_pubkey,
        amount,
        amount_blinding_factor,
        payment_id,
        enote_type,
        janus_anchor,
        verified_normal_janus,
    ))
}

pub fn make_carrot_uncontextualized_shared_key_receiver<VI: ViewIncomingKeyDevice>(
    k_view_dev: &VI,
    enote_ephemeral_pubkey: &EnoteEphemeralPubkey,
) -> device::Result<MontgomeryECDH> {
    k_view_dev.view_key_scalar_mult_x25519(enote_ephemeral_pubkey)
}

pub fn try_scan_carrot_coinbase_enote_sender_with_anchor_norm(
    enote: &CarrotCoinbaseEnoteV1,
    destination: &CarrotDestinationV1,
    anchor_norm: &JanusAnchor,
) -> Option<(OnetimeExtensionG, OnetimeExtensionT)> {
    let enote_ephemeral_privkey = EnoteEphemeralKey::derive(
        anchor_norm,
        &InputContext::new_coinbase(enote.block_index),
        &destination.address_spend_pubkey,
        &destination.payment_id,
    );

    try_scan_carrot_coinbase_enote_sender_with_ephemeral_key(
        enote,
        destination,
        &enote_ephemeral_privkey,
    )
}

pub fn try_scan_carrot_coinbase_enote_sender_with_ephemeral_key(
    enote: &CarrotCoinbaseEnoteV1,
    destination: &CarrotDestinationV1,
    enote_ephemeral_privkey: &EnoteEphemeralKey,
) -> Option<(OnetimeExtensionG, OnetimeExtensionT)> {
    // s_sr = d_e ConvertPointE(K^j_v)
    let s_sender_receiver_unctx = MontgomeryECDH::derive_as_sender(
        enote_ephemeral_privkey,
        &destination.address_view_pubkey,
    )?;

    let (sender_extension_g, sender_extension_t, address_spend_pubkey) =
        try_scan_carrot_coinbase_enote_checked(
            enote,
            &s_sender_receiver_unctx,
            core::slice::from_ref(&destination.address_spend_pubkey),
        )?;

    if &address_spend_pubkey != &destination.address_spend_pubkey {
        return None;
    }

    Some((sender_extension_g, sender_extension_t))
}

pub fn try_scan_carrot_coinbase_enote_receiver(
    enote: &CarrotCoinbaseEnoteV1,
    s_sender_receiver_unctx: &MontgomeryECDH,
    main_address_spend_pubkeys: &[AddressSpendPubkey],
) -> Option<(OnetimeExtensionG, OnetimeExtensionT, AddressSpendPubkey)> {
    try_scan_carrot_coinbase_enote_checked(
        enote,
        s_sender_receiver_unctx,
        main_address_spend_pubkeys,
    )
}

pub fn try_scan_carrot_enote_external_sender_with_anchor_norm(
    enote: &CarrotEnoteV1,
    encrypted_payment_id: Option<&EncryptedPaymentId>,
    destination: &CarrotDestinationV1,
    anchor_norm: &JanusAnchor,
    check_pid: bool,
) -> Option<(
    OnetimeExtensionG,
    OnetimeExtensionT,
    Amount,
    AmountBlindingKey,
    CarrotEnoteType,
)> {
    let enote_ephemeral_privkey = EnoteEphemeralKey::derive(
        anchor_norm,
        &InputContext::new_ringct(&enote.tx_first_key_image),
        &destination.address_spend_pubkey,
        &destination.payment_id,
    );

    try_scan_carrot_enote_external_sender_with_ephemeral_key(
        &enote,
        encrypted_payment_id,
        destination,
        &enote_ephemeral_privkey,
        check_pid,
    )
}

pub fn try_scan_carrot_enote_external_sender_with_ephemeral_key(
    enote: &CarrotEnoteV1,
    encrypted_payment_id: Option<&EncryptedPaymentId>,
    destination: &CarrotDestinationV1,
    enote_ephemeral_privkey: &EnoteEphemeralKey,
    check_pid: bool,
) -> Option<(
    OnetimeExtensionG,
    OnetimeExtensionT,
    Amount,
    AmountBlindingKey,
    CarrotEnoteType,
)> {
    // s_sr = d_e ConvertPointE(K^j_v)
    let s_sender_receiver_unctx = MontgomeryECDH::derive_as_sender(
        enote_ephemeral_privkey,
        &destination.address_view_pubkey,
    )?;

    try_scan_carrot_enote_external_sender_with_shared_secret(
        enote,
        encrypted_payment_id,
        destination,
        &s_sender_receiver_unctx,
        check_pid,
    )
}

pub fn try_scan_carrot_enote_external_sender_with_shared_secret(
    enote: &CarrotEnoteV1,
    encrypted_payment_id: Option<&EncryptedPaymentId>,
    destination: &CarrotDestinationV1,
    s_sender_receiver_unctx: &MontgomeryECDH,
    check_pid: bool,
) -> Option<(
    OnetimeExtensionG,
    OnetimeExtensionT,
    Amount,
    AmountBlindingKey,
    CarrotEnoteType,
)> {
    let (
        sender_extension_g,
        sender_extension_t,
        recovered_address_spend_pubkey,
        amount,
        amount_blinding_factor,
        recovered_payment_id,
        recovered_enote_type,
        _,
        verified_normal_janus,
    ) = try_scan_carrot_enote_external_normal_checked(
        enote,
        encrypted_payment_id,
        s_sender_receiver_unctx,
        core::slice::from_ref(&destination.address_spend_pubkey),
    )?;

    if !verified_normal_janus {
        return None;
    } else if recovered_address_spend_pubkey != destination.address_spend_pubkey {
        return None;
    } else if check_pid && recovered_payment_id != destination.payment_id {
        return None;
    } else if recovered_enote_type != CarrotEnoteType::Payment {
        return None;
    }

    Some((
        sender_extension_g,
        sender_extension_t,
        amount,
        amount_blinding_factor,
        recovered_enote_type,
    ))
}

pub fn try_scan_carrot_enote_external_receiver<VI: ViewIncomingKeyDevice>(
    enote: &CarrotEnoteV1,
    encrypted_payment_id: Option<&EncryptedPaymentId>,
    s_sender_receiver_unctx: &MontgomeryECDH,
    main_address_spend_pubkeys: &[AddressSpendPubkey],
    k_view_dev: &VI,
) -> Option<(
    OnetimeExtensionG,
    OnetimeExtensionT,
    AddressSpendPubkey,
    Amount,
    AmountBlindingKey,
    PaymentId,
    CarrotEnoteType,
)> {
    let (
        sender_extension_g,
        sender_extension_t,
        address_spend_pubkey,
        amount,
        amount_blinding_factor,
        payment_id,
        enote_type,
        nominal_janus_anchor,
        verified_normal_janus,
    ) = try_scan_carrot_enote_external_normal_checked(
        enote,
        encrypted_payment_id,
        s_sender_receiver_unctx,
        main_address_spend_pubkeys,
    )?;

    if !verified_normal_janus
        && unsafe {
            !verify_carrot_special_janus_protection(
                &enote.tx_first_key_image,
                &enote.enote_ephemeral_pubkey,
                &enote.onetime_address,
                k_view_dev,
                &nominal_janus_anchor,
            )
        }
    {
        return None;
    }

    Some((
        sender_extension_g,
        sender_extension_t,
        address_spend_pubkey,
        amount,
        amount_blinding_factor,
        payment_id,
        enote_type,
    ))
}

pub fn try_scan_carrot_enote_internal_receiver<VB: ViewBalanceSecretDevice>(
    enote: &CarrotEnoteV1,
    s_view_balance_dev: &VB,
) -> Option<(
    OnetimeExtensionG,
    OnetimeExtensionT,
    AddressSpendPubkey,
    Amount,
    AmountBlindingKey,
    CarrotEnoteType,
    JanusAnchor,
)> {
    // input_context
    let input_context = InputContext::new_ringct(&enote.tx_first_key_image);

    // vt = H_3(s_sr || input_context || Ko)
    let nominal_view_tag = s_view_balance_dev
        .make_internal_view_tag(&input_context, &enote.onetime_address)
        .ok()?;

    // test view tag
    if nominal_view_tag != enote.view_tag {
        return None;
    }

    // s^ctx_sr = H_32(s_vb, D_e, input_context)
    let s_sender_receiver = s_view_balance_dev
        .make_internal_sender_receiver_secret(&enote.enote_ephemeral_pubkey, &input_context)
        .ok()?;

    unsafe { try_scan_carrot_enote_internal_burnt(enote, &s_sender_receiver) }

    // janus protection checks are not needed for internal scans
}
