use curve25519_dalek::MontgomeryPoint;

use crate::core_types::*;
use crate::domain_separators;
use crate::hash_functions::*;
use crate::math_utils::*;
use crate::transcript::*;

pub fn make_carrot_enote_ephemeral_privkey(
    anchor_norm: &JanusAnchor,
    input_context: &InputContext,
    address_spend_pubkey: &AddressSpendPubkey,
    payment_id: &PaymentId,
) -> EnoteEphemeralKey {
    // k_e = (H_64(anchor_norm, input_context, K^j_s, pid)) mod l
    let transcript = make_carrot_transcript!(domain_separators::EPHEMERAL_PRIVKEY,
        JanusAnchor : anchor_norm, InputContext : input_context, AddressSpendPubkey : address_spend_pubkey,
        PaymentId : payment_id);
    EnoteEphemeralKey(ScalarSecret(derive_scalar(&transcript, &[])))
}

pub fn make_carrot_enote_ephemeral_pubkey_cryptonote(
    enote_ephemeral_privkey: &EnoteEphemeralKey,
) -> EnoteEphemeralPubkey {
    // D_e = d_e B
    EnoteEphemeralPubkey(MontgomeryPoint::mul_base(&enote_ephemeral_privkey.0.0))
}

pub fn make_carrot_enote_ephemeral_pubkey_subaddress(
    enote_ephemeral_privkey: &EnoteEphemeralKey,
    address_spend_pubkey: &AddressSpendPubkey,
) -> Option<EnoteEphemeralPubkey> {
    // D_e = ConvertPointE(d_e K^j_s)
    #[allow(non_snake_case)]
    let K_e = scalar_mul_key_vartime(&enote_ephemeral_privkey.0.0, &address_spend_pubkey.0)?;
    Some(EnoteEphemeralPubkey(convert_to_montgomery_vartime(&K_e)?))
}

pub fn make_carrot_enote_ephemeral_pubkey(
    enote_ephemeral_privkey: &EnoteEphemeralKey,
    address_spend_pubkey: &AddressSpendPubkey,
    is_subaddress: bool,
) -> Option<EnoteEphemeralPubkey> {
    if is_subaddress {
        // D_e = d_e ConvertPointE(K^j_s)
        make_carrot_enote_ephemeral_pubkey_subaddress(enote_ephemeral_privkey, address_spend_pubkey)
    } else
    // !is_subaddress
    {
        // D_e = d_e B
        Some(make_carrot_enote_ephemeral_pubkey_cryptonote(
            enote_ephemeral_privkey,
        ))
    }
}

pub fn make_carrot_uncontextualized_shared_key_receiver(
    k_view: &ViewIncomingKey,
    enote_ephemeral_pubkey: &EnoteEphemeralPubkey,
) -> MontgomeryECDH {
    // s_sr = k_v D_e
    MontgomeryECDH(&k_view.0.0 * &enote_ephemeral_pubkey.0)
}

pub fn make_carrot_uncontextualized_shared_key_sender(
    enote_ephemeral_privkey: &EnoteEphemeralKey,
    address_view_pubkey: &AddressViewPubkey,
) -> Option<MontgomeryECDH> {
    // if K^j_v not in prime order subgroup, then FAIL
    if is_invalid_or_has_torsion(&address_view_pubkey.0) {
        return None;
    }

    // s_sr = d_e * ConvertPointE(K^j_v)
    Some(MontgomeryECDH(
        &enote_ephemeral_privkey.0.0 * convert_to_montgomery_vartime(&address_view_pubkey.0)?,
    ))
}

pub fn make_carrot_view_tag(
    s_sender_receiver_unctx: &[u8; 32],
    input_context: &InputContext,
    onetime_address: &OutputPubkey,
) -> ViewTag {
    // vt = H_3(s_sr || input_context || Ko)
    let transcript = make_carrot_transcript!(domain_separators::VIEW_TAG,
        InputContext : input_context, OutputPubkey : onetime_address);
    ViewTag(derive_bytes_3(&transcript, s_sender_receiver_unctx))
}

pub fn make_carrot_input_context_coinbase(block_index: BlockIndex) -> InputContext {
    // input_context = "C" || IntToBytes256(block_index)
    let mut input_context = InputContext::default();
    input_context.0[0] = domain_separators::INPUT_CONTEXT_COINBASE;
    input_context.0[1..(1 + 8)].copy_from_slice(&block_index.to_le_bytes());
    input_context
}

pub fn make_carrot_input_context(first_rct_key_image: &KeyImage) -> InputContext {
    // input_context = "R" || KI_1
    let mut input_context = InputContext::default();
    input_context.0[0] = domain_separators::INPUT_CONTEXT_RINGCT;
    input_context.0[1..].copy_from_slice(&first_rct_key_image.0.0);
    input_context
}

pub fn make_carrot_sender_receiver_secret(
    s_sender_receiver_unctx: &[u8; 32],
    enote_ephemeral_pubkey: &EnoteEphemeralPubkey,
    input_context: &InputContext,
) -> SenderReceiverSecret {
    // s^ctx_sr = H_32(s_sr, D_e, input_context)
    let transcript = make_carrot_transcript!(domain_separators::SENDER_RECEIVER_SECRET,
        EnoteEphemeralPubkey : enote_ephemeral_pubkey, InputContext : input_context);
    SenderReceiverSecret(Uniform32Secret(derive_bytes_32(
        &transcript,
        s_sender_receiver_unctx,
    )))
}

pub fn make_carrot_onetime_address_extension_g(
    s_sender_receiver: &SenderReceiverSecret,
    amount_commitment: &AmountCommitment,
) -> OnetimeExtensionG {
    // k^o_g = H_n("..g..", s^ctx_sr, C_a)
    let transcript = make_carrot_transcript!(domain_separators::ONETIME_EXTENSION_G,
        AmountCommitment : amount_commitment);
    OnetimeExtensionG(ScalarSecret(derive_scalar(
        &transcript,
        &s_sender_receiver.0.0,
    )))
}

pub fn make_carrot_onetime_address_extension_t(
    s_sender_receiver: &SenderReceiverSecret,
    amount_commitment: &AmountCommitment,
) -> OnetimeExtensionT {
    // k^o_t = H_n("..t..", s^ctx_sr, C_a)
    let transcript = make_carrot_transcript!(domain_separators::ONETIME_EXTENSION_T,
        AmountCommitment : amount_commitment);
    OnetimeExtensionT(ScalarSecret(derive_scalar(
        &transcript,
        &s_sender_receiver.0.0,
    )))
}

pub fn make_carrot_onetime_address_extension_pubkey(
    s_sender_receiver: &SenderReceiverSecret,
    amount_commitment: &AmountCommitment,
) -> OnetimeExtension {
    // k^o_g = H_n("..g..", s^ctx_sr, C_a)
    let onetime_ext_g =
        make_carrot_onetime_address_extension_g(s_sender_receiver, amount_commitment);

    // k^o_t = H_n("..t..", s^ctx_sr, C_a)
    let onetime_ext_t =
        make_carrot_onetime_address_extension_t(s_sender_receiver, amount_commitment);

    // K^o_ext = k^o_g G + k^o_t T
    OnetimeExtension(scalar_mul_gt(&onetime_ext_g.0.0, &onetime_ext_t.0.0))
}

pub fn make_carrot_onetime_address(
    address_spend_pubkey: &AddressSpendPubkey,
    s_sender_receiver: &SenderReceiverSecret,
    amount_commitment: &AmountCommitment,
) -> Option<OutputPubkey> {
    // K^o_ext = k^o_g G + k^o_t T
    let sender_extension_pubkey =
        make_carrot_onetime_address_extension_pubkey(s_sender_receiver, amount_commitment);

    // Ko = K^j_s + K^o_ext
    Some(OutputPubkey(add_edwards(
        &address_spend_pubkey.0,
        &sender_extension_pubkey.0,
    )?))
}

pub fn make_carrot_amount_blinding_factor(
    s_sender_receiver: &SenderReceiverSecret,
    amount: Amount,
    address_spend_pubkey: &AddressSpendPubkey,
    enote_type: CarrotEnoteType,
) -> AmountBlindingKey {
    let enote_type_u8: u8 = match enote_type {
        CarrotEnoteType::Payment => 0,
        CarrotEnoteType::Change => 1,
    };
    // k_a = H_n(s^ctx_sr, a, K^j_s, enote_type)
    let transcript = make_carrot_transcript!(domain_separators::AMOUNT_BLINDING_FACTOR,
        Amount: &amount, AddressSpendPubkey : address_spend_pubkey, u8 : &enote_type_u8);
    AmountBlindingKey(ScalarSecret(derive_scalar(
        &transcript,
        &s_sender_receiver.0.0,
    )))
}

pub fn make_carrot_amount_commitment(
    amount: Amount,
    amount_blinding_factor: &AmountBlindingKey,
) -> AmountCommitment {
    AmountCommitment(commit(amount, &amount_blinding_factor.0.0))
}

pub fn make_carrot_anchor_encryption_mask(
    s_sender_receiver: &SenderReceiverSecret,
    onetime_address: &OutputPubkey,
) -> EncryptedJanusAnchor {
    // m_anchor = H_16(s^ctx_sr, Ko)
    let transcript = make_carrot_transcript!(domain_separators::ENCRYPTION_MASK_ANCHOR,
        OutputPubkey : onetime_address);
    EncryptedJanusAnchor(derive_bytes_16(&transcript, &s_sender_receiver.0.0))
}

pub fn encrypt_carrot_anchor(
    anchor: &JanusAnchor,
    s_sender_receiver: &SenderReceiverSecret,
    onetime_address: &OutputPubkey,
) -> EncryptedJanusAnchor {
    // m_anchor = H_16(s^ctx_sr, Ko)
    let mask = make_carrot_anchor_encryption_mask(s_sender_receiver, onetime_address);

    // anchor_enc = anchor XOR m_anchor
    anchor ^ &mask
}

pub fn decrypt_carrot_anchor(
    encrypted_anchor: &EncryptedJanusAnchor,
    s_sender_receiver: &SenderReceiverSecret,
    onetime_address: &OutputPubkey,
) -> JanusAnchor {
    // m_anchor = H_16(s^ctx_sr, Ko)
    let mask = make_carrot_anchor_encryption_mask(s_sender_receiver, onetime_address);

    // anchor = anchor_enc XOR m_anchor
    encrypted_anchor ^ &mask
}

pub fn make_carrot_amount_encryption_mask(
    s_sender_receiver: &SenderReceiverSecret,
    onetime_address: &OutputPubkey,
) -> EncryptedAmount {
    // m_a = H_8(s^ctx_sr, Ko)
    let transcript = make_carrot_transcript!(domain_separators::ENCRYPTION_MASK_AMOUNT,
        OutputPubkey : onetime_address);
    EncryptedAmount(derive_bytes_8(&transcript, &s_sender_receiver.0.0))
}

pub fn encrypt_carrot_amount(
    amount: Amount,
    s_sender_receiver: &SenderReceiverSecret,
    onetime_address: &OutputPubkey,
) -> EncryptedAmount {
    // m_a = H_8(s^ctx_sr, Ko)
    let mask = make_carrot_amount_encryption_mask(s_sender_receiver, onetime_address);

    // a_enc = a XOR m_a  [paying attention to system endianness]
    &amount ^ &mask
}

pub fn decrypt_carrot_amount(
    encrypted_amount: &EncryptedAmount,
    s_sender_receiver: &SenderReceiverSecret,
    onetime_address: &OutputPubkey,
) -> Amount {
    // m_a = H_8(s^ctx_sr, Ko)
    let mask = make_carrot_amount_encryption_mask(s_sender_receiver, onetime_address);

    // a = a_enc XOR m_a  [paying attention to system endianness]
    encrypted_amount ^ &mask
}

pub fn make_carrot_payment_id_encryption_mask(
    s_sender_receiver: &SenderReceiverSecret,
    onetime_address: &OutputPubkey,
) -> EncryptedPaymentId {
    // m_pid = H_8(s^ctx_sr, Ko)
    let transcript = make_carrot_transcript!(domain_separators::ENCRYPTION_MASK_PAYMENT_ID,
        OutputPubkey : onetime_address);
    EncryptedPaymentId(derive_bytes_8(&transcript, &s_sender_receiver.0.0))
}

pub fn encrypt_legacy_payment_id(
    payment_id: &PaymentId,
    s_sender_receiver: &SenderReceiverSecret,
    onetime_address: &OutputPubkey,
) -> EncryptedPaymentId {
    // m_pid = H_8(s^ctx_sr, Ko)
    let mask = make_carrot_payment_id_encryption_mask(s_sender_receiver, onetime_address);

    // pid_enc = pid XOR m_pid
    payment_id ^ &mask
}

pub fn decrypt_legacy_payment_id(
    encrypted_payment_id: &EncryptedPaymentId,
    s_sender_receiver: &SenderReceiverSecret,
    onetime_address: &OutputPubkey,
) -> PaymentId {
    // m_pid = H_8(s^ctx_sr, Ko)
    let mask = make_carrot_payment_id_encryption_mask(s_sender_receiver, onetime_address);

    // pid = pid_enc XOR m_pid
    encrypted_payment_id ^ &mask
}

pub fn make_carrot_janus_anchor_special(
    enote_ephemeral_pubkey: &EnoteEphemeralPubkey,
    input_context: &InputContext,
    onetime_address: &OutputPubkey,
    k_view: &ViewIncomingKey,
) -> JanusAnchor {
    // anchor_sp = H_16(D_e, input_context, Ko, k_v)
    let transcript = make_carrot_transcript!(domain_separators::JANUS_ANCHOR_SPECIAL,
        EnoteEphemeralPubkey : enote_ephemeral_pubkey, InputContext : input_context, OutputPubkey : onetime_address);
    JanusAnchor(derive_bytes_16(&transcript, &k_view.0.0.to_bytes()))
}

pub fn recover_address_spend_pubkey(
    onetime_address: &OutputPubkey,
    s_sender_receiver: &SenderReceiverSecret,
    amount_commitment: &AmountCommitment,
) -> Option<AddressSpendPubkey> {
    // K^o_ext = k^o_g G + k^o_t T
    let sender_extension_pubkey =
        make_carrot_onetime_address_extension_pubkey(s_sender_receiver, amount_commitment);

    // K^j_s = Ko - K^o_ext
    Some(AddressSpendPubkey(sub_edwards(
        &onetime_address.0,
        &sender_extension_pubkey.0,
    )?))
}

pub fn test_carrot_view_tag(
    s_sender_receiver_unctx: &[u8; 32],
    input_context: &InputContext,
    onetime_address: &OutputPubkey,
    view_tag: &ViewTag,
) -> bool {
    // vt' = H_3(s_sr || input_context || Ko)
    let nominal_view_tag =
        make_carrot_view_tag(s_sender_receiver_unctx, input_context, onetime_address);

    // vt' ?= vt
    nominal_view_tag == *view_tag
}

pub fn try_recompute_carrot_amount_commitment(
    s_sender_receiver: &SenderReceiverSecret,
    nominal_amount: Amount,
    nominal_address_spend_pubkey: &AddressSpendPubkey,
    nominal_enote_type: CarrotEnoteType,
    amount_commitment: &AmountCommitment,
) -> Option<AmountBlindingKey> {
    // k_a' = H_n(s^ctx_sr, a', K^j_s', enote_type')
    let amount_blinding_factor = make_carrot_amount_blinding_factor(
        s_sender_receiver,
        nominal_amount,
        nominal_address_spend_pubkey,
        nominal_enote_type,
    );

    // C_a' = k_a' G + a' H
    let nominal_amount_commitment = commit(nominal_amount, &amount_blinding_factor.0.0);

    // C_a' ?= C_a
    if &nominal_amount_commitment == &amount_commitment.0 {
        Some(amount_blinding_factor)
    } else {
        None
    }
}

pub fn try_get_carrot_amount(
    s_sender_receiver: &SenderReceiverSecret,
    encrypted_amount: &EncryptedAmount,
    onetime_address: &OutputPubkey,
    address_spend_pubkey: &AddressSpendPubkey,
    amount_commitment: &AmountCommitment,
) -> Option<(Amount, AmountBlindingKey, CarrotEnoteType)> {
    // a' = a_enc XOR m_a
    let amount = decrypt_carrot_amount(encrypted_amount, s_sender_receiver, onetime_address);

    // set enote_type <- "payment"
    let enote_type = CarrotEnoteType::Payment;

    // if C_a ?= k_a' G + a' H, then PASS
    if let Some(amount_blinding_factor) = try_recompute_carrot_amount_commitment(
        s_sender_receiver,
        amount,
        address_spend_pubkey,
        enote_type,
        amount_commitment,
    ) {
        return Some((amount, amount_blinding_factor, enote_type));
    }

    // set enote_type <- "change"
    let enote_type = CarrotEnoteType::Change;

    // if C_a ?= k_a' G + a' H, then PASS
    if let Some(amount_blinding_factor) = try_recompute_carrot_amount_commitment(
        s_sender_receiver,
        amount,
        address_spend_pubkey,
        enote_type,
        amount_commitment,
    ) {
        return Some((amount, amount_blinding_factor, enote_type));
    }

    // neither attempt at recomputing passed: so FAIL
    None
}

pub fn verify_carrot_normal_janus_protection(
    nominal_anchor: &JanusAnchor,
    input_context: &InputContext,
    nominal_address_spend_pubkey: &AddressSpendPubkey,
    is_subaddress: bool,
    nominal_payment_id: &PaymentId,
    enote_ephemeral_pubkey: &EnoteEphemeralPubkey,
) -> bool {
    // d_e' = H_n(anchor_norm, input_context, K^j_s, pid))
    let nominal_enote_ephemeral_privkey = make_carrot_enote_ephemeral_privkey(
        nominal_anchor,
        input_context,
        nominal_address_spend_pubkey,
        nominal_payment_id,
    );

    // recompute D_e' for d_e' and address type
    let Some(nominal_enote_ephemeral_pubkey) = make_carrot_enote_ephemeral_pubkey(
        &nominal_enote_ephemeral_privkey,
        nominal_address_spend_pubkey,
        is_subaddress,
    ) else {
        return false;
    };

    // D_e' ?= D_e
    &nominal_enote_ephemeral_pubkey.0 == &enote_ephemeral_pubkey.0
}

#[cfg(test)]
mod test {
    use crate::enote_utils::*;
    use crate::unit_testing::*;

    #[test]
    fn converge_make_carrot_enote_ephemeral_privkey() {
        assert_eq_hex!(
            "6d4645a0e398ff430f68eaa78240dd2c04051e9a50438cd9c9c3c0e12af68b0b",
            make_carrot_enote_ephemeral_privkey(
                &hex_into!("caee1381775487a0982557f0d2680b55"),
                &hex_into!("9423f74f3e869dc8427d8b35bb24c917480409c3f4750bff3c742f8e4d5af7bef7"),
                &hex_into!("1ebcddd5d98e26788ed8d8510de7f520e973902238e107a070aad104e166b6a0"),
                &hex_into!("4321734f56621440")));
    }

    #[test]
    fn converge_make_carrot_enote_ephemeral_pubkey_cryptonote() {
        assert_eq_hex!(
            "2987777565c02409dfe871cc27b2334f5ade9d4ad014012c568367b80e99c666",
            make_carrot_enote_ephemeral_pubkey_cryptonote(
                &hex_into!("f57ff2d7c898b755137b69e8d826801945ed72e9951850de908e9d645a0bb00d")));
    }

    #[test]
    fn converge_make_carrot_enote_ephemeral_pubkey_subaddress() {
        assert_eq_hex!(
            "d8b8ce01943edd05d7db66aeb15109c58ec270796f0c76c03d58a398926aca55",
            make_carrot_enote_ephemeral_pubkey_subaddress(
                &hex_into!("f57ff2d7c898b755137b69e8d826801945ed72e9951850de908e9d645a0bb00d"),
                &hex_into!("1ebcddd5d98e26788ed8d8510de7f520e973902238e107a070aad104e166b6a0")
            ).unwrap());
    }

    #[test]
    fn converge_make_carrot_uncontextualized_shared_key_receiver() {
        assert_eq_hex!(
            "baa47cfc380374b15cb5a3048099968962a66e287d78654c75b550d711e58451",
            make_carrot_uncontextualized_shared_key_receiver(
                &hex_into!("60eff3ec120a12bb44d4258816e015952fc5651040da8c8af58c17676485f200"),
                &hex_into!("d8b8ce01943edd05d7db66aeb15109c58ec270796f0c76c03d58a398926aca55")
            ));
    }

    #[test]
    fn converge_make_carrot_uncontextualized_shared_key_sender() {
        assert_eq_hex!(
            "baa47cfc380374b15cb5a3048099968962a66e287d78654c75b550d711e58451",
            make_carrot_uncontextualized_shared_key_sender(
                &hex_into!("f57ff2d7c898b755137b69e8d826801945ed72e9951850de908e9d645a0bb00d"),
                &hex_into!("75b7bc7759da5d9ad5ff421650949b27a13ea369685eb4d1bd59abc518e25fe2")
            ).unwrap());
    }

    #[test]
    fn converge_make_carrot_sender_receiver_secret() {
        assert_eq_hex!(
            "232e62041ee1262cb3fce0d10fdbd018cca5b941ff92283676d6112aa426f76c",
            make_carrot_sender_receiver_secret(
                &hex_into!("baa47cfc380374b15cb5a3048099968962a66e287d78654c75b550d711e58451"),
                &hex_into!("d8b8ce01943edd05d7db66aeb15109c58ec270796f0c76c03d58a398926aca55"),
                &hex_into!("9423f74f3e869dc8427d8b35bb24c917480409c3f4750bff3c742f8e4d5af7bef7")
            ));
    }

    #[test]
    fn converge_make_carrot_amount_blinding_factor_payment() {
        assert_eq_hex!(
            "9fc3581e926a844877479d829ff9deeae17ce77feaf2c3c972923510e04f1f02",
            make_carrot_amount_blinding_factor(
                &hex_into!("232e62041ee1262cb3fce0d10fdbd018cca5b941ff92283676d6112aa426f76c"),
                23000000000000,
                &hex_into!("1ebcddd5d98e26788ed8d8510de7f520e973902238e107a070aad104e166b6a0"),
                CarrotEnoteType::Payment
            ));
    }

    #[test]
    fn converge_make_carrot_amount_blinding_factor_change() {
        assert_eq_hex!(
            "dda34eac46030e4084f5a2c808d0a82ffaa82cbf01d4a74d7ee0d4fe72c31a0f",
            make_carrot_amount_blinding_factor(
                &hex_into!("232e62041ee1262cb3fce0d10fdbd018cca5b941ff92283676d6112aa426f76c"),
                23000000000000,
                &hex_into!("1ebcddd5d98e26788ed8d8510de7f520e973902238e107a070aad104e166b6a0"),
                CarrotEnoteType::Change
            ));
    }

    #[test]
    fn converge_make_carrot_amount_commitment() {
        assert_eq_hex!(
            "ca5f0fc2fe7a4fe628e6f08b2c0eb44f3af3b87e1619b2ed2de296f7e425512b",
            make_carrot_amount_commitment(
                23000000000000,
                &hex_into!("9fc3581e926a844877479d829ff9deeae17ce77feaf2c3c972923510e04f1f02"),
            ));
    }

    #[test]
    fn converge_make_carrot_onetime_address() {
        assert_eq_hex!(
            "4c93cf2d7ff8556eac73025ab3019a0db220b56bdf0387e0524724cc0e409d92",
            make_carrot_onetime_address(
                &hex_into!("1ebcddd5d98e26788ed8d8510de7f520e973902238e107a070aad104e166b6a0"),
                &hex_into!("232e62041ee1262cb3fce0d10fdbd018cca5b941ff92283676d6112aa426f76c"),
                &hex_into!("ca5f0fc2fe7a4fe628e6f08b2c0eb44f3af3b87e1619b2ed2de296f7e425512b")
            ).unwrap());
    }

    #[test]
    fn converge_make_carrot_view_tag() {
        assert_eq_hex!(
            "0176f6",
            make_carrot_view_tag(
                &hex_into!("baa47cfc380374b15cb5a3048099968962a66e287d78654c75b550d711e58451"),
                &hex_into!("9423f74f3e869dc8427d8b35bb24c917480409c3f4750bff3c742f8e4d5af7bef7"),
                &hex_into!("4c93cf2d7ff8556eac73025ab3019a0db220b56bdf0387e0524724cc0e409d92")
            ));
    }

    #[test]
    fn converge_make_carrot_anchor_encryption_mask() {
        assert_eq_hex!(
            "52d95a8e441f26a056f55094938cbfa8",
            make_carrot_anchor_encryption_mask(
                &hex_into!("232e62041ee1262cb3fce0d10fdbd018cca5b941ff92283676d6112aa426f76c"),
                &hex_into!("4c93cf2d7ff8556eac73025ab3019a0db220b56bdf0387e0524724cc0e409d92")
            ));
    }

    #[test]
    fn converge_make_carrot_amount_encryption_mask() {
        assert_eq_hex!(
            "98d25d1db65b6a3e",
            make_carrot_amount_encryption_mask(
                &hex_into!("232e62041ee1262cb3fce0d10fdbd018cca5b941ff92283676d6112aa426f76c"),
                &hex_into!("4c93cf2d7ff8556eac73025ab3019a0db220b56bdf0387e0524724cc0e409d92")
            ));
    }

    #[test]
    fn converge_make_carrot_payment_id_encryption_mask() {
        assert_eq_hex!(
            "b57a1560e82e2483",
            make_carrot_payment_id_encryption_mask(
                &hex_into!("232e62041ee1262cb3fce0d10fdbd018cca5b941ff92283676d6112aa426f76c"),
                &hex_into!("4c93cf2d7ff8556eac73025ab3019a0db220b56bdf0387e0524724cc0e409d92")
            ));
    }

    #[test]
    fn converge_make_carrot_janus_anchor_special() {
        assert_eq_hex!(
            "31afa8f580feaf736cd424ecc9ae5fd2",
            make_carrot_janus_anchor_special(
                &hex_into!("d8b8ce01943edd05d7db66aeb15109c58ec270796f0c76c03d58a398926aca55"),
                &hex_into!("9423f74f3e869dc8427d8b35bb24c917480409c3f4750bff3c742f8e4d5af7bef7"),
                &hex_into!("4c93cf2d7ff8556eac73025ab3019a0db220b56bdf0387e0524724cc0e409d92"),
                &hex_into!("60eff3ec120a12bb44d4258816e015952fc5651040da8c8af58c17676485f200")
            ));
    }
}
