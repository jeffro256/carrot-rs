use curve25519_dalek::MontgomeryPoint;
use curve25519_dalek::edwards::CompressedEdwardsY;
use zeroize::ZeroizeOnDrop;

use crate::as_crypto::AsEdwardsPoint;
use crate::as_crypto::AsMontgomeryPoint;
use crate::as_crypto::AsScalar;
use crate::consts::*;
use crate::domain_separators;
use crate::hash_functions::*;
use crate::math_utils::*;
use crate::random::Random;
use crate::transcript::*;
use crate::type_macros::*;
use crate::*;

define_tiny_edwards_type! {OutputPubkey, "ReRingCT transaction output pubkey / one-time address"}
define_tiny_edwards_type! {AmountCommitment, "ReRingCT transaction output amount commitment"}
define_tiny_edwards_type! {KeyImageGenerator, "ReRingCT key image generator, result of hash-to-point of an output pubkey"}
define_tiny_edwards_type! {KeyImage, "ReRingCT key image"}
define_tiny_edwards_type! {OnetimeExtension, "Difference between one-time address and address spend pubkey"}

define_tiny_montgomery_type! {MontgomeryECDH, "External sender-receiver uncontextualized ECDH exchange", ZeroizeOnDrop}
define_tiny_montgomery_type! {EnoteEphemeralPubkey, "Enote ephemeral pubkey",}

define_tiny_scalar_type! {AmountBlindingKey, "Blinding factor for an amount commitment"}
define_tiny_scalar_type! {EnoteEphemeralKey, "Private key for an enote ephemeral pubkey"}
define_tiny_scalar_type! {OnetimeExtensionG, "Opening for a one-time extension against the G generator"}
define_tiny_scalar_type! {OnetimeExtensionT, "Opening for a one-time extension against the T generator"}

define_tiny_byte_type! {SenderReceiverSecret, "Contextualized sender-receiver uniform byte secret", 32, ZeroizeOnDrop}

define_tiny_byte_type! {JanusAnchor,
    "Janus anchor holds normal enote ephemeral private key randomness or special HMAC of enote ephemeral pubkey",
    JANUS_ANCHOR_BYTES}
define_tiny_byte_type! {EncryptedJanusAnchor,
    "Enote janus anchor, encrypted", JANUS_ANCHOR_BYTES}

/// ReRingCT amount, 64-bit
pub type Amount = u64;
define_tiny_byte_type! {EncryptedAmount, "Encrypted amount", ENCRYPTED_AMOUNT_BYTES}

define_tiny_byte_type! {EncryptedPaymentId, "Encrypted payment ID", PAYMENT_ID_BYTES}

define_tiny_byte_type! {ViewTag, "Carrot view tag", VIEW_TAG_BYTES}

define_tiny_byte_type! {InputContext, "Carrot input context", INPUT_CONTEXT_BYTES}

/// Block index for coinbase enote input contexts
pub type BlockIndex = u64;

/// carrot enote types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CarrotEnoteType {
    Payment,
    Change,
}

impl EnoteEphemeralKey {
    pub fn derive(
        anchor_norm: &JanusAnchor,
        input_context: &InputContext,
        address_spend_pubkey: &AddressSpendPubkey,
        payment_id: &PaymentId,
    ) -> Self {
        // k_e = (H_64(anchor_norm, input_context, K^j_s, pid)) mod l
        let transcript = make_carrot_transcript!(domain_separators::EPHEMERAL_PRIVKEY,
            JanusAnchor : anchor_norm, InputContext : input_context, AddressSpendPubkey : address_spend_pubkey,
            PaymentId : payment_id);
        EnoteEphemeralKey(derive_scalar(&transcript, &[]))
    }
}

impl EnoteEphemeralPubkey {
    pub fn derive_to_cryptonote_address(enote_ephemeral_privkey: &EnoteEphemeralKey) -> Self {
        // D_e = d_e B
        Self(scalar_mul_base_montgomery(enote_ephemeral_privkey))
    }

    pub fn derive_to_subaddress(
        enote_ephemeral_privkey: &EnoteEphemeralKey,
        address_spend_pubkey: &AddressSpendPubkey,
    ) -> Option<Self> {
        // D_e = ConvertPointE(d_e K^j_s)
        #[allow(non_snake_case)]
        let K_e: CompressedEdwardsY =
            scalar_mul_key(enote_ephemeral_privkey, address_spend_pubkey)?;
        Some(Self(convert_to_montgomery_vartime(&K_e)?))
    }

    pub fn derive_to(
        enote_ephemeral_privkey: &EnoteEphemeralKey,
        address_spend_pubkey: &AddressSpendPubkey,
        is_subaddress: bool,
    ) -> Option<Self> {
        if is_subaddress {
            // D_e = d_e ConvertPointE(K^j_s)
            Self::derive_to_subaddress(enote_ephemeral_privkey, address_spend_pubkey)
        } else {
            // D_e = d_e B
            Some(Self::derive_to_cryptonote_address(enote_ephemeral_privkey))
        }
    }
}

impl MontgomeryECDH {
    pub fn derive_as_receiver(
        k_view: &ViewIncomingKey,
        enote_ephemeral_pubkey: &EnoteEphemeralPubkey,
    ) -> Self {
        // s_sr = k_v D_e
        Self(k_view.as_scalar_ref() * enote_ephemeral_pubkey.as_montgomery_ref())
    }

    pub fn derive_as_sender(
        enote_ephemeral_privkey: &EnoteEphemeralKey,
        address_view_pubkey: &AddressViewPubkey,
    ) -> Option<Self> {
        // if K^j_v not in prime order subgroup, then FAIL
        if is_invalid_or_has_torsion(address_view_pubkey) {
            return None;
        }

        // s_sr = d_e * ConvertPointE(K^j_v)
        Some(Self(
            enote_ephemeral_privkey.as_scalar_ref()
                * convert_to_montgomery_vartime(address_view_pubkey)?,
        ))
    }
}

impl InputContext {
    pub fn new_coinbase(block_index: BlockIndex) -> Self {
        // input_context = "C" || IntToBytes256(block_index)
        let mut input_context = [0u8; INPUT_CONTEXT_BYTES];
        input_context[0] = domain_separators::INPUT_CONTEXT_COINBASE;
        input_context[1..(1 + 8)].copy_from_slice(&block_index.to_le_bytes());
        Self::from(input_context)
    }

    pub fn new_ringct(first_rct_key_image: &KeyImage) -> Self {
        // input_context = "R" || KI_1
        let mut input_context = [0u8; INPUT_CONTEXT_BYTES];
        input_context[0] = domain_separators::INPUT_CONTEXT_RINGCT;
        input_context[1..].copy_from_slice(&first_rct_key_image.as_edwards_ref().0);
        Self::from(input_context)
    }
}

impl SenderReceiverSecret {
    pub fn derive(
        s_sender_receiver_unctx: &[u8; 32],
        enote_ephemeral_pubkey: &EnoteEphemeralPubkey,
        input_context: &InputContext,
    ) -> Self {
        // s^ctx_sr = H_32(s_sr, D_e, input_context)
        let transcript = make_carrot_transcript!(domain_separators::SENDER_RECEIVER_SECRET,
            EnoteEphemeralPubkey : enote_ephemeral_pubkey, InputContext : input_context);
        Self::from(derive_bytes_32(&transcript, s_sender_receiver_unctx))
    }
}

impl AmountBlindingKey {
    pub fn derive(
        s_sender_receiver: &SenderReceiverSecret,
        amount: Amount,
        address_spend_pubkey: &AddressSpendPubkey,
        enote_type: CarrotEnoteType,
    ) -> Self {
        let enote_type_u8: u8 = match enote_type {
            CarrotEnoteType::Payment => 0,
            CarrotEnoteType::Change => 1,
        };
        // k_a = H_n(s^ctx_sr, a, K^j_s, enote_type)
        let transcript = make_carrot_transcript!(domain_separators::AMOUNT_BLINDING_FACTOR,
            Amount: &amount, AddressSpendPubkey : address_spend_pubkey, u8 : &enote_type_u8);
        Self(derive_scalar(&transcript, s_sender_receiver.as_bytes()))
    }
}

impl AmountCommitment {
    pub fn commit(amount: Amount, amount_blinding_factor: &AmountBlindingKey) -> Self {
        // z G + a H
        Self(
            (curve25519_dalek::EdwardsPoint::mul_base(amount_blinding_factor.as_scalar_ref())
                + curve25519_dalek::Scalar::from(amount) * *monero_generators::H)
                .compress(),
        )
    }

    pub fn clear_commit(amount: Amount) -> Self {
        // G + a H
        Self::commit(amount, &AmountBlindingKey::from(1u64))
    }
}

impl OnetimeExtensionG {
    pub fn derive_coinbase(
        s_sender_receiver: &SenderReceiverSecret,
        amount: Amount,
        main_address_spend_pubkey: &AddressSpendPubkey
    ) -> Self {
        // k^g_o = H_n[s^ctx_sr]("..coinbase..G..", a, K^0_s)
        let transcript = make_carrot_transcript!(domain_separators::ONETIME_EXTENSION_G_COINBASE,
            Amount : &amount, AddressSpendPubkey: main_address_spend_pubkey);
        Self(derive_scalar(&transcript, s_sender_receiver.as_bytes()))
    }

    pub fn derive_ringct(
        s_sender_receiver: &SenderReceiverSecret,
        amount_commitment: &AmountCommitment,
    ) -> Self {
        // k^g_o = H_n[s^ctx_sr]("..G..", C_a)
        let transcript = make_carrot_transcript!(domain_separators::ONETIME_EXTENSION_G,
            AmountCommitment : amount_commitment);
        Self(derive_scalar(&transcript, s_sender_receiver.as_bytes()))
    }
}

impl OnetimeExtensionT {
    pub fn derive_coinbase(
        s_sender_receiver: &SenderReceiverSecret,
        amount: Amount,
        main_address_spend_pubkey: &AddressSpendPubkey
    ) -> Self {
        // k^t_o = H_n[s^ctx_sr]("..coinbase..T..", a, K^0_s)
        let transcript = make_carrot_transcript!(domain_separators::ONETIME_EXTENSION_T_COINBASE,
            Amount : &amount, AddressSpendPubkey : main_address_spend_pubkey);
        Self(derive_scalar(&transcript, s_sender_receiver.as_bytes()))
    }

    pub fn derive_ringct(
        s_sender_receiver: &SenderReceiverSecret,
        amount_commitment: &AmountCommitment,
    ) -> Self {
        // k^t_o = H_n[s^ctx_sr]("..T..", C_a)
        let transcript = make_carrot_transcript!(domain_separators::ONETIME_EXTENSION_T,
            AmountCommitment : amount_commitment);
        Self(derive_scalar(&transcript, s_sender_receiver.as_bytes()))
    }
}

impl OnetimeExtension {
    pub fn derive_from_scalars(
        onetime_ext_g: &OnetimeExtensionG,
        onetime_ext_t: &OnetimeExtensionT,
    ) -> Self {
        // K^o_ext = k^g_o G + k^t_o T
        Self(scalar_mul_gt(onetime_ext_g, onetime_ext_t))
    }

    pub fn derive_coinbase(
        s_sender_receiver: &SenderReceiverSecret,
        amount: Amount,
        main_address_spend_pubkey: &AddressSpendPubkey
    ) -> Self {
        // k^g_o = H_n[s^ctx_sr]("..coinbase..G..", a, K^0_s)
        let onetime_ext_g = OnetimeExtensionG::derive_coinbase(
            s_sender_receiver,
            amount,
            main_address_spend_pubkey
        );

        // k^t_o = H_n[s^ctx_sr]("..coinbase..T..", a, K^0_s)
        let onetime_ext_t = OnetimeExtensionT::derive_coinbase(
            s_sender_receiver,
            amount,
            main_address_spend_pubkey
        );

        // K^o_ext = k^g_o G + k^t_o T
        Self::derive_from_scalars(&onetime_ext_g, &onetime_ext_t)
    }

    pub fn derive_ringct(
        s_sender_receiver: &SenderReceiverSecret,
        amount_commitment: &AmountCommitment,
    ) -> Self {
        // k^g_o = H_n[s^ctx_sr]("..G..", C_a)
        let onetime_ext_g = OnetimeExtensionG::derive_ringct(s_sender_receiver, amount_commitment);

        // k^t_o = H_n[s^ctx_sr]("..T..", C_a)
        let onetime_ext_t = OnetimeExtensionT::derive_ringct(s_sender_receiver, amount_commitment);

        // K^o_ext = k^g_o G + k^t_o T
        Self::derive_from_scalars(&onetime_ext_g, &onetime_ext_t)
    }
}

impl OutputPubkey {
    pub fn derive_from_extension(
        address_spend_pubkey: &AddressSpendPubkey,
        sender_extension_pubkey: &OnetimeExtension,
    ) -> Option<Self> {
        // Ko = K^j_s + K^o_ext
        Some(Self(add_edwards(
            address_spend_pubkey,
            sender_extension_pubkey,
        )?))
    }
}

impl AddressSpendPubkey {
    pub fn recover_from_extension(
        onetime_address: &OutputPubkey,
        sender_extension_pubkey: &OnetimeExtension
    ) -> Option<Self> {
        // K^j_s = Ko - K^o_ext
        Some(Self::from_inner(sub_edwards(
            onetime_address,
            sender_extension_pubkey,
        )?))
    }
}

impl ViewTag {
    pub fn derive(
        s_sender_receiver_unctx: &[u8; 32],
        input_context: &InputContext,
        onetime_address: &OutputPubkey,
    ) -> Self {
        // vt = H_3(s_sr || input_context || Ko)
        let transcript = make_carrot_transcript!(domain_separators::VIEW_TAG,
            InputContext : input_context, OutputPubkey : onetime_address);
        Self::from(derive_bytes_3(&transcript, s_sender_receiver_unctx))
    }

    pub fn derive_and_test(
        &self,
        s_sender_receiver_unctx: &[u8; 32],
        input_context: &InputContext,
        onetime_address: &OutputPubkey,
    ) -> bool {
        // vt' = H_3(s_sr || input_context || Ko)
        let nominal_view_tag =
            Self::derive(s_sender_receiver_unctx, input_context, onetime_address);

        // vt' ?= vt
        &nominal_view_tag == self
    }
}

fn xor_bytes<const N: usize>(a: &[u8; N], b: &[u8; N]) -> [u8; N] {
    let mut c = a.clone();
    for i in 0..N {
        c[i] ^= b[i];
    }
    c
}

struct AnchorEncryptionMask([u8; JANUS_ANCHOR_BYTES]);
struct AmountEncryptionMask([u8; ENCRYPTED_AMOUNT_BYTES]);
struct PaymentIdEncryptionMask([u8; PAYMENT_ID_BYTES]);

impl AnchorEncryptionMask {
    pub fn derive(
        s_sender_receiver: &SenderReceiverSecret,
        onetime_address: &OutputPubkey,
    ) -> Self {
        // m_anchor = H_16(s^ctx_sr, Ko)
        let transcript = make_carrot_transcript!(domain_separators::ENCRYPTION_MASK_ANCHOR,
            OutputPubkey : onetime_address);
        Self(derive_bytes_16(&transcript, s_sender_receiver.as_bytes()))
    }
}

impl EncryptedJanusAnchor {
    pub fn encrypt(
        anchor: &JanusAnchor,
        s_sender_receiver: &SenderReceiverSecret,
        onetime_address: &OutputPubkey,
    ) -> Self {
        // m_anchor = H_16(s^ctx_sr, Ko)
        let mask = AnchorEncryptionMask::derive(s_sender_receiver, onetime_address);

        // anchor_enc = anchor XOR m_anchor
        Self::from(xor_bytes(anchor.as_bytes(), &mask.0))
    }

    pub fn decrypt(
        &self,
        s_sender_receiver: &SenderReceiverSecret,
        onetime_address: &OutputPubkey,
    ) -> JanusAnchor {
        // m_anchor = H_16(s^ctx_sr, Ko)
        let mask = AnchorEncryptionMask::derive(s_sender_receiver, onetime_address);

        // anchor = anchor_enc XOR m_anchor
        JanusAnchor::from(xor_bytes(self.as_bytes(), &mask.0))
    }
}

impl AmountEncryptionMask {
    pub fn derive(
        s_sender_receiver: &SenderReceiverSecret,
        onetime_address: &OutputPubkey,
    ) -> Self {
        // m_a = H_8(s^ctx_sr, Ko)
        let transcript = make_carrot_transcript!(domain_separators::ENCRYPTION_MASK_AMOUNT,
            OutputPubkey : onetime_address);
        Self(derive_bytes_8(&transcript, s_sender_receiver.as_bytes()))
    }
}

impl EncryptedAmount {
    pub fn encrypt(
        amount: Amount,
        s_sender_receiver: &SenderReceiverSecret,
        onetime_address: &OutputPubkey,
    ) -> Self {
        // m_a = H_8(s^ctx_sr, Ko)
        let mask = AmountEncryptionMask::derive(s_sender_receiver, onetime_address);

        // a_enc = a XOR m_a  [paying attention to system endianness]
        Self::from(xor_bytes(&amount.to_le_bytes(), &mask.0))
    }

    pub fn decrypt(
        &self,
        s_sender_receiver: &SenderReceiverSecret,
        onetime_address: &OutputPubkey,
    ) -> Amount {
        // m_a = H_8(s^ctx_sr, Ko)
        let mask = AmountEncryptionMask::derive(s_sender_receiver, onetime_address);

        // a = a_enc XOR m_a  [paying attention to system endianness]
        Amount::from_le_bytes(xor_bytes(self.as_bytes(), &mask.0))
    }
}

impl PaymentIdEncryptionMask {
    pub fn derive(
        s_sender_receiver: &SenderReceiverSecret,
        onetime_address: &OutputPubkey,
    ) -> Self {
        // m_pid = H_8(s^ctx_sr, Ko)
        let transcript = make_carrot_transcript!(domain_separators::ENCRYPTION_MASK_PAYMENT_ID,
            OutputPubkey : onetime_address);
        Self(derive_bytes_8(&transcript, s_sender_receiver.as_bytes()))
    }
}

impl EncryptedPaymentId {
    pub fn encrypt(
        payment_id: &PaymentId,
        s_sender_receiver: &SenderReceiverSecret,
        onetime_address: &OutputPubkey,
    ) -> EncryptedPaymentId {
        // m_pid = H_8(s^ctx_sr, Ko)
        let mask = PaymentIdEncryptionMask::derive(s_sender_receiver, onetime_address);

        // pid_enc = pid XOR m_pid
        Self::from(xor_bytes(payment_id.as_bytes(), &mask.0))
    }

    pub fn decrypt(
        &self,
        s_sender_receiver: &SenderReceiverSecret,
        onetime_address: &OutputPubkey,
    ) -> PaymentId {
        // m_pid = H_8(s^ctx_sr, Ko)
        let mask = PaymentIdEncryptionMask::derive(s_sender_receiver, onetime_address);

        // pid = pid_enc XOR m_pid
        PaymentId::from(xor_bytes(self.as_bytes(), &mask.0))
    }
}

impl JanusAnchor {
    pub fn new_randomness<R>(rng: &mut R) -> Self
    where
        R: rand_core::CryptoRngCore + ?Sized,
    {
        Self::new_random_with_params(rng, ())
    }

    pub fn derive_special(
        enote_ephemeral_pubkey: &EnoteEphemeralPubkey,
        input_context: &InputContext,
        onetime_address: &OutputPubkey,
        k_view: &ViewIncomingKey,
    ) -> Self {
        // anchor_sp = H_16(D_e, input_context, Ko, k_v)
        let transcript = make_carrot_transcript!(domain_separators::JANUS_ANCHOR_SPECIAL,
            EnoteEphemeralPubkey : enote_ephemeral_pubkey, InputContext : input_context, OutputPubkey : onetime_address);
        Self::from(derive_bytes_16(
            &transcript,
            k_view.as_scalar_ref().as_bytes(),
        ))
    }
}

pub fn try_recompute_carrot_amount_commitment(
    s_sender_receiver: &SenderReceiverSecret,
    nominal_amount: Amount,
    nominal_address_spend_pubkey: &AddressSpendPubkey,
    nominal_enote_type: CarrotEnoteType,
    amount_commitment: &AmountCommitment,
) -> Option<AmountBlindingKey> {
    // k_a' = H_n(s^ctx_sr, a', K^j_s', enote_type')
    let amount_blinding_factor = AmountBlindingKey::derive(
        s_sender_receiver,
        nominal_amount,
        nominal_address_spend_pubkey,
        nominal_enote_type,
    );

    // C_a' = k_a' G + a' H
    let nominal_amount_commitment =
        AmountCommitment::commit(nominal_amount, &amount_blinding_factor);

    // C_a' ?= C_a
    if &nominal_amount_commitment == amount_commitment {
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
    let amount = encrypted_amount.decrypt(s_sender_receiver, onetime_address);

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
    let nominal_enote_ephemeral_privkey = EnoteEphemeralKey::derive(
        nominal_anchor,
        input_context,
        nominal_address_spend_pubkey,
        nominal_payment_id,
    );

    // recompute D_e' for d_e' and address type
    let Some(nominal_enote_ephemeral_pubkey) = EnoteEphemeralPubkey::derive_to(
        &nominal_enote_ephemeral_privkey,
        nominal_address_spend_pubkey,
        is_subaddress,
    ) else {
        return false;
    };

    // D_e' ?= D_e
    &nominal_enote_ephemeral_pubkey == enote_ephemeral_pubkey
}

#[cfg(test)]
mod test {
    use crate::enote_components::*;
    use crate::unit_testing::*;

    impl ToTranscriptBytes for AnchorEncryptionMask {
        type Len = typenum::U16;
        fn to_transcript_bytes(&self) -> GenericArray<u8, Self::Len> {
            self.0.to_transcript_bytes()
        }
    }

    impl ToTranscriptBytes for AmountEncryptionMask {
        type Len = typenum::U8;
        fn to_transcript_bytes(&self) -> GenericArray<u8, Self::Len> {
            self.0.to_transcript_bytes()
        }
    }

    impl ToTranscriptBytes for PaymentIdEncryptionMask {
        type Len = typenum::U8;
        fn to_transcript_bytes(&self) -> GenericArray<u8, Self::Len> {
            self.0.to_transcript_bytes()
        }
    }

    #[test]
    fn converge_make_carrot_enote_ephemeral_privkey() {
        assert_eq_hex!(
            "6aea0ed0c34ad3483415377658841a75e0da8b462e637d8bf783b9bcd320b303",
            EnoteEphemeralKey::derive(
                &hex_into!("caee1381775487a0982557f0d2680b55"),
                &hex_into!("9423f74f3e869dc8427d8b35bb24c917480409c3f4750bff3c742f8e4d5af7bef7"),
                &hex_into!("8f2f38e702678ae59751dc55818240e0330851e77bfaff003b671885ed06871e"),
                &hex_into!("4321734f56621440")
            )
        );
    }

    #[test]
    fn converge_make_carrot_enote_ephemeral_pubkey_cryptonote() {
        assert_eq_hex!(
            "8df2a40a42ecc10348a461310c1afc2c2b1be7b29fd27a3921a1aefba5efa27b",
            EnoteEphemeralPubkey::derive_to_cryptonote_address(&hex_into!(
                "6aea0ed0c34ad3483415377658841a75e0da8b462e637d8bf783b9bcd320b303"
            ))
        );
    }

    #[test]
    fn converge_make_carrot_enote_ephemeral_pubkey_subaddress() {
        assert_eq_hex!(
            "a3c3cdf84fd301cfc4675096f1c896543f2efc1001d899bbab3a0fd137f6a630",
            EnoteEphemeralPubkey::derive_to_subaddress(
                &hex_into!("6aea0ed0c34ad3483415377658841a75e0da8b462e637d8bf783b9bcd320b303"),
                &hex_into!("8f2f38e702678ae59751dc55818240e0330851e77bfaff003b671885ed06871e")
            )
            .unwrap()
        );
    }

    #[test]
    fn converge_make_carrot_uncontextualized_shared_key_receiver() {
        assert_eq_hex!(
            "1f848f8384e7a9f217dc9dc2691703cf392eaf6c92931acd0fc840c900d3ed49",
            MontgomeryECDH::derive_as_receiver(
                &hex_into!("12624c702b4c1a22fd710a836894ed0705955502e6498e5c6e3ad6f5920bb00f"),
                &hex_into!("a3c3cdf84fd301cfc4675096f1c896543f2efc1001d899bbab3a0fd137f6a630")
            )
        );
    }

    #[test]
    fn converge_make_carrot_uncontextualized_shared_key_sender() {
        assert_eq_hex!(
            "1f848f8384e7a9f217dc9dc2691703cf392eaf6c92931acd0fc840c900d3ed49",
            MontgomeryECDH::derive_as_sender(
                &hex_into!("6aea0ed0c34ad3483415377658841a75e0da8b462e637d8bf783b9bcd320b303"),
                &hex_into!("369bdcf4f434f42eb09f4372cb6be30de7b17d21e4f98e244459a90b58cd0610")
            )
            .unwrap()
        );
    }

    #[test]
    fn converge_make_carrot_sender_receiver_secret() {
        assert_eq_hex!(
            "6e99852ed7b3744177bb669e73fd1c544d88555ea6fffe3787ca6af48d2fe9f6",
            SenderReceiverSecret::derive(
                &hex_into!("1f848f8384e7a9f217dc9dc2691703cf392eaf6c92931acd0fc840c900d3ed49"),
                &hex_into!("a3c3cdf84fd301cfc4675096f1c896543f2efc1001d899bbab3a0fd137f6a630"),
                &hex_into!("9423f74f3e869dc8427d8b35bb24c917480409c3f4750bff3c742f8e4d5af7bef7")
            )
        );
    }

    #[test]
    fn converge_make_carrot_amount_blinding_factor_payment() {
        assert_eq_hex!(
            "5a01cc9f8ca9556c429d623d848fe036c76593005c63a62df57afc4b51d3c20b",
            AmountBlindingKey::derive(
                &hex_into!("6e99852ed7b3744177bb669e73fd1c544d88555ea6fffe3787ca6af48d2fe9f6"),
                67000000000000,
                &hex_into!("8f2f38e702678ae59751dc55818240e0330851e77bfaff003b671885ed06871e"),
                CarrotEnoteType::Payment
            )
        );
    }

    #[test]
    fn converge_make_carrot_amount_blinding_factor_change() {
        assert_eq_hex!(
            "f69587a2e01d039758b5dd61999e4d60f226eb7b8027be2ff2656ecbb584d103",
            AmountBlindingKey::derive(
                &hex_into!("6e99852ed7b3744177bb669e73fd1c544d88555ea6fffe3787ca6af48d2fe9f6"),
                67000000000000,
                &hex_into!("8f2f38e702678ae59751dc55818240e0330851e77bfaff003b671885ed06871e"),
                CarrotEnoteType::Change
            )
        );
    }

    #[test]
    fn converge_make_carrot_amount_commitment() {
        assert_eq_hex!(
            "f5df40aeba877e8ccadd9dff363d90ec28efbfd1201573897cd70c61c026edb9",
            AmountCommitment::commit(
                67000000000000,
                &hex_into!("5a01cc9f8ca9556c429d623d848fe036c76593005c63a62df57afc4b51d3c20b"),
            )
        );
    }

    #[test]
    fn converge_make_carrot_onetime_address_coinbase() {
        assert_eq_hex!(
            "0c4ee83d079ebd77882f894b2e0a43e3d572af9c330871f1dfbcc62f5c64e4ae",
            OutputPubkey::derive_from_extension(
                &hex_into!("8f2f38e702678ae59751dc55818240e0330851e77bfaff003b671885ed06871e"),
                &OnetimeExtension::derive_coinbase(
                    &hex_into!("6e99852ed7b3744177bb669e73fd1c544d88555ea6fffe3787ca6af48d2fe9f6"),
                    67000000000000,
                    &hex_into!("8f2f38e702678ae59751dc55818240e0330851e77bfaff003b671885ed06871e")
                )
            )
            .unwrap()
        );
    }

    #[test]
    fn converge_make_carrot_onetime_address() {
        assert_eq_hex!(
            "522347147e41f22ebe155abc32b9def985b2e454045c6edd8921ee4253cd4516",
            OutputPubkey::derive_from_extension(
                &hex_into!("8f2f38e702678ae59751dc55818240e0330851e77bfaff003b671885ed06871e"),
                &OnetimeExtension::derive_ringct(
                    &hex_into!("6e99852ed7b3744177bb669e73fd1c544d88555ea6fffe3787ca6af48d2fe9f6"),
                    &hex_into!("f5df40aeba877e8ccadd9dff363d90ec28efbfd1201573897cd70c61c026edb9")
                )
            )
            .unwrap()
        );
    }

    #[test]
    fn converge_make_carrot_view_tag() {
        assert_eq_hex!(
            "5f58e1",
            ViewTag::derive(
                &hex_into!("1f848f8384e7a9f217dc9dc2691703cf392eaf6c92931acd0fc840c900d3ed49"),
                &hex_into!("9423f74f3e869dc8427d8b35bb24c917480409c3f4750bff3c742f8e4d5af7bef7"),
                &hex_into!("522347147e41f22ebe155abc32b9def985b2e454045c6edd8921ee4253cd4516")
            )
        );
    }

    #[test]
    fn converge_make_carrot_anchor_encryption_mask() {
        assert_eq_hex!(
            "6ba7e188fb315ad2158ac6b6652408d4",
            AnchorEncryptionMask::derive(
                &hex_into!("6e99852ed7b3744177bb669e73fd1c544d88555ea6fffe3787ca6af48d2fe9f6"),
                &hex_into!("522347147e41f22ebe155abc32b9def985b2e454045c6edd8921ee4253cd4516")
            )
        );
    }

    #[test]
    fn converge_make_carrot_amount_encryption_mask() {
        assert_eq_hex!(
            "2b739fdb6d1d5e50",
            AmountEncryptionMask::derive(
                &hex_into!("6e99852ed7b3744177bb669e73fd1c544d88555ea6fffe3787ca6af48d2fe9f6"),
                &hex_into!("522347147e41f22ebe155abc32b9def985b2e454045c6edd8921ee4253cd4516")
            )
        );
    }

    #[test]
    fn converge_make_carrot_payment_id_encryption_mask() {
        assert_eq_hex!(
            "043d7e9ed13a3484",
            PaymentIdEncryptionMask::derive(
                &hex_into!("6e99852ed7b3744177bb669e73fd1c544d88555ea6fffe3787ca6af48d2fe9f6"),
                &hex_into!("522347147e41f22ebe155abc32b9def985b2e454045c6edd8921ee4253cd4516")
            )
        );
    }

    #[test]
    fn converge_make_carrot_janus_anchor_special() {
        assert_eq_hex!(
            "70fe9b941fe1ef3b2345c87485f70a6e",
            JanusAnchor::derive_special(
                &hex_into!("8df2a40a42ecc10348a461310c1afc2c2b1be7b29fd27a3921a1aefba5efa27b"),
                &hex_into!("9423f74f3e869dc8427d8b35bb24c917480409c3f4750bff3c742f8e4d5af7bef7"),
                &hex_into!("522347147e41f22ebe155abc32b9def985b2e454045c6edd8921ee4253cd4516"),
                &hex_into!("12624c702b4c1a22fd710a836894ed0705955502e6498e5c6e3ad6f5920bb00f")
            )
        );
    }
}
