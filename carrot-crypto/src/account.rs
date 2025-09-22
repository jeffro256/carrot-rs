use curve25519_dalek::edwards::CompressedEdwardsY;

use crate::core_types::*;
use crate::domain_separators;
use crate::hash_functions::*;
use crate::math_utils::*;
use crate::transcript::*;

pub fn make_carrot_provespend_key(s_master: &Uniform32Secret) -> ProveSpendKey
{
    // k_ps = H_n(s_m)
    let transcript = make_carrot_transcript!(domain_separators::PROVE_SPEND_KEY,);
    ProveSpendKey(ScalarSecret(derive_scalar(&transcript, &s_master.0)))
}

pub fn make_carrot_viewbalance_secret(s_master: &Uniform32Secret) -> ViewBalanceSecret
{
    // s_vb = H_32(s_m)
    let transcript = make_carrot_transcript!(domain_separators::VIEW_BALANCE_SECRET,);
    ViewBalanceSecret(Uniform32Secret(derive_bytes_32(&transcript, &s_master.0)))
}

pub fn make_carrot_generateimage_key(s_view_balance: &ViewBalanceSecret) -> GenerateImageKey
{
    // k_gi = H_n(s_vb)
    let transcript = make_carrot_transcript!(domain_separators::GENERATE_IMAGE_KEY,);
    GenerateImageKey(ScalarSecret(derive_scalar(&transcript, &s_view_balance.0.0)))
}

pub fn make_carrot_viewincoming_key(s_view_balance: &ViewBalanceSecret) -> ViewIncomingKey
{
    // k_v = H_n(s_vb)
    let transcript = make_carrot_transcript!(domain_separators::INCOMING_VIEW_KEY,);
    ViewIncomingKey(ScalarSecret(derive_scalar(&transcript, &s_view_balance.0.0)))
}

pub fn make_carrot_generateaddress_secret(s_view_balance: &ViewBalanceSecret) -> GenerateAddressSecret
{
    // s_ga = H_32(s_vb)
    let transcript = make_carrot_transcript!(domain_separators::GENERATE_ADDRESS_SECRET,);
    GenerateAddressSecret(Uniform32Secret(derive_bytes_32(&transcript, &s_view_balance.0.0)))
}

pub fn make_carrot_spend_pubkey(k_generate_image: &GenerateImageKey, k_prove_spend: &ProveSpendKey)
    -> AddressSpendPubkey
{
    // K_s = k_gi G + k_ps T
    AddressSpendPubkey(scalar_mul_gt(&k_generate_image.0.0, &k_prove_spend.0.0))
}

pub fn make_carrot_account_view_pubkey(k_view: &ViewIncomingKey, spend_pubkey: &AddressSpendPubkey)
    -> AddressViewPubkey
{
    AddressViewPubkey(
        scalar_mul_key_vartime(&k_view.0.0, &spend_pubkey.0).unwrap_or(CompressedEdwardsY::default()))
}

pub fn make_carrot_primary_address_view_pubkey(k_view: &ViewIncomingKey) -> AddressViewPubkey {
    // K^0_v = k_v G
    AddressViewPubkey(scalar_mul_base(&k_view.0.0))
}

pub fn make_carrot_index_extension_generator(s_generate_address: &GenerateAddressSecret,
    j_major: u32,
    j_minor: u32) -> AddressIndexGeneratorSecret
{
    // s^j_gen = H_32[s_ga](j_major, j_minor)
    let transcript = make_carrot_transcript!(domain_separators::ADDRESS_INDEX_GEN,
        u32 : &j_major, u32 : &j_minor);
    AddressIndexGeneratorSecret(Uniform32Secret(derive_bytes_32(&transcript, &s_generate_address.0.0)))
}

pub fn make_carrot_subaddress_scalar(account_spend_pubkey: &AddressSpendPubkey,
    s_address_generator: &AddressIndexGeneratorSecret,
    j_major: u32,
    j_minor: u32) -> SubaddressScalarSecret
{
    // k^j_subscal = H_n(K_s, j_major, j_minor, s^j_gen)
    let transcript = make_carrot_transcript!(domain_separators::SUBADDRESS_SCALAR,
        AddressSpendPubkey : account_spend_pubkey, u32 : &j_major, u32 : &j_minor);
    SubaddressScalarSecret(ScalarSecret(derive_scalar(&transcript, &s_address_generator.0.0)))
}