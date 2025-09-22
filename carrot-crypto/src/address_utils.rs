use crate::core_types::*;
use crate::domain_separators;
use crate::hash_functions::*;
use crate::transcript::*;

pub fn make_carrot_index_extension_generator(s_generate_address: &GenerateAddressSecret,
    j_major: u32,
    j_minor: u32) -> AddressIndexGeneratorSecret
{
    // s^j_gen = H_32[s_ga](j_major, j_minor)
    let transcript = make_carrot_transcript!(domain_separators::ADDRESS_INDEX_GEN,
        u32 : j_major, u32 : j_minor);
    AddressIndexGeneratorSecret(Uniform32Secret(derive_bytes_32(&transcript, &s_generate_address.0.0)))
}

pub fn make_carrot_subaddress_scalar(account_spend_pubkey: &AddressSpendPubkey,
    s_address_generator: &AddressIndexGeneratorSecret,
    j_major: u32,
    j_minor: u32) -> SubaddressScalarSecret
{
    // k^j_subscal = H_n(K_s, j_major, j_minor, s^j_gen)
    let transcript = make_carrot_transcript!(domain_separators::SUBADDRESS_SCALAR,
        AddressSpendPubkey : account_spend_pubkey, u32 : j_major, u32 : j_minor);
    SubaddressScalarSecret(ScalarSecret(derive_scalar(&transcript, &s_address_generator.0.0)))
}
