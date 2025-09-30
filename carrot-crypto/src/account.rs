use curve25519_dalek::edwards::CompressedEdwardsY;

use crate::core_types::*;
use crate::domain_separators;
use crate::hash_functions::*;
use crate::math_utils::*;
use crate::transcript::*;

pub fn make_carrot_provespend_key(s_master: &Uniform32Secret) -> ProveSpendKey {
    // k_ps = H_n(s_m)
    let transcript = make_carrot_transcript!(domain_separators::PROVE_SPEND_KEY,);
    ProveSpendKey(ScalarSecret(derive_scalar(&transcript, &s_master.0)))
}

pub fn make_carrot_viewbalance_secret(s_master: &Uniform32Secret) -> ViewBalanceSecret {
    // s_vb = H_32(s_m)
    let transcript = make_carrot_transcript!(domain_separators::VIEW_BALANCE_SECRET,);
    ViewBalanceSecret(Uniform32Secret(derive_bytes_32(&transcript, &s_master.0)))
}

pub fn make_carrot_generateimage_key(s_view_balance: &ViewBalanceSecret) -> GenerateImageKey {
    // k_gi = H_n(s_vb)
    let transcript = make_carrot_transcript!(domain_separators::GENERATE_IMAGE_KEY,);
    GenerateImageKey(ScalarSecret(derive_scalar(
        &transcript,
        &s_view_balance.0.0,
    )))
}

pub fn make_carrot_viewincoming_key(s_view_balance: &ViewBalanceSecret) -> ViewIncomingKey {
    // k_v = H_n(s_vb)
    let transcript = make_carrot_transcript!(domain_separators::INCOMING_VIEW_KEY,);
    ViewIncomingKey(ScalarSecret(derive_scalar(
        &transcript,
        &s_view_balance.0.0,
    )))
}

pub fn make_carrot_generateaddress_secret(
    s_view_balance: &ViewBalanceSecret,
) -> GenerateAddressSecret {
    // s_ga = H_32(s_vb)
    let transcript = make_carrot_transcript!(domain_separators::GENERATE_ADDRESS_SECRET,);
    GenerateAddressSecret(Uniform32Secret(derive_bytes_32(
        &transcript,
        &s_view_balance.0.0,
    )))
}

pub fn make_carrot_spend_pubkey(
    k_generate_image: &GenerateImageKey,
    k_prove_spend: &ProveSpendKey,
) -> AddressSpendPubkey {
    // K_s = k_gi G + k_ps T
    AddressSpendPubkey(scalar_mul_gt(&k_generate_image.0.0, &k_prove_spend.0.0))
}

pub fn make_carrot_account_view_pubkey(
    k_view: &ViewIncomingKey,
    spend_pubkey: &AddressSpendPubkey,
) -> AddressViewPubkey {
    AddressViewPubkey(
        scalar_mul_key_vartime(&k_view.0.0, &spend_pubkey.0)
            .unwrap_or(CompressedEdwardsY::default()),
    )
}

pub fn make_carrot_primary_address_view_pubkey(k_view: &ViewIncomingKey) -> AddressViewPubkey {
    // K^0_v = k_v G
    AddressViewPubkey(scalar_mul_base(&k_view.0.0))
}

pub fn make_carrot_index_extension_generator(
    s_generate_address: &GenerateAddressSecret,
    j_major: u32,
    j_minor: u32,
) -> AddressIndexGeneratorSecret {
    // s^j_gen = H_32[s_ga](j_major, j_minor)
    let transcript = make_carrot_transcript!(domain_separators::ADDRESS_INDEX_GEN,
        u32 : &j_major, u32 : &j_minor);
    AddressIndexGeneratorSecret(Uniform32Secret(derive_bytes_32(
        &transcript,
        &s_generate_address.0.0,
    )))
}

pub fn make_carrot_subaddress_scalar(
    account_spend_pubkey: &AddressSpendPubkey,
    s_address_generator: &AddressIndexGeneratorSecret,
    j_major: u32,
    j_minor: u32,
) -> SubaddressScalarSecret {
    // k^j_subscal = H_n(K_s, j_major, j_minor, s^j_gen)
    let transcript = make_carrot_transcript!(domain_separators::SUBADDRESS_SCALAR,
        AddressSpendPubkey : account_spend_pubkey, u32 : &j_major, u32 : &j_minor);
    SubaddressScalarSecret(ScalarSecret(derive_scalar(
        &transcript,
        &s_address_generator.0.0,
    )))
}

#[cfg(test)]
mod test {
    use crate::account::*;
    use crate::unit_testing::*;

    #[test]
    fn converge_make_carrot_provespend_key() {
        assert_eq_hex!(
            "f10bf01839ea216e5d70b7c9ceaa8b8e9a432b5e98e6e48a8043ffb3fa229f0b",
            make_carrot_provespend_key(&hex_into!(
                "6e02e67b303dc713276bb1a4d70b0083b78e4f50e34e209da9f0377cdc3d376e"
            ))
        );
    }

    #[test]
    fn converge_make_carrot_viewbalance_secret() {
        assert_eq_hex!(
            "154c5e01902b20acc8436c9aa06b40355d78dfda0fc6af3d53a2220f1363a0f5",
            make_carrot_viewbalance_secret(&hex_into!(
                "6e02e67b303dc713276bb1a4d70b0083b78e4f50e34e209da9f0377cdc3d376e"
            ))
        );
    }

    #[test]
    fn converge_make_carrot_generateimage_key() {
        assert_eq_hex!(
            "336e3af233b3aa5bc95d5589aba67aab727727419899823acc6a6c4479e4ea04",
            make_carrot_generateimage_key(&hex_into!(
                "154c5e01902b20acc8436c9aa06b40355d78dfda0fc6af3d53a2220f1363a0f5"
            ))
        );
    }

    #[test]
    fn converge_make_carrot_viewincoming_key() {
        assert_eq_hex!(
            "60eff3ec120a12bb44d4258816e015952fc5651040da8c8af58c17676485f200",
            make_carrot_viewincoming_key(&hex_into!(
                "154c5e01902b20acc8436c9aa06b40355d78dfda0fc6af3d53a2220f1363a0f5"
            ))
        );
    }

    #[test]
    fn converge_make_carrot_generateaddress_secret() {
        assert_eq_hex!(
            "593ece76c5d24cbfe3c7ac9e2d455cdd4b372c89584700bf1c2e7bef2b70a4d1",
            make_carrot_generateaddress_secret(&hex_into!(
                "154c5e01902b20acc8436c9aa06b40355d78dfda0fc6af3d53a2220f1363a0f5"
            ))
        );
    }

    #[test]
    fn converge_make_carrot_spend_pubkey() {
        assert_eq_hex!(
            "c984806ae9be958800cfe04b5ed85279f48d78c3792b5abb2f5ce2b67adc491f",
            make_carrot_spend_pubkey(
                &hex_into!("336e3af233b3aa5bc95d5589aba67aab727727419899823acc6a6c4479e4ea04"),
                &hex_into!("f10bf01839ea216e5d70b7c9ceaa8b8e9a432b5e98e6e48a8043ffb3fa229f0b"))
        );
    }

    #[test]
    fn converge_make_carrot_index_extension_generator() {
        assert_eq_hex!(
            "79ad2383f44b4d26413adb7ae79c5658b2a8c20b6f5046bfa9f229bfcf1744a7",
            make_carrot_index_extension_generator(
                &hex_into!("593ece76c5d24cbfe3c7ac9e2d455cdd4b372c89584700bf1c2e7bef2b70a4d1"),
                5,
            16)
        );
    }

    #[test]
    fn converge_make_carrot_subaddress_scalar() {
        assert_eq_hex!(
            "25d97acc4f6b58478ee97ee9b308be756401130c1e9f3a48a5370c1a2ce0e50e",
            make_carrot_subaddress_scalar(
                &hex_into!("c984806ae9be958800cfe04b5ed85279f48d78c3792b5abb2f5ce2b67adc491f"),
                &hex_into!("79ad2383f44b4d26413adb7ae79c5658b2a8c20b6f5046bfa9f229bfcf1744a7"),
                5,
                16)
        );
    }
}
