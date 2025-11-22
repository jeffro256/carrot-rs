use zeroize::ZeroizeOnDrop;

use crate::domain_separators;
use crate::hash_functions::*;
use crate::math_utils::*;
use crate::transcript::*;
use crate::type_macros::*;

define_tiny_byte_type! {MasterSecret, "Master secret for a Carrot-derived account", 32, ZeroizeOnDrop}
define_tiny_byte_type! {ViewBalanceSecret, "View-balance secret for a Carrot-derived account", 32, ZeroizeOnDrop}
define_tiny_byte_type! {GenerateAddressSecret, "Generate-address secret for a Carrot-derived account", 32, ZeroizeOnDrop}
define_tiny_byte_type! {AddressIndexGeneratorSecret, "Address index generator secret for a Carrot-derived address", 32, ZeroizeOnDrop}

define_tiny_scalar_type! {ProveSpendKey, "Prove-spend key for a Carrot-derived account"}
define_tiny_scalar_type! {GenerateImageKey, "Generate-image key for a Carrot-derived account"}
define_tiny_scalar_type! {ViewIncomingKey, "View-incoming key for a Carrot-derived account"}
define_tiny_scalar_type! {SubaddressScalarSecret, "Subaddress scalar key for a Carrot-derived address"}

define_tiny_edwards_type! {AddressSpendPubkey, "Spend pubkey in an address or account, Carrot-derived or otherwise"}
define_tiny_edwards_type! {AddressViewPubkey, "View pubkey in an address or account, Carrot-derived or otherwise"}

impl ProveSpendKey {
    /// Derive Carrot key hierarchy prove-spend key from the master secret
    pub fn derive(s_master: &MasterSecret) -> Self {
        // k_ps = H_n(s_m)
        let transcript = make_carrot_transcript!(domain_separators::PROVE_SPEND_KEY,);
        Self(derive_scalar(&transcript, s_master.as_bytes()))
    }
}

impl ViewBalanceSecret {
    /// Derive Carrot key hierarchy view-balance secret from the master secret
    pub fn derive(s_master: &MasterSecret) -> Self {
        // s_vb = H_32(s_m)
        let transcript = make_carrot_transcript!(domain_separators::VIEW_BALANCE_SECRET,);
        Self::from(derive_bytes_32(&transcript, s_master.as_bytes()))
    }
}

impl GenerateImageKey {
    /// Derive Carrot key hierarchy generate-image key from the view-balance secret
    pub fn derive(s_view_balance: &ViewBalanceSecret) -> Self {
        // k_gi = H_n(s_vb)
        let transcript = make_carrot_transcript!(domain_separators::GENERATE_IMAGE_KEY,);
        Self(derive_scalar(&transcript, s_view_balance.as_bytes()))
    }
}

impl ViewIncomingKey {
    /// Derive Carrot key hierarchy view-incoming key from the view-balance secret
    pub fn derive(s_view_balance: &ViewBalanceSecret) -> Self {
        // k_v = H_n(s_vb)
        let transcript = make_carrot_transcript!(domain_separators::INCOMING_VIEW_KEY,);
        Self(derive_scalar(&transcript, s_view_balance.as_bytes()))
    }
}

impl GenerateAddressSecret {
    /// Derive Carrot key generate-address secret from the view-balance secret
    pub fn derive(s_view_balance: &ViewBalanceSecret) -> Self {
        // s_ga = H_32(s_vb)
        let transcript = make_carrot_transcript!(domain_separators::GENERATE_ADDRESS_SECRET,);
        Self::from(derive_bytes_32(&transcript, s_view_balance.as_bytes()))
    }
}

impl AddressSpendPubkey {
    /// Derive Carrot key hierarchy account spend pubkey key from private keys
    pub fn derive_carrot_account_spend_pubkey(
        k_generate_image: &GenerateImageKey,
        k_prove_spend: &ProveSpendKey,
    ) -> Self {
        // K_s = k_gi G + k_ps T
        Self(scalar_mul_gt(k_generate_image, k_prove_spend))
    }

    /// Derive Carrot key hierarchy subaddress spend pubkey from its subaddress scalar
    pub fn derive_subaddress_spend_pubkey(
        subaddr_scalar: &SubaddressScalarSecret,
        account_spend_pubkey: &AddressSpendPubkey,
    ) -> Option<Self> {
        Some(Self(scalar_mul_key(subaddr_scalar, account_spend_pubkey)?))
    }

    pub(crate) fn from_inner(p: CompressedEdwardsY) -> Self {
        Self(p)
    }
}

impl AddressViewPubkey {
    /// Derive Carrot key hierarchy account view pubkey from the spend pubkey
    pub fn derive_carrot_account_view_pubkey(
        k_view: &ViewIncomingKey,
        spend_pubkey: &AddressSpendPubkey,
    ) -> Option<Self> {
        // K^v = k_v K_s
        Some(Self(scalar_mul_key(k_view, spend_pubkey)?))
    }

    /// Derive the primary address view pubkey (same for Carrot and legacy) from the view-incoming key
    pub fn derive_primary_address_view_pubkey(k_view: &ViewIncomingKey) -> Self {
        // K^0_v = k_v G
        Self(scalar_mul_base(k_view))
    }

    /// Derive Carrot key hierarchy subaddress view pubkey from its subaddress scalar
    pub fn derive_subaddress_view_pubkey(
        subaddr_scalar: &SubaddressScalarSecret,
        account_view_pubkey: &AddressViewPubkey,
    ) -> Option<Self> {
        Some(Self(scalar_mul_key(subaddr_scalar, account_view_pubkey)?))
    }
}

impl AddressIndexGeneratorSecret {
    pub fn derive(s_generate_address: &GenerateAddressSecret, j_major: u32, j_minor: u32) -> Self {
        // s^j_gen = H_32[s_ga](j_major, j_minor)
        let transcript = make_carrot_transcript!(domain_separators::ADDRESS_INDEX_GEN,
            u32 : &j_major, u32 : &j_minor);
        Self::from(derive_bytes_32(&transcript, s_generate_address.as_bytes()))
    }
}

impl SubaddressScalarSecret {
    /// Derive subaddress scalar secret from account secrets and its index value
    pub fn derive(
        account_spend_pubkey: &AddressSpendPubkey,
        account_view_pubkey: &AddressViewPubkey,
        s_address_generator: &AddressIndexGeneratorSecret,
        j_major: u32,
        j_minor: u32,
    ) -> Self {
        // k^j_subscal = H_n[s^j_gen](K_s, K_v, j_major, j_minor)
        let transcript = make_carrot_transcript!(domain_separators::SUBADDRESS_SCALAR,
            AddressSpendPubkey : account_spend_pubkey, AddressViewPubkey : account_view_pubkey,
            u32 : &j_major, u32 : &j_minor);
        Self(derive_scalar(&transcript, s_address_generator.as_bytes()))
    }
}

#[cfg(test)]
mod test {
    use crate::account::*;
    use crate::unit_testing::*;

    #[test]
    fn converge_make_carrot_provespend_key() {
        assert_eq_hex!(
            "c9651fc906015afeefdb8d3bf7be621c36e035de2a85cb22dd4b869a22086f0e",
            ProveSpendKey::derive(&hex_into!(
                "6e02e67b303dc713276bb1a4d70b0083b78e4f50e34e209da9f0377cdc3d376e"
            ))
        );
    }

    #[test]
    fn converge_make_carrot_viewbalance_secret() {
        assert_eq_hex!(
            "59b2ee8646923309384704613418f5982b0167eb3cd87c6c067ee10700c3af91",
            ViewBalanceSecret::derive(&hex_into!(
                "6e02e67b303dc713276bb1a4d70b0083b78e4f50e34e209da9f0377cdc3d376e"
            ))
        );
    }

    #[test]
    fn converge_make_carrot_generateimage_key() {
        assert_eq_hex!(
            "b9c67add7cc5d660c62ad0541685eb84e6a13fef3f15fdc8fe52a8cdfbe7240f",
            GenerateImageKey::derive(&hex_into!(
                "154c5e01902b20acc8436c9aa06b40355d78dfda0fc6af3d53a2220f1363a0f5"
            ))
        );
    }

    #[test]
    fn converge_make_carrot_viewincoming_key() {
        assert_eq_hex!(
            "81df86e1c261aa719849e66c954992394f450eab7ff1bb2643663eabcd12af0c",
            ViewIncomingKey::derive(&hex_into!(
                "154c5e01902b20acc8436c9aa06b40355d78dfda0fc6af3d53a2220f1363a0f5"
            ))
        );
    }

    #[test]
    fn converge_make_carrot_generateaddress_secret() {
        assert_eq_hex!(
            "bb15de08485cbd8115283e65517fff91ccca190bac8a8591f52c49d09a7ae080",
            GenerateAddressSecret::derive(&hex_into!(
                "154c5e01902b20acc8436c9aa06b40355d78dfda0fc6af3d53a2220f1363a0f5"
            ))
        );
    }

    #[test]
    fn converge_make_carrot_spend_pubkey() {
        assert_eq_hex!(
            "c984806ae9be958800cfe04b5ed85279f48d78c3792b5abb2f5ce2b67adc491f",
            AddressSpendPubkey::derive_carrot_account_spend_pubkey(
                &hex_into!("336e3af233b3aa5bc95d5589aba67aab727727419899823acc6a6c4479e4ea04"),
                &hex_into!("f10bf01839ea216e5d70b7c9ceaa8b8e9a432b5e98e6e48a8043ffb3fa229f0b")
            )
        );
    }

    #[test]
    fn converge_make_carrot_index_extension_generator() {
        assert_eq_hex!(
            "d2e2e8a75026f0e953e3a46d0ea826f22649bbfc5f04b14a9da14063d6199cc2",
            AddressIndexGeneratorSecret::derive(
                &hex_into!("593ece76c5d24cbfe3c7ac9e2d455cdd4b372c89584700bf1c2e7bef2b70a4d1"),
                5,
                16
            )
        );
    }

    #[test]
    fn converge_make_carrot_subaddress_scalar() {
        assert_eq_hex!(
            "5ffc416bbd22770789d4a55c9efe0675abad116c3e33cf88bf2b0cbbb8b0ef0d",
            SubaddressScalarSecret::derive(
                &hex_into!("c984806ae9be958800cfe04b5ed85279f48d78c3792b5abb2f5ce2b67adc491f"),
                &hex_into!("a30c1b720a66557c03a9784c6dd0902c95ee56670e04907d18eaa20608a72e7e"),
                &hex_into!("79ad2383f44b4d26413adb7ae79c5658b2a8c20b6f5046bfa9f229bfcf1744a7"),
                5,
                16
            )
        );
    }
}
