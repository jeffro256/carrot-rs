use zeroize::ZeroizeOnDrop;

use crate::domain_separators;
use crate::hash_functions::*;
use crate::math_utils::*;
use crate::transcript::*;
use crate::type_macros::*;

define_tiny_byte_type! {MasterSecret, "Master secret for a Carrot-derived account", 32, ZeroizeOnDrop}
define_tiny_byte_type! {ViewBalanceSecret, "View-balance secret for a Carrot-derived account", 32, ZeroizeOnDrop}
define_tiny_byte_type! {GenerateAddressSecret, "Generate-address secret for a Carrot-derived account", 32, ZeroizeOnDrop}
define_tiny_byte_type! {GenerateImagePreimage, "Generate-image key preimage for a Carrot-derived account", 32, ZeroizeOnDrop}
define_tiny_byte_type! {AddressIndexPreimage1, "Address index preimage 1 for a Carrot-derived address", 32, ZeroizeOnDrop}
define_tiny_byte_type! {AddressIndexPreimage2, "Address index preimage 2 for a Carrot-derived address", 32, ZeroizeOnDrop}

define_tiny_scalar_type! {ProveSpendKey, "Prove-spend key for a Carrot-derived account"}
define_tiny_scalar_type! {GenerateImageKey, "Generate-image key for a Carrot-derived account"}
define_tiny_scalar_type! {ViewIncomingKey, "View-incoming key for a Carrot-derived account"}
define_tiny_scalar_type! {SubaddressScalarSecret, "Subaddress scalar key for a Carrot-derived address"}

define_tiny_edwards_type! {PartialAccountSpendPubkey, "Preimage to account spend pubkey in Carrot-derived account"}
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

impl PartialAccountSpendPubkey {
    /// Derive Carrot key hierarchy partial prove-spend pubkey from the prove-spend key
    pub fn derive(k_prove_spend: &ProveSpendKey) -> Self {
        // K_ps = k_ps T
        Self(scalar_mul_t(k_prove_spend))
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

impl GenerateImagePreimage {
    /// Derive Carrot key hierarchy generate-image preimage secret from the view-balance secret
    pub fn derive(s_view_balance: &ViewBalanceSecret) -> Self {
        // s_gp = H_32(s_vb)
        let transcript = make_carrot_transcript!(domain_separators::GENERATE_IMAGE_PREIMAGE,);
        Self(derive_bytes_32(&transcript, s_view_balance.as_bytes()))
    }
}

impl GenerateImageKey {
    /// Derive Carrot key hierarchy generate-image key from the view-balance secret
    pub fn derive(s_generate_image_preimage: &GenerateImagePreimage,
        partial_account_spend_pubkey: &PartialAccountSpendPubkey
    ) -> Self {
        // k_gi = H_n(s_gp, K_ps)
        let transcript = make_carrot_transcript!(domain_separators::GENERATE_IMAGE_KEY,
            PartialAccountSpendPubkey : partial_account_spend_pubkey);
        Self(derive_scalar(&transcript, s_generate_image_preimage.as_bytes()))
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

impl AddressIndexPreimage1 {
    /// Derive Carrot key hierarchy address index preimage 1 from account secrets and index
    pub fn derive(s_generate_address: &GenerateAddressSecret, j_major: u32, j_minor: u32) -> Self {
        // s^j_ap1 = H_32[s_ga](j_major, j_minor)
        let transcript = make_carrot_transcript!(domain_separators::ADDRESS_INDEX_PREIMAGE_1,
            u32 : &j_major, u32 : &j_minor);
        Self::from(derive_bytes_32(&transcript, s_generate_address.as_bytes()))
    }
}

impl AddressIndexPreimage2 {
    /// Derive Carrot key hierarchy address index preimage 2 from account public info and index
    pub fn derive(
        s_address_index_preimage_1: &AddressIndexPreimage1,
        j_major: u32,
        j_minor: u32,
        account_spend_pubkey: &AddressSpendPubkey,
        account_view_pubkey: &AddressViewPubkey
    ) -> Self {
        // s^j_ap2 = H_32[s^j_ap1](j_major, j_minor, K_s, K_v)
        let transcript = make_carrot_transcript!(domain_separators::ADDRESS_INDEX_PREIMAGE_2,
            u32 : &j_major,
            u32 : &j_minor,
            AddressSpendPubkey : account_spend_pubkey,
            AddressViewPubkey: account_view_pubkey);
        Self::from(derive_bytes_32(&transcript, s_address_index_preimage_1.as_bytes()))
    }
}

impl SubaddressScalarSecret {
    /// Derive subaddress scalar secret from account spend pubkey and preimages
    pub fn derive(
        s_address_index_preimage_2: &AddressIndexPreimage2,
        account_spend_pubkey: &AddressSpendPubkey
    ) -> Self {
        // k^j_subscal = H_n[s^j_ap2](K_s)
        let transcript = make_carrot_transcript!(domain_separators::SUBADDRESS_SCALAR,
            AddressSpendPubkey : account_spend_pubkey);
        Self(derive_scalar(&transcript, s_address_index_preimage_2.as_bytes()))
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
    fn converge_make_carrot_partial_spend_pubkey() {
        assert_eq_hex!(
            "eef3184e91505660c8ccbdeec1bd3b1b7b56d2c39efcad8a036f963470d6f498",
            PartialAccountSpendPubkey::derive(&hex_into!(
                "c9651fc906015afeefdb8d3bf7be621c36e035de2a85cb22dd4b869a22086f0e"
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
    fn converge_make_carrot_generateimage_preimage() {
        assert_eq_hex!(
            "0f3bf96a0642ab4cd10e8c64fba1cc535379ec18dbc7d304d50eb753197e266f",
            GenerateImagePreimage::derive(&hex_into!(
                "59b2ee8646923309384704613418f5982b0167eb3cd87c6c067ee10700c3af91"
            ))
        );
    }

    #[test]
    fn converge_make_carrot_generateimage_key() {
        assert_eq_hex!(
            "dabc1ed54dc44f68f67200a1a66ee30b3237f05c2f6dc0dd47e5743431ac800b",
            GenerateImageKey::derive(
                &hex_into!("0f3bf96a0642ab4cd10e8c64fba1cc535379ec18dbc7d304d50eb753197e266f"),
                &hex_into!("eef3184e91505660c8ccbdeec1bd3b1b7b56d2c39efcad8a036f963470d6f498")
            )
        );
    }

    #[test]
    fn converge_make_carrot_viewincoming_key() {
        assert_eq_hex!(
            "12624c702b4c1a22fd710a836894ed0705955502e6498e5c6e3ad6f5920bb00f",
            ViewIncomingKey::derive(&hex_into!(
                "59b2ee8646923309384704613418f5982b0167eb3cd87c6c067ee10700c3af91"
            ))
        );
    }

    #[test]
    fn converge_make_carrot_generateaddress_secret() {
        assert_eq_hex!(
            "039f0744fb138954072ee6bcbda4b5c085fd05e09b476a7b34ad20bf9ad440bc",
            GenerateAddressSecret::derive(&hex_into!(
                "59b2ee8646923309384704613418f5982b0167eb3cd87c6c067ee10700c3af91"
            ))
        );
    }

    #[test]
    fn converge_make_carrot_spend_pubkey() {
        assert_eq_hex!(
            "4198f391723f6c64eb75e4f0e341d576dc344e8a8ad3164444451855dbd862b4",
            AddressSpendPubkey::derive_carrot_account_spend_pubkey(
                &hex_into!("dabc1ed54dc44f68f67200a1a66ee30b3237f05c2f6dc0dd47e5743431ac800b"),
                &hex_into!("c9651fc906015afeefdb8d3bf7be621c36e035de2a85cb22dd4b869a22086f0e")
            )
        );
    }

    #[test]
    fn converge_make_carrot_address_index_preimage_1() {
        assert_eq_hex!(
            "9c21bf89635102f5379f97b5d08074e6ed36084544262f92a93d7644945475f1",
            AddressIndexPreimage1::derive(
                &hex_into!("039f0744fb138954072ee6bcbda4b5c085fd05e09b476a7b34ad20bf9ad440bc"),
                5,
                16
            )
        );
    }

    #[test]
    fn converge_make_carrot_address_index_preimage_2() {
        assert_eq_hex!(
            "523188ad4482797566397e9e7f13c9e7169b04aefd9eb449c31baaab82713a19",
            AddressIndexPreimage2::derive(
                &hex_into!("9c21bf89635102f5379f97b5d08074e6ed36084544262f92a93d7644945475f1"),
                5,
                16,
                &hex_into!("4198f391723f6c64eb75e4f0e341d576dc344e8a8ad3164444451855dbd862b4"),
                &hex_into!("14d12188409591353096b41abeccf66a88d916dfe0e6d1998672293ebc1cc83d")
            )
        );
    }

    #[test]
    fn converge_make_carrot_subaddress_scalar() {
        assert_eq_hex!(
            "016b3265a2b7b0d05bcffd6f4e87df9fd9b8cd2a39dfc38c4731ca243cca5f09",
            SubaddressScalarSecret::derive(
                &hex_into!("523188ad4482797566397e9e7f13c9e7169b04aefd9eb449c31baaab82713a19"),
                &hex_into!("4198f391723f6c64eb75e4f0e341d576dc344e8a8ad3164444451855dbd862b4")
            )
        );
    }
}
