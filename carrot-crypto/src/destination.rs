use crate::consts::*;
use crate::device::*;
use crate::random::Random;
use crate::type_macros::*;
use crate::*;

define_tiny_byte_type! {PaymentId, "Short payment ID in an integrated address", PAYMENT_ID_BYTES}

/// Destination address
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CarrotDestinationV1 {
    /// Address spend pubkey $K^j_s$
    pub address_spend_pubkey: AddressSpendPubkey,
    /// Address view pubkey $K^j_v$
    pub address_view_pubkey: AddressViewPubkey,
    /// True iff destination is a subaddress, i.e. not a primary/main address
    pub is_subaddress: bool,
    /// Payment ID $pid$
    pub payment_id: PaymentId,
}

impl CarrotDestinationV1 {
    /// Construct a primary/main address, Carrot-derived account or otherwise
    pub fn make_main_address(
        account_spend_pubkey: AddressSpendPubkey,
        primary_address_view_pubkey: AddressViewPubkey,
    ) -> Self {
        Self {
            address_spend_pubkey: account_spend_pubkey,
            address_view_pubkey: primary_address_view_pubkey,
            is_subaddress: false,
            payment_id: Default::default(),
        }
    }

    /// Construct a Carrot-derived account subaddress
    pub fn make_subaddress<G: GenerateAddressSecretDevice>(
        account_spend_pubkey: &AddressSpendPubkey,
        account_view_pubkey: &AddressViewPubkey,
        s_generate_address_dev: &G,
        major_index: u32,
        minor_index: u32,
    ) -> Option<Self> {
        if major_index == 0 && minor_index == 0 {
            return None;
        }

        // s^j_gen = H_32[s_ga](j_major, j_minor)
        let address_index_generator = s_generate_address_dev
            .make_index_extension_generator(major_index, minor_index)
            .ok()?;

        // k^j_subscal = H_n[s^j_gen](K_s, K_v, j_major, j_minor)
        let subaddress_scalar = SubaddressScalarSecret::derive(
            account_spend_pubkey,
            account_view_pubkey,
            &address_index_generator,
            major_index,
            minor_index,
        );

        // K^j_s = k^j_subscal * K_s
        let address_spend_pubkey = AddressSpendPubkey::derive_subaddress_spend_pubkey(
            &subaddress_scalar,
            account_spend_pubkey,
        )?;

        // K^j_v = k^j_subscal * K_v
        let address_view_pubkey = AddressViewPubkey::derive_subaddress_view_pubkey(
            &subaddress_scalar,
            account_view_pubkey,
        )?;

        Some(Self {
            address_spend_pubkey: address_spend_pubkey,
            address_view_pubkey: address_view_pubkey,
            is_subaddress: true,
            payment_id: Default::default(),
        })
    }

    /// Construct an integrated address, Carrot-derived account or otherwise
    pub fn make_integrated_address(
        account_spend_pubkey: AddressSpendPubkey,
        primary_address_view_pubkey: AddressViewPubkey,
        payment_id: PaymentId,
    ) -> Self {
        Self {
            address_spend_pubkey: account_spend_pubkey,
            address_view_pubkey: primary_address_view_pubkey,
            is_subaddress: false,
            payment_id: payment_id,
        }
    }

    /// Returns whether address is an integrated address
    pub fn is_integrated(&self) -> bool {
        return self.payment_id != Default::default();
    }
}

impl Random for CarrotDestinationV1 {
    type Params = (bool, bool);
    fn new_random_with_params<R: rand_core::CryptoRngCore + ?Sized>(
        rng: &mut R,
        p: Self::Params,
    ) -> Self {
        let (is_subaddress, is_integrated_address) = p;
        CarrotDestinationV1 {
            address_spend_pubkey: AddressSpendPubkey::new_random_with_params(rng, ()),
            address_view_pubkey: AddressViewPubkey::new_random_with_params(rng, ()),
            is_subaddress: is_subaddress,
            payment_id: if is_integrated_address {
                PaymentId::new_random_with_params(rng, ())
            } else {
                Default::default()
            },
        }
    }
}

#[cfg(test)]
mod test {
    use crate::account::*;
    use crate::destination::*;
    use crate::transcript::*;
    use crate::unit_testing::*;

    #[test]
    fn converge_make_subaddress() {
        let s_generate_address: GenerateAddressSecret =
            hex_into!("593ece76c5d24cbfe3c7ac9e2d455cdd4b372c89584700bf1c2e7bef2b70a4d1");

        let subaddress = CarrotDestinationV1::make_subaddress(
            &hex_into!("c984806ae9be958800cfe04b5ed85279f48d78c3792b5abb2f5ce2b67adc491f"),
            &AddressViewPubkey::derive_carrot_account_view_pubkey(
                &hex_into!("60eff3ec120a12bb44d4258816e015952fc5651040da8c8af58c17676485f200"),
                &hex_into!("c984806ae9be958800cfe04b5ed85279f48d78c3792b5abb2f5ce2b67adc491f"),
            )
            .unwrap(),
            &s_generate_address,
            5,
            16,
        )
        .unwrap();
        assert_eq_hex!(
            "605bc2e5e0d2adcb6480eaf02d8c76be5ef6c3a26b6d13569d000b371a62db99",
            subaddress.address_spend_pubkey
        );
        assert_eq_hex!(
            "06384ebd3a99beaaa7f2e1d5744e83b4152a13abcd31fb08295eed4862be4f21",
            subaddress.address_view_pubkey
        );
    }
}
