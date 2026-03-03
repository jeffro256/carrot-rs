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

        // s^j_ap1 = H_32[s_ga](j_major, j_minor)
        let s_address_index_preimage_1 = s_generate_address_dev
            .make_address_index_preimage_1(major_index, minor_index)
            .ok()?;

        // s^j_ap2 = H_32[s^j_ap1](j_major, j_minor, K_s, K_v)
        let s_address_index_preimage_2 = AddressIndexPreimage2::derive(
            &s_address_index_preimage_1,
            major_index,
            minor_index,
            account_spend_pubkey,
            account_view_pubkey
        );

        // k^j_subscal = H_n[s^j_ap1](K_s)
        let subaddress_scalar = SubaddressScalarSecret::derive(
            &s_address_index_preimage_2,
            account_spend_pubkey
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
            hex_into!("039f0744fb138954072ee6bcbda4b5c085fd05e09b476a7b34ad20bf9ad440bc");

        let subaddress = CarrotDestinationV1::make_subaddress(
            &hex_into!("4198f391723f6c64eb75e4f0e341d576dc344e8a8ad3164444451855dbd862b4"),
            &AddressViewPubkey::derive_carrot_account_view_pubkey(
                &hex_into!("12624c702b4c1a22fd710a836894ed0705955502e6498e5c6e3ad6f5920bb00f"),
                &hex_into!("4198f391723f6c64eb75e4f0e341d576dc344e8a8ad3164444451855dbd862b4"),
            )
            .unwrap(),
            &s_generate_address,
            5,
            16,
        )
        .unwrap();
        assert_eq_hex!(
            "8f2f38e702678ae59751dc55818240e0330851e77bfaff003b671885ed06871e",
            subaddress.address_spend_pubkey
        );
        assert_eq_hex!(
            "369bdcf4f434f42eb09f4372cb6be30de7b17d21e4f98e244459a90b58cd0610",
            subaddress.address_view_pubkey
        );
    }
}
