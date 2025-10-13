use carrot_crypto::{*, opening::{OpenedPoint, OpeningScalarSecret}};
use sha3::{digest::Output, Digest, Keccak256};
use std::collections::HashMap;

use crate::common::math::scalar_mul_gt;

#[derive(Clone, Copy)]
pub enum AddressDeriveType {
    Carrot,
    Legacy,
}

pub struct SubaddressIndex {
    pub major: u32,
    pub minor: u32,
}

impl SubaddressIndex {
    pub fn is_subaddress(&self) -> bool {
        return self.major != 0 || self.minor != 0;
    }
}

pub struct SubaddressIndexExtended {
    pub index: SubaddressIndex,
    pub derive_type: Option<AddressDeriveType>,
}

pub struct MockKeys {
    // legacy privkeys and pubkeys
    pub legacy_k_spend: ProveSpendKey,
    pub legacy_account_spend_pubkey: AddressSpendPubkey,

    // carrot secret keys (minus k_v, which is shared with legacy k_v)
    pub s_master: MasterSecret,
    pub k_prove_spend: ProveSpendKey,
    pub s_view_balance: ViewBalanceSecret,
    pub k_generate_image: GenerateImageKey,
    pub s_generate_address: GenerateAddressSecret,

    // shared keys
    pub k_view_incoming: ViewIncomingKey,
    pub primary_address_view_pubkey: AddressViewPubkey,

    // carrot public keys (minus K^0_v, which is shared with legacy K^0_v)
    pub carrot_account_spend_pubkey: AddressSpendPubkey,
    pub carrot_account_view_pubkey: AddressViewPubkey,

    pub subaddress_map: HashMap<AddressSpendPubkey, SubaddressIndexExtended>,

    pub default_derive_type: AddressDeriveType,
}

impl MockKeys {
    pub fn main_address(&self, derive_type: Option<AddressDeriveType>) -> CarrotDestinationV1 {
        let account_spend_pubkey = match self.resolve_derive_type(derive_type) {
            AddressDeriveType::Carrot => &self.carrot_account_spend_pubkey,
            AddressDeriveType::Legacy => &self.legacy_account_spend_pubkey,
        };

        CarrotDestinationV1::make_main_address(
            account_spend_pubkey.clone(),
            self.primary_address_view_pubkey.clone(),
        )
    }

    pub fn integrated_address(
        &self,
        payment_id: PaymentId,
        derive_type: Option<AddressDeriveType>,
    ) -> CarrotDestinationV1 {
        let account_spend_pubkey = match self.resolve_derive_type(derive_type) {
            AddressDeriveType::Carrot => &self.carrot_account_spend_pubkey,
            AddressDeriveType::Legacy => &self.legacy_account_spend_pubkey,
        };

        CarrotDestinationV1::make_integrated_address(
            account_spend_pubkey.clone(),
            self.primary_address_view_pubkey.clone(),
            payment_id,
        )
    }

    pub fn subaddress(&self, subaddr_index: &SubaddressIndexExtended) -> CarrotDestinationV1 {
        match self.resolve_derive_type(subaddr_index.derive_type) {
            AddressDeriveType::Carrot => {
                if subaddr_index.index.is_subaddress() {
                    CarrotDestinationV1::make_subaddress(
                        &self.carrot_account_spend_pubkey,
                        &self.carrot_account_view_pubkey,
                        &self.s_generate_address,
                        subaddr_index.index.major,
                        subaddr_index.index.minor,
                    )
                    .expect("CarrotDestinationV1::make_subaddress")
                } else {
                    CarrotDestinationV1::make_main_address(
                        self.carrot_account_spend_pubkey.clone(),
                        self.primary_address_view_pubkey.clone(),
                    )
                }
            }
            AddressDeriveType::Legacy => Self::make_legacy_subaddress(
                &self.k_view_incoming,
                &self.legacy_account_spend_pubkey,
                subaddr_index.index.major,
                subaddr_index.index.minor,
            ),
        }
    }

    pub fn opening_for_subaddress(
        &self,
        subaddr_index: &SubaddressIndexExtended,
    ) -> (OpeningScalarSecret, OpeningScalarSecret, AddressSpendPubkey) {
        let is_subaddress = subaddr_index.index.is_subaddress();
        let major_index = subaddr_index.index.major;
        let minor_index = subaddr_index.index.minor;

        let (address_privkey_g, address_privkey_t) =
            match self.resolve_derive_type(subaddr_index.derive_type) {
                AddressDeriveType::Carrot => {
                    // s^j_gen = H_32[s_ga](j_major, j_minor)
                    let address_index_generator = AddressIndexGeneratorSecret::derive(
                        &self.s_generate_address,
                        major_index,
                        minor_index,
                    );

                    let subaddress_scalar = if is_subaddress {
                        // k^j_subscal = H_n(K_s, j_major, j_minor, s^j_gen)
                        SubaddressScalarSecret::derive(
                            &self.carrot_account_spend_pubkey,
                            &address_index_generator,
                            major_index,
                            minor_index,
                        )
                    } else {
                        // k^j_subscal = 1
                        SubaddressScalarSecret::from(1u64)
                    };

                    // k^g_a = k_gi * k^j_subscal
                    let address_privkey_g = &self.k_generate_image * &subaddress_scalar;

                    // k^t_a = k_ps * k^j_subscal
                    let address_privkey_t = &self.k_prove_spend * &subaddress_scalar;

                    (address_privkey_g, address_privkey_t)
                }
                AddressDeriveType::Legacy => {
                    // m = Hn(k_v || j_major || j_minor) if subaddress else 0
                    let subaddress_extension = Self::make_legacy_subaddress_extension(
                        &self.k_view_incoming,
                        major_index,
                        minor_index,
                    );

                    // k^g_a = k_s + m
                    let address_privkey_g = &self.legacy_k_spend + &subaddress_extension;

                    // k^t_a = 0
                    (address_privkey_g, OpeningScalarSecret::default())
                }
            };

        // perform sanity check
        let addr = self.subaddress(subaddr_index);
        let recomputed_address_spend_pubkey = AddressSpendPubkey::from(OpenedPoint::scalar_mul_gt(
            &address_privkey_g, &address_privkey_t));

        assert_eq!(recomputed_address_spend_pubkey, addr.address_spend_pubkey);

        (
            address_privkey_g,
            address_privkey_t,
            recomputed_address_spend_pubkey,
        )
    }

    pub fn try_searching_for_opening_for_subaddress(
        &self,
        address_spend_pubkey: &AddressSpendPubkey,
    ) -> Option<(OpeningScalarSecret, OpeningScalarSecret)> {
        let subaddr_index = self.subaddress_map.get(address_spend_pubkey)?;

        let (address_privkey_g, address_privkey_t, recomputed_address_spend_pubkey) =
            self.opening_for_subaddress(subaddr_index);

        assert_eq!(&recomputed_address_spend_pubkey, address_spend_pubkey);

        Some((address_privkey_g, address_privkey_t))
    }

    pub fn try_searching_for_opening_for_onetime_address(
        &self,
        address_spend_pubkey: &AddressSpendPubkey,
        sender_extension_g: &OnetimeExtensionG,
        sender_extension_t: &OnetimeExtensionT,
    ) -> Option<(OpeningScalarSecret, OpeningScalarSecret)> {
        // k^{j,g}_addr, k^{j,t}_addr
        let (address_privkey_g, address_privkey_t) =
            self.try_searching_for_opening_for_subaddress(address_spend_pubkey)?;

        // x = k^{j,g}_addr + k^g_o
        let x = &address_privkey_g + sender_extension_g;

        // y = k^{j,t}_addr + k^t_o
        let y = &address_privkey_t + sender_extension_t;

        Some((x, y))
    }

    pub fn can_open_fcmp_onetime_address(
        &self,
        address_spend_pubkey: &AddressSpendPubkey,
        sender_extension_g: &OnetimeExtensionG,
        sender_extension_t: &OnetimeExtensionT,
        onetime_address: &OutputPubkey,
    ) -> bool {
        // first test that K^j_s + k^g_o G + k^t_o T ?= K_o
        // otherwise, there's a problem with the scan funcs
        let sender_extension_pubkey = OnetimeExtension::derive_from_extension_scalars(
            sender_extension_g,
            sender_extension_t);
        let recomputed_onetime_address = OutputPubkey::derive_from_extension(address_spend_pubkey,
            sender_extension_pubkey).expect("OutputPubkey::derive_from_extension");
        assert_eq!(&recomputed_onetime_address, onetime_address);

        let Some((x, y)) = self.try_searching_for_opening_for_onetime_address(
            address_spend_pubkey,
            sender_extension_g,
            sender_extension_t,
        ) else {
            return false;
        };

        // O' = x G + y T
        let recomputed_onetime_address = OutputPubkey::from(OpenedPoint::scalar_mul_gt(&x, &y));

        // O' ?= O
        &recomputed_onetime_address == onetime_address
    }

    fn resolve_derive_type(&self, derive_type: Option<AddressDeriveType>) -> AddressDeriveType {
        derive_type.unwrap_or(self.default_derive_type)
    }

    fn make_legacy_subaddress_extension(
        k_view: &ViewIncomingKey,
        major_index: u32,
        minor_index: u32,
    ) -> OpeningScalarSecret {
        if major_index == 0 && minor_index == 0 {
            return OpeningScalarSecret::default();
        }

        let mut data = [0u8; (8 + 32 + 4 + 4)];
        // "Subaddr" || IntToBytes(0)
        data[0..7].copy_from_slice("SubAddr".as_bytes());
        data[8] = 0;
        // ... || k_v
        data[8..40].copy_from_slice(k_view.as_bytes());
        // ... || IntToBytes32(j_major)
        data[40..44].copy_from_slice(&major_index.to_be_bytes());
        // ... || IntToBytes32(j_minor)
        data[44..48].copy_from_slice(&minor_index.to_be_bytes());

        // k^j_subext = ScalarDeriveLegacy("SubAddr" || IntToBytes8(0) || k_v || IntToBytes32(j_major) || IntToBytes32(j_minor))
        let mut hasher = Keccak256::default();
        hasher.update(&data);
        let hash = hasher.finalize();
        OpeningScalarSecret::from_bytes_mod_order(hash.into())
    }

    fn make_legacy_view_key(legacy_k_spend: &ProveSpendKey) -> ViewIncomingKey {
        let mut hasher = Keccak256::default();
        hasher.update(legacy_k_spend.as_bytes());
        let hash = hasher.finalize();
        ViewIncomingKey::from_bytes_mod_order(hash.into())
    }

    fn make_legacy_subaddress(
        k_view: &ViewIncomingKey,
        account_spend_pubkey: &AddressSpendPubkey,
        major_index: u32,
        minor_index: u32,
    ) -> CarrotDestinationV1 {
        let subaddress_extension_scalar =
            Self::make_legacy_subaddress_extension(&k_view, major_index, minor_index);
        let subaddress_extension = OpenedPoint::scalar_mul_gt(&subaddress_extension_scalar, 
            &OpeningScalarSecret::default());
        let address_spend_pubkey = AddressSpendPubkey::from(account_spend_pubkey +
            &subaddress_extension);
        let address_view_pubkey = AddressViewPubkey::derive_carrot_account_view_pubkey(k_view,
            &address_spend_pubkey).expect("derive_carrot_account_view_pubkey (legacy)");
        let is_subaddress = major_index != 0 || minor_index != 0;
        CarrotDestinationV1 {
            address_spend_pubkey: address_spend_pubkey,
            address_view_pubkey: address_view_pubkey,
            is_subaddress: is_subaddress,
            payment_id: PaymentId::default(),
        }
    }

    fn from_master_keys(
        s_master: MasterSecret,
        legacy_k_spend: ProveSpendKey,
        default_derive_type: AddressDeriveType,
    ) -> Self {
        // derive legacy pubkeys
        let legacy_account_spend_pubkey = AddressSpendPubkey::derive_carrot_account_spend_pubkey(
            &GenerateImageKey::from_bytes_mod_order(legacy_k_spend.as_bytes().clone()),
            &ProveSpendKey::default(),
        );

        // derive carrot privkeys
        let k_prove_spend = ProveSpendKey::derive(&s_master);
        let s_view_balance = ViewBalanceSecret::derive(&s_master);
        let k_generate_image = GenerateImageKey::derive(&s_view_balance);
        let s_generate_address = GenerateAddressSecret::derive(&s_view_balance);

        // derive view-incoming {pub/priv}key, dependent on address derive type
        let k_view_incoming = match default_derive_type {
            AddressDeriveType::Carrot => ViewIncomingKey::derive(&s_view_balance),
            AddressDeriveType::Legacy => Self::make_legacy_view_key(&legacy_k_spend),
        };
        let primary_address_view_pubkey =
            AddressViewPubkey::derive_primary_address_view_pubkey(&k_view_incoming);

        // derive carrot account pubkeys
        let carrot_account_spend_pubkey =
            AddressSpendPubkey::derive_carrot_account_spend_pubkey(&k_generate_image, &k_prove_spend);
        let carrot_account_view_pubkey = AddressViewPubkey::derive_carrot_account_view_pubkey(
            &k_view_incoming,
            &carrot_account_spend_pubkey,
        ).unwrap();

        // derive subaddress map, Carrot and Legacy
        let mut subaddress_map = HashMap::new();
        let derive_types = [AddressDeriveType::Carrot, AddressDeriveType::Legacy];
        for major_index in 0..=crate::common::MAX_SUBADDRESS_MAJOR_INDEX {
            for minor_index in 0..=crate::common::MAX_SUBADDRESS_MINOR_INDEX {
                for derive_type in derive_types.iter() {
                    let address_spend_pubkey = match derive_type {
                        AddressDeriveType::Carrot => {
                            if major_index != 0 || minor_index != 0 {
                                CarrotDestinationV1::make_subaddress(
                                    &carrot_account_spend_pubkey,
                                    &carrot_account_view_pubkey,
                                    &s_generate_address,
                                    major_index,
                                    minor_index,
                                )
                                .unwrap()
                                .address_spend_pubkey
                            } else {
                                carrot_account_spend_pubkey.clone()
                            }
                        }
                        AddressDeriveType::Legacy => {
                            Self::make_legacy_subaddress(
                                &k_view_incoming,
                                &legacy_account_spend_pubkey,
                                major_index,
                                minor_index,
                            )
                            .address_spend_pubkey
                        }
                    };
                    subaddress_map.insert(
                        address_spend_pubkey,
                        SubaddressIndexExtended {
                            index: SubaddressIndex {
                                major: major_index,
                                minor: minor_index,
                            },
                            derive_type: Some(derive_type.clone()),
                        },
                    );
                }
            }
        }

        Self {
            legacy_k_spend: legacy_k_spend,
            legacy_account_spend_pubkey: legacy_account_spend_pubkey,
            s_master: s_master,
            k_prove_spend: k_prove_spend,
            s_view_balance: s_view_balance,
            k_generate_image: k_generate_image,
            s_generate_address: s_generate_address,
            k_view_incoming: k_view_incoming,
            primary_address_view_pubkey: primary_address_view_pubkey,
            carrot_account_spend_pubkey: carrot_account_spend_pubkey,
            carrot_account_view_pubkey: carrot_account_view_pubkey,
            subaddress_map: subaddress_map,
            default_derive_type: default_derive_type,
        }
    }
}

impl random::Random for MockKeys {
    type Params = AddressDeriveType;
    fn new_random_with_params<R: rand_core::CryptoRngCore + ?Sized>(
        rng: &mut R,
        p: Self::Params,
    ) -> Self {
        Self::from_master_keys(
            MasterSecret::new_random_with_params(rng, ()),
            ProveSpendKey::new_random_with_params(rng, ()),
            p,
        )
    }
}
