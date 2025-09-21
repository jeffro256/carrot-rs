// Carrot addressing protocol domain separators
pub const AMOUNT_BLINDING_FACTOR: &str = "Carrot commitment mask";
pub const ONETIME_EXTENSION_G: &str = "Carrot key extension G";
pub const ONETIME_EXTENSION_T: &str = "Carrot key extension T";
pub const ENCRYPTION_MASK_ANCHOR: &str = "Carrot encryption mask anchor";
pub const ENCRYPTION_MASK_AMOUNT: &str = "Carrot encryption mask a";
pub const ENCRYPTION_MASK_PAYMENT_ID: &str = "Carrot encryption mask pid";
pub const JANUS_ANCHOR_SPECIAL: &str = "Carrot janus anchor special";
pub const EPHEMERAL_PRIVKEY: &str = "Carrot sending key normal";
pub const VIEW_TAG: &str = "Carrot view tag";
pub const SENDER_RECEIVER_SECRET: &str = "Carrot sender-receiver secret";
pub const INPUT_CONTEXT_COINBASE: u8 = b'C';
pub const INPUT_CONTEXT_RINGCT: u8 = b'R';

// Carrot account secret domain separators
pub const PROVE_SPEND_KEY: &str = "Carrot prove-spend key";
pub const VIEW_BALANCE_SECRET: &str = "Carrot view-balance secret";
pub const GENERATE_IMAGE_KEY: &str = "Carrot generate-image key";
pub const INCOMING_VIEW_KEY: &str = "Carrot incoming view key";
pub const GENERATE_ADDRESS_SECRET: &str = "Carrot generate-address secret";

// Carrot address domain separators
pub const ADDRESS_INDEX_GEN: &str = "Carrot address index generator";
pub const SUBADDRESS_SCALAR: &str = "Carrot subaddress scalar";
