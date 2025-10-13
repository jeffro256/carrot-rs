use crate::as_crypto::AsScalar;
use crate::device::*;
use crate::*;

impl ViewIncomingKeyDevice for ViewIncomingKey {
    #[allow(non_snake_case)]
    fn view_key_scalar_mult_ed25519(
        &self,
        P: &curve25519_dalek::EdwardsPoint,
    ) -> Result<curve25519_dalek::EdwardsPoint> {
        Ok(self.as_scalar_ref() * P)
    }

    #[allow(non_snake_case)]
    fn view_key_scalar_mult_x25519(&self, D: &EnoteEphemeralPubkey) -> Result<MontgomeryECDH> {
        Ok(MontgomeryECDH::derive_as_receiver(self, D))
    }

    fn make_janus_anchor_special(
        &self,
        enote_ephemeral_pubkey: &EnoteEphemeralPubkey,
        input_context: &InputContext,
        onetime_address: &OutputPubkey,
    ) -> Result<JanusAnchor> {
        Ok(JanusAnchor::derive_special(
            enote_ephemeral_pubkey,
            input_context,
            onetime_address,
            self,
        ))
    }
}

impl ViewBalanceSecretDevice for ViewBalanceSecret {
    fn make_internal_view_tag(
        &self,
        input_context: &InputContext,
        onetime_address: &OutputPubkey,
    ) -> Result<ViewTag> {
        Ok(ViewTag::derive(
            self.as_bytes(),
            input_context,
            onetime_address,
        ))
    }

    fn make_internal_sender_receiver_secret(
        &self,
        enote_ephemeral_pubkey: &EnoteEphemeralPubkey,
        input_context: &InputContext,
    ) -> Result<SenderReceiverSecret> {
        Ok(SenderReceiverSecret::derive(
            self.as_bytes(),
            enote_ephemeral_pubkey,
            input_context,
        ))
    }
}

impl GenerateAddressSecretDevice for GenerateAddressSecret {
    fn make_index_extension_generator(
        &self,
        major_index: u32,
        minor_index: u32,
    ) -> Result<AddressIndexGeneratorSecret> {
        Ok(AddressIndexGeneratorSecret::derive(
            self,
            major_index,
            minor_index,
        ))
    }
}
