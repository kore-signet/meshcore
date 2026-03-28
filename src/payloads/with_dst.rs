use core::marker::PhantomData;

use arrayref::array_ref;

use crate::{
    DecodeError, DecodeResult, EncodeResult, PacketPayload, PayloadType, SerDeser,
    crypto::{
        AesImpl, ContainsEncryptable, DecryptedView, Encryptable, HmacImpl, VerifiablePayload,
    },
    io::{ByteVecImpl, SliceWriter, TinyReadExt},
};
use alloc::borrow::Cow;

pub struct EncryptedMessageWithDst<'a, P>
where
    P: SerDeser + Encryptable,
{
    pub destination_hash: u8,
    pub source_hash: u8,
    pub mac: [u8; 2],
    pub ciphertext: Cow<'a, [u8]>,
    pub _haunted: PhantomData<P>,
}

impl<'a, P: SerDeser + Encryptable> EncryptedMessageWithDst<'a, P> {
    pub fn mac<H: HmacImpl>(&self, mac_key: &[u8]) -> [u8; 32] {
        H::mac(&self.ciphertext, mac_key)
    }
}

impl<'a, P: PacketPayload + Encryptable> PacketPayload for EncryptedMessageWithDst<'a, P> {
    const PAYLOAD_TYPE: PayloadType = P::PAYLOAD_TYPE;
}

impl<'a, P: SerDeser + Encryptable> SerDeser for EncryptedMessageWithDst<'a, P> {
    type Representation<'data> = EncryptedMessageWithDst<'data, P>;

    fn encode_size<'data>(object: &Self::Representation<'data>) -> usize {
        1 + 1 + 2 + object.ciphertext.len()
    }

    fn encode<'data, 'out>(
        object: &Self::Representation<'data>,
        out: &'out mut [u8],
    ) -> EncodeResult<&'out [u8]> {
        let mut out = SliceWriter::new(out);
        out.write_u8(object.destination_hash);
        out.write_u8(object.source_hash);
        out.write_slice(&object.mac);
        out.write_slice(&object.ciphertext);
        Ok(out.finish())
    }

    fn decode<'data>(mut data: &'data [u8]) -> DecodeResult<Self::Representation<'data>> {
        Ok(EncryptedMessageWithDst {
            destination_hash: data.read_u8()?,
            source_hash: data.read_u8()?,
            mac: *data.read_chunk::<2>()?,
            ciphertext: data.into(),
            _haunted: PhantomData,
        })
    }
}

impl<'a, P: SerDeser + Encryptable> ContainsEncryptable for EncryptedMessageWithDst<'a, P> {
    type Output = P;

    async fn decrypt<'s, B: AesImpl>(
        &self,
        key: &[u8; 16],
        scratch: &'s mut impl ByteVecImpl,
    ) -> DecodeResult<DecryptedView<'s, Self::Output>> {
        B::decrypt(key, &self.ciphertext, scratch)
            .await
            .map_err(|_| DecodeError::FailedDecrypt)
            .map(DecryptedView::new)
    }

    async fn decrypt_owned<B: AesImpl>(
        &self,
        key: &[u8; 16],
    ) -> DecodeResult<DecryptedView<'static, Self::Output>> {
        B::decrypt_to_vec(key, &self.ciphertext)
            .await
            .map_err(|_| DecodeError::FailedDecrypt)
            .map(DecryptedView::new)
    }
}

impl<'a, P: SerDeser + Encryptable> VerifiablePayload for EncryptedMessageWithDst<'a, P> {
    fn verify<H: HmacImpl>(&self, mac_key: &[u8]) -> bool {
        let mac = self.mac::<H>(mac_key);

        *array_ref![&mac, 0, 2] == self.mac
    }
}
