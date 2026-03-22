use alloc::borrow::Cow;
use yoke::Yokeable;

use crate::{
    DecodeError, DecodeResult, EncodeError, EncodeResult, PacketPayload, PayloadType, SerDeser,
    crypto::{AesImpl, ContainsEncryptable, DecryptedView, HmacImpl, VerifiablePayload},
    io::{ByteVecImpl, SliceWriter, TinyReadExt},
    payloads::text::TextMessageData,
};

#[derive(Yokeable, Debug)]
pub struct GroupText<'a> {
    pub channel: u8,
    pub mac: [u8; 2],
    pub msg: Cow<'a, [u8]>,
}

impl<'a> GroupText<'a> {
    pub fn new(channel: u8, msg: impl Into<Cow<'a, [u8]>>, mac_key: &[u8]) -> GroupText<'a> {
        let msg = msg.into();
        GroupText {
            channel,
            mac: hmac_sha256::HMAC::mac(&msg, mac_key)[..2]
                .try_into()
                .unwrap(),
            msg,
        }
    }
}

impl<'a> PacketPayload for GroupText<'a> {
    const PAYLOAD_TYPE: PayloadType = PayloadType::GrpTxt;
}

impl<'a> SerDeser for GroupText<'a> {
    type Representation<'data> = GroupText<'data>;

    fn encode_size<'data>(object: &Self::Representation<'data>) -> usize {
        1 + 2 + object.msg.len()
    }

    fn encode<'data, 'out>(
        object: &Self::Representation<'data>,
        out: &'out mut [u8],
    ) -> EncodeResult<&'out [u8]> {
        if out.len() < GroupText::encode_size(object) {
            return Err(EncodeError::BufferTooSmall);
        }

        let mut out = SliceWriter::new(out);
        out.write_u8(object.channel);
        out.write_slice(&object.mac);
        out.write_slice(&object.msg);
        Ok(out.finish())
    }

    fn decode<'data>(mut data: &'data [u8]) -> DecodeResult<Self::Representation<'data>> {
        Ok(GroupText {
            channel: data.read_u8()?,
            mac: *data.read_chunk::<2>()?,
            msg: Cow::Borrowed(data),
        })
    }
}

impl<'a> VerifiablePayload for GroupText<'a> {
    fn verify<H: HmacImpl>(&self, mac_key: &[u8]) -> bool {
        H::mac(&self.msg, mac_key)[..2] == self.mac
    }
}

impl<'a> ContainsEncryptable for GroupText<'a> {
    type Output = TextMessageData<'static>;

    async fn decrypt<'s, B: AesImpl>(
        &self,
        key: &[u8; 16],
        scratch: &'s mut impl ByteVecImpl,
    ) -> DecodeResult<DecryptedView<'s, Self::Output>> {
        B::decrypt(key, &self.msg, scratch)
            .await
            .map_err(|_| DecodeError::FailedDecrypt)
            .map(DecryptedView::new)
    }

    async fn decrypt_owned<B: AesImpl>(
        &self,
        key: &[u8; 16],
    ) -> DecodeResult<DecryptedView<'static, Self::Output>> {
        B::decrypt_to_vec(key, &self.msg)
            .await
            .map_err(|_| DecodeError::FailedDecrypt)
            .map(DecryptedView::new)
    }
}
