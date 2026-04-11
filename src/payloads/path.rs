use alloc::borrow::Cow;
use modular_bitfield::Specifier;
use yoke::Yokeable;

use crate::{
    DecodeError, DecodeResult, EncodeError, EncodeResult, PacketPayload, Path, PathLen,
    PayloadType, SerDeser,
    crypto::Encryptable,
    io::{SliceWriter, TinyReadExt},
};

#[derive(Yokeable, Debug)]
pub struct ReturnedPath<'a> {
    pub path: Path<'a>,
    pub extra: Option<(PayloadType, Cow<'a, [u8]>)>,
    // pub extra: Cow<'a, [u8]>,
}

impl<'a> SerDeser for ReturnedPath<'a> {
    type Representation<'data> = ReturnedPath<'data>;

    fn encode_size<'data>(object: &Self::Representation<'data>) -> usize {
        let extra_len = if let Some((_, data)) = object.extra.as_ref() {
            1 + data.len()
        } else {
            0
        };

        1 + object.path.byte_size() + extra_len
    }

    fn encode<'data, 'out>(
        object: &Self::Representation<'data>,
        out: &'out mut [u8],
    ) -> EncodeResult<&'out [u8]> {
        if out.len() < ReturnedPath::encode_size(object) {
            return Err(EncodeError::BufferTooSmall);
        }

        let mut out = SliceWriter::new(out);
        out.write_u8(object.path.path_len_header().into_bytes()[0]);
        out.write_slice(object.path.raw_bytes());

        if let Some((extra_type, extra_data)) = object.extra.as_ref() {
            out.write_u8((*extra_type as u8));
            out.write_slice(extra_data);
        }

        Ok(out.finish())
    }

    fn decode<'data>(mut data: &'data [u8]) -> DecodeResult<Self::Representation<'data>> {
        let path_len = PathLen::from_bytes([data.read_u8()?]);
        let path = if path_len.len() == 0 {
            &[]
        } else {
            data.read_slice(path_len.byte_size())?
        };

        let extra = if !data.is_empty() {
            let extra_type = PayloadType::from_bytes(data.read_u8()? & 0x0F)
                .map_err(|_| DecodeError::InvalidBitPattern)?;
            Some((extra_type, Cow::Borrowed(data)))
        } else {
            None
        };

        // let path = data.read_slice(path_len as usize)?;

        Ok(ReturnedPath {
            path: Path {
                mode: path_len.mode(),
                backing: Cow::Borrowed(path),
            },
            extra,
        })
    }
}

impl<'a> PacketPayload for ReturnedPath<'a> {
    const PAYLOAD_TYPE: PayloadType = PayloadType::Path;
}

impl<'a> Encryptable for ReturnedPath<'a> {}

impl<'a> ReturnedPath<'a> {
    pub fn decode_payload_as<'d, P: PacketPayload>(
        &'d self,
    ) -> DecodeResult<P::Representation<'d>> {
        if let Some((extra_type, extra)) = self.extra.as_ref()
            && P::PAYLOAD_TYPE == *extra_type
        {
            return P::decode(extra);
        }

        Err(DecodeError::WrongPayloadType)
    }
}
