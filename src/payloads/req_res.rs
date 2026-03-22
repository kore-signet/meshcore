use alloc::borrow::Cow;

use crate::{
    DecodeResult, EncodeError, EncodeResult, PacketPayload, PayloadType, SerDeser,
    crypto::Encryptable,
    io::{SliceWriter, TinyReadExt},
};

pub struct RequestPayload<'a> {
    pub time: u32,
    pub data: Cow<'a, [u8]>,
}

impl<'a> SerDeser for RequestPayload<'a> {
    type Representation<'data> = RequestPayload<'data>;

    fn encode_size<'data>(object: &Self::Representation<'data>) -> usize {
        4 + object.data.len()
    }

    fn encode<'data, 'out>(
        object: &Self::Representation<'data>,
        out: &'out mut [u8],
    ) -> EncodeResult<&'out [u8]> {
        if out.len() < RequestPayload::encode_size(object) {
            return Err(EncodeError::BufferTooSmall);
        };

        let mut out = SliceWriter::new(out);
        out.write_u32_le(object.time);
        out.write_slice(&object.data);
        Ok(out.finish())
    }

    fn decode<'data>(mut data: &'data [u8]) -> DecodeResult<Self::Representation<'data>> {
        Ok(RequestPayload {
            time: data.read_u32_le()?,
            data: Cow::Borrowed(data),
        })
    }
}

impl<'a> PacketPayload for RequestPayload<'a> {
    const PAYLOAD_TYPE: PayloadType = PayloadType::Request;
}

impl<'a> Encryptable for RequestPayload<'a> {}

pub struct ResponsePayload<'a, T: SerDeser> {
    pub data: T::Representation<'a>,
}

impl<'a, T: SerDeser> SerDeser for ResponsePayload<'a, T> {
    type Representation<'data> = ResponsePayload<'data, T>;

    fn encode_size<'data>(object: &Self::Representation<'data>) -> usize {
        T::encode_size(&object.data)
    }

    fn encode<'data, 'out>(
        object: &Self::Representation<'data>,
        out: &'out mut [u8],
    ) -> EncodeResult<&'out [u8]> {
        if out.len() < ResponsePayload::encode_size(object) {
            return Err(EncodeError::BufferTooSmall);
        };

        T::encode(&object.data, out)
    }

    fn decode<'data>(data: &'data [u8]) -> DecodeResult<Self::Representation<'data>> {
        Ok(ResponsePayload {
            data: T::decode(data)?,
        })
    }
}

impl<'a, T: SerDeser> PacketPayload for ResponsePayload<'a, T> {
    const PAYLOAD_TYPE: PayloadType = PayloadType::Response;
}

impl<'a, T: SerDeser> Encryptable for ResponsePayload<'a, T> {}

pub struct RepeaterLogin<'a> {
    pub timestamp: u32,
    pub password: Cow<'a, [u8]>,
}

impl<'a> SerDeser for RepeaterLogin<'a> {
    type Representation<'data> = RepeaterLogin<'data>;

    fn encode_size<'data>(object: &Self::Representation<'data>) -> usize {
        4 + object.password.len()
    }

    fn encode<'data, 'out>(
        object: &Self::Representation<'data>,
        out: &'out mut [u8],
    ) -> EncodeResult<&'out [u8]> {
        if out.len() < RepeaterLogin::encode_size(object) {
            return Err(EncodeError::BufferTooSmall);
        }

        let mut out = SliceWriter::new(out);

        out.write_u32_le(object.timestamp);
        out.write_slice(&object.password);

        Ok(out.finish())
    }

    fn decode<'data>(mut data: &'data [u8]) -> DecodeResult<Self::Representation<'data>> {
        Ok(RepeaterLogin {
            timestamp: data.read_u32_le()?,
            password: Cow::Borrowed(data),
        })
    }
}

impl<'a> Encryptable for RepeaterLogin<'a> {}
