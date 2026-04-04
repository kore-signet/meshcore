use alloc::{borrow::Cow, string::String, vec::Vec};
use modular_bitfield::{Specifier, bitfield, prelude::B2};
use serde::{Deserialize, Serialize};
use yoke::Yokeable;

use crate::{
    DecodeError, DecodeResult, EncodeError, EncodeResult, PacketPayload, PayloadType, SerDeser,
    crypto::Encryptable,
    identity::LocalIdentity,
    io::{SliceWriter, TinyReadExt},
};

#[bitfield]
#[derive(Clone, Copy, Debug)]
pub struct TextHeader {
    pub attempt: B2,
    pub text_type: TextType,
}

#[derive(Specifier, Debug, Clone, Copy, Serialize, Deserialize)]
#[bits = 6]
pub enum TextType {
    PlainText = 0x00,
    CliCommand = 0x01,
    SignedPlainText = 0x02,
}

#[derive(Yokeable)]
pub struct TextMessageData<'a> {
    pub timestamp: u32,
    pub header: TextHeader,
    pub message: Cow<'a, [u8]>,
}

impl<'a> TextMessageData<'a> {
    pub fn plaintext(timestamp: u32, message: impl Into<Cow<'a, [u8]>>) -> Self {
        Self {
            timestamp,
            header: TextHeader::new().with_text_type(TextType::PlainText),
            message: message.into(),
        }
    }

    pub fn signed_plaintext(
        timestamp: u32,
        message: impl Into<Cow<'a, [u8]>>,
        identity: &LocalIdentity,
    ) -> Self {
        let msg = message.into();
        let mut data = Vec::with_capacity(msg.len() + 4);
        data.extend_from_slice(&identity.pubkey()[0..4]);
        data.extend_from_slice(&msg);

        Self {
            timestamp,
            header: TextHeader::new().with_text_type(TextType::SignedPlainText),
            message: Cow::Owned(data),
        }
    }

    pub fn cli_command(timestamp: u32, message: impl Into<Cow<'a, [u8]>>) -> Self {
        Self {
            timestamp,
            header: TextHeader::new().with_text_type(TextType::CliCommand),
            message: message.into(),
        }
    }

    pub fn as_utf8(&self) -> DecodeResult<&str> {
        core::str::from_utf8(&self.message).map_err(DecodeError::from)
    }
}

impl<'a> SerDeser for TextMessageData<'a> {
    type Representation<'data> = TextMessageData<'data>;

    fn encode_size<'data>(object: &Self::Representation<'data>) -> usize {
        4 + 1 + object.message.len()
    }

    fn encode<'data, 'out>(
        object: &Self::Representation<'data>,
        out: &'out mut [u8],
    ) -> EncodeResult<&'out [u8]> {
        if out.len() < TextMessageData::encode_size(object) {
            return Err(EncodeError::BufferTooSmall);
        }

        let mut out = SliceWriter::new(out);
        out.write_u32_le(object.timestamp);
        out.write_u8(object.header.into_bytes()[0]);
        out.write_slice(&object.message);

        Ok(out.finish())
    }

    fn decode<'data>(mut data: &'data [u8]) -> DecodeResult<TextMessageData<'data>> {
        let timestamp = data.read_u32_le()?;
        let text_header = TextHeader::from_bytes(*data.read_chunk::<1>()?);
        if text_header.text_type_or_err().is_err() {
            return Err(DecodeError::InvalidBitPattern);
        }

        Ok(TextMessageData {
            timestamp,
            header: text_header,
            message: Cow::Borrowed(data),
        })
    }
}

impl PacketPayload for TextMessageData<'static> {
    const PAYLOAD_TYPE: PayloadType = PayloadType::TxtMsg;
}

impl<'a> Encryptable for TextMessageData<'static> {}

impl<'a> core::fmt::Debug for TextMessageData<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PlaintextMessage")
            .field("timestamp", &self.timestamp)
            .field("text_type", &self.header.text_type_or_err())
            .field("attempt", &self.header.attempt())
            .field("message", &String::from_utf8_lossy(&self.message))
            .finish()
    }
}
