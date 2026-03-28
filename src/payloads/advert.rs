use crate::{
    DecodeError, DecodeResult, EncodeError, EncodeResult, PacketPayload, PayloadType, SerDeser,
    io::{SliceWriter, TinyReadExt},
};
use alloc::borrow::Cow;
use bitflags::bitflags;
use modular_bitfield::Specifier;

pub struct Advert<'a> {
    pub public_key: [u8; 32],
    pub timestamp: u32,
    pub signature: [u8; 64],
    pub appdata: Option<AdvertisementExtraData<'a>>,
}

impl<'a> PacketPayload for Advert<'a> {
    const PAYLOAD_TYPE: PayloadType = PayloadType::Advert;
}

impl<'a> SerDeser for Advert<'a> {
    type Representation<'data> = Advert<'data>;

    fn encode_size<'data>(object: &Self::Representation<'data>) -> usize {
        32 // public key
        + 4 // timestamp
        + 64 // signature
        + object.appdata.as_ref().map_or(0, AdvertisementExtraData::encode_size)
    }

    fn encode<'data, 'out>(
        object: &Self::Representation<'data>,
        out: &'out mut [u8],
    ) -> EncodeResult<&'out [u8]> {
        if out.len() < Advert::encode_size(object) {
            return Err(EncodeError::BufferTooSmall);
        }

        let mut out = SliceWriter::new(out);
        out.write_slice(&object.public_key);
        out.write_u32_le(object.timestamp);
        out.write_slice(&object.signature);

        if let Some(extra) = object.appdata.as_ref() {
            let extra_len = AdvertisementExtraData::encode(extra, out.remainder())?.len();
            out.advance(extra_len);
        }

        Ok(out.finish())
    }

    fn decode<'data>(mut data: &'data [u8]) -> DecodeResult<Advert<'data>> {
        Ok(Advert {
            public_key: *data.read_chunk()?,
            timestamp: data.read_u32_le()?,
            signature: *data.read_chunk()?,
            appdata: if data.is_empty() {
                None
            } else {
                Some(AdvertisementExtraData::decode(data)?)
            },
        })
    }
}

pub struct AdvertisementExtraData<'a> {
    pub flags: AppdataFlags,
    pub latitude: Option<u32>,
    pub longitude: Option<u32>,
    pub feature_1: Option<[u8; 2]>,
    pub feature_2: Option<[u8; 2]>,
    pub name: Option<Cow<'a, [u8]>>,
}

#[derive(Clone, Copy, Debug, Specifier)]
#[repr(u8)]
#[bits = 3]
pub enum AdvertType {
    None = 0x00,
    ChatNode = 0x01,
    Repeater = 0x02,
    RoomServer = 0x03,
    Sensor = 0x04,
}

bitflags! {
    #[derive(Copy, Clone, Debug)]
    pub struct AppdataFlags: u8 {
        const IS_CHAT_NODE = 0x01;
        const IS_REPEATER = 0x02;
        const IS_ROOM_SERVER = 0x03;
        const IS_SENSOR = 0x04;
        const HAS_LOCATION = 0x10;
        const HAS_FEATURE_1 = 0x20;
        const HAS_FEATURE_2 = 0x40;
        const HAS_NAME = 0x80;

        const _ = !0;
    }
}

impl<'a> SerDeser for AdvertisementExtraData<'a> {
    type Representation<'data> = AdvertisementExtraData<'data>;

    fn encode_size<'data>(object: &Self::Representation<'data>) -> usize {
        1 + if object.latitude.is_some() { 4 } else { 0 }
            + if object.longitude.is_some() { 4 } else { 0 }
            + if object.feature_1.is_some() { 2 } else { 0 }
            + if object.feature_2.is_some() { 2 } else { 0 }
            + object.name.as_ref().map_or(0, |v| v.len())
    }

    fn encode<'data, 'out>(
        object: &Self::Representation<'data>,
        out: &'out mut [u8],
    ) -> EncodeResult<&'out [u8]> {
        if out.len() < AdvertisementExtraData::encode_size(object) {
            return Err(EncodeError::BufferTooSmall);
        }

        let mut out = SliceWriter::new(out);
        out.write_u8(object.flags.bits());

        if let Some(lat) = object.latitude {
            out.write_u32_le(lat);
        }

        if let Some(long) = object.longitude {
            out.write_u32_le(long);
        }

        if let Some(feature_1) = object.feature_1 {
            out.write_slice(&feature_1);
        }

        if let Some(feature_2) = object.feature_2 {
            out.write_slice(&feature_2);
        }

        if let Some(name) = object.name.as_ref() {
            out.write_slice(name);
        }

        Ok(out.finish())
    }

    fn decode<'data>(mut data: &'data [u8]) -> DecodeResult<AdvertisementExtraData<'data>> {
        let flags =
            AppdataFlags::from_bits(data.read_u8()?).ok_or(DecodeError::InvalidBitPattern)?;
        Ok(AdvertisementExtraData {
            flags,
            latitude: if flags.contains(AppdataFlags::HAS_LOCATION) {
                Some(data.read_u32_le()?)
            } else {
                None
            },
            longitude: if flags.contains(AppdataFlags::HAS_LOCATION) {
                Some(data.read_u32_le()?)
            } else {
                None
            },
            feature_1: if flags.contains(AppdataFlags::HAS_FEATURE_1) {
                Some(*data.read_chunk::<2>()?)
            } else {
                None
            },
            feature_2: if flags.contains(AppdataFlags::HAS_FEATURE_2) {
                Some(*data.read_chunk::<2>()?)
            } else {
                None
            },
            name: if flags.contains(AppdataFlags::HAS_NAME) {
                Some(Cow::Borrowed(data))
            } else {
                None
            },
        })
    }
}

impl<'a> core::fmt::Debug for Advert<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Advertisement")
            .field("public_key", &hex::encode(self.public_key))
            .field("timestamp", &self.timestamp)
            .field("signature", &hex::encode(self.signature))
            .field("appdata", &self.appdata)
            .finish()
    }
}

impl<'a> core::fmt::Debug for AdvertisementExtraData<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AdvertisementExtraData")
            .field("flags", &self.flags)
            .field("latitude", &self.latitude)
            .field("longitude", &self.longitude)
            .field("feature_1", &self.feature_1)
            .field("feature_2", &self.feature_2)
            .field(
                "name",
                &self
                    .name
                    .as_ref()
                    .and_then(|v| core::str::from_utf8(v).ok()),
            )
            .finish()
    }
}
