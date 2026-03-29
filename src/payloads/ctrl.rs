use bitflags::bitflags;
use modular_bitfield::{
    Specifier, bitfield,
    prelude::{B1, B3, B4},
};

use crate::{
    DecodeError, PacketPayload, PayloadType, SerDeser,
    io::{SliceWriter, TinyReadExt},
    payloads::AdvertType,
};

#[derive(Clone, Copy)]
#[bitfield]
pub struct DiscoveryFilter {
    _res: B1,
    pub chat_nodes: bool,
    pub repeaters: bool,
    pub room_servers: bool,
    pub sensors: bool,
    _res2: B3,
}

impl core::fmt::Debug for DiscoveryFilter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DiscoveryFilter")
            .field("chat_nodes", &self.chat_nodes())
            .field("repeaters", &self.repeaters())
            .field("room_servers", &self.room_servers())
            .field("sensors", &self.sensors())
            .finish()
    }
}

#[derive(Specifier, Copy, Clone, Debug)]
#[bits = 4]
pub enum CtrlPacketType {
    DiscoverReq = 8,
    DiscoverResp = 9,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct DiscoverReqFlags: u8 {
        const PREFIX_ONLY = 0x01;
        const _ = !0;
    }
}

#[derive(Clone, Copy)]
#[bitfield]
pub struct CtrlPacketHeader {
    pub extra: B4,
    pub packet_ty: CtrlPacketType,
}

impl core::fmt::Debug for CtrlPacketHeader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CtrlPacketHeader")
            .field("bytes", &self.bytes)
            .finish()
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ControlPayload {
    DiscoverRequest {
        flags: DiscoverReqFlags,
        filter: DiscoveryFilter,
        tag: [u8; 4],
        since: Option<u32>,
    },
    DiscoverResponse {
        node_type: AdvertType,
        snr: i8,
        tag: [u8; 4],
        key: DiscoverResponseKey,
    },
}

impl PacketPayload for ControlPayload {
    const PAYLOAD_TYPE: crate::PayloadType = PayloadType::Control;
}

impl SerDeser for ControlPayload {
    type Representation<'data> = ControlPayload;

    fn encode_size<'data>(object: &Self::Representation<'data>) -> usize {
        match object {
            ControlPayload::DiscoverRequest {
                flags: _,
                filter: _,
                tag: _,
                since,
            } => {
                1 // flags/req type
                + 1 // filter
                + 4 // tag
                + if since.is_some() { 4 } else { 0 } // since
            }
            ControlPayload::DiscoverResponse {
                node_type: _,
                snr: _,
                tag: _,
                key,
            } => {
                1 // flags/req type
                + 1 // snr
                + 4 // tag
                + key.as_ref().len() // key len
            }
        }
    }

    fn encode<'data, 'out>(
        object: &Self::Representation<'data>,
        out: &'out mut [u8],
    ) -> crate::EncodeResult<&'out [u8]> {
        if out.len() < ControlPayload::encode_size(object) {
            return Err(crate::EncodeError::BufferTooSmall);
        }

        let mut out = SliceWriter::new(out);
        match object {
            ControlPayload::DiscoverRequest {
                flags,
                filter,
                tag,
                since,
            } => {
                let flags = CtrlPacketHeader::new()
                    .with_packet_ty(CtrlPacketType::DiscoverReq)
                    .with_extra(flags.bits());
                out.write_u8(flags.into_bytes()[0]);
                out.write_u8(filter.into_bytes()[0]);
                out.write_slice(tag);
                if let Some(since) = since {
                    out.write_u32_le(*since);
                }
            }
            ControlPayload::DiscoverResponse {
                node_type,
                snr,
                tag,
                key,
            } => {
                let flags = CtrlPacketHeader::new()
                    .with_packet_ty(CtrlPacketType::DiscoverResp)
                    .with_extra(*node_type as u8)
                    .into_bytes();
                out.write_u8(flags[0]);
                out.write_i8(*snr); // todo might need to adjust this to respect the weird *4 clamping thing it does
                out.write_slice(tag);
                out.write_slice(key.as_ref());
            }
        }

        Ok(out.finish())
    }

    fn decode<'data>(mut data: &'data [u8]) -> crate::DecodeResult<Self::Representation<'data>> {
        let flags = CtrlPacketHeader::from_bytes([data.read_u8()?]);
        let packet_ty = flags
            .packet_ty_or_err()
            .map_err(|_| DecodeError::InvalidBitPattern)?;

        match packet_ty {
            CtrlPacketType::DiscoverReq => {
                let flags = DiscoverReqFlags::from_bits(flags.extra())
                    .ok_or(DecodeError::InvalidBitPattern)?;
                let filter = DiscoveryFilter::from_bytes([data.read_u8()?]);

                let tag = data.read_chunk::<4>()?;
                let since = if !data.is_empty() {
                    Some(data.read_u32_le()?)
                } else {
                    None
                };

                Ok(ControlPayload::DiscoverRequest {
                    flags,
                    filter,
                    tag: *tag,
                    since,
                })
            }
            CtrlPacketType::DiscoverResp => {
                let node_type = AdvertType::from_bytes(flags.extra())
                    .map_err(|_| DecodeError::InvalidBitPattern)?;
                let snr = data.read_i8()?;
                let tag = data.read_chunk::<4>()?;
                let key = if data.len() > 8 {
                    DiscoverResponseKey::Full(*data.read_chunk::<32>()?)
                } else {
                    DiscoverResponseKey::Prefix(*data.read_chunk::<8>()?)
                };

                Ok(ControlPayload::DiscoverResponse {
                    node_type,
                    snr,
                    tag: *tag,
                    key,
                })
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum DiscoverResponseKey {
    Prefix([u8; 8]),
    Full([u8; 32]),
}

impl AsRef<[u8]> for DiscoverResponseKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            DiscoverResponseKey::Prefix(v) => v,
            DiscoverResponseKey::Full(v) => v,
        }
    }
}
