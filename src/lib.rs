#![no_std]

extern crate alloc;

use alloc::vec;
use alloc::{borrow::Cow, vec::Vec};
use core::fmt::Debug;
use core::time::Duration;
use modular_bitfield::prelude::B6;
use serde::Deserialize;
use serde::Serialize;

use modular_bitfield::{Specifier, bitfield, prelude::B2};

pub mod crypto;
mod debug;
pub mod io;
pub mod payloads;
pub mod repeater_protocol;
pub mod timing;
use io::*;

use crate::crypto::{AesImpl, Encryptable};
use crate::timing::AirtimeEstConfig;
pub mod identity;

#[derive(Debug)]
pub enum DecodeError {
    UnexpectedEof,
    HmacMismatch,
    FailedDecrypt,
    InvalidBitPattern,
    WrongPayloadType,
    Utf8,
}

impl From<core::str::Utf8Error> for DecodeError {
    fn from(_value: core::str::Utf8Error) -> Self {
        DecodeError::Utf8
    }
}

#[derive(Debug)]
pub enum EncodeError {
    BufferTooSmall,
}

pub type EncodeResult<T> = Result<T, EncodeError>;
pub type DecodeResult<T> = Result<T, DecodeError>;

pub trait SerDeser: Sized {
    type Representation<'data>;

    fn encode_size<'data>(object: &Self::Representation<'data>) -> usize;
    fn encode<'data, 'out>(
        object: &Self::Representation<'data>,
        out: &'out mut [u8],
    ) -> EncodeResult<&'out [u8]>;
    fn decode<'data>(data: &'data [u8]) -> DecodeResult<Self::Representation<'data>>;

    fn encode_into_vec<'data, 'buf>(
        obj: &Self::Representation<'data>,
        out: &'buf mut impl ByteVecImpl,
    ) -> EncodeResult<&'buf [u8]> {
        out.clear();
        out.resize(Self::encode_size(obj), 0);
        let len = Self::encode(obj, out)?.len();
        out.truncate(len);
        Ok(&out[..])
    }

    fn encode_to_vec<'data>(obj: &Self::Representation<'data>) -> EncodeResult<Vec<u8>> {
        let mut out = vec![0u8; Self::encode_size(obj)];
        Self::encode_into_vec(obj, &mut out)?;
        Ok(out)
    }
}

pub trait PacketPayload: Sized + SerDeser {
    const PAYLOAD_TYPE: PayloadType;
}

// path len offset is either 3 or 7 depending on if packet has transport codes
#[bitfield]
pub struct PathLen {
    pub len: B6,
    pub mode: PathHashMode,
}

impl PathLen {
    pub fn byte_size(&self) -> usize {
        self.len() as usize * self.mode().byte_size()
    }
}

#[derive(Specifier, Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[bits = 2]
pub enum PathHashMode {
    OneByte = 0b00,
    TwoByte = 0b01,
    ThreeByte = 0b10,
    FourByte = 0b11, // unsupported? i think?
}

impl PathHashMode {
    pub const fn byte_size(&self) -> usize {
        match self {
            PathHashMode::OneByte => 1,
            PathHashMode::TwoByte => 2,
            PathHashMode::ThreeByte => 3,
            PathHashMode::FourByte => 4,
        }
    }
}

#[derive(Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(transparent)]
pub struct PathNode<const SIZE: usize>(pub [u8; SIZE]);

impl<const SIZE: usize> core::fmt::Debug for PathNode<SIZE> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}",
            const_hex::const_encode::<SIZE, false>(&self.0).as_str()
        )
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Path<'a> {
    pub mode: PathHashMode,
    backing: Cow<'a, [u8]>,
}

impl Path<'static> {
    pub fn empty(mode: PathHashMode) -> Path<'static> {
        Path {
            mode,
            backing: Cow::Borrowed(&[]),
        }
    }
}

impl<'a> Path<'a> {
    pub fn from_bytes(mode: PathHashMode, bytes: impl Into<Cow<'a, [u8]>>) -> Path<'a> {
        Path {
            mode,
            backing: bytes.into(),
        }
    }

    pub fn to_owned(&self) -> Path<'static> {
        Path {
            mode: self.mode,
            backing: Cow::Owned(self.backing.clone().into_owned()),
        }
    }

    pub fn view_as<const SIZE: usize>(&self) -> Option<&[PathNode<SIZE>]> {
        if self.mode.byte_size() != SIZE {
            return None;
        }

        Some(bytemuck::cast_slice(self.backing.as_ref()))
    }

    pub fn is_empty(&self) -> bool {
        self.backing.is_empty()
    }

    pub fn len(&self) -> usize {
        self.backing.len() * self.mode.byte_size()
    }

    pub fn byte_size(&self) -> usize {
        self.backing.len()
    }

    pub fn raw_bytes(&self) -> &[u8] {
        &self.backing
    }

    pub fn path_len_header(&self) -> PathLen {
        PathLen::new()
            .with_len(self.len() as u8)
            .with_mode(self.mode)
    }
}

struct PathDebug<'a, const SIZE: usize>(&'a [PathNode<SIZE>]);

impl<'a, const SIZE: usize> core::fmt::Debug for PathDebug<'a, SIZE> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.0.is_empty() {
            write!(f, "direct")?;
            return Ok(());
        }

        let mut iter = self.0.iter().peekable();
        while let Some(val) = iter.next() {
            write!(f, "{val:?}")?;
            if iter.peek().is_some() {
                write!(f, "->")?;
            }
        }

        Ok(())
    }
}

impl<'a> core::fmt::Debug for Path<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // let mut binding = f.debug_struct("Path");
        // let fmt = binding.field("mode", &self.mode);
        match self.mode {
            PathHashMode::OneByte => {
                write!(f, "{:?}", &PathDebug(self.view_as::<1>().unwrap()))
            }
            PathHashMode::TwoByte => {
                write!(f, "{:?}", &PathDebug(self.view_as::<2>().unwrap()))
            }
            PathHashMode::ThreeByte => {
                write!(f, "{:?}", &PathDebug(self.view_as::<3>().unwrap()))
            }
            PathHashMode::FourByte => {
                write!(f, "{:?}", &PathDebug(self.view_as::<4>().unwrap()))
            }
        }
        // .field("backing", &self.backing).finish()
    }
}

pub struct Packet<'a> {
    pub header: PacketHeader,
    pub transport_codes: Option<[u16; 2]>,
    pub path: Path<'a>,
    pub payload: Cow<'a, [u8]>,
}

impl<'a> Packet<'a> {
    pub fn direct<P: PacketPayload>(
        path: Path<'a>,
        payload: impl Into<Cow<'a, [u8]>>,
    ) -> Packet<'a> {
        Packet {
            header: PacketHeader::new()
                .with_payload_type(P::PAYLOAD_TYPE)
                .with_route_type(RouteType::Direct),
            transport_codes: None,
            path,
            payload: payload.into(),
        }
    }

    pub fn flood<P: PacketPayload>(
        path: Path<'a>,
        payload: impl Into<Cow<'a, [u8]>>,
    ) -> Packet<'a> {
        Packet {
            header: PacketHeader::new()
                .with_payload_type(P::PAYLOAD_TYPE)
                .with_route_type(RouteType::Flood),
            transport_codes: None,
            path,
            payload: payload.into(),
        }
    }

    pub fn decode_payload_as<'d, P: PacketPayload>(
        &'d self,
    ) -> DecodeResult<P::Representation<'d>> {
        if P::PAYLOAD_TYPE != self.header.payload_type() {
            return Err(DecodeError::WrongPayloadType);
        }

        P::decode(&self.payload)
    }

    pub fn timeout_est(&self, path: &Path<'_>, route_type: RouteType) -> Duration {
        let est_config = AirtimeEstConfig {
            spreading_factor: 7,
            bandwidth: 62500,
            coding_rate: 5,
            preamble_length: 8,
        };

        let airtime = timing::estimate_airtime(Packet::encode_size(self) as i32, &est_config);

        match route_type {
            RouteType::Direct | RouteType::TransportDirect => {
                timing::direct_timeout_ms(airtime, path.len() as u32)
            }
            RouteType::Flood | RouteType::TransportFlood => timing::flood_timeout_ms(airtime),
        }
    }
}

impl<'a> SerDeser for Packet<'a> {
    type Representation<'data> = Packet<'data>;

    fn encode_size<'data>(object: &Self::Representation<'data>) -> usize {
        1 + if object.transport_codes.is_some() {
            2 * 2
        } else {
            0
        } + 1
            + object.path.byte_size()
            + object.payload.len()
    }

    fn encode<'data, 'out>(
        obj: &Self::Representation<'data>,
        out: &'out mut [u8],
    ) -> EncodeResult<&'out [u8]> {
        let mut out_writer = SliceWriter::new(out);
        out_writer.write_u8(obj.header.into_bytes()[0]);
        if let Some(transport_codes) = obj.transport_codes {
            out_writer.write_u16_le(transport_codes[0]);
            out_writer.write_u16_le(transport_codes[1]);
        }
        out_writer.write_u8(obj.path.path_len_header().into_bytes()[0]);
        out_writer.write_slice(obj.path.raw_bytes());
        out_writer.write_slice(&obj.payload);

        Ok(out_writer.finish())
    }

    fn decode<'data>(mut data: &'data [u8]) -> DecodeResult<Self::Representation<'data>> {
        let header = PacketHeader::from_bytes(*data.read_chunk::<1>()?);

        if header.route_type_or_err().is_err() || header.payload_type_or_err().is_err() {
            return Err(DecodeError::InvalidBitPattern);
        }

        let transport_codes = if matches!(
            header.route_type(),
            RouteType::TransportDirect | RouteType::TransportFlood
        ) {
            Some([data.read_u16_le()?, data.read_u16_le()?])
        } else {
            None
        };

        let path_len = PathLen::from_bytes([data.read_u8()?]);
        if path_len.mode_or_err().map_err(|_| DecodeError::InvalidBitPattern)? == PathHashMode::FourByte {
            return Err(DecodeError::InvalidBitPattern);
        }

        let path = Cow::Borrowed(data.read_slice(path_len.byte_size())?);

        Ok(Packet {
            header,
            transport_codes,
            path: Path {
                mode: path_len.mode(),
                backing: path,
            },
            payload: Cow::Borrowed(data),
        })
    }
}

#[bitfield]
#[repr(u8)]
#[derive(Clone, Copy)]
pub struct PacketHeader {
    pub route_type: RouteType,
    pub payload_type: PayloadType,
    pub payload_version: B2,
}

#[derive(Specifier, Debug)]
#[bits = 2]
pub enum RouteType {
    TransportFlood = 0b00,
    Flood = 0b01,
    Direct = 0b10,
    TransportDirect = 0b11,
}

impl RouteType {
    pub fn is_flood(&self) -> bool {
        matches!(self, RouteType::Flood | RouteType::TransportFlood)
    }
}

#[derive(Specifier, Debug, PartialEq, Eq, Clone, Copy)]
#[bits = 4]
#[repr(u8)]
pub enum PayloadType {
    Request = 0x00,
    Response = 0x01,
    TxtMsg = 0x02,
    Ack = 0x03,
    Advert = 0x04,
    GrpTxt = 0x05,
    AnonReq = 0x07,
    Path = 0x08,
    Trace = 0x09,
    Multipart = 0x0A,
    Control = 0x0B,
    RawCustom = 0x0F,
}
