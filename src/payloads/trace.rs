use modular_bitfield::Specifier;

use crate::{
    DecodeError, PacketPayload, Path, PathHashMode, PayloadType, SerDeser,
    io::{SliceWriter, TinyReadExt},
};

pub struct TracePacket<'a> {
    pub tag: [u8; 4],
    pub auth_code: [u8; 4],
    pub flags: u8,
    pub path: Path<'a>,
}

impl<'a> SerDeser for TracePacket<'a> {
    type Representation<'data> = TracePacket<'data>;

    fn encode_size<'data>(object: &Self::Representation<'data>) -> usize {
        4 // tag
        + 4 // auth_code
        + 1 // flags
        + object.path.len()
    }

    fn encode<'data, 'out>(
        object: &Self::Representation<'data>,
        out: &'out mut [u8],
    ) -> crate::EncodeResult<&'out [u8]> {
        if out.len() < TracePacket::encode_size(object) {
            return Err(crate::EncodeError::BufferTooSmall);
        }

        let mut out = SliceWriter::new(out);

        out.write_slice(&object.tag);
        out.write_slice(&object.auth_code);
        out.write_u8(object.flags | (object.path.mode as u8 & 0x03));
        out.write_slice(object.path.raw_bytes());

        Ok(out.finish())
    }

    fn decode<'data>(mut data: &'data [u8]) -> crate::DecodeResult<Self::Representation<'data>> {
        let tag = data.read_chunk::<4>()?;
        let auth_code = data.read_chunk::<4>()?;

        let flags = data.read_u8()?;
        let hash_mode =
            PathHashMode::from_bytes(flags & 0x3).map_err(|_| DecodeError::InvalidBitPattern)?;
        let path = Path::from_bytes(hash_mode, data);

        Ok(TracePacket {
            tag: *tag,
            auth_code: *auth_code,
            flags,
            path,
        })
    }
}

impl<'a> PacketPayload for TracePacket<'a> {
    const PAYLOAD_TYPE: crate::PayloadType = PayloadType::Trace;
}
