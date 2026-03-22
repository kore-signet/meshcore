use crate::{
    SerDeser,
    io::{SliceWriter, TinyReadExt},
};

#[derive(Debug, Clone, Copy)]
pub struct LoginResponse {
    pub timestamp: u32,
    pub response_code: u8,
    pub keep_alive_interval: u8,
    pub is_admin: bool,
    pub reserved: u8,
    pub random_blob: [u8; 4],
}

impl SerDeser for LoginResponse {
    type Representation<'data> = LoginResponse;

    fn encode_size<'data>(_object: &Self::Representation<'data>) -> usize {
        4 //timestamp
        + 1 // response_code
        + 1 // keep_alive_interval
        +1 // is_admin
        +1 // reserved
        +4 // random_blob
    }

    fn encode<'data, 'out>(
        object: &Self::Representation<'data>,
        out: &'out mut [u8],
    ) -> crate::EncodeResult<&'out [u8]> {
        if out.len() < LoginResponse::encode_size(object) {
            return Err(crate::EncodeError::BufferTooSmall);
        };

        let mut out = SliceWriter::new(out);
        out.write_u32_le(object.timestamp);
        out.write_u8(object.response_code);
        out.write_u8(object.keep_alive_interval);
        out.write_u8(object.is_admin as u8);
        out.write_u8(object.reserved);
        out.write_slice(&object.random_blob);

        Ok(out.finish())
    }

    fn decode<'data>(mut data: &'data [u8]) -> crate::DecodeResult<Self::Representation<'data>> {
        Ok(LoginResponse {
            timestamp: data.read_u32_le()?,
            response_code: data.read_u8()?,
            keep_alive_interval: data.read_u8()?,
            is_admin: data.read_u8()? > 0,
            reserved: data.read_u8()?,
            random_blob: *data.read_chunk::<4>()?,
        })
    }
}
