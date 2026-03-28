use modular_bitfield::{Specifier, bitfield, prelude::B6};

use crate::{
    SerDeser,
    io::{SliceWriter, TinyReadExt},
};

#[bitfield]
#[derive(Clone, Copy)]
pub struct Permissions {
    pub role: AclRole,
    reserved: B6,
}

impl core::fmt::Debug for Permissions {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Permissions")
            .field("role", &self.role())
            .finish()
    }
}

#[derive(Specifier, Clone, Copy, Debug)]
#[bits = 2]
pub enum AclRole {
    Guest = 0x00,
    ReadOnly = 0x01,
    ReadWrite = 0x02,
    Admin = 0x03,
}

/*
            # timestamp(4) + response_code(1) + keep_alive(1) + is_admin(1) +
            # permissions(1) + random(4) + firmware_ver(1)
*/
#[derive(Debug, Clone, Copy)]
pub struct LoginResponse {
    pub timestamp: u32,
    pub response_code: u8,
    pub keep_alive_interval: u8,
    pub is_admin: bool,
    pub permissions: Permissions,
    pub random_blob: [u8; 4],
    pub firmware_ver: u8,
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
        +1 // firmware ver
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
        out.write_u8(object.permissions.into_bytes()[0]);
        out.write_slice(&object.random_blob);
        out.write_u8(object.firmware_ver);

        Ok(out.finish())
    }

    fn decode<'data>(mut data: &'data [u8]) -> crate::DecodeResult<Self::Representation<'data>> {
        Ok(LoginResponse {
            timestamp: data.read_u32_le()?,
            response_code: data.read_u8()?,
            keep_alive_interval: data.read_u8()?,
            is_admin: data.read_u8()? > 0,
            permissions: Permissions::from_bytes([data.read_u8()?]),
            random_blob: *data.read_chunk::<4>()?,
            firmware_ver: data.read_u8()?,
        })
    }
}
