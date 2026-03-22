use crate::{Packet, PacketHeader};
use core::fmt::Debug;

impl<'a> Debug for Packet<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Packet")
            .field("header", &self.header)
            .field("transport_codes", &self.transport_codes)
            .field("path", &self.path)
            .field("payload", &hex::encode(&self.payload))
            .finish()
    }
}

impl Debug for PacketHeader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PacketHeader")
            .field("route_type", &self.route_type())
            .field("payload_type", &self.payload_type())
            .field("payload_version", &self.payload_version())
            .finish()
    }
}
