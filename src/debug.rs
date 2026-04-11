
use crate::{Packet, PacketHeader, Path, PathHashMode, PathNode};
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

#[cfg(feature = "defmt")]
impl<'a> defmt::Format for Packet<'a> {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(fmt, "<packet>");
        defmt::write!(fmt, "header: {}", self.header);
        defmt::write!(fmt, "path: {}", self.path);
        defmt::write!(fmt, "payload: {=[u8]:x}", &self.payload);
        defmt::write!(fmt, "</packet>");
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

#[cfg(feature = "defmt")]
impl defmt::Format for PacketHeader {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(fmt, "[routing <{}> | payload <{}> (ver {=u8})]", self.route_type(), self.payload_type(), self.payload_version())
    }
}


pub(crate) struct PathDebug<'a, const SIZE: usize>(&'a [PathNode<SIZE>]);

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

#[cfg(feature = "defmt")]
impl<'a> defmt::Format for Path<'a> {
    fn format(&self, f: defmt::Formatter) {
        // let mut binding = f.debug_struct("Path");
        // let fmt = binding.field("mode", &self.mode);
        match self.mode {
            PathHashMode::OneByte => {
                defmt::write!(f, "{=[?]}", self.view_as::<1>().unwrap())
            }
            PathHashMode::TwoByte => {
                defmt::write!(f, "{=[?]}", self.view_as::<2>().unwrap())
            }
            PathHashMode::ThreeByte => {
                defmt::write!(f, "{=[?]}", self.view_as::<3>().unwrap())
            }
            PathHashMode::FourByte => {
                defmt::write!(f, "{=[?]}", self.view_as::<4>().unwrap())
            }
        }
        // .field("backing", &self.backing).finish()
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
