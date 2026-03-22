use arrayref::array_ref;

use crate::{
    DecodeResult, EncodeResult, PacketPayload, PayloadType, SerDeser,
    identity::ForeignIdentity,
    io::{SliceWriter, TinyReadExt},
    payloads::text::TextMessageData,
};

pub struct Ack {
    pub crc: [u8; 4],
}

impl Ack {
    pub async fn calculate<S: sha2::Digest>(
        msg: &TextMessageData<'_>,
        sender: &ForeignIdentity,
    ) -> Ack {
        let msg_text = core::str::from_utf8(&msg.message)
            .unwrap()
            .trim_end_matches('\x00');

        let mut hasher = S::new();
        hasher.update(msg.timestamp.to_le_bytes());
        hasher.update(msg.header.attempt().to_le_bytes());
        hasher.update(msg_text);
        hasher.update(&sender.verify_key[..]);

        let hash = hasher.finalize();

        Ack {
            crc: *array_ref![&hash, 0, 4],
        }
    }
}

impl SerDeser for Ack {
    type Representation<'data> = Ack;

    fn encode_size<'data>(_object: &Self::Representation<'data>) -> usize {
        4
    }

    fn encode<'data, 'out>(
        object: &Self::Representation<'data>,
        out: &'out mut [u8],
    ) -> EncodeResult<&'out [u8]> {
        let mut out = SliceWriter::new(out);
        out.write_slice(&object.crc);
        Ok(out.finish())
    }

    fn decode<'data>(mut data: &'data [u8]) -> DecodeResult<Self::Representation<'data>> {
        data.read_chunk::<4>().map(|crc| Ack { crc: *crc })
    }
}

impl PacketPayload for Ack {
    const PAYLOAD_TYPE: PayloadType = PayloadType::Ack;
}
