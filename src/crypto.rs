use core::marker::PhantomData;

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit as _, block_padding::NoPadding};
use alloc::{borrow::Cow, vec::Vec};
use sha2::{Digest, Sha256};

use crate::{DecodeResult, PacketPayload, SerDeser, io::ByteVecImpl};

type Aes128EcbEnc = ecb::Encryptor<aes::Aes128>;
type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;

#[derive(Copy, Clone)]
pub struct ChannelKeys {
    pub hash: u8,
    pub secret: [u8; 16],
}

impl ChannelKeys {
    pub fn public() -> ChannelKeys {
        let key: [u8; 16] = hex::decode("8b3387e9c5cdea6ac9e5edbaa115cd72")
            .unwrap()
            .try_into()
            .unwrap();

        ChannelKeys::from_secret(key)
    }

    pub fn from_hashtag(channel: &str) -> ChannelKeys {
        let secret: [u8; 16] = Sha256::digest(channel)[0..16].try_into().unwrap();

        ChannelKeys::from_secret(secret)
    }

    pub fn from_secret(secret: [u8; 16]) -> ChannelKeys {
        let digest_of_key = Sha256::digest(secret);
        ChannelKeys {
            hash: digest_of_key[0],
            secret,
        }
    }
}

pub trait VerifiablePayload: Sized + PacketPayload {
    fn verify<H: HmacImpl>(&self, mac_key: &[u8]) -> bool;
}

pub trait HmacImpl {
    fn mac(val: &[u8], mac_key: &[u8]) -> [u8; 32];
}

pub struct CpuHMAC;

impl HmacImpl for CpuHMAC {
    fn mac(val: &[u8], mac_key: &[u8]) -> [u8; 32] {
        hmac_sha256::HMAC::mac(val, mac_key)
    }
}

pub type CpuSHA = sha2::Sha256;

pub trait AesImpl {
    type Error;

    fn decrypt<'s>(
        key: &[u8; 16],
        input: &[u8],
        output: &'s mut impl ByteVecImpl,
    ) -> impl Future<Output = Result<&'s [u8], Self::Error>>;
    fn encrypt<'s>(
        key: &[u8; 16],
        input: &[u8],
        output: &'s mut impl ByteVecImpl,
    ) -> impl Future<Output = Result<&'s [u8], Self::Error>>;

    fn decrypt_in_place<'s>(
        key: &[u8; 16],
        data: &'s mut impl ByteVecImpl,
    ) -> impl Future<Output = Result<&'s [u8], Self::Error>>;
    fn encrypt_in_place<'s>(
        key: &[u8; 16],
        data: &'s mut impl ByteVecImpl,
    ) -> impl Future<Output = Result<&'s [u8], Self::Error>>;

    fn decrypt_to_vec(
        key: &[u8; 16],
        input: &[u8],
    ) -> impl Future<Output = Result<Vec<u8>, Self::Error>> {
        async {
            let mut out = Vec::with_capacity(input.len());
            Self::decrypt(key, input, &mut out).await?;
            Ok(out)
        }
    }

    fn encrypt_to_vec(
        key: &[u8; 16],
        input: &[u8],
    ) -> impl Future<Output = Result<Vec<u8>, Self::Error>> {
        async {
            let mut out = Vec::with_capacity(input.len());
            Self::encrypt(key, input, &mut out).await?;
            Ok(out)
        }
    }
}

pub struct CpuAES;

pub const CIPHER_BLOCK_SIZE: usize = 16;

impl AesImpl for CpuAES {
    type Error = core::convert::Infallible;

    async fn decrypt<'s>(
        key: &[u8; 16],
        input: &[u8],
        output: &'s mut impl ByteVecImpl,
    ) -> Result<&'s [u8], Self::Error> {
        output.resize(input.len(), 0);
        Aes128EcbDec::new(key.into())
            .decrypt_padded_b2b_mut::<NoPadding>(input, output.as_mut())
            .unwrap();

        Ok(&output[..])
    }

    async fn encrypt<'s>(
        key: &[u8; 16],
        input: &[u8],
        output: &'s mut impl ByteVecImpl,
    ) -> Result<&'s [u8], Self::Error> {
        let pad_len = (CIPHER_BLOCK_SIZE - (input.len() % CIPHER_BLOCK_SIZE)) % CIPHER_BLOCK_SIZE;
        output.clear();
        output.resize(input.len() + pad_len, 0);
        output[..input.len()].copy_from_slice(input);
        let len = output.len();

        Aes128EcbEnc::new(key.into())
            .encrypt_padded_mut::<NoPadding>(output, len)
            .unwrap();
        Ok(&output[..])
        // Aes128EcbEnc::new(key.into())
        // .encrypt_padded_mut::<ZeroPadding>(out_buf, out_len)
    }

    async fn encrypt_in_place<'s>(
        key: &[u8; 16],
        data: &'s mut impl ByteVecImpl,
    ) -> Result<&'s [u8], Self::Error> {
        let pad_len = (CIPHER_BLOCK_SIZE - (data.len() % CIPHER_BLOCK_SIZE)) % CIPHER_BLOCK_SIZE;
        data.resize(data.len() + pad_len, 0);
        let data_len = data.len();
        Aes128EcbEnc::new(key.into())
            .encrypt_padded_mut::<NoPadding>(data, data_len)
            .unwrap();
        Ok(&data[..])
    }

    async fn decrypt_in_place<'s>(
        key: &[u8; 16],
        data: &'s mut impl ByteVecImpl,
    ) -> Result<&'s [u8], Self::Error> {
        Aes128EcbDec::new(key.into())
            .decrypt_padded_mut::<NoPadding>(data)
            .unwrap();
        Ok(&data[..])
    }
}

pub trait Encryptable: SerDeser {
    fn encrypt<'a, 'd, B: AesImpl>(
        obj: &<Self as SerDeser>::Representation<'a>,
        key: &[u8; 16],
        buf: &'d mut impl ByteVecImpl,
    ) -> impl Future<Output = Result<&'d [u8], B::Error>> {
        async {
            buf.clear();
            buf.resize(<Self as SerDeser>::encode_size(obj), 0);
            <Self as SerDeser>::encode(obj, buf).unwrap();
            B::encrypt_in_place(key, buf).await?;
            Ok(&buf[..])
        }
    }

    fn encrypt_to_vec<'a, B: AesImpl>(
        obj: &<Self as SerDeser>::Representation<'a>,
        key: &[u8; 16],
    ) -> impl core::future::Future<Output = Result<Vec<u8>, B::Error>> {
        async {
            let mut out_buf = Vec::new();
            Self::encrypt::<B>(obj, key, &mut out_buf).await?;
            Ok(out_buf)
        }
    }
}

pub trait ContainsEncryptable {
    type Output: Encryptable;

    fn decrypt<'s, B: AesImpl>(
        &self,
        key: &[u8; 16],
        scratch: &'s mut impl ByteVecImpl,
    ) -> impl Future<Output = DecodeResult<DecryptedView<'s, Self::Output>>>;
    fn decrypt_owned<B: AesImpl>(
        &self,
        key: &[u8; 16],
    ) -> impl Future<Output = DecodeResult<DecryptedView<'static, Self::Output>>>;
}

pub struct DecryptedView<'a, ViewAs: SerDeser> {
    decrypted_bytes: Cow<'a, [u8]>,
    _spooky: PhantomData<ViewAs>,
}

impl<'a, ViewAs: SerDeser> DecryptedView<'a, ViewAs> {
    pub fn new(bytes: impl Into<Cow<'a, [u8]>>) -> Self {
        DecryptedView {
            decrypted_bytes: bytes.into(),
            _spooky: PhantomData,
        }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.decrypted_bytes
    }

    pub fn decoded(&'a self) -> DecodeResult<ViewAs::Representation<'a>> {
        ViewAs::decode(&self.decrypted_bytes)
    }
}
