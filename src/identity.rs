use alloc::boxed::Box;
use arrayref::array_ref;
use ed25519_compact::{
    KeyPair, Noise, PublicKey, SecretKey, Signature,
    x25519::{self, DHOutput},
};
use once_cell::race::OnceBox;
use serde::{Deserialize, Serialize};

use crate::{
    AesImpl, ByteVecImpl, Encryptable, SerDeser,
    payloads::{Advert, AdvertisementExtraData, AnonymousRequest, EncryptedMessageWithDst},
};

#[derive(Clone)]
pub struct LocalIdentity {
    pub signing_keys: ed25519_compact::KeyPair,
    pub encryption_keys: ed25519_compact::x25519::KeyPair,
}

#[derive(Serialize, Deserialize)]
pub struct SerializedLocalIdentity {
    #[serde(with = "serde_arrays")]
    sk: [u8; 64],
}

impl Serialize for LocalIdentity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        SerializedLocalIdentity {
            sk: *self.signing_keys.sk,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for LocalIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let serialized = SerializedLocalIdentity::deserialize(deserializer)?;
        Ok(LocalIdentity::from_sk(serialized.sk))
    }
}

impl LocalIdentity {
    pub fn as_foreign(&self) -> ForeignIdentity {
        ForeignIdentity {
            verify_key: self.signing_keys.pk,
            encrypt_key: OnceBox::new(), // encrypt_key: self.encryption_keys.pk,
        }
    }
}

#[derive(Clone)]
pub struct ForeignIdentity {
    pub verify_key: PublicKey,
    pub encrypt_key: OnceBox<x25519::PublicKey>, // pub encrypt_key: x25519::PublicKey,
}

impl ForeignIdentity {
    pub fn new(pk: [u8; 32]) -> Self {
        let pk = PublicKey::new(pk);
        ForeignIdentity {
            verify_key: pk,
            encrypt_key: OnceBox::new(), // encrypt_key: x25519::PublicKey::from_ed25519(&pk)
                                         //     .unwrap_or(x25519::PublicKey::base_point()), // todo: this is invalid
        }
    }

    pub fn verify(&self, data: &[u8], signature: &Signature) -> bool {
        self.verify_key.verify(data, signature).is_ok()
    }

    pub fn encrypt_key(&self) -> &x25519::PublicKey {
        self.encrypt_key.get_or_init(|| {
            Box::new(
                x25519::PublicKey::from_ed25519(&self.verify_key)
                    .unwrap_or(x25519::PublicKey::base_point()),
            )
        })
    }
}

impl LocalIdentity {
    pub fn from_sk(sk: [u8; 64]) -> Self {
        let pk = SecretKey::new(sk).public_key();
        LocalIdentity::new(*pk, sk)
    }

    pub fn new(pk: [u8; 32], sk: [u8; 64]) -> Self {
        let key_pair = KeyPair {
            pk: PublicKey::new(pk),
            sk: SecretKey::new(sk),
        };

        let x25519_keypair = x25519::KeyPair {
            pk: x25519::PublicKey::from_ed25519(&key_pair.pk).unwrap(),
            sk: x25519::SecretKey::from_ed25519(&key_pair.sk).unwrap(),
        };

        LocalIdentity {
            signing_keys: key_pair,
            encryption_keys: x25519_keypair,
        }
    }

    pub fn make_advert<'a>(
        &self,
        timestamp: u32,
        appdata: AdvertisementExtraData<'a>,
        random_bytes: [u8; 16],
    ) -> Advert<'a> {
        let mut scratch_buf = alloc::vec![0; AdvertisementExtraData::encode_size(&appdata)];

        let mut signature = self
            .signing_keys
            .sk
            .sign_incremental(Noise::new(random_bytes));
        signature.absorb(**self.pubkey());
        signature.absorb(timestamp.to_le_bytes());

        let appdata_bytes = AdvertisementExtraData::encode(&appdata, &mut scratch_buf).unwrap();
        signature.absorb(appdata_bytes);

        let signature = signature.sign();
        Advert {
            public_key: **self.pubkey(),
            timestamp,
            signature: *signature,
            appdata: Some(appdata),
        }
    }

    pub fn pubkey(&self) -> &PublicKey {
        &self.signing_keys.pk
    }

    pub fn shared_secret(&self, other: &ForeignIdentity) -> DHOutput {
        other.encrypt_key().dh(&self.encryption_keys.sk).unwrap()
    }

    pub fn sign(&self, data: &[u8]) -> Signature {
        self.signing_keys.sk.sign(data, None)
    }

    pub async fn make_message<'a, 's, P, B: AesImpl>(
        &self,
        message: &P::Representation<'a>,
        destination: &ForeignIdentity,
        scratch: &'s mut impl ByteVecImpl,
    ) -> Result<EncryptedMessageWithDst<'s, P>, B::Error>
    where
        P: SerDeser + Encryptable,
    {
        let key = self.shared_secret(destination);
        self.make_message_with_key::<P, B>(message, destination.verify_key[0], *key, scratch)
            .await
    }

    pub async fn make_message_with_key<'a, 's, P, B: AesImpl>(
        &self,
        message: &P::Representation<'a>,
        dest_hash: u8,
        key: [u8; 32],
        scratch: &'s mut impl ByteVecImpl,
    ) -> Result<EncryptedMessageWithDst<'s, P>, B::Error>
    where
        P: SerDeser + Encryptable,
    {
        let aes_key = array_ref![&key, 0, 16];
        let mac_key = array_ref![&key, 0, 32];

        let message_encrypted = P::encrypt::<B>(message, aes_key, scratch).await?;
        let mac = hmac_sha256::HMAC::mac(message_encrypted, mac_key);
        Ok(EncryptedMessageWithDst {
            destination_hash: dest_hash,
            source_hash: self.signing_keys.pk[0],
            mac: *array_ref![&mac, 0, 2],
            ciphertext: alloc::borrow::Cow::Borrowed(message_encrypted),
            _haunted: core::marker::PhantomData,
        })
    }

    pub async fn make_anon_req<'a, 's, P, B: AesImpl>(
        &self,
        message: &P::Representation<'a>,
        destination: &ForeignIdentity,
        scratch: &'s mut impl ByteVecImpl,
    ) -> Result<AnonymousRequest<'s, P>, B::Error>
    where
        P: SerDeser + Encryptable,
    {
        let key = self.shared_secret(destination);
        self.make_anon_req_with_key::<P, B>(message, destination.verify_key[0], *key, scratch)
            .await
    }

    pub async fn make_anon_req_with_key<'a, 's, P, B: AesImpl>(
        &self,
        message: &P::Representation<'a>,
        dest_hash: u8,
        key: [u8; 32],
        scratch: &'s mut impl ByteVecImpl,
    ) -> Result<AnonymousRequest<'s, P>, B::Error>
    where
        P: SerDeser + Encryptable,
    {
        let aes_key = array_ref![&key, 0, 16];
        let mac_key = array_ref![&key, 0, 32];

        let message_encrypted = P::encrypt::<B>(message, aes_key, scratch).await?;
        let mac = hmac_sha256::HMAC::mac(message_encrypted, mac_key);
        Ok(AnonymousRequest {
            destination_hash: dest_hash,
            sender_key: *self.signing_keys.pk,
            mac: *array_ref![&mac, 0, 2],
            ciphertext: alloc::borrow::Cow::Borrowed(message_encrypted),
            _haunted: core::marker::PhantomData,
        })
    }
}
