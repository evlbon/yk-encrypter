//! Ядро: формат `ykpiv1:`, ECDH/HKDF/AES-GCM и PIV поверх PC/SC.
//! Совместимо с Swift-версией (../Sources) и TS-модулем (yk-encrypter.ts).

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hkdf::Hkdf;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePublicKey, LineEnding};
use p256::{PublicKey, SecretKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub const PREFIX: &str = "ykpiv1:";
const POINT_LEN: usize = 65;
const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;
const HKDF_INFO: &[u8] = b"yk-encrypter/piv-p256/v1/aes-256-gcm";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Неверный формат данных: {0}")]
    BadFormat(String),
    #[error("Не удалось расшифровать: другой YubiKey или данные повреждены")]
    DecryptFailed,
    #[error("Неверный публичный ключ: {0}")]
    BadKey(String),
    #[error("Служба смарт-карт недоступна ({0})")]
    NoService(pcsc::Error),
    #[error("YubiKey не найден — вставьте ключ")]
    YubiKeyNotFound,
    #[error("Ошибка PC/SC: {0}")]
    Pcsc(#[from] pcsc::Error),
    #[error("PIN должен быть длиной 6–8 символов")]
    PinFormat,
    #[error("Неверный PIN, осталось попыток: {0}")]
    WrongPin(u8),
    #[error("PIN заблокирован. Разблокируйте через PUK: ykman piv access unblock-pin")]
    PinBlocked,
    #[error("Карта отказала: PIN не проверен")]
    SecurityStatus,
    #[error("Слот 9d пуст или ключ не P-256")]
    SlotEmpty,
    #[error("Неожиданный ответ YubiKey: {0}")]
    Unexpected(String),
    #[error("Ошибка карты: ins=0x{ins:02x} sw=0x{sw:04x}")]
    Apdu { ins: u8, sw: u16 },
}

pub type Result<T> = std::result::Result<T, Error>;

// ---------------------------------------------------------------------------
// Криптография (без YubiKey)
// ---------------------------------------------------------------------------

/// Шифрует публичным ключом YubiKey (PEM, SPKI P-256).
pub fn encrypt(plaintext: &str, recipient_pem: &str) -> Result<String> {
    let recipient = PublicKey::from_public_key_pem(recipient_pem).map_err(|e| Error::BadKey(e.to_string()))?;
    let eph = EphemeralSecret::random(&mut OsRng);
    let eph_pub = eph.public_key().to_encoded_point(false).as_bytes().to_vec();
    let mut shared = eph.diffie_hellman(&recipient).raw_secret_bytes().to_vec();
    let out = seal(plaintext, &shared, &eph_pub);
    shared.zeroize();
    out
}

/// Расшифровывает; `ecdh` получает эфемерную точку (65 байт) и возвращает общий секрет (32 байта).
pub fn decrypt(payload: &str, ecdh: impl FnOnce(&[u8]) -> Result<Vec<u8>>) -> Result<String> {
    let body = payload
        .strip_prefix(PREFIX)
        .ok_or_else(|| Error::BadFormat(format!("ожидается {PREFIX}…")))?;
    let blob = URL_SAFE_NO_PAD
        .decode(body.trim())
        .map_err(|_| Error::BadFormat("base64url".into()))?;
    if blob.len() < POINT_LEN + IV_LEN + TAG_LEN {
        return Err(Error::BadFormat("слишком короткие данные".into()));
    }
    let (eph_pub, rest) = blob.split_at(POINT_LEN);
    let (iv, rest) = rest.split_at(IV_LEN);
    let (tag, ciphertext) = rest.split_at(TAG_LEN);
    if eph_pub[0] != 0x04 {
        return Err(Error::BadFormat("эфемерный ключ".into()));
    }

    let mut shared = ecdh(eph_pub)?;
    let mut key = derive_key(&shared, eph_pub);
    shared.zeroize();

    let cipher = Aes256Gcm::new_from_slice(&key).expect("key length");
    key.zeroize();
    let mut ct_tag = Vec::with_capacity(ciphertext.len() + TAG_LEN);
    ct_tag.extend_from_slice(ciphertext);
    ct_tag.extend_from_slice(tag);
    let plain = cipher
        .decrypt(Nonce::from_slice(iv), Payload { msg: &ct_tag, aad: eph_pub })
        .map_err(|_| Error::DecryptFailed)?;
    String::from_utf8(plain).map_err(|_| Error::DecryptFailed)
}

/// Программный ECDH для тестов: приватный ключ P-256 в PEM (PKCS#8).
pub fn software_ecdh(private_key_pem: &str) -> Result<impl Fn(&[u8]) -> Result<Vec<u8>>> {
    let secret = SecretKey::from_pkcs8_pem(private_key_pem).map_err(|e| Error::BadKey(e.to_string()))?;
    Ok(move |eph_pub: &[u8]| {
        let peer = PublicKey::from_sec1_bytes(eph_pub).map_err(|e| Error::BadKey(e.to_string()))?;
        let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
        Ok(shared.raw_secret_bytes().to_vec())
    })
}

/// Сырая точка (65 байт) → PEM.
pub fn pem_from_point(point: &[u8]) -> Result<String> {
    let key = PublicKey::from_sec1_bytes(point).map_err(|e| Error::BadKey(e.to_string()))?;
    key.to_public_key_pem(LineEnding::LF).map_err(|e| Error::BadKey(e.to_string()))
}

/// Короткий отпечаток публичного ключа для UI (SHA-256 от точки, 4 байта).
pub fn fingerprint(pem: &str) -> Option<String> {
    let key = PublicKey::from_public_key_pem(pem).ok()?;
    let digest = Sha256::digest(key.to_encoded_point(false).as_bytes());
    Some(digest[..4].iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":"))
}

fn seal(plaintext: &str, shared: &[u8], eph_pub: &[u8]) -> Result<String> {
    let mut key = derive_key(shared, eph_pub);
    let cipher = Aes256Gcm::new_from_slice(&key).expect("key length");
    key.zeroize();
    let mut iv = [0u8; IV_LEN];
    OsRng.fill_bytes(&mut iv);
    let ct_tag = cipher
        .encrypt(Nonce::from_slice(&iv), Payload { msg: plaintext.as_bytes(), aad: eph_pub })
        .map_err(|_| Error::Unexpected("AES-GCM".into()))?;
    let (ciphertext, tag) = ct_tag.split_at(ct_tag.len() - TAG_LEN);

    let mut out = Vec::with_capacity(POINT_LEN + IV_LEN + TAG_LEN + ciphertext.len());
    out.extend_from_slice(eph_pub);
    out.extend_from_slice(&iv);
    out.extend_from_slice(tag);
    out.extend_from_slice(ciphertext);
    Ok(format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(out)))
}

fn derive_key(shared: &[u8], eph_pub: &[u8]) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    Hkdf::<Sha256>::new(Some(eph_pub), shared)
        .expand(HKDF_INFO, &mut key)
        .expect("hkdf length");
    key
}

// ---------------------------------------------------------------------------
// PIV поверх PC/SC
// ---------------------------------------------------------------------------

const PIV_AID: &[u8] = &[0xa0, 0x00, 0x00, 0x03, 0x08];
const SLOT: u8 = 0x9d;
const ALG_ECCP256: u8 = 0x11;
const INS_SELECT: u8 = 0xa4;
const INS_VERIFY: u8 = 0x20;
const INS_GENERAL_AUTH: u8 = 0x87;
const INS_GET_RESPONSE: u8 = 0xc0;
const INS_GET_METADATA: u8 = 0xf7;

pub struct Piv {
    card: pcsc::Card,
}

impl Piv {
    /// Есть ли YubiKey среди ридеров (без подключения к карте).
    pub fn is_present() -> bool {
        Self::find_reader().is_ok()
    }

    fn find_reader() -> Result<std::ffi::CString> {
        let ctx = pcsc::Context::establish(pcsc::Scope::User).map_err(Error::NoService)?;
        let mut buf = [0u8; 4096];
        let readers = match ctx.list_readers(&mut buf) {
            Ok(r) => r,
            Err(pcsc::Error::NoReadersAvailable) => return Err(Error::YubiKeyNotFound),
            Err(e) => return Err(Error::Pcsc(e)),
        };
        readers
            .filter(|r| r.to_string_lossy().to_ascii_lowercase().contains("yubi"))
            .map(|r| r.to_owned())
            .next()
            .ok_or(Error::YubiKeyNotFound)
    }

    /// Находит YubiKey, подключается и выбирает PIV-приложение.
    pub fn open() -> Result<Self> {
        let reader = Self::find_reader()?;
        let ctx = pcsc::Context::establish(pcsc::Scope::User).map_err(Error::NoService)?;
        let card = match ctx.connect(&reader, pcsc::ShareMode::Shared, pcsc::Protocols::ANY) {
            Ok(c) => c,
            Err(pcsc::Error::NoSmartcard | pcsc::Error::RemovedCard | pcsc::Error::UnknownReader) => {
                return Err(Error::YubiKeyNotFound)
            }
            Err(e) => return Err(Error::Pcsc(e)),
        };
        let piv = Piv { card };
        piv.send(INS_SELECT, 0x04, 0x00, PIV_AID)?;
        Ok(piv)
    }

    pub fn verify_pin(&self, pin: &str) -> Result<()> {
        let len = pin.len();
        if !(6..=8).contains(&len) || pin.bytes().any(|b| b == 0xff) {
            return Err(Error::PinFormat);
        }
        let mut padded = [0xffu8; 8];
        padded[..len].copy_from_slice(pin.as_bytes());
        let res = self.send(INS_VERIFY, 0x00, 0x80, &padded);
        padded.zeroize();
        res.map(|_| ())
    }

    /// ECDH на карте: отдаём публичную точку (65 байт), получаем общий секрет (32 байта).
    pub fn ecdh(&self, peer_point: &[u8]) -> Result<Vec<u8>> {
        let mut inner = tlv(0x82, &[]);
        inner.extend(tlv(0x85, peer_point));
        let dyn_auth = tlv(0x7c, &inner);
        let resp = self.send(INS_GENERAL_AUTH, ALG_ECCP256, SLOT, &dyn_auth)?;
        let outer = tlv_get(&resp, 0x7c).ok_or_else(|| Error::Unexpected("GENERAL AUTHENTICATE".into()))?;
        let shared = tlv_get(outer, 0x82).ok_or_else(|| Error::Unexpected("GENERAL AUTHENTICATE".into()))?;
        if shared.len() != 32 {
            return Err(Error::Unexpected("длина общего секрета".into()));
        }
        Ok(shared.to_vec())
    }

    /// Публичный ключ слота 9d (сырая точка 65 байт). PIN не нужен. YubiKey >= 5.3.
    pub fn public_key_point(&self) -> Result<Vec<u8>> {
        let resp = self.send(INS_GET_METADATA, 0x00, SLOT, &[])?;
        match tlv_get(&resp, 0x01) {
            Some([alg]) if *alg == ALG_ECCP256 => {}
            _ => return Err(Error::SlotEmpty),
        }
        let point = tlv_get(&resp, 0x04)
            .and_then(|pk| tlv_get(pk, 0x86))
            .filter(|p| p.len() == POINT_LEN)
            .ok_or_else(|| Error::Unexpected("GET METADATA".into()))?;
        Ok(point.to_vec())
    }

    fn send(&self, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Result<Vec<u8>> {
        assert!(data.len() <= 255);
        let mut apdu = vec![0x00, ins, p1, p2];
        if !data.is_empty() {
            apdu.push(data.len() as u8);
            apdu.extend_from_slice(data);
        }
        let mut out = Vec::new();
        let mut rbuf = [0u8; pcsc::MAX_BUFFER_SIZE];
        let mut resp = self.card.transmit(&apdu, &mut rbuf)?.to_vec();
        loop {
            if resp.len() < 2 {
                return Err(Error::Unexpected("короткий ответ".into()));
            }
            let (sw1, sw2) = (resp[resp.len() - 2], resp[resp.len() - 1]);
            out.extend_from_slice(&resp[..resp.len() - 2]);
            if sw1 == 0x61 {
                let mut rbuf = [0u8; pcsc::MAX_BUFFER_SIZE];
                resp = self.card.transmit(&[0x00, INS_GET_RESPONSE, 0, 0, sw2], &mut rbuf)?.to_vec();
                continue;
            }
            let sw = u16::from(sw1) << 8 | u16::from(sw2);
            return if sw == 0x9000 { Ok(out) } else { Err(sw_error(ins, sw)) };
        }
    }
}

fn sw_error(ins: u8, sw: u16) -> Error {
    match (ins, sw) {
        (INS_VERIFY, sw) if sw & 0xfff0 == 0x63c0 => Error::WrongPin((sw & 0x0f) as u8),
        (INS_VERIFY, 0x6983) => Error::PinBlocked,
        (INS_GENERAL_AUTH, 0x6982) => Error::SecurityStatus,
        (INS_GENERAL_AUTH, 0x6a80 | 0x6a86) => Error::SlotEmpty,
        (INS_GET_METADATA, 0x6a82) => Error::SlotEmpty,
        (INS_SELECT, 0x6a82) => Error::Unexpected("PIV-приложение не найдено".into()),
        _ => Error::Apdu { ins, sw },
    }
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    assert!(value.len() <= 255);
    let mut out = vec![tag];
    if value.len() < 0x80 {
        out.push(value.len() as u8);
    } else {
        out.extend_from_slice(&[0x81, value.len() as u8]);
    }
    out.extend_from_slice(value);
    out
}

fn tlv_get(buf: &[u8], want: u8) -> Option<&[u8]> {
    let mut i = 0;
    while i + 1 < buf.len() {
        let tag = buf[i];
        let mut len = buf[i + 1] as usize;
        i += 2;
        if len == 0x81 {
            len = *buf.get(i)? as usize;
            i += 1;
        } else if len == 0x82 {
            len = (*buf.get(i)? as usize) << 8 | *buf.get(i + 1)? as usize;
            i += 2;
        }
        let end = (i + len).min(buf.len());
        if tag == want {
            return Some(&buf[i..end]);
        }
        i = end;
    }
    None
}

/// Полный цикл расшифровки на YubiKey. `on_touch` вызывается перед ECDH (момент, когда нужно касание).
pub fn decrypt_with_yubikey(payload: &str, pin: &str, on_touch: impl FnOnce()) -> Result<String> {
    decrypt(payload, |eph_pub| {
        let piv = Piv::open()?;
        piv.verify_pin(pin)?;
        on_touch();
        piv.ecdh(eph_pub)
    })
}

/// Публичный ключ слота 9d с YubiKey (PEM).
pub fn read_public_key_pem() -> Result<String> {
    let piv = Piv::open()?;
    pem_from_point(&piv.public_key_point()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::pkcs8::EncodePrivateKey;

    fn keypair() -> (String, String) {
        let secret = SecretKey::random(&mut OsRng);
        let priv_pem = secret.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        let pub_pem = secret.public_key().to_public_key_pem(LineEnding::LF).unwrap();
        (priv_pem, pub_pem)
    }

    #[test]
    fn roundtrip() {
        let (priv_pem, pub_pem) = keypair();
        let ecdh = software_ecdh(&priv_pem).unwrap();
        for s in ["", "hello", "привет, мир 🔐", &"x".repeat(10_000)] {
            let enc = encrypt(s, &pub_pem).unwrap();
            assert!(enc.starts_with(PREFIX));
            assert_ne!(encrypt(s, &pub_pem).unwrap(), enc);
            assert_eq!(decrypt(&enc, &ecdh).unwrap(), s);
        }
    }

    #[test]
    fn rejects_tamper_and_foreign_key() {
        let (priv_pem, pub_pem) = keypair();
        let (_, other_pub) = keypair();
        let ecdh = software_ecdh(&priv_pem).unwrap();

        let enc = encrypt("secret", &pub_pem).unwrap();
        let mut blob = URL_SAFE_NO_PAD.decode(&enc[PREFIX.len()..]).unwrap();
        *blob.last_mut().unwrap() ^= 1;
        let bad = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(blob));
        assert!(matches!(decrypt(&bad, &ecdh), Err(Error::DecryptFailed)));

        let foreign = encrypt("secret", &other_pub).unwrap();
        assert!(matches!(decrypt(&foreign, &ecdh), Err(Error::DecryptFailed)));

        assert!(matches!(decrypt("nope:abc", &ecdh), Err(Error::BadFormat(_))));
        assert!(matches!(decrypt("ykpiv1:AAAA", &ecdh), Err(Error::BadFormat(_))));
    }

    #[test]
    fn pem_point_roundtrip_and_fingerprint() {
        let (_, pub_pem) = keypair();
        let key = PublicKey::from_public_key_pem(&pub_pem).unwrap();
        let point = key.to_encoded_point(false).as_bytes().to_vec();
        assert_eq!(pem_from_point(&point).unwrap().trim(), pub_pem.trim());
        assert_eq!(fingerprint(&pub_pem).unwrap().len(), 11);
    }

    #[test]
    fn tlv_parse() {
        let buf = [0x01, 0x01, 0x11, 0x04, 0x03, 0x86, 0x01, 0xaa];
        assert_eq!(tlv_get(&buf, 0x01), Some(&[0x11][..]));
        assert_eq!(tlv_get(tlv_get(&buf, 0x04).unwrap(), 0x86), Some(&[0xaa][..]));
        assert_eq!(tlv_get(&buf, 0x05), None);
    }
}
