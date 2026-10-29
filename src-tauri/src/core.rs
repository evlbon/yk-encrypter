//! Ядро: формат `ykpiv1:`, ECDH/HKDF/AES-GCM и PIV поверх PC/SC.
//! Совместимо с TS-модулем (yk-encrypter.ts) и Swift-версией (тег swift-macos).

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hkdf::Hkdf;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::Generate;
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePublicKey, LineEnding};
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const PREFIX: &str = "ykpiv1:";
const POINT_LEN: usize = 65;
const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;
const HKDF_INFO: &[u8] = b"yk-encrypter/piv-p256/v1/aes-256-gcm";

/// Секретные байты: обнуляются при drop, включая пути с ошибками.
pub type Secret = Zeroizing<Vec<u8>>;

/// Ошибки ядра. Display — английский текст для CLI/логов; UI локализует по `code()`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("bad payload format: {0}")]
    BadFormat(String),
    #[error("decryption failed: wrong YubiKey or corrupted payload")]
    DecryptFailed,
    #[error("bad public key: {0}")]
    BadKey(String),
    #[error("smart card service unavailable ({0})")]
    NoService(pcsc::Error),
    #[error("YubiKey not found — plug it in")]
    YubiKeyNotFound,
    #[error("PC/SC error: {0}")]
    Pcsc(#[from] pcsc::Error),
    #[error("PIN must be 6–8 characters")]
    PinFormat,
    #[error("wrong PIN, {0} tries left")]
    WrongPin(u8),
    #[error("PIN is blocked; unblock it with PUK: ykman piv access unblock-pin")]
    PinBlocked,
    #[error("card refused: PIN not verified")]
    SecurityStatus,
    #[error("slot 9d is empty or holds a non-P-256 key")]
    SlotEmpty,
    #[error("slot 9d policy is too weak (pin={pin}, touch={touch}); regenerate with --pin-policy always --touch-policy always")]
    WeakPolicy { pin: Policy, touch: Policy },
    #[error("unexpected YubiKey response: {0}")]
    Unexpected(String),
    #[error("card error: ins=0x{ins:02x} sw=0x{sw:04x}")]
    Apdu { ins: u8, sw: u16 },
}

impl Error {
    /// Стабильный код для локализации в UI.
    pub fn code(&self) -> &'static str {
        match self {
            Error::BadFormat(_) => "bad_format",
            Error::DecryptFailed => "decrypt_failed",
            Error::BadKey(_) => "bad_key",
            Error::NoService(_) => "no_service",
            Error::YubiKeyNotFound => "yubikey_not_found",
            Error::Pcsc(_) => "pcsc",
            Error::PinFormat => "pin_format",
            Error::WrongPin(_) => "wrong_pin",
            Error::PinBlocked => "pin_blocked",
            Error::SecurityStatus => "security_status",
            Error::SlotEmpty => "slot_empty",
            Error::WeakPolicy { .. } => "weak_policy",
            Error::Unexpected(_) => "unexpected",
            Error::Apdu { .. } => "apdu",
        }
    }

    /// Оставшиеся попытки PIN (только для WrongPin).
    pub fn pin_tries(&self) -> Option<u8> {
        match self {
            Error::WrongPin(n) => Some(*n),
            _ => None,
        }
    }

    /// Техническая деталь для показа после локализованного текста (sw, причина парсинга и т.п.).
    pub fn detail(&self) -> Option<String> {
        match self {
            Error::BadFormat(s) | Error::BadKey(s) | Error::Unexpected(s) => Some(s.clone()),
            Error::NoService(e) | Error::Pcsc(e) => Some(e.to_string()),
            Error::Apdu { ins, sw } => Some(format!("ins=0x{ins:02x} sw=0x{sw:04x}")),
            Error::WeakPolicy { pin, touch } => Some(format!("pin={pin}, touch={touch}")),
            _ => None,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

// ---------------------------------------------------------------------------
// Криптография (без YubiKey)
// ---------------------------------------------------------------------------

/// Шифрует публичным ключом YubiKey (PEM, SPKI P-256).
pub fn encrypt(plaintext: &str, recipient_pem: &str) -> Result<String> {
    let recipient = PublicKey::from_public_key_pem(recipient_pem).map_err(|e| Error::BadKey(e.to_string()))?;
    let eph = EphemeralSecret::try_generate().map_err(|_| Error::Unexpected("system RNG".into()))?;
    let eph_pub = eph.public_key().to_sec1_bytes().into_vec(); // uncompressed, 65 байт
    debug_assert_eq!(eph_pub.len(), POINT_LEN);
    let shared: Secret = Zeroizing::new(eph.diffie_hellman(&recipient).raw_secret_bytes().to_vec());
    seal(plaintext, &shared, &eph_pub)
}

/// Расшифровывает; `ecdh` получает эфемерную точку (65 байт) и возвращает общий секрет (32 байта).
pub fn decrypt(payload: &str, ecdh: impl FnOnce(&[u8]) -> Result<Secret>) -> Result<String> {
    let body = payload
        .strip_prefix(PREFIX)
        .ok_or_else(|| Error::BadFormat(format!("expected {PREFIX}…")))?;
    let blob = URL_SAFE_NO_PAD
        .decode(body.trim())
        .map_err(|_| Error::BadFormat("base64url".into()))?;
    if blob.len() < POINT_LEN + IV_LEN + TAG_LEN {
        return Err(Error::BadFormat("payload too short".into()));
    }
    let (eph_pub, rest) = blob.split_at(POINT_LEN);
    let (iv, rest) = rest.split_at(IV_LEN);
    let (tag, ciphertext) = rest.split_at(TAG_LEN);
    if eph_pub[0] != 0x04 {
        return Err(Error::BadFormat("bad ephemeral key".into()));
    }

    let shared = ecdh(eph_pub)?;
    let key = derive_key(&shared, eph_pub);
    let cipher = Aes256Gcm::new_from_slice(key.as_slice()).expect("key length");

    let mut ct_tag = Vec::with_capacity(ciphertext.len() + TAG_LEN);
    ct_tag.extend_from_slice(ciphertext);
    ct_tag.extend_from_slice(tag);
    let nonce = Nonce::try_from(iv).map_err(|_| Error::BadFormat("iv".into()))?;
    let plain: Secret = Zeroizing::new(
        cipher
            .decrypt(&nonce, Payload { msg: &ct_tag, aad: eph_pub })
            .map_err(|_| Error::DecryptFailed)?,
    );
    std::str::from_utf8(&plain).map(str::to_owned).map_err(|_| Error::DecryptFailed)
}

/// Программный ECDH для тестов: приватный ключ P-256 в PEM (PKCS#8).
pub fn software_ecdh(private_key_pem: &str) -> Result<impl Fn(&[u8]) -> Result<Secret>> {
    let secret = SecretKey::from_pkcs8_pem(private_key_pem).map_err(|e| Error::BadKey(e.to_string()))?;
    Ok(move |eph_pub: &[u8]| {
        let peer = PublicKey::from_sec1_bytes(eph_pub).map_err(|e| Error::BadKey(e.to_string()))?;
        Ok(Zeroizing::new(secret.diffie_hellman(&peer).raw_secret_bytes().to_vec()))
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
    let digest = Sha256::digest(key.to_sec1_bytes());
    Some(digest[..4].iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":"))
}

fn seal(plaintext: &str, shared: &[u8], eph_pub: &[u8]) -> Result<String> {
    let key = derive_key(shared, eph_pub);
    let cipher = Aes256Gcm::new_from_slice(key.as_slice()).expect("key length");
    let mut iv = [0u8; IV_LEN];
    getrandom::fill(&mut iv).map_err(|_| Error::Unexpected("system RNG".into()))?;
    let ct_tag = cipher
        .encrypt(&Nonce::from(iv), Payload { msg: plaintext.as_bytes(), aad: eph_pub })
        .map_err(|_| Error::Unexpected("AES-GCM".into()))?;
    let (ciphertext, tag) = ct_tag.split_at(ct_tag.len() - TAG_LEN);

    let mut out = Vec::with_capacity(POINT_LEN + IV_LEN + TAG_LEN + ciphertext.len());
    out.extend_from_slice(eph_pub);
    out.extend_from_slice(&iv);
    out.extend_from_slice(tag);
    out.extend_from_slice(ciphertext);
    Ok(format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(out)))
}

fn derive_key(shared: &[u8], eph_pub: &[u8]) -> Zeroizing<[u8; KEY_LEN]> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(Some(eph_pub), shared)
        .expand(HKDF_INFO, key.as_mut_slice())
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

/// Политика PIN / касания слота (коды из PIV GET METADATA).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Policy {
    Never,
    Once,
    Always,
    Cached,
    Unknown,
}

impl Policy {
    fn pin(code: u8) -> Policy {
        match code {
            1 => Policy::Never,
            2 => Policy::Once,
            3 => Policy::Always,
            _ => Policy::Unknown,
        }
    }
    fn touch(code: u8) -> Policy {
        match code {
            1 => Policy::Never,
            2 => Policy::Always,
            3 => Policy::Cached,
            _ => Policy::Unknown,
        }
    }
}

impl std::fmt::Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Policy::Never => "never",
            Policy::Once => "once",
            Policy::Always => "always",
            Policy::Cached => "cached",
            Policy::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

/// Что лежит в слоте 9d.
#[derive(Debug, Clone)]
pub struct SlotInfo {
    pub point: Vec<u8>,
    pub pin_policy: Policy,
    pub touch_policy: Policy,
}

impl SlotInfo {
    /// Слабая политика: расшифровка возможна без PIN или без касания.
    pub fn is_weak(&self) -> bool {
        self.pin_policy == Policy::Never || self.touch_policy == Policy::Never
    }
}

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
        let mut padded = Zeroizing::new([0xffu8; 8]);
        padded[..len].copy_from_slice(pin.as_bytes());
        self.send(INS_VERIFY, 0x00, 0x80, padded.as_slice()).map(|_| ())
    }

    /// ECDH на карте: отдаём публичную точку (65 байт), получаем общий секрет (32 байта).
    pub fn ecdh(&self, peer_point: &[u8]) -> Result<Secret> {
        let mut inner = tlv(0x82, &[]);
        inner.extend(tlv(0x85, peer_point));
        let dyn_auth = tlv(0x7c, &inner);
        let resp = self.send(INS_GENERAL_AUTH, ALG_ECCP256, SLOT, &dyn_auth)?;
        let outer = tlv_get(&resp, 0x7c).ok_or_else(|| Error::Unexpected("GENERAL AUTHENTICATE".into()))?;
        let shared = tlv_get(outer, 0x82).ok_or_else(|| Error::Unexpected("GENERAL AUTHENTICATE".into()))?;
        if shared.len() != 32 {
            return Err(Error::Unexpected("shared secret length".into()));
        }
        Ok(Zeroizing::new(shared.to_vec()))
    }

    /// Метаданные слота 9d: публичная точка и политики. PIN не нужен. YubiKey >= 5.3.
    pub fn slot_info(&self) -> Result<SlotInfo> {
        let resp = self.send(INS_GET_METADATA, 0x00, SLOT, &[])?;
        match tlv_get(&resp, 0x01) {
            Some([alg]) if *alg == ALG_ECCP256 => {}
            _ => return Err(Error::SlotEmpty),
        }
        let (pin_policy, touch_policy) = match tlv_get(&resp, 0x02) {
            Some([pin, touch]) => (Policy::pin(*pin), Policy::touch(*touch)),
            _ => (Policy::Unknown, Policy::Unknown),
        };
        let point = tlv_get(&resp, 0x04)
            .and_then(|pk| tlv_get(pk, 0x86))
            .filter(|p| p.len() == POINT_LEN)
            .ok_or_else(|| Error::Unexpected("GET METADATA".into()))?;
        Ok(SlotInfo { point: point.to_vec(), pin_policy, touch_policy })
    }

    /// Все буферы обмена — Zeroizing: в них бывают PIN (VERIFY) и общий секрет (GENERAL AUTHENTICATE).
    fn send(&self, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Result<Secret> {
        assert!(data.len() <= 255);
        let mut apdu: Secret = Zeroizing::new(vec![0x00, ins, p1, p2]);
        if !data.is_empty() {
            apdu.push(data.len() as u8);
            apdu.extend_from_slice(data);
        }
        let mut out: Secret = Zeroizing::new(Vec::new());
        let mut rbuf = Zeroizing::new([0u8; pcsc::MAX_BUFFER_SIZE]);
        let mut resp_len = self.card.transmit(&apdu, rbuf.as_mut_slice())?.len();
        loop {
            if resp_len < 2 {
                return Err(Error::Unexpected("short response".into()));
            }
            let resp = &rbuf[..resp_len];
            let (sw1, sw2) = (resp[resp_len - 2], resp[resp_len - 1]);
            out.extend_from_slice(&resp[..resp_len - 2]);
            if sw1 == 0x61 {
                let get = [0x00, INS_GET_RESPONSE, 0, 0, sw2];
                resp_len = self.card.transmit(&get, rbuf.as_mut_slice())?.len();
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
        (INS_SELECT, 0x6a82) => Error::Unexpected("PIV applet not found".into()),
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

/// Полный цикл расшифровки на YubiKey. Отказывает, если политика слота позволяет расшифровку
/// без PIN или без касания. `on_touch` вызывается перед ECDH (момент, когда нужно касание).
pub fn decrypt_with_yubikey(payload: &str, pin: &str, on_touch: impl FnOnce()) -> Result<String> {
    decrypt(payload, |eph_pub| {
        let piv = Piv::open()?;
        let info = piv.slot_info()?;
        if info.is_weak() {
            return Err(Error::WeakPolicy { pin: info.pin_policy, touch: info.touch_policy });
        }
        piv.verify_pin(pin)?;
        on_touch();
        piv.ecdh(eph_pub)
    })
}

/// Слот 9d с YubiKey: PEM публичного ключа и политики.
pub fn read_slot() -> Result<(String, SlotInfo)> {
    let piv = Piv::open()?;
    let info = piv.slot_info()?;
    Ok((pem_from_point(&info.point)?, info))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::pkcs8::EncodePrivateKey;

    fn keypair() -> (String, String) {
        let secret = SecretKey::try_generate().unwrap();
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
        let point = key.to_sec1_bytes().into_vec();
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

    #[test]
    fn policy_codes_and_weakness() {
        let strong = SlotInfo { point: vec![], pin_policy: Policy::pin(3), touch_policy: Policy::touch(2) };
        assert_eq!((strong.pin_policy, strong.touch_policy), (Policy::Always, Policy::Always));
        assert!(!strong.is_weak());
        let cached = SlotInfo { point: vec![], pin_policy: Policy::pin(2), touch_policy: Policy::touch(3) };
        assert!(!cached.is_weak());
        let no_touch = SlotInfo { point: vec![], pin_policy: Policy::pin(3), touch_policy: Policy::touch(1) };
        assert!(no_touch.is_weak());
        let no_pin = SlotInfo { point: vec![], pin_policy: Policy::pin(1), touch_policy: Policy::touch(2) };
        assert!(no_pin.is_weak());
    }
}
