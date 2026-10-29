# yk-encrypter

Шифрование строк с помощью YubiKey. Приватный ключ живёт в PIV-слоте 9d (P-256) и никогда не покидает ключ;
расшифровка требует сам YubiKey, PIN и касание.

## Схема

- **encrypt**: эфемерная пара P-256 → ECDH с публичным ключом YubiKey → HKDF-SHA256 → AES-256-GCM.
  Нужен только публичный ключ, YubiKey не нужен.
- **decrypt**: эфемерная точка из payload → GENERAL AUTHENTICATE на карте (ECDH приватным ключом) → тот же HKDF → AES-GCM.
- Формат: `ykpiv1:` + base64url( ephPub(65) | iv(12) | tag(16) | ciphertext ). AAD = ephPub, HKDF salt = ephPub,
  info = `yk-encrypter/piv-p256/v1/aes-256-gcm`.

Все реализации в репозитории читают друг друга.

## Реализации

| Папка    | Что это                                             | Платформы              |
|----------|-----------------------------------------------------|------------------------|
| `Sources/`, `build.sh` | SwiftUI-приложение + CLI `ykenc` (CryptoTokenKit, CryptoKit) | macOS 14+ |
| `tauri/` | Tauri 2 + Rust (крейт `yubikey`, PC/SC)             | macOS, Windows, Linux  |

## Настройка YubiKey (один раз)

```sh
brew install ykman
ykman piv keys generate -a eccp256 --pin-policy always --touch-policy always 9d piv-9d.pub.pem
ykman piv access change-pin
ykman piv access change-puk
ykman piv access change-management-key --generate --protect
```

## macOS (Swift)

```sh
./build.sh            # dist/YkEncrypter.app, dist/ykenc, dist/YkEncrypter.zip, dist/YkEncrypter.dmg
```

Нужны только Command Line Tools. Приложение подписано ad-hoc с entitlement `com.apple.security.smartcard`;
на другом Mac первый запуск разрешается через System Settings → Privacy & Security → Open Anyway.

## Tauri (macOS / Windows / Linux)

См. `tauri/README.md`. Windows-сборка собирается в GitHub Actions (`.github/workflows/build.yml`).
