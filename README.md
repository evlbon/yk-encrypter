# YubiKey Encrypter

Encrypt and decrypt strings with a YubiKey. The private key lives in PIV slot 9d (P-256) and never leaves the key;
decryption requires the YubiKey itself, its PIN and a touch. Desktop app (Tauri 2 + Rust) for macOS, Windows and Linux,
UI in English and Russian.

Шифрование строк с помощью YubiKey. Приватный ключ живёт в PIV-слоте 9d и никогда не покидает ключ; расшифровка
требует сам YubiKey, PIN и касание. Интерфейс на английском и русском.

## Scheme

- **encrypt**: ephemeral P-256 key pair → ECDH with the YubiKey public key → HKDF-SHA256 → AES-256-GCM.
  Only the public key is needed; the YubiKey can stay in the drawer.
- **decrypt**: ephemeral point from the payload → GENERAL AUTHENTICATE on the card (ECDH with the private key) →
  same HKDF → AES-GCM.
- Format: `ykpiv1:` + base64url( ephPub(65) | iv(12) | tag(16) | ciphertext ). AAD = ephPub, HKDF salt = ephPub,
  info = `yk-encrypter/piv-p256/v1/aes-256-gcm`.

The earlier SwiftUI/CryptoTokenKit macOS version is kept at tag `swift-macos`; it reads the same format.

## YubiKey setup (once)

```sh
brew install ykman            # or: pip install yubikey-manager
ykman piv keys generate -a eccp256 --pin-policy always --touch-policy always 9d piv-9d.pub.pem
ykman piv access change-pin
ykman piv access change-puk
ykman piv access change-management-key --generate --protect
```

## Layout

- `src-tauri/src/core.rs` — ECDH/HKDF/AES-GCM and PIV over PC/SC (`pcsc` crate, no other YubiKey dependencies).
- `src-tauri/src/lib.rs` — Tauri commands: `yubikey_present`, `read_public_key`, `encrypt`, `decrypt`; event `yk-touch`.
  Errors are returned as `{ code, message, detail?, tries? }` and localized in the UI.
- `src-tauri/src/bin/ykenc.rs` — CLI (`pubkey`, `enc`, `dec`, `dec-soft`). Plaintext is read from stdin only and the
  PIN is prompted without echo (or taken from `YK_PIV_PIN`), so neither lands in process arguments or shell history.

## Security properties

- Decryption is refused unless slot 9d has PIN policy ≠ `never` **and** touch policy ≠ `never` (checked via GET METADATA
  before every operation), so a key generated without `--touch-policy always` cannot be used silently.
- The UI keeps the PIN only for the duration of one operation; it is cleared afterwards, on mode switch and on window blur.
- PIN, APDU buffers, ECDH shared secrets, derived AES keys and decrypted plaintext are wrapped in `Zeroizing` and wiped on drop.
- The stored recipient key is replaced only by pressing ↻; if the connected YubiKey holds a different key, the UI warns.
- `ui/` — vanilla TypeScript (`main.ts`, `i18n.ts`), bundled by esbuild into `ui/dist/main.js`.

## Build

Requirements: Rust (rustup), Node 22. macOS: Command Line Tools. Windows: Visual Studio Build Tools (C++) and WebView2
(preinstalled on Windows 11). Linux: `libpcsclite-dev libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev`.

```sh
npm ci
npm run dev                                              # app window in dev mode
npm run build                                            # bundles in src-tauri/target/release/bundle/
cargo test --manifest-path src-tauri/Cargo.toml --lib    # crypto and format tests
cargo run --manifest-path src-tauri/Cargo.toml --bin ykenc -- pubkey
printf '%s' 'secret text' | ykenc enc piv-9d.pub.pem > msg.txt       # encrypt (no YubiKey needed)
ykenc dec < msg.txt                                                   # decrypt: PIN prompt + touch
```

## Releases

The version lives in `src-tauri/tauri.conf.json` (mirrored in `Cargo.toml` and `package.json`). CI runs on every push
to `main` but only *builds and publishes* when the version has no tag yet:

```sh
npm run bump 1.0.1          # updates the three files + lock files
git commit -am "v1.0.1" && git push
```

`.github/workflows/build.yml` then builds Windows `.msi` + NSIS `.exe` and macOS `.dmg` (Apple Silicon), creates the
tag `v1.0.1` and a GitHub Release with the installers attached. Pushes without a version bump are a no-op in CI.
Windows can only be built there — Tauri does not cross-compile.

Installers are unsigned. macOS: System Settings → Privacy & Security → *Open Anyway* on first launch.
Windows: SmartScreen → *More info* → *Run anyway*. The Windows smart card service is built in; no drivers needed.
