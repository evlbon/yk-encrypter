<h1 align="center">YubiKey Encrypter</h1>

<p align="center">
  Encrypt and decrypt text with a YubiKey. The private key never leaves the hardware;<br>
  decryption needs the key itself, its PIN and a touch.
</p>

<p align="center">
  <a href="https://github.com/evlbon/yk-encrypter/actions/workflows/build.yml"><img alt="release workflow" src="https://github.com/evlbon/yk-encrypter/actions/workflows/build.yml/badge.svg"></a>
  <a href="https://github.com/evlbon/yk-encrypter/releases/latest"><img alt="latest release" src="https://img.shields.io/github/v/release/evlbon/yk-encrypter?label=release"></a>
  <a href="https://github.com/evlbon/yk-encrypter/releases"><img alt="downloads" src="https://img.shields.io/github/downloads/evlbon/yk-encrypter/total"></a>
  <a href="LICENSE"><img alt="license" src="https://img.shields.io/github/license/evlbon/yk-encrypter"></a>
  <img alt="platforms" src="https://img.shields.io/badge/platforms-macOS%20%7C%20Windows%20%7C%20Linux-blue">
  <img alt="Tauri 2" src="https://img.shields.io/badge/Tauri-2-24C8D8?logo=tauri&logoColor=white">
  <img alt="Rust" src="https://img.shields.io/badge/Rust-stable-000000?logo=rust">
</p>

---

**What it is.** A small desktop app (Tauri 2 + Rust, ~6 MB) with an English/Russian UI and a CLI. You paste text, get a
`ykpiv1:…` string back; to read it again you need the same YubiKey, its PIN and a touch. Encryption works without the
YubiKey plugged in, so you can encrypt on one machine and decrypt on another.

**What it is not.** Not a password manager, not file encryption, not a replacement for age/GPG. It is deliberately
small: one key, one slot, one format, ~400 lines of crypto and card code you can read in an evening.

## Download

Grab the installer for your OS from the [latest release](https://github.com/evlbon/yk-encrypter/releases/latest):

| OS      | File                      | Notes                                                                                   |
|---------|---------------------------|-----------------------------------------------------------------------------------------|
| macOS   | `*.dmg` (Apple Silicon)   | Ad-hoc signed, not notarized — see below                                                |
| Windows | `*.msi` or `*-setup.exe`  | Unsigned: SmartScreen → **More info** → **Run anyway**. No drivers needed (built-in smart card service) |
| Linux   | build from source         | needs `pcscd` running and `libpcsclite`                                                 |

**macOS first launch.** The app is ad-hoc signed (no Apple Developer ID, no notarization), so Gatekeeper refuses it
once. Either open System Settings → Privacy & Security, scroll down and press **Open Anyway**, or clear the
quarantine flag in Terminal and launch normally:

```sh
xattr -dr com.apple.quarantine "/Applications/YubiKey Encrypter.app"
```

If macOS says the app is *damaged* instead, the download was tampered with or the bundle signature is broken — re-download
from the release page rather than forcing it open.

## Quick start

1. **Prepare the YubiKey once** (YubiKey 5 series, firmware ≥ 5.3). Install [ykman](https://developers.yubico.com/yubikey-manager/) and run:

   ```sh
   ykman piv keys generate -a eccp256 --pin-policy always --touch-policy always 9d piv-9d.pub.pem
   ykman piv access change-pin
   ykman piv access change-puk
   ykman piv access change-management-key --generate --protect
   ```

   This creates a P-256 key *inside* the YubiKey (PIV slot 9d) and replaces the factory PIN/PUK/management key.
   Keep `piv-9d.pub.pem` if you want to encrypt from scripts; the app reads the public key from the YubiKey itself.

2. **Run the app**, plug in the YubiKey. The header turns green and shows the key fingerprint. The app remembers the
   public key, so from now on you can encrypt without the YubiKey.

3. **Encrypt**: paste text → *Encrypt* → copy the `ykpiv1:…` string.
   **Decrypt**: paste the string → enter PIN → *Decrypt* → touch the YubiKey when the status says so.

## How it works

```
encrypt:  ephemeral P-256 ──ECDH──▶ shared secret ──HKDF-SHA256──▶ AES-256-GCM key ──▶ ciphertext
                                 (with the YubiKey public key)

decrypt:  ephemeral public point ──▶ YubiKey (GENERAL AUTHENTICATE, ECDH with the private key)
          ──▶ shared secret ──HKDF──▶ same AES key ──▶ plaintext
```

- Format: `ykpiv1:` + base64url( `ephPub(65)` ‖ `iv(12)` ‖ `tag(16)` ‖ `ciphertext` ).
  AAD = ephPub, HKDF salt = ephPub, info = `yk-encrypter/piv-p256/v1/aes-256-gcm`.
- Every message uses a fresh ephemeral key and nonce, so the same text never encrypts to the same string.
- The YubiKey is talked to over PC/SC with five APDUs (SELECT, GET METADATA, VERIFY, GENERAL AUTHENTICATE,
  GET RESPONSE); no vendor SDK involved. This is the same construction as `age-plugin-yubikey`, minus the age wrapping.

## Security properties

- **Fail closed on weak slots.** Before every decryption the app reads the slot's PIN and touch policy and refuses if
  either is `never`. A key generated without `--touch-policy always` cannot be used silently.
- **PIN lifetime = one operation.** The UI clears the PIN after each attempt, on mode switch, on *Clear* and when the
  window loses focus. The CLI reads it with a hidden prompt (or from `YK_PIV_PIN` for scripts), never from arguments.
- **Secrets are wiped.** PIN, APDU buffers, ECDH shared secrets, derived AES keys and decrypted plaintext are
  `Zeroizing` and cleared on drop, including on error paths.
- **No silent recipient switch.** The stored public key changes only when you press ↻. If the plugged-in YubiKey holds
  a different key, the header and status line say so.
- **Nothing to steal from the host.** No private key material, no PIN, no secret ever lives on disk. The stored public
  key and the UI language are the only persistent state.

> **Disclaimer.** This code has had a code review but no independent security audit. The cryptography is standard and
> the private key never leaves the YubiKey, but if you rely on it for anything serious, read `src-tauri/src/core.rs`
> yourself. Losing the YubiKey means losing everything encrypted with it: there is no backup key unless you also
> encrypt for a second YubiKey.

## Compatibility

| Component | Requirement                                                                 |
|-----------|-----------------------------------------------------------------------------|
| YubiKey   | 5 series (firmware ≥ 5.3 for GET METADATA); 5C Nano tested. Works over USB; NFC untested |
| macOS     | 12+ (Apple Silicon build in releases; Intel builds from source)             |
| Windows   | 10/11 with WebView2 (preinstalled on 11; the installer fetches it otherwise) |
| Linux     | `pcscd` + `libpcsclite`, WebKitGTK 4.1                                      |

Known limitation: if the firmware predates 5.3, GET METADATA fails and the app reports the slot as empty.

## CLI

`ykenc` ships inside the app: `YubiKey Encrypter.app/Contents/MacOS/ykenc` on macOS, next to `yk-encrypter.exe` in the
install directory on Windows. After `npm run build` it is also in `src-tauri/target/release/`.

```sh
ykenc pubkey                                     # PEM of slot 9d + its policies (stderr)
printf '%s' 'secret text' | ykenc enc pub.pem    # encrypt, YubiKey not needed
ykenc dec < msg.txt                              # decrypt: hidden PIN prompt, then touch
YK_PIV_PIN=123456 ykenc dec "ykpiv1:…"           # for scripts
```

Plaintext is accepted from stdin only, so it never lands in process arguments or shell history.

## Build from source

Requirements: Rust (rustup), Node 22. macOS: Command Line Tools. Windows: Visual Studio Build Tools (C++).
Linux: `libpcsclite-dev libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev`.

```sh
npm ci
npm run dev                                              # app in dev mode
npm run build                                            # installers in src-tauri/target/release/bundle/
cargo test --manifest-path src-tauri/Cargo.toml --lib    # crypto and format tests
```

Layout:

- `src-tauri/src/core.rs` — ECDH/HKDF/AES-GCM and PIV over PC/SC (`pcsc` crate; no other YubiKey dependencies).
- `src-tauri/src/lib.rs` — Tauri commands (`yubikey_present`, `read_key`, `encrypt`, `decrypt`) and the `yk-touch` event.
  Errors come back as `{ code, message, detail?, tries? }` and are localized in the UI.
- `src-tauri/src/bin/ykenc.rs` — the CLI.
- `ui/` — vanilla TypeScript (`main.ts`, `i18n.ts`), bundled by esbuild into `ui/dist/main.js`.

## Releases

The version lives in `src-tauri/tauri.conf.json` (mirrored in `Cargo.toml` and `package.json`). CI runs on every push
to `main` but builds and publishes only when that version has no tag yet:

```sh
npm run bump 1.0.1
git commit -am "v1.0.1" && git push
```

GitHub Actions then builds Windows `.msi` + `.exe` and macOS `.dmg`, creates tag `v1.0.1` and a Release with the
installers attached. Windows can only be built there — Tauri does not cross-compile.

## FAQ

**Can I encrypt for someone else's YubiKey?** Yes: get their public key (`ykman piv keys export 9d`, or the ↻ button
with their key plugged in) and use it with `ykenc enc`. The app itself holds one recipient key at a time.

**What if I lose the YubiKey?** The data is gone. Encrypt important things for two YubiKeys, or keep a software
backup of the data elsewhere. There is no key escrow by design.

**Does it work over NFC?** Not tested. PC/SC readers with NFC should work in principle; the YubiKey OTP/HID interface
is not used at all.

**Why P-256 and not RSA?** ECDH gives a clean key-agreement API on the card with no padding to get wrong, and it is
fast: a decryption takes well under a second plus the touch.

**Why not age-plugin-yubikey?** Use it if you need files and the age ecosystem. This is for the "copy a secret into
a chat / note" case with a GUI and a two-field UI.

## History

The first version was a SwiftUI/CryptoTokenKit macOS app; it lives at tag [`swift-macos`](https://github.com/evlbon/yk-encrypter/tree/swift-macos)
and reads the same format. It was replaced by this cross-platform Tauri version.

## По-русски

Приложение шифрует текст ключом, который хранится в YubiKey (PIV-слот 9d, P-256) и никогда его не покидает.
Расшифровка требует сам YubiKey, PIN и касание. Шифровать можно без ключа, расшифровывать — только с ним.
Установщики для macOS и Windows в разделе [Releases](https://github.com/evlbon/yk-encrypter/releases/latest);
при первом запуске система предупредит о неподписанном приложении, разрешите его в настройках. Настройка YubiKey —
четыре команды `ykman` из раздела Quick start. Интерфейс переключается между русским и английским кнопкой в шапке.

## License

MIT, see [LICENSE](LICENSE).
