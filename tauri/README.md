# YubiKey Encrypter — Tauri 2 + Rust

Кросс-платформенная версия (macOS, Windows, Linux). Формат `ykpiv1:` тот же, что у Swift- и TS-версий.

## Структура

- `src-tauri/src/core.rs` — ECDH/HKDF/AES-GCM и PIV поверх PC/SC (крейт `pcsc`, без лишних зависимостей).
- `src-tauri/src/lib.rs` — Tauri-команды: `yubikey_present`, `read_public_key`, `encrypt`, `decrypt`, событие `yk-touch`.
- `src-tauri/src/bin/ykenc.rs` — CLI (`pubkey`, `enc`, `dec`, `dec-soft`).
- `ui/` — интерфейс: `index.html`, `style.css`, `main.ts` (собирается esbuild'ом в `ui/dist/main.js`).

## Сборка локально

Нужны Rust (rustup), Node 22, на macOS — Command Line Tools, на Windows — Visual Studio Build Tools (C++) и WebView2
(в Windows 11 уже есть), на Linux — `libpcsclite-dev libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev`.

```sh
npm ci
npm run dev        # окно приложения в режиме разработки
npm run build      # бандлы в src-tauri/target/release/bundle/
cargo test --manifest-path src-tauri/Cargo.toml --lib   # тесты криптографии и формата
```

CLI: `cargo run --manifest-path src-tauri/Cargo.toml --bin ykenc -- pubkey`.

## Windows

Собирается только на Windows (Tauri не кросс-компилирует). В репозитории есть `.github/workflows/build.yml`:
при пуше в `main` GitHub Actions собирает `.msi` и `.exe` (NSIS) для Windows и `.dmg` для macOS, артефакты
лежат во вкладке Actions. Установщик не подписан, SmartScreen покажет предупреждение: «Подробнее» → «Выполнить в любом случае».

Служба смарт-карт в Windows встроена, YubiKey работает без драйверов.
