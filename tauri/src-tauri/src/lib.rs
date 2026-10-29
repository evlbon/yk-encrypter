pub mod core;

use tauri::{AppHandle, Emitter};

#[tauri::command]
fn yubikey_present() -> bool {
    core::Piv::is_present()
}

#[tauri::command]
async fn read_public_key() -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(core::read_public_key_pem)
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn key_fingerprint(pem: String) -> Option<String> {
    core::fingerprint(&pem)
}

#[tauri::command]
fn encrypt(text: String, pem: String) -> Result<String, String> {
    core::encrypt(&text, &pem).map_err(|e| e.to_string())
}

/// Расшифровка на YubiKey. Перед ECDH шлёт событие `yk-touch` (пора касаться ключа).
#[tauri::command]
async fn decrypt(app: AppHandle, payload: String, pin: String) -> Result<String, String> {
    let result = tauri::async_runtime::spawn_blocking(move || {
        core::decrypt_with_yubikey(&payload, &pin, || {
            let _ = app.emit("yk-touch", ());
        })
    })
    .await
    .map_err(|e| e.to_string())?;
    result.map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .invoke_handler(tauri::generate_handler![
            yubikey_present,
            read_public_key,
            key_fingerprint,
            encrypt,
            decrypt
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
