pub mod core;

use serde::Serialize;
use tauri::{AppHandle, Emitter};

/// Ошибка для фронтенда: код для локализации + английский текст + детали.
#[derive(Serialize)]
pub struct ApiError {
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tries: Option<u8>,
}

impl From<core::Error> for ApiError {
    fn from(e: core::Error) -> Self {
        ApiError { code: e.code(), message: e.to_string(), detail: e.detail(), tries: e.pin_tries() }
    }
}

impl From<tauri::Error> for ApiError {
    fn from(e: tauri::Error) -> Self {
        ApiError { code: "internal", message: e.to_string(), detail: None, tries: None }
    }
}

#[tauri::command]
fn yubikey_present() -> bool {
    core::Piv::is_present()
}

#[tauri::command]
async fn read_public_key() -> Result<String, ApiError> {
    Ok(tauri::async_runtime::spawn_blocking(core::read_public_key_pem).await??)
}

#[tauri::command]
fn key_fingerprint(pem: String) -> Option<String> {
    core::fingerprint(&pem)
}

#[tauri::command]
fn encrypt(text: String, pem: String) -> Result<String, ApiError> {
    Ok(core::encrypt(&text, &pem)?)
}

/// Расшифровка на YubiKey. Перед ECDH шлёт событие `yk-touch` (пора касаться ключа).
#[tauri::command]
async fn decrypt(app: AppHandle, payload: String, pin: String) -> Result<String, ApiError> {
    Ok(tauri::async_runtime::spawn_blocking(move || {
        core::decrypt_with_yubikey(&payload, &pin, || {
            let _ = app.emit("yk-touch", ());
        })
    })
    .await??)
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
