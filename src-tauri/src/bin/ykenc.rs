//! CLI к ядру. Формат совместим с TS- и Swift-версиями.
//!   ykenc pubkey                              — PEM публичного ключа слота 9d + политики (в stderr)
//!   ykenc enc <pubkey.pem>   < plaintext      — зашифровать; открытый текст ТОЛЬКО из stdin
//!   ykenc dec [payload]      [< payload]      — расшифровать на YubiKey; PIN скрытым вводом или YK_PIV_PIN
//!   ykenc dec-soft <priv.pem> [payload]       — расшифровать программно (для тестов)
//!
//! Открытый текст и PIN намеренно не принимаются аргументами: аргументы процесса видны
//! другим процессам и попадают в историю shell.
use std::io::{self, IsTerminal, Read};
use std::process::exit;
use yk_encrypter_lib::core;
use zeroize::Zeroizing;

const USAGE: &str = "usage: ykenc pubkey
       ykenc enc <pubkey.pem>            (plaintext from stdin)
       ykenc dec [payload]               (payload from arg or stdin; PIN prompted or YK_PIV_PIN)
       ykenc dec-soft <privkey.pem> [payload]";

fn read_stdin() -> Zeroizing<String> {
    let mut s = Zeroizing::new(String::new());
    if io::stdin().read_to_string(&mut s).is_err() {
        eprintln!("stdin is not valid UTF-8");
        exit(1);
    }
    s
}

fn payload_arg(args: &[String], i: usize) -> String {
    match args.get(i) {
        Some(p) => p.clone(),
        None => read_stdin().trim().to_string(),
    }
}

fn read_pin() -> Zeroizing<String> {
    if let Ok(pin) = std::env::var("YK_PIV_PIN") {
        return Zeroizing::new(pin);
    }
    if !io::stdin().is_terminal() {
        eprintln!("no TTY to read PIN; set YK_PIV_PIN");
        exit(1);
    }
    match rpassword::prompt_password("PIV PIN: ") {
        Ok(pin) => Zeroizing::new(pin),
        Err(e) => {
            eprintln!("cannot read PIN: {e}");
            exit(1);
        }
    }
}

fn run(args: &[String]) -> core::Result<String> {
    let arg = |i: usize| args.get(i).map(String::as_str);
    match (arg(0), args.len()) {
        (Some("pubkey"), 1) => {
            let (pem, info) = core::read_slot()?;
            eprintln!(
                "slot 9d: P-256, pin policy = {}, touch policy = {}{}",
                info.pin_policy,
                info.touch_policy,
                if info.is_weak() { "  (WEAK: decryption will be refused)" } else { "" }
            );
            Ok(pem)
        }
        (Some("enc"), 2) => {
            let pem = std::fs::read_to_string(&args[1]).map_err(|e| core::Error::BadKey(e.to_string()))?;
            let text = read_stdin();
            core::encrypt(&text, &pem).map(|s| s + "\n")
        }
        (Some("dec"), 1 | 2) => {
            let payload = payload_arg(args, 1);
            let pin = read_pin();
            core::decrypt_with_yubikey(&payload, &pin, || {
                eprintln!("(touch your YubiKey if touch policy is enabled)")
            })
        }
        (Some("dec-soft"), 2 | 3) => {
            let pem = std::fs::read_to_string(&args[1]).map_err(|e| core::Error::BadKey(e.to_string()))?;
            let payload = payload_arg(args, 2);
            let ecdh = core::software_ecdh(&pem)?;
            core::decrypt(&payload, ecdh)
        }
        _ => {
            eprintln!("{USAGE}");
            exit(2);
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(out) => print!("{out}"),
        Err(e) => {
            eprintln!("{e}");
            exit(1);
        }
    }
}
