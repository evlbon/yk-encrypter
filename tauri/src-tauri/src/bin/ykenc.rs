//! CLI к ядру. Формат совместим с Swift- и TS-версиями.
//!   ykenc pubkey                             — PEM публичного ключа слота 9d с YubiKey
//!   ykenc enc "<text>" <pubkey.pem>          — зашифровать (YubiKey не нужен)
//!   ykenc dec "<ykpiv1:...>"                 — расшифровать на YubiKey (PIN из YK_PIV_PIN или запрос)
//!   ykenc dec-soft "<ykpiv1:...>" <priv.pem> — расшифровать программно (для тестов)
use std::io::{self, BufRead, IsTerminal, Write};
use std::process::exit;
use yk_encrypter_lib::core;

const USAGE: &str = "usage: ykenc pubkey
       ykenc enc \"<text>\" <pubkey.pem>
       ykenc dec \"<ykpiv1:...>\"
       ykenc dec-soft \"<ykpiv1:...>\" <privkey.pem>";

fn read_pin() -> String {
    if let Ok(pin) = std::env::var("YK_PIV_PIN") {
        return pin;
    }
    if !io::stdin().is_terminal() {
        eprintln!("no TTY to read PIN; set YK_PIV_PIN");
        exit(1);
    }
    eprint!("PIV PIN: ");
    io::stderr().flush().ok();
    let mut pin = String::new();
    io::stdin().lock().read_line(&mut pin).ok();
    pin.trim_end_matches(['\r', '\n']).to_string()
}

fn run(args: &[String]) -> core::Result<String> {
    let arg = |i: usize| args.get(i).map(String::as_str);
    match (arg(0), args.len()) {
        (Some("pubkey"), 1) => core::read_public_key_pem(),
        (Some("enc"), 3) => {
            let pem = std::fs::read_to_string(&args[2]).map_err(|e| core::Error::BadKey(e.to_string()))?;
            core::encrypt(&args[1], &pem).map(|s| s + "\n")
        }
        (Some("dec"), 2) => {
            let pin = read_pin();
            core::decrypt_with_yubikey(&args[1], &pin, || eprintln!("(если включён touch — коснись YubiKey)"))
                .map(|s| s + "\n")
        }
        (Some("dec-soft"), 3) => {
            let pem = std::fs::read_to_string(&args[2]).map_err(|e| core::Error::BadKey(e.to_string()))?;
            let ecdh = core::software_ecdh(&pem)?;
            core::decrypt(&args[1], ecdh).map(|s| s + "\n")
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
