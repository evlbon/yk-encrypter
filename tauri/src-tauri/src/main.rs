// Не открывать консольное окно на Windows в release-сборке.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    yk_encrypter_lib::run()
}
