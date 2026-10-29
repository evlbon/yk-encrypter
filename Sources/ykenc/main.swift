// CLI к ядру. Формат совместим с src/yk-encrypter/yk-encrypter.ts.
//   ykenc pubkey                          — PEM публичного ключа слота 9d с YubiKey
//   ykenc enc "<text>" <pubkey.pem>       — зашифровать (YubiKey не нужен)
//   ykenc dec "<ykpiv1:...>"              — расшифровать на YubiKey (PIN из YK_PIV_PIN или запрос)
//   ykenc dec-soft "<ykpiv1:...>" <priv.pem> — расшифровать программно (для тестов)
import Darwin
import Foundation
import YkEncrypterCore

let usage = """
usage: ykenc pubkey
       ykenc enc "<text>" <pubkey.pem>
       ykenc dec "<ykpiv1:...>"
       ykenc dec-soft "<ykpiv1:...>" <privkey.pem>
"""

func fail(_ message: String, code: Int32 = 1) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(code)
}

func readPIN() -> String {
    if let pin = ProcessInfo.processInfo.environment["YK_PIV_PIN"] { return pin }
    guard isatty(STDIN_FILENO) != 0, let c = getpass("PIV PIN: ") else { fail("no TTY to read PIN; set YK_PIV_PIN") }
    return String(cString: c)
}

Task {
    do {
        let args = Array(CommandLine.arguments.dropFirst())
        switch args.first {
        case "pubkey":
            let point = try await PIVCard.withYubiKey { try await $0.publicKeyPoint() }
            print(try YkCrypto.pem(fromPoint: point), terminator: "")
        case "enc" where args.count == 3:
            let pem = try String(contentsOfFile: args[2], encoding: .utf8)
            print(try YkCrypto.encrypt(args[1], recipientPEM: pem))
        case "dec" where args.count == 2:
            let pin = readPIN()
            let text = try await YkCrypto.decrypt(args[1]) { ephPub in
                try await PIVCard.withYubiKey { piv in
                    try await piv.verifyPIN(pin)
                    FileHandle.standardError.write(Data("(если включён touch — коснись YubiKey)\n".utf8))
                    return try await piv.ecdh(peerPoint: ephPub)
                }
            }
            print(text)
        case "dec-soft" where args.count == 3:
            let pem = try String(contentsOfFile: args[2], encoding: .utf8)
            let ecdh = try YkCrypto.softwareECDH(privateKeyPEM: pem)
            print(try await YkCrypto.decrypt(args[1]) { try ecdh($0) })
        default:
            fail(usage, code: 2)
        }
        exit(0)
    } catch {
        fail(error.localizedDescription)
    }
}
dispatchMain()
