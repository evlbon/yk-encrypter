import Foundation
import SwiftUI
import YkEncrypterCore

@MainActor
final class AppModel: ObservableObject {
    enum Mode: String, CaseIterable, Identifiable {
        case encrypt, decrypt
        var id: String { rawValue }
        var title: String { self == .encrypt ? "Зашифровать" : "Расшифровать" }
    }

    enum Phase: Equatable {
        case idle, working(String)
    }

    @Published var mode: Mode = .encrypt { didSet { output = ""; error = nil } }
    @Published var input = ""
    @Published var pin = ""
    @Published var output = ""
    @Published var error: String?
    @Published var phase: Phase = .idle
    @Published private(set) var yubiKeyPresent = PIVCard.isYubiKeyPresent()
    @Published private(set) var recipientPEM: String? = UserDefaults.standard.string(forKey: AppModel.pemKey) {
        didSet { UserDefaults.standard.set(recipientPEM, forKey: AppModel.pemKey) }
    }

    private static let pemKey = "recipientPublicKeyPEM"
    private var presenceTimer: Timer?

    var isBusy: Bool { phase != .idle }
    var recipientFingerprint: String? { recipientPEM.flatMap(YkCrypto.fingerprint(pem:)) }

    var canRun: Bool {
        guard !isBusy, !input.isEmpty else { return false }
        switch mode {
        case .encrypt: return recipientPEM != nil
        case .decrypt: return !pin.isEmpty && yubiKeyPresent
        }
    }

    init() {
        presenceTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                let present = PIVCard.isYubiKeyPresent()
                if present != self.yubiKeyPresent { self.yubiKeyPresent = present }
            }
        }
        if recipientPEM == nil, yubiKeyPresent {
            Task { await refreshPublicKey() }
        }
    }

    /// Считывает публичный ключ слота 9d с YubiKey и запоминает его (PIN не нужен).
    func refreshPublicKey() async {
        error = nil
        phase = .working("Читаю публичный ключ…")
        defer { phase = .idle }
        do {
            let point = try await PIVCard.withYubiKey { try await $0.publicKeyPoint() }
            recipientPEM = try YkCrypto.pem(fromPoint: point)
        } catch {
            self.error = error.localizedDescription
        }
    }

    func run() async {
        error = nil
        output = ""
        do {
            switch mode {
            case .encrypt:
                guard let pem = recipientPEM else { throw PIVError.yubiKeyNotFound }
                output = try YkCrypto.encrypt(input, recipientPEM: pem)
            case .decrypt:
                let pin = self.pin
                phase = .working("Проверяю PIN…")
                defer { phase = .idle }
                output = try await YkCrypto.decrypt(input) { ephPub in
                    try await PIVCard.withYubiKey { piv in
                        try await piv.verifyPIN(pin)
                        self.phase = .working("Коснитесь YubiKey…")
                        return try await piv.ecdh(peerPoint: ephPub)
                    }
                }
            }
        } catch {
            self.error = error.localizedDescription
            if case PIVError.wrongPIN = error { pin = "" }
        }
    }

    func copyOutput() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(output, forType: .string)
    }

    func pasteInput() {
        if let s = NSPasteboard.general.string(forType: .string) { input = s }
    }

    func clear() {
        input = ""
        output = ""
        error = nil
    }
}
