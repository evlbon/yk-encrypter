import CryptoKit
import Foundation

/// Формат payload: "ykpiv1:" + base64url( ephPub(65) | iv(12) | tag(16) | ciphertext ).
/// Полностью совместим с src/yk-encrypter/yk-encrypter.ts.
public enum YkCrypto {
    public static let prefix = "ykpiv1:"
    static let pointLen = 65
    static let ivLen = 12
    static let tagLen = 16
    static let keyLen = 32
    static let hkdfInfo = Data("yk-encrypter/piv-p256/v1/aes-256-gcm".utf8)

    public enum Error: LocalizedError {
        case badFormat(String)
        case decryptFailed

        public var errorDescription: String? {
            switch self {
            case .badFormat(let why): return "Неверный формат данных: \(why)"
            case .decryptFailed: return "Не удалось расшифровать: другой YubiKey или данные повреждены"
            }
        }
    }

    /// Шифрует публичным ключом YubiKey (PEM, SPKI P-256). YubiKey не нужен.
    public static func encrypt(_ plaintext: String, recipientPEM: String) throws -> String {
        let recipient = try P256.KeyAgreement.PublicKey(pemRepresentation: recipientPEM)
        let eph = P256.KeyAgreement.PrivateKey()
        let ephPub = eph.publicKey.x963Representation // 65 байт, 0x04 | X | Y
        let shared = try eph.sharedSecretFromKeyAgreement(with: recipient).withUnsafeBytes { Data($0) }
        return try seal(plaintext, shared: shared, ephPub: ephPub)
    }

    /// Расшифровывает; `ecdh` получает эфемерную точку (65 байт) и возвращает общий секрет (32 байта).
    /// В приложении это операция на YubiKey, в тестах — программный ECDH.
    public static func decrypt(_ payload: String, ecdh: (Data) async throws -> Data) async throws -> String {
        guard payload.hasPrefix(prefix) else { throw Error.badFormat("ожидается \(prefix)…") }
        guard let blob = Data(base64url: String(payload.dropFirst(prefix.count))) else {
            throw Error.badFormat("base64url")
        }
        guard blob.count >= pointLen + ivLen + tagLen else { throw Error.badFormat("слишком короткие данные") }

        var off = 0
        func take(_ n: Int) -> Data { defer { off += n }; return blob.subdata(in: off..<(off + n)) }
        let ephPub = take(pointLen)
        let iv = take(ivLen)
        let tag = take(tagLen)
        let ciphertext = blob.subdata(in: off..<blob.count)
        guard ephPub.first == 0x04 else { throw Error.badFormat("эфемерный ключ") }

        let shared = try await ecdh(ephPub)
        let key = deriveKey(shared: shared, ephPub: ephPub)
        do {
            let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: iv), ciphertext: ciphertext, tag: tag)
            let plain = try AES.GCM.open(box, using: key, authenticating: ephPub)
            guard let text = String(data: plain, encoding: .utf8) else { throw Error.decryptFailed }
            return text
        } catch {
            throw Error.decryptFailed
        }
    }

    /// Программный ECDH для тестов: приватный ключ P-256 в PEM (PKCS#8 или SEC1).
    public static func softwareECDH(privateKeyPEM: String) throws -> (Data) throws -> Data {
        let priv = try P256.KeyAgreement.PrivateKey(pemRepresentation: privateKeyPEM)
        return { ephPub in
            let pub = try P256.KeyAgreement.PublicKey(x963Representation: ephPub)
            return try priv.sharedSecretFromKeyAgreement(with: pub).withUnsafeBytes { Data($0) }
        }
    }

    /// Сырая точка (65 байт) → PEM.
    public static func pem(fromPoint point: Data) throws -> String {
        try P256.KeyAgreement.PublicKey(x963Representation: point).pemRepresentation + "\n"
    }

    /// Короткий отпечаток публичного ключа для UI.
    public static func fingerprint(pem: String) -> String? {
        guard let key = try? P256.KeyAgreement.PublicKey(pemRepresentation: pem) else { return nil }
        let digest = SHA256.hash(data: key.x963Representation)
        return digest.prefix(4).map { String(format: "%02x", $0) }.joined(separator: ":")
    }

    // MARK: - internals

    static func seal(_ plaintext: String, shared: Data, ephPub: Data) throws -> String {
        let key = deriveKey(shared: shared, ephPub: ephPub)
        let nonce = AES.GCM.Nonce()
        let box = try AES.GCM.seal(Data(plaintext.utf8), using: key, nonce: nonce, authenticating: ephPub)
        var out = Data()
        out.append(ephPub)
        out.append(contentsOf: nonce)
        out.append(box.tag)
        out.append(box.ciphertext)
        return prefix + out.base64url()
    }

    static func deriveKey(shared: Data, ephPub: Data) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: shared),
            salt: ephPub,
            info: hkdfInfo,
            outputByteCount: keyLen
        )
    }
}

extension Data {
    func base64url() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    init?(base64url: String) {
        var s = base64url.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while s.count % 4 != 0 { s += "=" }
        self.init(base64Encoded: s)
    }

    var hex: String { map { String(format: "%02x", $0) }.joined() }
}
