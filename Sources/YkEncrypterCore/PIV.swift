import CryptoTokenKit
import Foundation

public enum PIVError: LocalizedError {
    case noSmartCardAccess
    case yubiKeyNotFound
    case sessionFailed
    case pinFormat
    case wrongPIN(retriesLeft: Int)
    case pinBlocked
    case securityStatus
    case slotEmpty
    case unexpectedResponse(String)
    case apdu(ins: UInt8, sw: UInt16)

    public var errorDescription: String? {
        switch self {
        case .noSmartCardAccess: return "Нет доступа к смарт-картам (CryptoTokenKit недоступен)"
        case .yubiKeyNotFound: return "YubiKey не найден — вставьте ключ"
        case .sessionFailed: return "Не удалось открыть сессию с YubiKey"
        case .pinFormat: return "PIN должен быть длиной 6–8 символов"
        case .wrongPIN(let n): return "Неверный PIN, осталось попыток: \(n)"
        case .pinBlocked: return "PIN заблокирован. Разблокируйте через PUK: ykman piv access unblock-pin"
        case .securityStatus: return "Карта отказала: PIN не проверен"
        case .slotEmpty: return "Слот 9d пуст или ключ не P-256"
        case .unexpectedResponse(let what): return "Неожиданный ответ YubiKey: \(what)"
        case .apdu(let ins, let sw):
            return String(format: "Ошибка карты: ins=0x%02x sw=0x%04x", ins, sw)
        }
    }
}

/// PIV-приложение YubiKey поверх CryptoTokenKit. Только то, что нужно для слота 9d (P-256).
public final class PIVCard {
    static let aid = Data([0xa0, 0x00, 0x00, 0x03, 0x08])
    static let slot: UInt8 = 0x9d
    static let algECCP256: UInt8 = 0x11
    static let insSelect: UInt8 = 0xa4
    static let insVerify: UInt8 = 0x20
    static let insGeneralAuth: UInt8 = 0x87
    static let insGetMetadata: UInt8 = 0xf7

    private let card: TKSmartCard

    private init(card: TKSmartCard) { self.card = card }

    /// Есть ли подключённый YubiKey (по имени слота; без открытия сессии).
    public static func isYubiKeyPresent() -> Bool {
        yubiKeySlotName() != nil
    }

    private static func yubiKeySlotName() -> String? {
        TKSmartCardSlotManager.default?.slotNames.first { $0.localizedCaseInsensitiveContains("yubi") }
    }

    /// Находит YubiKey, открывает сессию и PIV, выполняет body, закрывает сессию.
    public static func withYubiKey<T>(_ body: (PIVCard) async throws -> T) async throws -> T {
        guard let manager = TKSmartCardSlotManager.default else { throw PIVError.noSmartCardAccess }
        guard let name = yubiKeySlotName(), let slot = await manager.getSlot(withName: name) else {
            throw PIVError.yubiKeyNotFound
        }
        guard slot.state == .validCard, let card = slot.makeSmartCard() else { throw PIVError.yubiKeyNotFound }
        card.useExtendedLength = false
        guard try await card.beginSession() else { throw PIVError.sessionFailed }
        defer { card.endSession() }

        let piv = PIVCard(card: card)
        try await piv.select()
        return try await body(piv)
    }

    func select() async throws {
        _ = try await send(ins: Self.insSelect, p1: 0x04, p2: 0x00, data: Self.aid)
    }

    public func verifyPIN(_ pin: String) async throws {
        guard (6...8).contains(pin.utf8.count), pin.utf8.allSatisfy({ $0 != 0xff }) else { throw PIVError.pinFormat }
        var padded = Data(repeating: 0xff, count: 8)
        padded.replaceSubrange(0..<pin.utf8.count, with: Array(pin.utf8))
        defer { padded.resetBytes(in: 0..<padded.count) }
        _ = try await send(ins: Self.insVerify, p1: 0x00, p2: 0x80, data: padded)
    }

    /// ECDH на карте: отдаём публичную точку (65 байт), получаем общий секрет (32 байта).
    public func ecdh(peerPoint: Data) async throws -> Data {
        let dynAuth = TLV.encode(0x7c, TLV.encode(0x82, Data()) + TLV.encode(0x85, peerPoint))
        let resp = try await send(ins: Self.insGeneralAuth, p1: Self.algECCP256, p2: Self.slot, data: dynAuth)
        guard let outer = TLV.parse(resp)[0x7c], let shared = TLV.parse(outer)[0x82], shared.count == 32 else {
            throw PIVError.unexpectedResponse("GENERAL AUTHENTICATE")
        }
        return shared
    }

    /// Публичный ключ слота 9d (сырая точка 65 байт). PIN не нужен. YubiKey >= 5.3.
    public func publicKeyPoint() async throws -> Data {
        let resp = try await send(ins: Self.insGetMetadata, p1: 0x00, p2: Self.slot, data: nil)
        let meta = TLV.parse(resp)
        guard meta[0x01]?.first == Self.algECCP256 else { throw PIVError.slotEmpty }
        guard let pub = meta[0x04], let point = TLV.parse(pub)[0x86], point.count == 65 else {
            throw PIVError.unexpectedResponse("GET METADATA")
        }
        return point
    }

    private func send(ins: UInt8, p1: UInt8, p2: UInt8, data: Data?) async throws -> Data {
        // TKSmartCard.send сам обрабатывает 61xx / GET RESPONSE. Без le CTK не запрашивает данные ответа,
        // поэтому для всех команд кроме VERIFY просим до 256 байт (le: 0).
        let le: Int? = ins == Self.insVerify ? nil : 0
        let (sw, response) = try await card.send(ins: ins, p1: p1, p2: p2, data: data, le: le)
        if ProcessInfo.processInfo.environment["YKENC_DEBUG"] != nil {
            let req = String(format: "00 %02x %02x %02x", ins, p1, p2) + " " + (data?.hex ?? "")
            FileHandle.standardError.write(Data("APDU > \(req)\nAPDU < \(response.hex) sw=\(String(format: "%04x", sw))\n".utf8))
        }
        if sw == 0x9000 { return response }
        throw Self.error(ins: ins, sw: sw)
    }

    private static func error(ins: UInt8, sw: UInt16) -> PIVError {
        if ins == insVerify {
            if sw & 0xfff0 == 0x63c0 { return .wrongPIN(retriesLeft: Int(sw & 0x0f)) }
            if sw == 0x6983 { return .pinBlocked }
        }
        if ins == insGeneralAuth {
            if sw == 0x6982 { return .securityStatus }
            if sw == 0x6a80 || sw == 0x6a86 { return .slotEmpty }
        }
        if ins == insGetMetadata, sw == 0x6a82 { return .slotEmpty }
        return .apdu(ins: ins, sw: sw)
    }
}

enum TLV {
    static func encode(_ tag: UInt8, _ value: Data) -> Data {
        precondition(value.count <= 255)
        var out = Data([tag])
        if value.count < 0x80 { out.append(UInt8(value.count)) } else { out.append(contentsOf: [0x81, UInt8(value.count)]) }
        out.append(value)
        return out
    }

    static func parse(_ buf: Data) -> [UInt8: Data] {
        var out: [UInt8: Data] = [:]
        var i = buf.startIndex
        while i < buf.endIndex {
            let tag = buf[i]; i += 1
            guard i < buf.endIndex else { break }
            var len = Int(buf[i]); i += 1
            if len == 0x81, i < buf.endIndex {
                len = Int(buf[i]); i += 1
            } else if len == 0x82, i + 1 < buf.endIndex {
                len = Int(buf[i]) << 8 | Int(buf[i + 1]); i += 2
            }
            let end = min(i + len, buf.endIndex)
            out[tag] = buf.subdata(in: i..<end)
            i = end
        }
        return out
    }
}
