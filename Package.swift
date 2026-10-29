// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "YkEncrypter",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "YkEncrypter", targets: ["YkEncrypter"]),
        .executable(name: "ykenc", targets: ["ykenc"]),
    ],
    targets: [
        // Ядро: PIV поверх CryptoTokenKit + ECDH/HKDF/AES-GCM на CryptoKit.
        .target(name: "YkEncrypterCore"),
        // SwiftUI-приложение.
        .executableTarget(name: "YkEncrypter", dependencies: ["YkEncrypterCore"]),
        // CLI для тестов и скриптов (формат совместим с src/yk-encrypter/yk-encrypter.ts).
        .executableTarget(name: "ykenc", dependencies: ["YkEncrypterCore"]),
    ]
)
