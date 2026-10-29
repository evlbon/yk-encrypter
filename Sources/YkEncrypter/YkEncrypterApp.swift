import SwiftUI

@main
struct YkEncrypterApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup("YubiKey Encrypter") {
            ContentView()
                .environmentObject(model)
        }
        .windowResizability(.contentMinSize)
        .commands {
            CommandGroup(replacing: .newItem) {}
        }
    }
}
