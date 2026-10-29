import SwiftUI
import YkEncrypterCore

struct ContentView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            header
            Picker("", selection: $model.mode) {
                ForEach(AppModel.Mode.allCases) { Text($0.title).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()

            inputSection
            if model.mode == .decrypt { pinField }
            actionRow
            outputSection
        }
        .padding(20)
        .frame(minWidth: 560, minHeight: 520)
        .disabled(model.isBusy)
    }

    // MARK: - header

    private var header: some View {
        HStack(spacing: 10) {
            Circle()
                .fill(model.yubiKeyPresent ? Color.green : Color.secondary.opacity(0.4))
                .frame(width: 9, height: 9)
            Text(model.yubiKeyPresent ? "YubiKey подключён" : "YubiKey не найден")
                .foregroundStyle(model.yubiKeyPresent ? .primary : .secondary)
            Spacer()
            if let fp = model.recipientFingerprint {
                Label("ключ 9d · \(fp)", systemImage: "key.fill")
                    .font(.callout.monospaced())
                    .foregroundStyle(.secondary)
                    .help("Отпечаток публичного ключа, которым шифруем")
            } else {
                Label("публичный ключ не считан", systemImage: "key.slash")
                    .font(.callout)
                    .foregroundStyle(.orange)
            }
            Button {
                Task { await model.refreshPublicKey() }
            } label: {
                Image(systemName: "arrow.clockwise")
            }
            .help("Считать публичный ключ с YubiKey")
            .disabled(!model.yubiKeyPresent)
        }
    }

    // MARK: - input / pin

    private var inputSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(model.mode == .encrypt ? "Текст" : "Зашифрованная строка")
                    .font(.headline)
                Spacer()
                Button("Вставить") { model.pasteInput() }
                    .buttonStyle(.link)
                Button("Очистить") { model.clear() }
                    .buttonStyle(.link)
                    .disabled(model.input.isEmpty && model.output.isEmpty)
            }
            TextEditor(text: $model.input)
                .font(.body.monospaced())
                .scrollContentBackground(.hidden)
                .padding(6)
                .background(RoundedRectangle(cornerRadius: 8).fill(Color(nsColor: .textBackgroundColor)))
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.secondary.opacity(0.3)))
                .frame(minHeight: 120)
        }
    }

    private var pinField: some View {
        HStack {
            Text("PIN").font(.headline)
            SecureField("PIN PIV-приложения", text: $model.pin)
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 220)
                .onSubmit { if model.canRun { Task { await model.run() } } }
            Spacer()
        }
    }

    // MARK: - action

    private var actionRow: some View {
        HStack(spacing: 12) {
            Button {
                Task { await model.run() }
            } label: {
                Text(model.mode.title).frame(minWidth: 140)
            }
            .keyboardShortcut(.return, modifiers: .command)
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(!model.canRun)

            if case .working(let text) = model.phase {
                ProgressView().controlSize(.small)
                Text(text)
                    .foregroundStyle(text.contains("Коснитесь") ? Color.orange : Color.secondary)
                    .fontWeight(text.contains("Коснитесь") ? .semibold : .regular)
            } else if let error = model.error {
                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red)
                Text(error).foregroundStyle(.red).lineLimit(2)
            } else if model.mode == .decrypt, !model.yubiKeyPresent {
                Text("Для расшифровки вставьте YubiKey").foregroundStyle(.secondary)
            } else if model.mode == .encrypt, model.recipientPEM == nil {
                Text("Сначала считайте публичный ключ с YubiKey (кнопка ↻)").foregroundStyle(.secondary)
            }
            Spacer()
        }
    }

    // MARK: - output

    private var outputSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("Результат").font(.headline)
                Spacer()
                Button("Скопировать") { model.copyOutput() }
                    .buttonStyle(.link)
                    .disabled(model.output.isEmpty)
            }
            ScrollView {
                Text(model.output.isEmpty ? " " : model.output)
                    .font(.body.monospaced())
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(8)
            }
            .background(RoundedRectangle(cornerRadius: 8).fill(Color(nsColor: .textBackgroundColor)))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.secondary.opacity(0.3)))
            .frame(minHeight: 120)
        }
    }
}
