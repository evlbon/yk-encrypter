#!/bin/zsh
# Собирает dist/YkEncrypter.app (и CLI dist/ykenc). Нужны только Command Line Tools.
set -euo pipefail
cd "$(dirname "$0")"

swift build -c release 2>&1 | grep -v -E "^\[|^Compiling|^Build complete|^Emitting|^Write|^Linking|^Planning|^Fetching|^Creating" || true
BIN=$(swift build -c release --show-bin-path)
[ -x "$BIN/YkEncrypter" ] || { echo "build failed"; exit 1; }

APP=dist/YkEncrypter.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN/YkEncrypter" "$APP/Contents/MacOS/"
cp Resources/Info.plist "$APP/Contents/"
cp "$BIN/ykenc" dist/ykenc

if swift Resources/make-icon.swift "$APP/Contents/Resources/AppIcon.icns" 2>/dev/null; then
  :
else
  echo "warning: icon generation failed, app will have the default icon"
fi

# Ad-hoc подпись с entitlement com.apple.security.smartcard — без него CryptoTokenKit не видит карты.
codesign --force --sign - --entitlements Resources/YkEncrypter.entitlements "$APP" >/dev/null
codesign --force --sign - --entitlements Resources/YkEncrypter.entitlements dist/ykenc >/dev/null
echo "built: $PWD/$APP"
echo "cli:   $PWD/dist/ykenc"

# Упаковка для передачи: zip (сохраняет подпись и права) и dmg.
rm -f dist/YkEncrypter.zip dist/YkEncrypter.dmg
ditto -c -k --keepParent "$APP" dist/YkEncrypter.zip
hdiutil create -quiet -volname "YubiKey Encrypter" -srcfolder "$APP" -ov -format UDZO dist/YkEncrypter.dmg
echo "zip:   $PWD/dist/YkEncrypter.zip"
echo "dmg:   $PWD/dist/YkEncrypter.dmg"
