export type Lang = "en" | "ru";

const dict = {
  en: {
    present: "YubiKey connected",
    absent: "YubiKey not found",
    keyLabel: "key 9d",
    keyMissing: "public key not read",
    keyBroken: "stored key is corrupted",
    keyHint: "Fingerprint of the public key used for encryption",
    refreshHint: "Read the public key from the connected YubiKey and use it for encryption",
    modeEncrypt: "Encrypt",
    modeDecrypt: "Decrypt",
    inputText: "Text",
    inputPayload: "Encrypted string",
    paste: "Paste",
    clear: "Clear",
    pin: "PIN",
    pinPlaceholder: "PIV application PIN",
    result: "Result",
    copy: "Copy",
    copied: "Copied",
    readingKey: "Reading public key…",
    verifyingPin: "Verifying PIN…",
    touch: "Touch your YubiKey…",
    needKeyForDecrypt: "Insert the YubiKey to decrypt",
    needPubKey: "Read the public key from the YubiKey first (↻ button)",
    mismatch: "The connected YubiKey holds a different key ({fp}). Encryption uses the stored key; press ↻ to switch.",
    weakPolicy:
      "Slot policy is weak (PIN: {pin}, touch: {touch}) — decryption will be refused. Regenerate with --pin-policy always --touch-policy always.",
    errors: {
      bad_format: "Invalid data format",
      decrypt_failed: "Decryption failed: different YubiKey or corrupted data",
      bad_key: "Invalid public key",
      no_service: "Smart card service is unavailable",
      yubikey_not_found: "YubiKey not found — plug it in",
      pcsc: "Smart card error",
      pin_format: "PIN must be 6–8 characters",
      wrong_pin: "Wrong PIN, tries left: {tries}",
      pin_blocked: "PIN is blocked. Unblock it with the PUK: ykman piv access unblock-pin",
      security_status: "The card refused: PIN not verified",
      slot_empty: "Slot 9d is empty or holds a non-P-256 key",
      weak_policy: "Refused: slot 9d allows decryption without PIN or touch. Regenerate the key with --pin-policy always --touch-policy always",
      unexpected: "Unexpected response from the YubiKey",
      apdu: "Card error",
      internal: "Internal error",
    } as Record<string, string>,
  },
  ru: {
    present: "YubiKey подключён",
    absent: "YubiKey не найден",
    keyLabel: "ключ 9d",
    keyMissing: "публичный ключ не считан",
    keyBroken: "сохранённый ключ повреждён",
    keyHint: "Отпечаток публичного ключа, которым шифруем",
    refreshHint: "Считать публичный ключ с подключённого YubiKey и использовать его для шифрования",
    modeEncrypt: "Зашифровать",
    modeDecrypt: "Расшифровать",
    inputText: "Текст",
    inputPayload: "Зашифрованная строка",
    paste: "Вставить",
    clear: "Очистить",
    pin: "PIN",
    pinPlaceholder: "PIN PIV-приложения",
    result: "Результат",
    copy: "Скопировать",
    copied: "Скопировано",
    readingKey: "Читаю публичный ключ…",
    verifyingPin: "Проверяю PIN…",
    touch: "Коснитесь YubiKey…",
    needKeyForDecrypt: "Для расшифровки вставьте YubiKey",
    needPubKey: "Сначала считайте публичный ключ с YubiKey (кнопка ↻)",
    mismatch: "В подключённом YubiKey другой ключ ({fp}). Шифрование идёт сохранённым ключом; нажмите ↻, чтобы перейти на новый.",
    weakPolicy:
      "Политика слота слабая (PIN: {pin}, касание: {touch}) — расшифровка будет отклонена. Перегенерируйте ключ с --pin-policy always --touch-policy always.",
    errors: {
      bad_format: "Неверный формат данных",
      decrypt_failed: "Не удалось расшифровать: другой YubiKey или данные повреждены",
      bad_key: "Неверный публичный ключ",
      no_service: "Служба смарт-карт недоступна",
      yubikey_not_found: "YubiKey не найден — вставьте ключ",
      pcsc: "Ошибка смарт-карты",
      pin_format: "PIN должен быть длиной 6–8 символов",
      wrong_pin: "Неверный PIN, осталось попыток: {tries}",
      pin_blocked: "PIN заблокирован. Разблокируйте через PUK: ykman piv access unblock-pin",
      security_status: "Карта отказала: PIN не проверен",
      slot_empty: "Слот 9d пуст или ключ не P-256",
      weak_policy: "Отказ: слот 9d позволяет расшифровку без PIN или без касания. Перегенерируйте ключ с --pin-policy always --touch-policy always",
      unexpected: "Неожиданный ответ YubiKey",
      apdu: "Ошибка карты",
      internal: "Внутренняя ошибка",
    } as Record<string, string>,
  },
};

export type Strings = (typeof dict)["en"];

export interface ApiError {
  code: string;
  message: string;
  detail?: string;
  tries?: number;
}

export function detectLang(): Lang {
  const saved = localStorage.getItem("lang");
  if (saved === "en" || saved === "ru") return saved;
  return navigator.language.toLowerCase().startsWith("ru") ? "ru" : "en";
}

export function strings(lang: Lang): Strings {
  return dict[lang];
}

/** Подстановка {name} → значение. */
export function fmt(template: string, vars: Record<string, string | number | undefined>): string {
  return template.replace(/\{(\w+)\}/g, (_, k: string) => String(vars[k] ?? "?"));
}

/** Локализует ошибку из Rust; неизвестные коды показывают английский текст из бэкенда. */
export function formatError(lang: Lang, e: unknown): string {
  const err = e as Partial<ApiError> | undefined;
  if (!err || typeof err !== "object" || !err.code) return String(e);
  const t = dict[lang].errors[err.code];
  if (!t) return err.message ?? err.code;
  let text = fmt(t, { tries: err.tries });
  // Детали показываем только для технических ошибок, где они помогают.
  if (err.detail && ["pcsc", "no_service", "apdu", "unexpected", "bad_key", "weak_policy"].includes(err.code)) {
    text += ` (${err.detail})`;
  }
  return text;
}
