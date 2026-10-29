import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { readText, writeText } from "@tauri-apps/plugin-clipboard-manager";
import { detectLang, fmt, formatError, strings, type Lang } from "./i18n.js";

type Mode = "encrypt" | "decrypt";

interface KeyInfo {
  pem: string;
  fingerprint: string | null;
  pin_policy: string;
  touch_policy: string;
  weak: boolean;
}

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const el = {
  dot: $("dot"),
  presence: $("presence"),
  keyinfo: $("keyinfo"),
  refresh: $<HTMLButtonElement>("refresh"),
  lang: $<HTMLButtonElement>("lang"),
  segs: Array.from(document.querySelectorAll<HTMLButtonElement>(".seg")),
  inputLabel: $("inputLabel"),
  input: $<HTMLTextAreaElement>("input"),
  paste: $<HTMLButtonElement>("paste"),
  clear: $<HTMLButtonElement>("clear"),
  pinRow: $("pinRow"),
  pinLabel: $("pinLabel"),
  pin: $<HTMLInputElement>("pin"),
  run: $<HTMLButtonElement>("run"),
  message: $("message"),
  outputLabel: $("outputLabel"),
  output: $<HTMLTextAreaElement>("output"),
  copy: $<HTMLButtonElement>("copy"),
};

const PEM_KEY = "recipientPublicKeyPEM";
let lang: Lang = detectLang();
let t = strings(lang);
let mode: Mode = "encrypt";
let busy = false;
let present = false;
/** Ключ, которым шифруем (сохранён на этом компьютере). Меняется только кнопкой ↻. */
let pem: string | null = localStorage.getItem(PEM_KEY);
let fingerprint: string | null = null;
/** Что реально лежит в подключённом YubiKey (читается при подключении). */
let cardKey: KeyInfo | null = null;
let lastError: unknown = null;
let status: "" | "readingKey" | "verifyingPin" | "touch" | "copied" = "";

const mismatch = () => cardKey !== null && pem !== null && cardKey.pem !== pem;

function clearPin() {
  el.pin.value = "";
}

function render() {
  document.documentElement.lang = lang;
  el.lang.textContent = lang === "en" ? "RU" : "EN";
  el.lang.title = lang === "en" ? "Переключить на русский" : "Switch to English";

  el.dot.classList.toggle("on", present);
  el.presence.textContent = present ? t.present : t.absent;
  el.refresh.disabled = !present || busy;
  el.refresh.title = t.refreshHint;
  el.keyinfo.title = t.keyHint;
  el.keyinfo.classList.remove("missing", "mismatch");
  if (!pem) {
    el.keyinfo.textContent = t.keyMissing;
    el.keyinfo.classList.add("missing");
  } else if (!fingerprint) {
    el.keyinfo.textContent = t.keyBroken;
    el.keyinfo.classList.add("missing");
  } else {
    el.keyinfo.textContent = `${t.keyLabel} · ${fingerprint}`;
    if (mismatch()) el.keyinfo.classList.add("mismatch");
  }

  el.segs.forEach((b) => {
    b.classList.toggle("active", b.dataset.mode === mode);
    b.textContent = b.dataset.mode === "encrypt" ? t.modeEncrypt : t.modeDecrypt;
  });
  el.inputLabel.textContent = mode === "encrypt" ? t.inputText : t.inputPayload;
  el.paste.textContent = t.paste;
  el.clear.textContent = t.clear;
  el.pinRow.classList.toggle("hidden", mode !== "decrypt");
  el.pinLabel.textContent = t.pin;
  el.pin.placeholder = t.pinPlaceholder;
  el.run.textContent = mode === "encrypt" ? t.modeEncrypt : t.modeDecrypt;
  el.outputLabel.textContent = t.result;
  el.copy.textContent = t.copy;

  const hasInput = el.input.value.length > 0;
  const can = !busy && hasInput && (mode === "encrypt" ? pem !== null : el.pin.value.length > 0 && present);
  el.run.disabled = !can;
  el.copy.disabled = el.output.value.length === 0;
  el.clear.disabled = !hasInput && el.output.value.length === 0 && el.pin.value.length === 0;
  el.input.disabled = busy;
  el.pin.disabled = busy;

  // Строка статуса: ошибка > ход операции > предупреждения > подсказка.
  let text = "";
  let kind = "";
  if (lastError) {
    text = formatError(lang, lastError);
    kind = "error";
  } else if (status === "touch") {
    text = t.touch;
    kind = "touch";
  } else if (status === "readingKey") text = t.readingKey;
  else if (status === "verifyingPin") text = t.verifyingPin;
  else if (status === "copied") text = t.copied;
  else if (mismatch()) {
    text = fmt(t.mismatch, { fp: cardKey?.fingerprint ?? "?" });
    kind = "warn";
  } else if (cardKey?.weak) {
    text = fmt(t.weakPolicy, { pin: cardKey.pin_policy, touch: cardKey.touch_policy });
    kind = "warn";
  } else if (mode === "decrypt" && !present) text = t.needKeyForDecrypt;
  else if (mode === "encrypt" && !pem) text = t.needPubKey;
  el.message.textContent = text;
  el.message.className = "message" + (kind ? ` ${kind}` : "");
}

async function updateFingerprint() {
  fingerprint = pem ? await invoke<string | null>("key_fingerprint", { pem }) : null;
  render();
}

/** Читает слот подключённого YubiKey, не трогая сохранённый ключ. */
async function inspectCard() {
  try {
    cardKey = await invoke<KeyInfo>("read_key");
  } catch {
    cardKey = null; // слот пуст / не P-256 — сообщит кнопка ↻, если её нажать
  }
  render();
}

async function pollPresence() {
  try {
    const p = await invoke<boolean>("yubikey_present");
    if (p !== present) {
      present = p;
      cardKey = null;
      render();
      if (present) {
        await inspectCard();
        if (!pem && cardKey) await adoptCardKey();
      }
    }
  } catch {
    /* служба смарт-карт недоступна — показываем "не найден" */
  }
}

/** Явная замена сохранённого ключа на ключ из подключённого YubiKey. */
async function adoptCardKey() {
  busy = true;
  lastError = null;
  status = "readingKey";
  render();
  try {
    cardKey = await invoke<KeyInfo>("read_key");
    pem = cardKey.pem;
    localStorage.setItem(PEM_KEY, pem);
    await updateFingerprint();
  } catch (e) {
    lastError = e;
  } finally {
    busy = false;
    status = "";
    render();
  }
}

async function run() {
  if (el.run.disabled) return;
  busy = true;
  lastError = null;
  el.output.value = "";
  status = mode === "decrypt" ? "verifyingPin" : "";
  render();
  try {
    if (mode === "encrypt") {
      el.output.value = await invoke<string>("encrypt", { text: el.input.value, pem });
    } else {
      el.output.value = await invoke<string>("decrypt", { payload: el.input.value.trim(), pin: el.pin.value });
    }
  } catch (e) {
    lastError = e;
  } finally {
    // PIN живёт только на время одной операции.
    clearPin();
    busy = false;
    status = "";
    render();
  }
}

// --- события ---
el.lang.addEventListener("click", () => {
  lang = lang === "en" ? "ru" : "en";
  localStorage.setItem("lang", lang);
  t = strings(lang);
  render();
});
el.segs.forEach((b) =>
  b.addEventListener("click", () => {
    mode = b.dataset.mode as Mode;
    el.output.value = "";
    clearPin();
    lastError = null;
    render();
  }),
);
el.input.addEventListener("input", render);
el.pin.addEventListener("input", render);
el.pin.addEventListener("keydown", (e) => {
  if (e.key === "Enter") void run();
});
el.run.addEventListener("click", () => void run());
el.refresh.addEventListener("click", () => void adoptCardKey());
el.copy.addEventListener("click", async () => {
  await writeText(el.output.value);
  status = "copied";
  render();
  setTimeout(() => {
    if (status === "copied") {
      status = "";
      render();
    }
  }, 1500);
});
el.paste.addEventListener("click", async () => {
  try {
    el.input.value = await readText();
    render();
  } catch {
    /* буфер пуст */
  }
});
el.clear.addEventListener("click", () => {
  el.input.value = "";
  el.output.value = "";
  clearPin();
  lastError = null;
  render();
});
document.addEventListener("keydown", (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === "Enter") void run();
});
window.addEventListener("blur", clearPin);

void listen("yk-touch", () => {
  status = "touch";
  render();
});

render();
void updateFingerprint();
void pollPresence();
setInterval(pollPresence, 1000);
