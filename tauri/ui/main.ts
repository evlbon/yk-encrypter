import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { readText, writeText } from "@tauri-apps/plugin-clipboard-manager";

type Mode = "encrypt" | "decrypt";

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const el = {
  dot: $("dot"),
  presence: $("presence"),
  keyinfo: $("keyinfo"),
  refresh: $<HTMLButtonElement>("refresh"),
  segs: Array.from(document.querySelectorAll<HTMLButtonElement>(".seg")),
  inputLabel: $("inputLabel"),
  input: $<HTMLTextAreaElement>("input"),
  paste: $<HTMLButtonElement>("paste"),
  clear: $<HTMLButtonElement>("clear"),
  pinRow: $("pinRow"),
  pin: $<HTMLInputElement>("pin"),
  run: $<HTMLButtonElement>("run"),
  message: $("message"),
  output: $<HTMLTextAreaElement>("output"),
  copy: $<HTMLButtonElement>("copy"),
};

const PEM_KEY = "recipientPublicKeyPEM";
let mode: Mode = "encrypt";
let busy = false;
let present = false;
let pem: string | null = localStorage.getItem(PEM_KEY);

function setMessage(text: string, kind: "" | "touch" | "error" = "") {
  el.message.textContent = text;
  el.message.className = "message" + (kind ? ` ${kind}` : "");
}

async function renderKey() {
  if (!pem) {
    el.keyinfo.textContent = "публичный ключ не считан";
    el.keyinfo.classList.add("missing");
    return;
  }
  const fp = await invoke<string | null>("key_fingerprint", { pem });
  el.keyinfo.textContent = fp ? `ключ 9d · ${fp}` : "ключ повреждён";
  el.keyinfo.classList.toggle("missing", !fp);
}

function render() {
  el.dot.classList.toggle("on", present);
  el.presence.textContent = present ? "YubiKey подключён" : "YubiKey не найден";
  el.refresh.disabled = !present || busy;

  el.segs.forEach((b) => b.classList.toggle("active", b.dataset.mode === mode));
  el.inputLabel.textContent = mode === "encrypt" ? "Текст" : "Зашифрованная строка";
  el.pinRow.classList.toggle("hidden", mode !== "decrypt");
  el.run.textContent = mode === "encrypt" ? "Зашифровать" : "Расшифровать";

  const hasInput = el.input.value.length > 0;
  const can = !busy && hasInput && (mode === "encrypt" ? pem !== null : el.pin.value.length > 0 && present);
  el.run.disabled = !can;
  el.copy.disabled = el.output.value.length === 0;
  el.clear.disabled = !hasInput && el.output.value.length === 0;
  el.input.disabled = busy;
  el.pin.disabled = busy;

  if (!busy && !el.message.classList.contains("error")) {
    if (mode === "decrypt" && !present) setMessage("Для расшифровки вставьте YubiKey");
    else if (mode === "encrypt" && !pem) setMessage("Сначала считайте публичный ключ с YubiKey (кнопка ↻)");
    else setMessage("");
  }
}

async function pollPresence() {
  try {
    const p = await invoke<boolean>("yubikey_present");
    if (p !== present) {
      present = p;
      render();
      if (present && !pem) void refreshKey();
    }
  } catch {
    /* служба смарт-карт недоступна — просто показываем "не найден" */
  }
}

async function refreshKey() {
  busy = true;
  setMessage("Читаю публичный ключ…");
  render();
  try {
    pem = await invoke<string>("read_public_key");
    localStorage.setItem(PEM_KEY, pem);
    setMessage("");
    await renderKey();
  } catch (e) {
    setMessage(String(e), "error");
  } finally {
    busy = false;
    render();
  }
}

async function run() {
  if (el.run.disabled) return;
  busy = true;
  el.output.value = "";
  setMessage(mode === "decrypt" ? "Проверяю PIN…" : "");
  render();
  try {
    if (mode === "encrypt") {
      el.output.value = await invoke<string>("encrypt", { text: el.input.value, pem });
    } else {
      el.output.value = await invoke<string>("decrypt", { payload: el.input.value.trim(), pin: el.pin.value });
    }
    setMessage("");
  } catch (e) {
    const msg = String(e);
    setMessage(msg, "error");
    if (msg.startsWith("Неверный PIN")) el.pin.value = "";
  } finally {
    busy = false;
    render();
  }
}

// --- события ---
el.segs.forEach((b) =>
  b.addEventListener("click", () => {
    mode = b.dataset.mode as Mode;
    el.output.value = "";
    setMessage("");
    render();
  }),
);
el.input.addEventListener("input", render);
el.pin.addEventListener("input", render);
el.pin.addEventListener("keydown", (e) => {
  if (e.key === "Enter") void run();
});
el.run.addEventListener("click", () => void run());
el.refresh.addEventListener("click", () => void refreshKey());
el.copy.addEventListener("click", () => void writeText(el.output.value));
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
  setMessage("");
  render();
});
document.addEventListener("keydown", (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === "Enter") void run();
});

void listen("yk-touch", () => setMessage("Коснитесь YubiKey…", "touch"));

void renderKey();
render();
void pollPresence();
setInterval(pollPresence, 1000);
