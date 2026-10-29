#!/usr/bin/env node
// Бамп версии во всех трёх местах сразу: src-tauri/tauri.conf.json, src-tauri/Cargo.toml, package.json.
// Использование: npm run bump 1.0.1   (затем commit + push в main → CI соберёт и выпустит v1.0.1)
import { readFileSync, writeFileSync } from "node:fs";
import { execSync } from "node:child_process";

const version = process.argv[2];
if (!/^\d+\.\d+\.\d+$/.test(version ?? "")) {
  console.error("usage: npm run bump <major.minor.patch>");
  process.exit(2);
}

const edit = (file, fn) => {
  const before = readFileSync(file, "utf8");
  const after = fn(before);
  if (after === before) throw new Error(`${file}: version field not found`);
  writeFileSync(file, after);
  console.log(`${file} → ${version}`);
};

edit("src-tauri/tauri.conf.json", (s) => s.replace(/("version":\s*")[^"]+(")/, `$1${version}$2`));
edit("package.json", (s) => s.replace(/("version":\s*")[^"]+(")/, `$1${version}$2`));
edit("src-tauri/Cargo.toml", (s) => s.replace(/^(version\s*=\s*")[^"]+(")/m, `$1${version}$2`));

// Обновить Cargo.lock и package-lock.json без установки.
execSync("cargo update --manifest-path src-tauri/Cargo.toml --workspace --offline", { stdio: "inherit" });
execSync("npm install --package-lock-only --ignore-scripts", { stdio: "inherit" });
console.log(`\nnow: git commit -am "v${version}" && git push`);
