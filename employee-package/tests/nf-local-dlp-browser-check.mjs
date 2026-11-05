import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const currentDir = path.dirname(fileURLToPath(import.meta.url));
const html = fs.readFileSync(path.join(currentDir, '..', 'nf-local-dlp-v2.html'), 'utf8');

test('is a self-contained offline artifact with a deny-by-default CSP', () => {
  assert.match(html, /Content-Security-Policy/u);
  assert.match(html, /default-src 'none'/u);
  assert.match(html, /connect-src 'none'/u);
  assert.doesNotMatch(html, /<script[^>]+\bsrc=/iu);
  assert.doesNotMatch(html, /<link[^>]+\bhref=/iu);
  assert.doesNotMatch(html, /\bfetch\s*\(|XMLHttpRequest|WebSocket|sendBeacon|EventSource/iu);
  assert.doesNotMatch(html, /localStorage|sessionStorage|indexedDB|document\.cookie|serviceWorker/iu);
});

test('does not render user content through HTML injection sinks', () => {
  assert.doesNotMatch(html, /\.innerHTML\s*=|insertAdjacentHTML|document\.write\s*\(/u);
  assert.doesNotMatch(html, /eval\s*\(|new\s+Function\s*\(/u);
});

test('contains the complete paste and TXT or MD file workflow', () => {
  assert.match(html, /id="sourceText"/u);
  assert.match(html, /id="fileInput"/u);
  assert.match(html, /accept="\.txt,\.md,text\/plain,text\/markdown"/u);
  assert.match(html, /id="dropZone"/u);
  assert.match(html, /id="runCheck"/u);
  assert.match(html, /id="clearAll"/u);
  assert.match(html, /id="copyResult"/u);
  assert.match(html, /id="downloadTxt"/u);
  assert.match(html, /id="downloadJson"/u);
  assert.match(html, /MAX_FILE_BYTES\s*=\s*5\s*\*\s*1024\s*\*\s*1024/u);
});

test('contains Russian decision states and the human-review warning', () => {
  assert.match(html, /Можно передавать/u);
  assert.match(html, /Нужна проверка/u);
  assert.match(html, /Передачу остановить/u);
  assert.match(html, /не заменяет правовую проверку/u);
  assert.match(html, /Данные не покидают эту вкладку/u);
});

test('contains a dated legal and technical self-assessment with current Russian sources', () => {
  assert.match(html, /Юридико-техническое заключение/u);
  assert.match(html, /№ NF-DLP-01\/2026/u);
  assert.match(html, /10 августа 2026 года/u);
  assert.match(html, /положительное с обязательными условиями/u);
  assert.match(html, /не является заключением государственного органа/u);
  assert.match(html, /152-ФЗ/u);
  assert.match(html, /98-ФЗ/u);
  assert.match(html, /149-ФЗ/u);
  assert.match(html, /243-ФЗ/u);
  assert.match(html, /265-ФЗ/u);
  assert.match(html, /Постановление Правительства РФ № 1119/u);
  assert.match(html, /Приказ ФСТЭК России № 21/u);
  assert.match(html, /Норма и требование/u);
  assert.match(html, /Механизм NF DLP/u);
  assert.match(html, /Остаточный риск/u);
});

test('documents the DLP algorithm, mandatory operating conditions, and print workflow', () => {
  assert.match(html, /id="legalAssessment"/u);
  assert.match(html, /Алгоритм обработки/u);
  assert.match(html, /Псевдонимизация не равна гарантированному обезличиванию/u);
  assert.match(html, /Исходник нельзя передавать внешней ИИ-модели/u);
  assert.match(html, /id="printLegalAssessment"/u);
  assert.match(html, /window\.print\(\)/u);
  assert.match(html, /@media print/u);
});

test('documents deterministic local Russian-name detection without a neural model', () => {
  assert.match(html, /имена спикеров/u);
  assert.match(html, /без нейросети/u);
  assert.match(html, /77\/77/u);
  assert.match(html, /повторная проверка очищенного текста/iu);
});

test('uses generic download names instead of repeating the uploaded file name', () => {
  assert.match(html, /nf-dlp-result\.txt/u);
  assert.match(html, /nf-dlp-report\.json/u);
  assert.doesNotMatch(html, /return base \|\| 'nf-dlp-result'/u);
});

test('all inline scripts compile as JavaScript', () => {
  const scripts = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gu)];
  assert.ok(scripts.length >= 2, 'Expected engine and UI scripts');
  for (const [index, match] of scripts.entries()) {
    assert.doesNotThrow(() => new vm.Script(match[1], { filename: `inline-${index + 1}.js` }));
  }
});
