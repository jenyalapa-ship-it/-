import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const currentDir = path.dirname(fileURLToPath(import.meta.url));
const htmlPath = path.join(currentDir, '..', 'nf-local-dlp-v2.html');

function loadEngine() {
  const html = fs.readFileSync(htmlPath, 'utf8');
  const match = html.match(/<script id="dlp-engine">([\s\S]*?)<\/script>/u);
  assert.ok(match, 'Inline DLP engine script must exist');
  const sandbox = {
    crypto: webcrypto,
    TextEncoder,
    TextDecoder,
    btoa: (value) => Buffer.from(value, 'binary').toString('base64'),
    atob: (value) => Buffer.from(value, 'base64').toString('binary'),
  };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(match[1], sandbox, { filename: 'nf-local-dlp-engine.js' });
  return sandbox.NFDLP;
}

test('reporting mode replaces identities but preserves financial literals exactly', () => {
  const engine = loadEngine();
  const source = [
    'Компания: ООО «Тестовый контур»',
    '[00:12] Иван Тестов: Выручка: 12\u202f450\u00a0000 ₽',
    'EBITDA: 18,4%',
    'Почта: ivan.testov@example.test',
  ].join('\n');
  const result = engine.scan(source, { mode: 'reporting', sessionTag: 'A1B2', sessionId: 'session-test' });

  assert.match(result.sanitizedText, /⟦DP2:A1B2:PERSON:/u);
  assert.match(result.sanitizedText, /⟦DP2:A1B2:EMAIL:/u);
  assert.ok(!result.sanitizedText.includes('Иван Тестов'));
  assert.ok(!result.sanitizedText.includes('ivan.testov@example.test'));
  assert.ok(result.sanitizedText.includes('12\u202f450\u00a0000 ₽'));
  assert.ok(result.sanitizedText.includes('18,4%'));
  assert.equal(result.financialIntegrity.detected, 2);
  assert.equal(result.financialIntegrity.preserved, 2);
  assert.equal(result.financialIntegrity.unchanged, true);
  assert.ok(!JSON.stringify(result).includes('Иван Тестов'));
  assert.ok(result._vault.entries.some((entry) => entry.original === 'Иван Тестов'));
});

test('encrypted vault contains no plaintext and round-trips with AES-GCM', async () => {
  const engine = loadEngine();
  const source = 'ФИО: Иван Тестов\nВыручка: 12 450 000 ₽';
  const result = engine.scan(source, { mode: 'reporting', sessionTag: 'C3D4', sessionId: 'session-encryption' });
  const password = 'correct horse battery staple';
  const envelope = await engine.encryptVault(result._vault, password, source);
  const serialized = JSON.stringify(envelope);

  assert.equal(envelope.schema, 'dp-vault/1');
  assert.equal(envelope.cipher.name, 'AES-256-GCM');
  assert.ok(!serialized.includes('Иван Тестов'));
  assert.ok(!serialized.includes('12 450 000'));

  const opened = await engine.decryptVault(serialized, password);
  assert.equal(opened.payload.sessionId, 'session-encryption');
  assert.ok(opened.payload.entries.some((entry) => entry.original === 'Иван Тестов'));
  await assert.rejects(() => engine.decryptVault(serialized, 'wrong password'), /неверный пароль|изменён/u);
});

test('restores known tokens and blocks corrupted or foreign tokens', () => {
  const engine = loadEngine();
  const source = 'ФИО: Иван Тестов\nПочта: ivan.testov@example.test\nВыручка: 5 000 000 ₽';
  const result = engine.scan(source, { mode: 'reporting', sessionTag: 'E5F6', sessionId: 'session-restore' });
  const response = `Анализ завершён. ${result.sanitizedText}`;
  const restored = engine.restoreText(response, result._vault);

  assert.equal(restored.status, 'OK');
  assert.ok(restored.restoredText.includes('Иван Тестов'));
  assert.ok(restored.restoredText.includes('ivan.testov@example.test'));
  assert.equal(restored.summary.financialPresent, restored.summary.financialExpected);

  const token = result._vault.entries[0].token;
  const corrupted = response.replace(token, token.replace(/:[A-F0-9]{2}⟧$/u, ':00⟧'));
  const blocked = engine.restoreText(corrupted, result._vault);
  assert.equal(blocked.status, 'BLOCK');
  assert.ok(blocked.summary.invalidChecksum > 0 || blocked.summary.unknown > 0);
});
