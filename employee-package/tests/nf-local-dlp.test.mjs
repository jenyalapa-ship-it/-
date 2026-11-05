import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const currentDir = path.dirname(fileURLToPath(import.meta.url));
const htmlPath = path.join(currentDir, '..', 'nf-local-dlp-v2.html');

function loadEngine() {
  const html = fs.readFileSync(htmlPath, 'utf8');
  const match = html.match(/<script id="dlp-engine">([\s\S]*?)<\/script>/u);
  assert.ok(match, 'Inline DLP engine script must exist');

  const sandbox = {};
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(match[1], sandbox, { filename: 'nf-local-dlp-engine.js' });
  assert.ok(sandbox.NFDLP, 'Engine must expose globalThis.NFDLP');
  return sandbox.NFDLP;
}

function categories(result) {
  return new Set(result.findings.map((finding) => finding.category));
}

test('allows a generalized business note without changing it', () => {
  const engine = loadEngine();
  const text = 'Команда обсудила отклонение от плана и согласовала три действия на следующий месяц.';
  const result = engine.scan(text, { mode: 'balanced' });

  assert.equal(result.decision, 'ALLOW');
  assert.equal(result.sourceRisk, 'LOW');
  assert.equal(result.sanitizedText, text);
  assert.equal(result.metrics.findings, 0);
});

test('masks direct contacts and exact financial amounts while preserving analytical scale', () => {
  const engine = loadEngine();
  const text = [
    'ФИО: Иван Тестов',
    'Почта: ivan.testov@example.test',
    'Повторная почта: ivan.testov@example.test',
    'Телефон: +7 900 000-00-00',
    'Выручка: 12 450 000 ₽',
    'EBITDA: 18,4%',
  ].join('\n');

  const result = engine.scan(text, { mode: 'balanced' });

  assert.equal(result.decision, 'REVIEW');
  assert.equal(result.sourceRisk, 'HIGH');
  assert.match(result.sanitizedText, /\[ФИО_01\]/u);
  assert.match(result.sanitizedText, /\[EMAIL_01\]/u);
  assert.match(result.sanitizedText, /^Почта: \[EMAIL_01\]$/mu);
  assert.equal((result.sanitizedText.match(/\[EMAIL_01\]/gu) || []).length, 2);
  assert.match(result.sanitizedText, /\[ФИНПОКАЗАТЕЛЬ_01: ~ 10–50 млн ₽\]/u);
  assert.match(result.sanitizedText, /18,4%/u);
  assert.ok(!result.sanitizedText.includes('Иван Тестов'));
  assert.ok(!result.sanitizedText.includes('ivan.testov@example.test'));
  assert.ok(!result.sanitizedText.includes('12 450 000'));

  const emailLog = result.replacements.find((item) => item.category === 'email');
  assert.equal(emailLog.count, 2);
  assert.ok(!JSON.stringify(result).includes('ivan.testov@example.test'));
});

test('blocks credentials, payment data, and individualized health data', () => {
  const engine = loadEngine();
  const text = [
    'API key: sk-test-abcdefghijklmnopqrstuvwxyz123456',
    'Карта: 4111 1111 1111 1111',
    'Состояние здоровья сотрудника: HRV 42 мс, диагноз: тестовый.',
  ].join('\n');

  const result = engine.scan(text, { mode: 'balanced' });
  const detected = categories(result);

  assert.equal(result.decision, 'BLOCK');
  assert.equal(result.sourceRisk, 'CRITICAL');
  assert.ok(detected.has('credential'));
  assert.ok(detected.has('payment_card'));
  assert.ok(detected.has('health_biometric'));
  assert.ok(!result.sanitizedText.includes('sk-test-abcdefghijklmnopqrstuvwxyz123456'));
  assert.ok(!result.sanitizedText.includes('4111 1111 1111 1111'));
  assert.ok(!result.sanitizedText.includes('HRV 42'));
});

test('validates INN and SNILS control digits before masking', () => {
  const engine = loadEngine();
  const valid = engine.scan('ИНН: 7712345671; СНИЛС: 112-233-445 95', { mode: 'balanced' });
  const invalid = engine.scan('ИНН: 7712345670; СНИЛС: 112-233-445 94', { mode: 'balanced' });

  assert.equal(valid.decision, 'BLOCK');
  assert.ok(categories(valid).has('inn'));
  assert.ok(categories(valid).has('snils'));
  assert.ok(!valid.sanitizedText.includes('7712345671'));
  assert.ok(!valid.sanitizedText.includes('112-233-445 95'));
  assert.equal(invalid.decision, 'ALLOW');
  assert.equal(invalid.sanitizedText, 'ИНН: 7712345670; СНИЛС: 112-233-445 94');
});

test('detects labelled bank details without treating them as payment cards', () => {
  const engine = loadEngine();
  const text = 'БИК: 044525225\nР/с: 40702810900000000001\nК/с: 30101810400000000225';
  const result = engine.scan(text, { mode: 'balanced' });
  const detected = categories(result);

  assert.equal(result.decision, 'REVIEW');
  assert.ok(detected.has('bik'));
  assert.ok(detected.has('bank_account'));
  assert.ok(detected.has('correspondent_account'));
  assert.ok(!detected.has('payment_card'));
  assert.ok(!result.sanitizedText.includes('044525225'));
  assert.ok(!result.sanitizedText.includes('40702810900000000001'));
});

test('keeps generic WHOOP program context but blocks personal health context', () => {
  const engine = loadEngine();
  const generic = engine.scan('Планируем внедрение WHOOP для бизнеса и обучение команды.', { mode: 'balanced' });
  const personal = engine.scan('WHOOP сотрудника: восстановление 37%, HRV 41 мс.', { mode: 'balanced' });

  assert.equal(generic.decision, 'ALLOW');
  assert.equal(generic.sanitizedText, 'Планируем внедрение WHOOP для бизнеса и обучение команды.');
  assert.equal(personal.decision, 'BLOCK');
  assert.ok(categories(personal).has('health_biometric'));
});

test('masks a person name after a capitalized Russian role label', () => {
  const engine = loadEngine();
  const result = engine.scan('Сотрудник: Мария Примерова', { mode: 'balanced' });

  assert.equal(result.decision, 'REVIEW');
  assert.ok(categories(result).has('person_name'));
  assert.equal(result.sanitizedText, 'Сотрудник: [ФИО_01]');
  assert.ok(!JSON.stringify(result).includes('Мария Примерова'));
});

test('strict mode additionally masks dates, percentages, and formal organization names', () => {
  const engine = loadEngine();
  const text = 'ООО «Тестовый контур» согласовало план 10.08.2026. Рост составил 18,4%.';
  const balanced = engine.scan(text, { mode: 'balanced' });
  const strict = engine.scan(text, { mode: 'strict' });

  assert.match(balanced.sanitizedText, /10\.08\.2026/u);
  assert.match(balanced.sanitizedText, /18,4%/u);
  assert.equal(strict.decision, 'REVIEW');
  assert.match(strict.sanitizedText, /\[ОРГАНИЗАЦИЯ_01\]/u);
  assert.match(strict.sanitizedText, /\[ДАТА_01\]/u);
  assert.match(strict.sanitizedText, /\[ПРОЦЕНТ_01\]/u);
});

test('masks exact financial values in Markdown tables without erasing balanced percentages', () => {
  const engine = loadEngine();
  const text = [
    '| Метрика | Факт |',
    '| --- | ---: |',
    '| Выручка | 12 450 000 |',
    '| EBITDA | 18,4% |',
  ].join('\n');
  const result = engine.scan(text, { mode: 'balanced' });

  assert.equal(result.decision, 'REVIEW');
  assert.match(result.sanitizedText, /\| Выручка \| \[ФИНПОКАЗАТЕЛЬ_01: ~ 10–50 млн ден\. ед\.\] \|/u);
  assert.match(result.sanitizedText, /\| EBITDA \| 18,4% \|/u);
  assert.ok(!result.sanitizedText.includes('12 450 000'));
});

test('safe JSON report excludes source text, raw values, and pseudonym mappings', () => {
  const engine = loadEngine();
  const secret = 'finance.owner@example.test';
  const result = engine.scan(`Email: ${secret}`, { mode: 'balanced' });
  const report = engine.buildSafeReport(result, { sourceName: 'source.md' });
  const json = JSON.stringify(report);

  assert.equal(report.schemaVersion, '1.0');
  assert.equal(report.source.name, 'Загруженный MD');
  assert.equal(report.decision, 'REVIEW');
  assert.ok(!json.includes(secret));
  assert.ok(!json.includes('originalText'));
  assert.ok(!json.includes('mapping'));
  assert.match(report.sanitizedText, /\[EMAIL_01\]/u);
});

test('fails closed on oversized pasted input', () => {
  const engine = loadEngine();
  assert.throws(
    () => engine.scan('а'.repeat(engine.MAX_TEXT_CHARS + 1), { mode: 'balanced' }),
    /слишком большой/u,
  );
});

test('masks repeated Russian speaker names while preserving timestamps and Markdown', () => {
  const engine = loadEngine();
  const text = [
    '[00:12] Иван Петров: Добрый день.',
    '**Иван Петров:** Выручка выросла.',
  ].join('\n');
  const result = engine.scan(text, { mode: 'balanced' });

  assert.equal(result.decision, 'REVIEW');
  assert.ok(categories(result).has('person_name'));
  assert.equal(result.sanitizedText, '[00:12] [ФИО_01]: Добрый день.\n**[ФИО_01]:** Выручка выросла.');
  assert.equal((result.sanitizedText.match(/\[ФИО_01\]/gu) || []).length, 2);
  assert.ok(!JSON.stringify(result).includes('Иван Петров'));
});

test('masks names after numbered speaker roles and diarization identifiers', () => {
  const engine = loadEngine();
  const text = [
    'Спикер 1 — Алексей Иванов',
    'Участник 2: Анна Смирнова',
    '[SPEAKER_00] Пётр Соколов: Начинаем.',
  ].join('\n');
  const result = engine.scan(text, { mode: 'balanced' });

  assert.equal(result.decision, 'REVIEW');
  assert.equal(result.sanitizedText, [
    'Спикер 1 — [ФИО_01]',
    'Участник 2: [ФИО_02]',
    '[SPEAKER_00] [ФИО_03]: Начинаем.',
  ].join('\n'));
  for (const name of ['Алексей Иванов', 'Анна Смирнова', 'Пётр Соколов']) {
    assert.ok(!JSON.stringify(result).includes(name));
  }
});

test('masks known Russian first names and common short forms as speaker labels', () => {
  const engine = loadEngine();
  const text = 'Иван: Первый вопрос.\nВаня: Второй вопрос.\nСвета — Согласна.';
  const result = engine.scan(text, { mode: 'balanced' });

  assert.equal(result.decision, 'REVIEW');
  assert.equal(result.sanitizedText, '[ФИО_01]: Первый вопрос.\n[ФИО_02]: Второй вопрос.\n[ФИО_03] — Согласна.');
});

test('masks uppercase names and an initial with a Russian surname in speaker position', () => {
  const engine = loadEngine();
  const text = 'ИВАН ПЕТРОВ: Доклад готов.\nИ. Соколов: Дополню.';
  const result = engine.scan(text, { mode: 'balanced' });

  assert.equal(result.decision, 'REVIEW');
  assert.equal(result.sanitizedText, '[ФИО_01]: Доклад готов.\n[ФИО_02]: Дополню.');
});

test('does not mask ordinary business headings as transcript speakers', () => {
  const engine = loadEngine();
  const text = [
    'Итог: согласовать бюджет.',
    'Решение: обновить прогноз.',
    'Денежный поток: положительный.',
    'Контрольная точка: 15 августа.',
    'EBITDA: 18,4%.',
  ].join('\n');
  const result = engine.scan(text, { mode: 'balanced' });

  assert.equal(result.decision, 'ALLOW');
  assert.equal(result.sanitizedText, text);
});

test('uses distinct stable pseudonyms for different transcript speakers', () => {
  const engine = loadEngine();
  const text = 'Мария Соколова: Начинаем.\nИван Петров: Согласен.\nМария Соколова: Завершаем.';
  const result = engine.scan(text, { mode: 'balanced' });

  assert.equal(result.sanitizedText, '[ФИО_01]: Начинаем.\n[ФИО_02]: Согласен.\n[ФИО_01]: Завершаем.');
  assert.equal(result.replacements.find((row) => row.pseudonym === '[ФИО_01]').count, 2);
});

test('masks Russian first-name and surname pairs inside ordinary transcript sentences', () => {
  const engine = loadEngine();
  const text = 'На встрече Иван Петров подтвердил решение. Анна Смирнова подготовила прогноз.';
  const result = engine.scan(text, { mode: 'balanced' });

  assert.equal(result.decision, 'REVIEW');
  assert.equal(result.sanitizedText, 'На встрече [ФИО_01] подтвердил решение. [ФИО_02] подготовила прогноз.');
  assert.ok(!JSON.stringify(result).includes('Иван Петров'));
  assert.ok(!JSON.stringify(result).includes('Анна Смирнова'));
});

test('masks a known Russian first name with an atypical surname inside a sentence', () => {
  const engine = loadEngine();
  const text = 'Иван Блок представил финансовый прогноз.';
  const result = engine.scan(text, { mode: 'balanced' });

  assert.equal(result.decision, 'REVIEW');
  assert.equal(result.sanitizedText, '[ФИО_01] представил финансовый прогноз.');
});

test('masks common inflected Russian first-name and surname pairs', () => {
  const engine = loadEngine();
  const text = 'Документ согласован Иваном Петровым и передан Анне Смирновой.';
  const result = engine.scan(text, { mode: 'balanced' });

  assert.equal(result.decision, 'REVIEW');
  assert.equal(result.sanitizedText, 'Документ согласован [ФИО_01] и передан [ФИО_02].');
});

test('reuses a speaker pseudonym for exact first-name and surname mentions in dialogue text', () => {
  const engine = loadEngine();
  const text = 'Иван Петров: Начинаем.\nПозже Иван подтвердил расчёт, а Петров добавил комментарий.';
  const result = engine.scan(text, { mode: 'balanced' });

  assert.equal(result.sanitizedText, '[ФИО_01]: Начинаем.\nПозже [ФИО_01] подтвердил расчёт, а [ФИО_01] добавил комментарий.');
  assert.equal(result.replacements.find((row) => row.pseudonym === '[ФИО_01]').count, 3);
});

test('uses one pseudonym for the same labelled person and transcript speaker', () => {
  const engine = loadEngine();
  const text = 'ФИО: Иван Блок\nИван Блок: Подтверждаю.';
  const result = engine.scan(text, { mode: 'balanced' });

  assert.equal(result.sanitizedText, 'ФИО: [ФИО_01]\n[ФИО_01]: Подтверждаю.');
  assert.equal(result.replacements.length, 1);
  assert.equal(result.replacements[0].count, 2);
});

test('does not treat capitalized business phrases as Russian people', () => {
  const engine = loadEngine();
  const text = 'Денежный Поток улучшился. Северная Звезда — название проекта. Новая Москва растёт.';
  const result = engine.scan(text, { mode: 'balanced' });

  assert.equal(result.decision, 'ALLOW');
  assert.equal(result.sanitizedText, text);
});

test('does not treat business diagnosis metaphors as personal health data', () => {
  const engine = loadEngine();
  const text = [
    'Состояние нашего бизнеса пока в диагнозе.',
    'Диагноз может меняться, и компания перейдёт в состояние сбалансированного роста.',
  ].join('\n');
  const result = engine.scan(text, { mode: 'balanced' });

  assert.equal(result.decision, 'ALLOW');
  assert.equal(result.sanitizedText, text);
  assert.ok(!categories(result).has('health_biometric'));
});

test('masks percentages written with Russian words only in strict mode', () => {
  const engine = loadEngine();
  const text = 'Конверсия — восемьдесят восемь процентов, выполнение плана — пятьдесят семь процентов, депозит — до одиннадцати процентов.';
  const balanced = engine.scan(text, { mode: 'balanced' });
  const strict = engine.scan(text, { mode: 'strict' });

  assert.equal(balanced.sanitizedText, text);
  assert.ok(categories(strict).has('percentage'));
  assert.equal((strict.sanitizedText.match(/\[ПРОЦЕНТ_\d+\]/gu) || []).length, 3);
  assert.ok(!strict.sanitizedText.includes('восемьдесят восемь процентов'));
  assert.ok(!strict.sanitizedText.includes('пятьдесят семь процентов'));
  assert.ok(!strict.sanitizedText.includes('одиннадцати процентов'));
});

test('masks a numeric percentage followed by the Russian word in strict mode', () => {
  const engine = loadEngine();
  const text = 'Готовность — 88 процентов, материалы — 13,92 на материалы процентов.';
  const balanced = engine.scan(text, { mode: 'balanced' });
  const strict = engine.scan(text, { mode: 'strict' });

  assert.equal(balanced.sanitizedText, text);
  assert.equal((strict.sanitizedText.match(/\[ПРОЦЕНТ_\d+\]/gu) || []).length, 2);
  assert.ok(!strict.sanitizedText.includes('88 процентов'));
  assert.ok(!strict.sanitizedText.includes('13,92 на материалы процентов'));
});

test('masks single Russian names in strong transcript contexts and links a short form', () => {
  const engine = loadEngine();
  const text = [
    '[00:00:11] Жаргал.',
    '[00:13:15] Там был момент, когда Юля выравнивала материалы.',
    '[00:20:47] Сейчас подождите, пожалуйста, Елена.',
    '[00:20:55] Так, Юлия Николаевна.',
    '[00:21:00] Мария.',
    '[00:51:58] Так, Ирина, подскажите.',
  ].join('\n');
  const result = engine.scan(text, { mode: 'balanced' });

  for (const name of ['Жаргал', 'Юля', 'Елена', 'Юлия Николаевна', 'Мария', 'Ирина']) {
    assert.ok(!result.sanitizedText.includes(name));
  }
  assert.match(result.sanitizedText, /когда \[ФИО_02\] выравнивала/u);
  assert.match(result.sanitizedText, /Так, \[ФИО_02\]\./u);
  assert.equal(result.metrics.residualWarnings, 0);
});

test('masks explicitly identified client names in strict mode', () => {
  const engine = loadEngine();
  const text = [
    'По компании РомашкаСтоматология.',
    'Стоматология SmileDemo (голос 1):',
    'Стоматология SmileDemo (голос 1):',
  ].join('\n');
  const result = engine.scan(text, { mode: 'strict' });

  assert.ok(categories(result).has('organization'));
  assert.ok(!result.sanitizedText.includes('РомашкаСтоматология'));
  assert.ok(!result.sanitizedText.includes('SmileDemo'));
  assert.equal((result.sanitizedText.match(/\[ОРГАНИЗАЦИЯ_02\]/gu) || []).length, 2);
});

test('masks financial amounts with magnitude words and spoken ranges', () => {
  const engine = loadEngine();
  const text = [
    'Цель — увеличить выручку до 6 миллионов рублей.',
    'Бюджет — от 80 до 100 тысяч рублей.',
  ].join('\n');
  const result = engine.scan(text, { mode: 'balanced' });

  assert.ok(categories(result).has('financial_amount'));
  assert.ok(!result.sanitizedText.includes('6 миллионов рублей'));
  assert.ok(!result.sanitizedText.includes('80 до 100 тысяч рублей'));
  assert.equal((result.sanitizedText.match(/\[ФИНПОКАЗАТЕЛЬ_\d+:/gu) || []).length, 2);
});

test('safe JSON report does not repeat a sensitive uploaded file name', () => {
  const engine = loadEngine();
  const result = engine.scan('Обобщённый вывод.', { mode: 'balanced' });
  const report = engine.buildSafeReport(result, {
    sourceName: 'Петрова_ООО_Ромашка_2026_01_01_1200_MSK_1234567890.txt',
  });
  const json = JSON.stringify(report);

  assert.equal(report.source.name, 'Загруженный TXT');
  assert.ok(!json.includes('Петрова'));
  assert.ok(!json.includes('1234567890'));
});
