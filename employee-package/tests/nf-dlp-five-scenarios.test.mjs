import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const currentDir = path.dirname(fileURLToPath(import.meta.url));
const html = fs.readFileSync(path.join(currentDir, '..', 'nf-local-dlp-v2.html'), 'utf8');
const engineScript = html.match(/<script id="dlp-engine">([\s\S]*?)<\/script>/u)?.[1];
assert.ok(engineScript, 'Inline DLP engine script must exist');
const sandbox = {};
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(engineScript, sandbox, { filename: 'nf-local-dlp-engine.js' });
const engine = sandbox.NFDLP;

const scenarios = [
  {
    name: 'contacts and financial results produce REVIEW',
    mode: 'balanced',
    decision: 'REVIEW',
    categories: ['person_name', 'email', 'phone', 'organization', 'financial_amount'],
    sensitive: ['Иван Тестов', 'ivan.testov@example.test', '+7 900 000-00-00', 'ООО «Тестовый контур»', '12 450 000 ₽'],
    preserved: ['ускорить сбор дебиторской задолженности', 'EBITDA: 18,4%'],
    transcript: [
      'Транскрипция встречи финансового директора',
      'Клиент: ООО «Тестовый контур»',
      'ФИО: Иван Тестов',
      'Почта: ivan.testov@example.test',
      'Телефон: +7 900 000-00-00',
      'Выручка: 12 450 000 ₽',
      'EBITDA: 18,4%',
      'Решение: ускорить сбор дебиторской задолженности и внедрить платёжный календарь.',
    ].join('\n'),
  },
  {
    name: 'passport and SNILS produce BLOCK',
    mode: 'balanced',
    decision: 'BLOCK',
    categories: ['person_name', 'passport', 'snils'],
    sensitive: ['Мария Примерова', '45 10 123456', '112-233-445 95'],
    preserved: ['Подготовить новую доверенность после проверки юристом.'],
    transcript: [
      'Транскрипция кадрового вопроса',
      'Сотрудник: Мария Примерова',
      'Паспорт: 45 10 123456',
      'СНИЛС: 112-233-445 95',
      'Решение: Подготовить новую доверенность после проверки юристом.',
    ].join('\n'),
  },
  {
    name: 'counterparty bank details produce REVIEW',
    mode: 'balanced',
    decision: 'REVIEW',
    categories: ['organization', 'inn', 'bik', 'bank_account', 'correspondent_account'],
    sensitive: ['ООО «Синтетический поставщик»', '7712345671', '044525225', '40702810900000000001', '30101810400000000225'],
    preserved: ['перенести оплату на пятницу', 'не допустить кассового разрыва'],
    transcript: [
      'Транскрипция платёжного комитета',
      'Контрагент: ООО «Синтетический поставщик»',
      'ИНН: 7712345671',
      'БИК: 044525225',
      'Р/с: 40702810900000000001',
      'К/с: 30101810400000000225',
      'Решение: перенести оплату на пятницу, чтобы не допустить кассового разрыва.',
    ].join('\n'),
  },
  {
    name: 'individual WHOOP and health data produce BLOCK',
    mode: 'balanced',
    decision: 'BLOCK',
    categories: ['person_name', 'health_biometric'],
    sensitive: ['Павел Демонстрационный', 'WHOOP сотрудника: восстановление 37%, HRV 41 мс, сон 5 ч 20 мин.', 'Состояние здоровья сотрудника: диагноз тестовый, назначено наблюдение.'],
    preserved: ['Обсуждать только обезличенные групповые показатели.'],
    transcript: [
      'Транскрипция встречи по программе благополучия',
      'ФИО: Павел Демонстрационный',
      'WHOOP сотрудника: восстановление 37%, HRV 41 мс, сон 5 ч 20 мин.',
      'Состояние здоровья сотрудника: диагноз тестовый, назначено наблюдение.',
      'Решение: Обсуждать только обезличенные групповые показатели.',
    ].join('\n'),
  },
  {
    name: 'strict Markdown report produces REVIEW and masks exact ratios',
    mode: 'strict',
    decision: 'REVIEW',
    categories: ['organization', 'email', 'date', 'percentage', 'financial_amount'],
    sensitive: ['АО «Демонстрационный клиент»', 'owner@example.test', '10.08.2026', '12 450 000', '18,4%'],
    preserved: ['сократить срок закрытия месяца до пяти рабочих дней', '| Метрика | Факт |'],
    transcript: [
      '# Транскрипция отчётной встречи',
      'Компания: АО «Демонстрационный клиент»',
      'Email: owner@example.test',
      'Дата встречи: 10.08.2026',
      '',
      '| Метрика | Факт |',
      '| --- | ---: |',
      '| Выручка | 12 450 000 |',
      '| EBITDA | 18,4% |',
      '',
      'Решение: сократить срок закрытия месяца до пяти рабочих дней.',
    ].join('\n'),
  },
];

for (const scenario of scenarios) {
  test(scenario.name, () => {
    const result = engine.scan(scenario.transcript, { mode: scenario.mode });
    const detected = new Set(result.findings.map((finding) => finding.category));

    assert.equal(result.decision, scenario.decision);
    for (const category of scenario.categories) assert.ok(detected.has(category), `Missing category: ${category}`);
    for (const value of scenario.sensitive) assert.ok(!result.sanitizedText.includes(value), `Sensitive value leaked: ${value}`);
    for (const fragment of scenario.preserved) assert.ok(result.sanitizedText.includes(fragment), `Business meaning lost: ${fragment}`);
    assert.ok(!JSON.stringify(result).includes(scenario.sensitive[0]), 'Result object must not retain the first sensitive value');
  });
}
