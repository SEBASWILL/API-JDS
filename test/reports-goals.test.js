import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { startServer } from './helpers.js';
import { dayKey, addDays, weekStart, daysInMonth } from '../src/dates.js';

let s;
before(async () => { s = await startServer(); });
after(() => s.stop());
const tx = (t, body) => s.api('POST', '/v1/transactions', body, t);

test('reporte diario: respeta la zona horaria (22:30 en Bogotá no es el día siguiente)', async () => {
  const { accessToken: t } = await s.register('tz@test.com');
  await tx(t, { merchant: 'Cena', amount: 50000, occurred_at: '2026-10-25T03:30:00Z' }); // 24 oct 22:30 en Bogotá
  const bog = await s.api('GET', '/v1/reports/daily?tz=America/Bogota&from=2026-10-24&to=2026-10-25', null, t);
  assert.equal(bog.body.days[0].date, '2026-10-24');
  assert.equal(bog.body.days[0].total, 50000);
  assert.equal(bog.body.days[1].total, 0);
  const utc = await s.api('GET', '/v1/reports/daily?tz=UTC&from=2026-10-24&to=2026-10-25', null, t);
  assert.equal(utc.body.days[0].total, 0);
  assert.equal(utc.body.days[1].total, 50000);
});

test('reporte diario: rellena días vacíos, excluye declinadas y calcula el resumen', async () => {
  const { accessToken: t } = await s.register('daily@test.com');
  const at = (d) => `${d}T17:00:00Z`; // mediodía en Bogotá
  await tx(t, { merchant: 'Rappi', amount: 20000, category: 'comida', occurred_at: at('2026-03-10') });
  await tx(t, { merchant: 'RAPPI', amount: 10000, category: 'comida', occurred_at: at('2026-03-10') });
  await tx(t, { merchant: 'Netflix', amount: 40000, status: 'declined', occurred_at: at('2026-03-10') });
  await tx(t, { type: 'cash', merchant: 'Uber', amount: 15000, category: 'transporte', occurred_at: at('2026-03-11') });

  const r = await s.api('GET', '/v1/reports/daily?tz=America/Bogota&from=2026-03-09&to=2026-03-12', null, t);
  assert.equal(r.status, 200);
  const { days, summary } = r.body;
  assert.deepEqual(days.map((d) => d.total), [0, 30000, 15000, 0]);
  assert.equal(days[1].count, 2);
  assert.deepEqual(days[1].by_category, { comida: 30000 });
  assert.equal(days[1].by_type.card, 30000);
  assert.equal(days[2].by_type.cash, 15000);
  assert.equal(summary.total, 45000);
  assert.equal(summary.avg_per_day, 11250);
  assert.equal(summary.max_day.date, '2026-03-10');
  assert.equal(summary.zero_days, 2);
  assert.equal(summary.top_merchants[0].total, 30000);
  assert.equal(summary.top_merchants[0].count, 2);
  assert.equal(summary.top_merchants[0].merchant.toLowerCase(), 'rappi');
  assert.ok(!summary.top_merchants.some((m) => m.merchant === 'Netflix'));
});

test('reporte diario: valida rango y zona horaria', async () => {
  const { accessToken: t } = await s.register('val@test.com');
  assert.equal((await s.api('GET', '/v1/reports/daily?tz=Mars/Olympus', null, t)).status, 400);
  assert.equal((await s.api('GET', '/v1/reports/daily?from=2026-03-10&to=2026-03-01', null, t)).status, 400);
  assert.equal((await s.api('GET', '/v1/reports/daily?from=2020-01-01&to=2026-01-01', null, t)).status, 400);
  assert.equal((await s.api('GET', '/v1/reports/daily?from=hoy', null, t)).status, 400);
  const def = await s.api('GET', '/v1/reports/daily', null, t); // por defecto: últimos 30 días
  assert.equal(def.body.days.length, 30);
});

test('reporte semanal: semanas de lunes a domingo y variación frente a la anterior', async () => {
  const { accessToken: t } = await s.register('weekly@test.com');
  const today = dayKey(new Date(), 'UTC');
  const thisWeek = weekStart(today);
  const prevWeek = addDays(thisWeek, -7);
  await tx(t, { merchant: 'A', amount: 30000, occurred_at: `${thisWeek}T12:00:00Z` });
  await tx(t, { merchant: 'B', amount: 20000, occurred_at: `${prevWeek}T12:00:00Z` });

  const r = await s.api('GET', '/v1/reports/weekly?tz=UTC&weeks=3', null, t);
  assert.equal(r.status, 200);
  const w = r.body.weeks;
  assert.equal(w.length, 3);
  assert.ok(w.every((x) => new Date(x.start + 'T00:00:00Z').getUTCDay() === 1), 'todas empiezan en lunes');
  assert.equal(w[2].start, thisWeek);
  assert.equal(w[2].end, addDays(thisWeek, 6));
  assert.equal(w[2].total, 30000);
  assert.equal(w[2].change_pct, 50);
  assert.equal(w[1].start, prevWeek);
  assert.equal(w[1].total, 20000);
  assert.equal(w[1].change_pct, null); // la semana anterior a esa no tuvo gasto
  assert.equal(w[0].total, 0);
  assert.equal(r.body.summary.total, 50000);
  assert.equal((await s.api('GET', '/v1/reports/weekly?weeks=0', null, t)).status, 400);
});

test('metas: crear, listar, editar, duplicado, validación y borrar', async () => {
  const { accessToken: t } = await s.register('goals@test.com');
  const total = await s.api('POST', '/v1/goals', { limit: '2.000.000' }, t);
  assert.equal(total.status, 201);
  assert.equal(total.body.limit, 2000000);
  assert.equal(total.body.category, null);
  assert.equal((await s.api('POST', '/v1/goals', { category: '', limit: 5 }, t)).status, 409); // otra meta total
  const comida = await s.api('POST', '/v1/goals', { category: 'comida', limit: 600000 }, t);
  assert.equal(comida.status, 201);
  assert.equal((await s.api('GET', '/v1/goals', null, t)).body.length, 2);

  const up = await s.api('PATCH', `/v1/goals/${comida.body.id}`, { limit: '700.000' }, t);
  assert.equal(up.body.limit, 700000);
  assert.equal((await s.api('PATCH', `/v1/goals/${comida.body.id}`, { category: null }, t)).status, 409);
  assert.equal((await s.api('PATCH', '/v1/goals/no-existe', { limit: 5 }, t)).status, 404);
  assert.equal((await s.api('POST', '/v1/goals', { category: 'ocio', limit: 'abc' }, t)).status, 400);
  assert.equal((await s.api('POST', '/v1/goals', { category: 'ocio', limit: 0 }, t)).status, 400);

  assert.equal((await s.api('DELETE', `/v1/goals/${comida.body.id}`, null, t)).status, 204);
  assert.equal((await s.api('DELETE', `/v1/goals/${comida.body.id}`, null, t)).status, 404);
});

test('progreso: gastado, lo que queda, estado, gasto diario y proyección', async () => {
  const { accessToken: t } = await s.register('progress@test.com');
  const now = new Date();
  const today = dayKey(now, 'UTC');
  const [y, m, d] = today.split('-').map(Number);
  const dim = daysInMonth(y, m);
  const left = dim - d + 1;

  await s.api('POST', '/v1/goals', { limit: 100000 }, t);
  await s.api('POST', '/v1/goals', { category: 'comida', limit: 50000 }, t);
  await tx(t, { merchant: 'Mes pasado', amount: 999999, occurred_at: `${addDays(today, -40)}T12:00:00Z` }); // no cuenta
  await tx(t, { merchant: 'Almuerzo', amount: 50000, category: 'comida', occurred_at: now.toISOString() });

  let p = (await s.api('GET', '/v1/goals/progress?tz=UTC', null, t)).body;
  assert.equal(p.month, today.slice(0, 7));
  assert.equal(p.days_in_month, dim);
  assert.equal(p.days_elapsed, d);
  assert.equal(p.days_left, left);
  const [tot, com] = p.goals; // la meta total va primero
  assert.equal(tot.category, null);
  assert.equal(tot.spent, 50000);
  assert.equal(tot.remaining, 50000);
  assert.equal(tot.percent, 50);
  assert.equal(tot.status, 'ok');
  assert.equal(tot.daily_allowance, Math.round(50000 / left));
  assert.equal(tot.projected, Math.round((50000 / d) * dim));
  assert.equal(com.category, 'comida');
  assert.equal(com.status, 'exceeded'); // 50.000 de 50.000
  assert.equal(com.remaining, 0);
  assert.equal(com.daily_allowance, 0);

  await tx(t, { merchant: 'Otros', amount: 30000, category: 'otros', occurred_at: now.toISOString() });
  await tx(t, { merchant: 'Rechazada', amount: 25000, status: 'declined', occurred_at: now.toISOString() });
  p = (await s.api('GET', '/v1/goals/progress?tz=UTC', null, t)).body;
  assert.equal(p.goals[0].spent, 80000);
  assert.equal(p.goals[0].status, 'warning'); // 80 %

  await tx(t, { merchant: 'Más', amount: 30000, occurred_at: now.toISOString() });
  p = (await s.api('GET', '/v1/goals/progress?tz=UTC', null, t)).body;
  assert.equal(p.goals[0].spent, 110000);
  assert.equal(p.goals[0].remaining, -10000);
  assert.equal(p.goals[0].status, 'exceeded');
  assert.equal(p.goals[0].daily_allowance, 0);
  assert.equal((await s.api('GET', '/v1/goals/progress?tz=Nope/Zone', null, t)).status, 400);
});

test('aislamiento: nadie ve, edita ni borra metas o reportes de otro', async () => {
  const a = await s.register('ga@test.com');
  const b = await s.register('gb@test.com');
  const g = await s.api('POST', '/v1/goals', { category: 'comida', limit: 100000 }, a.accessToken);
  await tx(a.accessToken, { merchant: 'Secreto', amount: 777, occurred_at: new Date().toISOString() });
  assert.equal((await s.api('PATCH', `/v1/goals/${g.body.id}`, { limit: 1 }, b.accessToken)).status, 404);
  assert.equal((await s.api('DELETE', `/v1/goals/${g.body.id}`, null, b.accessToken)).status, 404);
  assert.equal((await s.api('GET', '/v1/goals', null, b.accessToken)).body.length, 0);
  assert.equal((await s.api('GET', '/v1/goals/progress', null, b.accessToken)).body.goals.length, 0);
  assert.equal((await s.api('GET', '/v1/reports/daily', null, b.accessToken)).body.summary.total, 0);
  // y sin sesión no se entra
  assert.equal((await s.api('GET', '/v1/goals')).status, 401);
  assert.equal((await s.api('GET', '/v1/reports/weekly')).status, 401);
});

test('DUMP: las metas tampoco aparecen en claro en la base de datos', async () => {
  const { accessToken: t } = await s.register('dump-metas@test.com');
  await s.api('POST', '/v1/goals', { category: 'meta-categoria-secreta-555', limit: 7654321 }, t);
  s.db.pragma('wal_checkpoint(TRUNCATE)');
  const raw = fs.readFileSync(s.dbFile);
  let cells = '';
  for (const row of s.db.prepare('SELECT * FROM goals').all()) {
    for (const v of Object.values(row)) cells += Buffer.isBuffer(v) ? v.toString('latin1') + v.toString('base64') + v.toString('hex') : String(v);
  }
  for (const secret of ['meta-categoria-secreta-555', '7654321']) {
    assert.ok(!raw.includes(Buffer.from(secret)), `el archivo contiene ${secret}`);
    assert.ok(!cells.includes(secret), `la tabla goals contiene ${secret}`);
    assert.ok(!cells.includes(Buffer.from(secret).toString('base64')), `base64 de ${secret}`);
  }
});

test('integridad: una meta movida a otra fila se detecta', async () => {
  const { accessToken: t } = await s.register('tamper-goals@test.com');
  const g1 = await s.api('POST', '/v1/goals', { limit: 1000 }, t);
  const g2 = await s.api('POST', '/v1/goals', { category: 'ocio', limit: 2000 }, t);
  const blob = s.db.prepare('SELECT data FROM goals WHERE id=?').get(g1.body.id).data;
  s.db.prepare('UPDATE goals SET data=? WHERE id=?').run(blob, g2.body.id);
  const r = await s.api('GET', '/v1/goals', null, t);
  assert.equal(r.status, 500);
  assert.match(r.body.error, /Integridad/);
});
