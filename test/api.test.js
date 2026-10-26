import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { loadConfig } from '../src/config.js';
import { openDb } from '../src/db.js';
import { createApp } from '../src/app.js';
import { parseAmount } from '../src/amount.js';

const PEPPER = 'a'.repeat(64);
const env = { PEPPER, SCRYPT_N: '1024', AUTH_RATE_MAX: '1000' };
let dir, dbFile, db, server, base;

const api = async (method, url, body, token) => {
  const res = await fetch(base + url, {
    method,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
};

const register = async (email, password = 'una-clave-larga-123') => {
  const r = await api('POST', '/v1/auth/register', { email, password });
  assert.equal(r.status, 201);
  return r.body;
};

before(async () => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gastos-'));
  dbFile = path.join(dir, 'test.db');
  db = openDb(dbFile);
  const app = createApp(db, loadConfig(env));
  await new Promise((ok) => { server = app.listen(0, ok); });
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => { server.close(); db.close(); fs.rmSync(dir, { recursive: true, force: true }); });

test('parseAmount entiende formatos colombianos y anglosajones', () => {
  assert.equal(parseAmount('$25.000,00'), 25000);
  assert.equal(parseAmount('COP 25,000.00'), 25000);
  assert.equal(parseAmount('25.000'), 25000);
  assert.equal(parseAmount('1.234.567'), 1234567);
  assert.equal(parseAmount('12,50'), 12.5);
  assert.equal(parseAmount(25000), 25000);
  assert.equal(parseAmount('abc'), null);
  assert.equal(parseAmount(-5), null);
});

test('registro, login y contraseña incorrecta', async () => {
  await register('ana@test.com');
  const ok = await api('POST', '/v1/auth/login', { email: 'ANA@test.com', password: 'una-clave-larga-123' });
  assert.equal(ok.status, 200);
  assert.ok(ok.body.accessToken);
  const bad = await api('POST', '/v1/auth/login', { email: 'ana@test.com', password: 'otra-clave-123456' });
  assert.equal(bad.status, 401);
  const ghost = await api('POST', '/v1/auth/login', { email: 'nadie@test.com', password: 'otra-clave-123456' });
  assert.equal(ghost.status, 401);
  const dup = await api('POST', '/v1/auth/register', { email: 'ana@test.com', password: 'una-clave-larga-123' });
  assert.equal(dup.status, 409);
});

test('CRUD: tarjeta, efectivo, actualizar estado a declinada, borrar', async () => {
  const { accessToken: t } = await register('crud@test.com');
  const card = await api('POST', '/v1/transactions', {
    merchant: 'Éxito', amount: '$45.900,00', card: 'Visa 1234', description: 'mercado',
  }, t);
  assert.equal(card.status, 201);
  assert.equal(card.body.amount, 45900);

  const cash = await api('POST', '/v1/transactions', { type: 'cash', merchant: 'Tienda', amount: 3000, card: 'ignorada' }, t);
  assert.equal(cash.status, 201);
  assert.equal(cash.body.card, null);

  const patched = await api('PATCH', `/v1/transactions/${card.body.id}`, { status: 'declined', description: 'rechazada' }, t);
  assert.equal(patched.body.status, 'declined');
  assert.equal(patched.body.merchant, 'Éxito');

  const list = await api('GET', '/v1/transactions?type=cash', null, t);
  assert.equal(list.body.total, 1);

  const summary = await api('GET', '/v1/transactions/summary', null, t);
  assert.equal(summary.body.total, 3000);
  assert.equal(summary.body.declined_count, 1);

  assert.equal((await api('DELETE', `/v1/transactions/${cash.body.id}`, null, t)).status, 204);
  assert.equal((await api('GET', `/v1/transactions/${cash.body.id}`, null, t)).status, 404);

  const invalid = await api('POST', '/v1/transactions', { merchant: '', amount: 'x' }, t);
  assert.equal(invalid.status, 400);
});

test('Atajo iOS: token de ingesta crea transacciones pero no puede leerlas', async () => {
  const { accessToken: t } = await register('ios@test.com');
  const tok = await api('POST', '/v1/ingest-tokens', { label: 'iPhone de Ana' }, t);
  assert.equal(tok.status, 201);
  const it = tok.body.token;

  const r = await api('POST', '/v1/ingest', {
    merchant: 'Rappi', amount: '$25.000,00', card: 'Visa 4242', date: 'fecha rara', extra: 'se ignora',
  }, it);
  assert.equal(r.status, 201);

  const list = await api('GET', '/v1/transactions', null, t);
  assert.equal(list.body.total, 1);
  assert.equal(list.body.items[0].amount, 25000);
  assert.equal(list.body.items[0].source, 'ios-shortcut');

  assert.equal((await api('GET', '/v1/transactions', null, it)).status, 401); // no lee
  assert.equal((await api('POST', '/v1/ingest', { merchant: 'x', amount: 1 }, t)).status, 401); // access no ingesta

  const labels = await api('GET', '/v1/ingest-tokens', null, t);
  assert.equal(labels.body[0].label, 'iPhone de Ana');

  await api('DELETE', `/v1/ingest-tokens/${labels.body[0].id}`, null, t);
  assert.equal((await api('POST', '/v1/ingest', { merchant: 'x', amount: 1 }, it)).status, 401);
});

test('aislamiento: un usuario no ve ni toca datos de otro', async () => {
  const a = await register('a@test.com');
  const b = await register('b@test.com');
  const tx = await api('POST', '/v1/transactions', { merchant: 'Secreto A', amount: 100 }, a.accessToken);
  assert.equal((await api('GET', `/v1/transactions/${tx.body.id}`, null, b.accessToken)).status, 404);
  assert.equal((await api('PATCH', `/v1/transactions/${tx.body.id}`, { amount: 1 }, b.accessToken)).status, 404);
  assert.equal((await api('DELETE', `/v1/transactions/${tx.body.id}`, null, b.accessToken)).status, 404);
  assert.equal((await api('GET', '/v1/transactions', null, b.accessToken)).body.total, 0);
});

test('DUMP: la base de datos no contiene ningún dato en claro', async () => {
  const { accessToken: t } = await register('dump-victima@test.com', 'clave-super-secreta-999');
  const secrets = ['Comercio-Ultra-Secreto-777', 'descripcion-privada-xyz', 'Visa 9876', 'dump-victima@test.com'];
  await api('POST', '/v1/transactions', {
    merchant: secrets[0], description: secrets[1], card: secrets[2], amount: 123456, category: 'categoria-privada',
  }, t);
  const tok = await api('POST', '/v1/ingest-tokens', { label: 'etiqueta-privada-zzz' }, t);
  secrets.push('categoria-privada', 'etiqueta-privada-zzz', 'clave-super-secreta-999', tok.body.token.split('.')[1]);

  db.pragma('wal_checkpoint(TRUNCATE)');
  const raw = fs.readFileSync(dbFile);
  // Además del archivo crudo, miramos cada celda como texto, base64 y hex.
  let cells = '';
  for (const { name } of db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all()) {
    for (const row of db.prepare(`SELECT * FROM ${name}`).all()) {
      for (const v of Object.values(row)) {
        cells += Buffer.isBuffer(v) ? v.toString('latin1') + v.toString('base64') + v.toString('hex') : String(v);
      }
    }
  }
  for (const s of secrets) {
    assert.ok(!raw.includes(Buffer.from(s)), `el archivo contiene "${s}"`);
    assert.ok(!cells.includes(s), `una celda contiene "${s}"`);
    assert.ok(!cells.includes(Buffer.from(s).toString('base64')), `base64 de "${s}"`);
  }
  assert.ok(!cells.includes('123456'), 'el monto aparece en claro');
});

test('integridad: mover/alterar un blob cifrado se detecta', async () => {
  const { accessToken: t, user } = await register('tamper@test.com');
  const t1 = await api('POST', '/v1/transactions', { merchant: 'uno', amount: 1 }, t);
  const t2 = await api('POST', '/v1/transactions', { merchant: 'dos', amount: 2 }, t);
  const blob = db.prepare('SELECT data FROM transactions WHERE id=?').get(t1.body.id).data;
  db.prepare('UPDATE transactions SET data=? WHERE id=?').run(blob, t2.body.id);
  const r = await api('GET', `/v1/transactions/${t2.body.id}`, null, t);
  assert.equal(r.status, 500);
  assert.match(r.body.error, /Integridad/);
});

test('sin el PEPPER del servidor, un dump no permite iniciar sesión', async () => {
  await register('pepper@test.com', 'clave-con-pepper-123');
  const other = createApp(db, loadConfig({ ...env, PEPPER: 'b'.repeat(64) }));
  const s = await new Promise((ok) => { const x = other.listen(0, () => ok(x)); });
  const res = await fetch(`http://127.0.0.1:${s.address().port}/v1/auth/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'pepper@test.com', password: 'clave-con-pepper-123' }),
  });
  s.close();
  assert.equal(res.status, 401);
});

test('refresh rota tokens; cambiar contraseña y recuperar conservan los datos', async () => {
  const reg = await register('rot@test.com', 'clave-original-123');
  await api('POST', '/v1/transactions', { merchant: 'Persistente', amount: 500 }, reg.accessToken);

  const r1 = await api('POST', '/v1/auth/refresh', { refreshToken: reg.refreshToken });
  assert.equal(r1.status, 200);
  assert.equal((await api('POST', '/v1/auth/refresh', { refreshToken: reg.refreshToken })).status, 401); // reuso

  const cp = await api('POST', '/v1/auth/change-password',
    { currentPassword: 'clave-original-123', newPassword: 'clave-nueva-4567' }, r1.body.accessToken);
  assert.equal(cp.status, 200);
  assert.equal((await api('GET', '/v1/transactions', null, r1.body.accessToken)).status, 401); // sesiones viejas revocadas
  assert.equal((await api('POST', '/v1/auth/login', { email: 'rot@test.com', password: 'clave-original-123' })).status, 401);

  const rec = await api('POST', '/v1/auth/recover',
    { email: 'rot@test.com', recoveryKey: reg.recoveryKey, newPassword: 'clave-recuperada-89' });
  assert.equal(rec.status, 200);
  const list = await api('GET', '/v1/transactions', null, rec.body.accessToken);
  assert.equal(list.body.items[0].merchant, 'Persistente');
  // la llave de recuperación vieja ya no sirve
  const again = await api('POST', '/v1/auth/recover',
    { email: 'rot@test.com', recoveryKey: reg.recoveryKey, newPassword: 'otra-clave-0000000' });
  assert.equal(again.status, 401);
});
