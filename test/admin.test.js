import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer } from './helpers.js';
import { dayKey, addDays } from '../src/dates.js';

const ADMIN = 'profe@test.com';
let s, admin, ana, beto;
before(async () => {
  s = await startServer({ ADMIN_EMAIL: ADMIN });
  admin = await s.register(ADMIN);
  ana = await s.register('ana@test.com');
  beto = await s.register('beto@test.com');
  for (const amount of [1000, 2000, 3000]) {
    await s.api('POST', '/v1/transactions', { merchant: 'Comercio-Secreto-Ana', amount, category: 'cat-secreta' }, ana.accessToken);
  }
  await s.api('POST', '/v1/transactions', { merchant: 'Beto', amount: 55555 }, beto.accessToken);
  await s.api('POST', '/v1/goals', { limit: 777777 }, ana.accessToken);
});
after(() => s.stop());

const stats = (qs = '') => s.api('GET', '/v1/admin/stats' + qs, null, admin.accessToken);

test('el admin ve cuántas cuentas, transacciones y metas hay', async () => {
  const { status, body } = await stats();
  assert.equal(status, 200);
  assert.deepEqual(body.users, {
    total: 3, verified: 3, pending_verification: 0, mfa_enabled: 3,
    new_in_range: 3, active_in_range: 3, with_open_session: 3,
  });
  assert.equal(body.transactions.total, 4);
  assert.equal(body.transactions.in_range, 4);
  assert.equal(body.transactions.users_with_transactions, 2);
  assert.equal(body.transactions.max_per_user_in_range, 3);
  assert.equal(body.transactions.avg_per_active_user, 2);
  assert.equal(body.goals.total, 1);
  assert.equal(body.daily.length, 30);
  const hoy = body.daily.find((d) => d.date === dayKey(new Date(), 'America/Bogota'));
  assert.deepEqual([hoy.registros, hoy.transacciones, hoy.metas], [3, 4, 1]);
  assert.equal(body.transactions.busiest_day.count, 4);
});

test('las estadísticas no revelan montos, comercios, categorías ni correos', async () => {
  const text = JSON.stringify((await stats()).body) + JSON.stringify((await s.api('GET', '/v1/admin/users', null, admin.accessToken)).body);
  for (const secreto of ['Comercio-Secreto-Ana', 'cat-secreta', '55555', '777777', '6000', 'ana@test.com', 'beto@test.com', ADMIN]) {
    assert.ok(!text.includes(secreto), `aparece ${secreto}`);
  }
});

test('el filtro de tiempo deja fuera lo que no cae en el rango', async () => {
  const hoy = dayKey(new Date(), 'America/Bogota');
  const ayer = await stats(`?from=${addDays(hoy, -10)}&to=${addDays(hoy, -1)}`);
  assert.equal(ayer.body.transactions.in_range, 0);
  assert.equal(ayer.body.users.new_in_range, 0);
  assert.equal(ayer.body.transactions.total, 4); // los totales no dependen del rango
  assert.equal(ayer.body.daily.length, 10);

  for (const qs of ['?from=2026-13-01', `?from=${hoy}&to=${addDays(hoy, -1)}`, '?from=2020-01-01&to=2022-01-01', '?tz=Marte/Base']) {
    assert.equal((await stats(qs)).status, 400, qs);
  }
});

test('las transacciones viejas sin fecha de registro se cuentan aparte', async () => {
  await s.db.run('UPDATE transactions SET created_at = NULL WHERE id = (SELECT id FROM transactions LIMIT 1)');
  const { body } = await stats();
  assert.equal(body.transactions.without_registration_date, 1);
  assert.equal(body.transactions.in_range, 3);
  assert.equal(body.transactions.total, 4);
});

test('el admin lista las cuentas y busca una por correo', async () => {
  const { body: users } = await s.api('GET', '/v1/admin/users', null, admin.accessToken);
  assert.equal(users.length, 3);
  assert.equal(users.find((u) => u.id === admin.user.id).is_admin, true);
  const a = users.find((u) => u.id === ana.user.id);
  assert.deepEqual([a.transactions, a.goals, a.mfa_enabled], [3, 1, true]);

  const found = await s.api('GET', '/v1/admin/users?email=ANA@test.com', null, admin.accessToken);
  assert.deepEqual(found.body.map((u) => u.id), [ana.user.id]);
  assert.deepEqual((await s.api('GET', '/v1/admin/users?email=nadie@test.com', null, admin.accessToken)).body, []);
});

test('un usuario normal o sin sesión no entra al panel', async () => {
  for (const [m, url] of [['GET', '/v1/admin/stats'], ['GET', '/v1/admin/users'],
    ['DELETE', '/v1/admin/users/latest'], ['DELETE', `/v1/admin/users/${beto.user.id}`]]) {
    assert.equal((await s.api(m, url, null, ana.accessToken)).status, 403, url);
    assert.equal((await s.api(m, url)).status, 401, url);
  }
});

test('eliminar el último usuario creado borra también sus datos y sesiones', async () => {
  const r = await s.api('DELETE', '/v1/admin/users/latest', null, admin.accessToken);
  assert.equal(r.status, 200);
  assert.deepEqual([r.body.deleted.id, r.body.deleted.transactions], [beto.user.id, 1]);
  assert.equal((await s.api('GET', '/v1/transactions', null, beto.accessToken)).status, 401);
  assert.equal((await s.api('POST', '/v1/auth/login', { email: 'beto@test.com', password: 'una-clave-larga-123' })).status, 401);
  assert.equal((await s.db.get('SELECT COUNT(*) n FROM credentials WHERE user_id = $1', [beto.user.id])).n, 0);
  assert.equal((await stats()).body.users.total, 2);
});

test('eliminar por id; el admin no se puede borrar a sí mismo', async () => {
  assert.equal((await s.api('DELETE', `/v1/admin/users/${admin.user.id}`, null, admin.accessToken)).status, 400);
  assert.equal((await s.api('DELETE', '/v1/admin/users/no-existe', null, admin.accessToken)).status, 404);
  const r = await s.api('DELETE', `/v1/admin/users/${ana.user.id}`, null, admin.accessToken);
  assert.deepEqual([r.status, r.body.deleted.transactions, r.body.deleted.goals], [200, 3, 1]);
  assert.equal((await s.db.get('SELECT COUNT(*) n FROM transactions')).n, 0);
  // Solo queda el admin: "latest" no lo toca.
  assert.equal((await s.api('DELETE', '/v1/admin/users/latest', null, admin.accessToken)).status, 404);
});

test('sin ADMIN_EMAIL o sin verificar el correo nadie es admin', async () => {
  const sinAdmin = await startServer();
  try {
    const u = await sinAdmin.register(ADMIN);
    assert.equal((await sinAdmin.api('GET', '/v1/admin/stats', null, u.accessToken)).status, 403);
  } finally {
    await sinAdmin.stop();
  }
});
