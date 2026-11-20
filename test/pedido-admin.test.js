// PEDIDO DE PRUEBAS (José) · Sección 1: pruebas automáticas nuevas en el backend (A-01 a A-05).
//
// Cada prueba lleva el ID del pedido para citarla en la matriz de pruebas.
//
// Estado de las rutas al escribir estas pruebas:
//   - Las "métricas" del plan son /v1/admin/stats (la misma ruta que usa la web en la pestaña Admin),
//     junto con /v1/admin/users.
//   - El ingest todavía no asigna categoría por comercio ni recuerda correcciones (siempre guarda null).
//   - GET /v1/me/export y DELETE /v1/me todavía no existen.
// Las pruebas de esas funciones van marcadas `todo`: se ejecutan y muestran el resultado, pero no
// rompen `npm test`. Cuando Wilches entregue cada función, QUITAR la marca `todo` para que proteja.
//
//   node --test test/pedido-admin.test.js

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, mailer } from './helpers.js';

const PW = 'una-clave-larga-123';
const ADMIN = 'admin-pedido@test.com';

// Rutas del panel. Las "métricas" del plan son /v1/admin/stats.
const STATS = '/v1/admin/stats';
const USERS = '/v1/admin/users';

// Datos de prueba para A-04. Ajustar cuando Wilches defina el catálogo de comercios conocidos.
const COMERCIO_CONOCIDO = { merchant: 'Uber', category: 'transporte' };
const COMERCIO_DESCONOCIDO = 'Panaderia Doña Rosa Z9';

const sum = (arr, k) => arr.reduce((a, x) => a + x[k], 0);

// ===========================================================================
// Servidor 1: datos conocidos (admin + N usuarios + M gastos) para A-01, A-02 y A-03.
// Va en un servidor propio para que los conteos sean exactos.
// ===========================================================================
let s, admin, u1, u2, u3, u4, ingestU2;

// N y M del plan: cuántos usuarios y gastos se crean, y cómo se reparten.
const GASTOS = { u1: 3, u2: 2, u3: 1, u4: 0 }; // manuales
const INGEST_U2 = 1; //                           por el Atajo (ingest)
const METAS = { u1: 1, u3: 2 };
const M = Object.values(GASTOS).reduce((a, b) => a + b, 0) + INGEST_U2; // 7 gastos en total

before(async () => {
  s = await startServer({ ADMIN_EMAIL: ADMIN });
  admin = await s.register(ADMIN);
  u1 = await s.register('a-u1@test.com');
  u2 = await s.register('a-u2@test.com');
  u3 = await s.register('a-u3@test.com');
  u4 = await s.register('a-u4@test.com');
  // Un usuario que se registró pero no verificó el correo (cuenta pendiente, sin sesión).
  assert.equal((await s.api('POST', '/v1/auth/register', { email: 'a-pendiente@test.com', password: PW })).status, 201);

  const tokens = { u1: u1.accessToken, u2: u2.accessToken, u3: u3.accessToken, u4: u4.accessToken };
  for (const [u, n] of Object.entries(GASTOS)) {
    for (let i = 0; i < n; i++) {
      const r = await s.api('POST', '/v1/transactions',
        { merchant: `Comercio-Secreto-${u}-${i}`, amount: 123457, category: 'cat-secreta' }, tokens[u]);
      assert.equal(r.status, 201);
    }
  }
  for (const [u, n] of Object.entries(METAS)) {
    for (let i = 0; i < n; i++) {
      assert.equal((await s.api('POST', '/v1/goals', { category: `meta-${i}`, limit: 987653 }, tokens[u])).status, 201);
    }
  }
  ingestU2 = (await s.api('POST', '/v1/ingest-tokens', { label: 'iPhone de prueba' }, u2.accessToken)).body.token;
  for (let i = 0; i < INGEST_U2; i++) {
    assert.equal((await s.api('POST', '/v1/ingest', { merchant: 'Comercio-Secreto-Atajo', amount: '$123.457' }, ingestU2)).status, 201);
  }
});
after(() => s.stop());

// ===========================================================================
// A-01 · Un usuario normal no entra al panel del admin
// ===========================================================================
test('A-01 usuario normal llama a /v1/admin/stats (métricas) y /v1/admin/users: 403', async () => {
  for (const url of [STATS, `${STATS}?from=2026-01-01&to=2026-01-31`, USERS, `${USERS}?email=a-u2@test.com`]) {
    const r = await s.api('GET', url, null, u1.accessToken);
    assert.equal(r.status, 403, `${url} con usuario normal`);
    assert.match(r.body.error, /administrador/i, `${url}: el 403 debe explicar el motivo`);
    assert.equal((await s.api('GET', url)).status, 401, `${url} sin token`);
  }
});

test('A-01b un usuario normal no se vuelve admin por tener sesión, MFA o gastos', async () => {
  // u1 tiene correo verificado, MFA activo, gastos y metas: aun así no es admin.
  assert.equal((await s.api('GET', USERS, null, u1.accessToken)).status, 403);
  // Un token de ingesta (el del Atajo) tampoco entra.
  assert.equal((await s.api('GET', USERS, null, ingestU2)).status, 401);
  // Tampoco puede borrar cuentas.
  assert.equal((await s.api('DELETE', `${USERS}/${u2.user.id}`, null, u1.accessToken)).status, 403);
  assert.equal((await s.db.get('SELECT COUNT(*) n FROM users WHERE id = $1', [u2.user.id])).n, 1, 'u2 sigue existiendo');
});

// ===========================================================================
// A-02 · El admin sí entra y solo ve conteos (sin correos ni datos cifrados)
// ===========================================================================

/** Revisa que una respuesta del panel no filtre correos, comercios, montos, categorías ni bytes cifrados. */
async function assertSinDatosPrivados(body, url) {
  const text = JSON.stringify(body);
  assert.ok(!/[\w.+-]+@[\w-]+\.[\w.]+/.test(text), `${url}: aparece un correo`);
  for (const secreto of ['Comercio-Secreto', 'cat-secreta', 'meta-0', 'iPhone de prueba']) {
    assert.ok(!text.includes(secreto), `${url}: aparece "${secreto}"`);
  }
  for (const monto of [/\b123457\b/, /\b987653\b/]) assert.ok(!monto.test(text), `${url}: aparece el monto ${monto}`);
  // Nada de columnas sensibles ni bytes: buffers serializados, HMAC del correo (64 hex) o base64 largo.
  for (const campo of ['email', 'email_lookup', 'kdf_salt', 'wrapped_dek_pw', 'wrapped_dek_rec', 'wrapped_dek',
    'totp_enc', 'email_code_hash', 'data', 'label', 'label_enc']) {
    assert.ok(!new RegExp(`"${campo}"\\s*:`).test(text), `${url}: aparece el campo ${campo}`);
  }
  assert.ok(!text.includes('"type":"Buffer"'), `${url}: aparece un buffer`);
  assert.ok(!/[0-9a-f]{64}/i.test(text), `${url}: aparece un hash de 64 hex (¿HMAC del correo?)`);
  // Base64 largo = bytes cifrados. Se quitan antes los UUID (ids), que sí pueden aparecer.
  assert.ok(!/[A-Za-z0-9+/_-]{40,}={0,2}/.test(text.replace(/[0-9a-f-]{36}/g, '')), `${url}: aparece un bloque base64 largo`);
}

test('A-02 el administrador llama a /v1/admin/stats (métricas) y /v1/admin/users: 200 con conteos', async () => {
  const st = await s.api('GET', STATS, null, admin.accessToken);
  assert.equal(st.status, 200);
  assert.equal(typeof st.body.users.total, 'number');
  assert.equal(typeof st.body.transactions.total, 'number');
  assert.equal(typeof st.body.goals.total, 'number');
  assert.ok(Array.isArray(st.body.daily));
  await assertSinDatosPrivados(st.body, STATS);

  const us = await s.api('GET', USERS, null, admin.accessToken);
  assert.equal(us.status, 200);
  assert.ok(Array.isArray(us.body) && us.body.length > 0);
  for (const u of us.body) {
    assert.deepEqual(Object.keys(u).sort(),
      ['created_at', 'email_verified', 'goals', 'id', 'is_admin', 'last_activity_at', 'mfa_enabled', 'transactions'],
      'cada cuenta solo trae metadatos');
  }
  await assertSinDatosPrivados(us.body, USERS);

  // La búsqueda por correo tampoco devuelve el correo (se compara su HMAC).
  const buscado = await s.api('GET', `${USERS}?email=a-u2@test.com`, null, admin.accessToken);
  assert.deepEqual(buscado.body.map((u) => u.id), [u2.user.id]);
  await assertSinDatosPrivados(buscado.body, `${USERS}?email=`);
});

// ===========================================================================
// A-03 · Las métricas coinciden exactamente con los datos conocidos
// ===========================================================================
test(`A-03 las métricas coinciden con los datos conocidos (6 cuentas, ${M} gastos, 3 metas)`, async () => {
  const { status, body } = await s.api('GET', STATS, null, admin.accessToken);
  assert.equal(status, 200);

  // 5 cuentas completas (admin + u1..u4) + 1 pendiente de verificar.
  assert.deepEqual(body.users, {
    total: 6,
    verified: 5,
    pending_verification: 1,
    mfa_enabled: 5,
    new_in_range: 6,
    active_in_range: 5, // la pendiente nunca inició sesión ni registró nada
    with_open_session: 5,
  });

  // M = 6 manuales + 1 por el Atajo. u1 tiene 3, u2 tiene 3 (2 + 1 ingest), u3 tiene 1.
  assert.equal(body.transactions.total, M);
  assert.equal(body.transactions.in_range, M);
  assert.equal(body.transactions.without_registration_date, 0);
  assert.equal(body.transactions.users_with_transactions, 3);
  assert.equal(body.transactions.users_with_transactions_in_range, 3);
  assert.equal(body.transactions.max_per_user_in_range, 3);
  assert.equal(body.transactions.avg_per_active_user, Math.round((M / 3) * 100) / 100);
  assert.equal(body.transactions.avg_per_day, Math.round((M / body.range.days) * 100) / 100);

  assert.deepEqual(body.goals, { total: 3, users_with_goals: 2, in_range: 3 });
  assert.deepEqual(body.sessions, { logins_in_range: 5, active_ingest_tokens: 1 });

  // La serie diaria suma lo mismo que los totales (sin depender de si la prueba cruza la medianoche).
  assert.equal(body.daily.length, 30);
  assert.equal(sum(body.daily, 'registros'), 6);
  assert.equal(sum(body.daily, 'transacciones'), M);
  assert.equal(sum(body.daily, 'metas'), 3);
  assert.equal(sum(body.daily, 'logins'), 5);

  // Por cuenta, en /users.
  const { body: users } = await s.api('GET', USERS, null, admin.accessToken);
  assert.equal(users.length, 6);
  const de = (u) => users.find((x) => x.id === u.user.id);
  assert.deepEqual([de(admin).transactions, de(admin).goals, de(admin).is_admin], [0, 0, true]);
  assert.deepEqual([de(u1).transactions, de(u1).goals], [3, 1]);
  assert.deepEqual([de(u2).transactions, de(u2).goals], [3, 0]);
  assert.deepEqual([de(u3).transactions, de(u3).goals], [1, 2]);
  assert.deepEqual([de(u4).transactions, de(u4).goals], [0, 0]);
  assert.equal(users.filter((u) => !u.email_verified).length, 1);
  assert.equal(users.filter((u) => u.is_admin).length, 1);
});

test('A-03b los conteos se actualizan al crear y borrar datos', async () => {
  const antes = (await s.api('GET', STATS, null, admin.accessToken)).body;
  const r = await s.api('POST', '/v1/transactions', { merchant: 'Comercio-Secreto-extra', amount: 1000 }, u4.accessToken);
  const despues = (await s.api('GET', STATS, null, admin.accessToken)).body;
  assert.equal(despues.transactions.total, antes.transactions.total + 1);
  assert.equal(despues.transactions.users_with_transactions, antes.transactions.users_with_transactions + 1);

  assert.equal((await s.api('DELETE', `/v1/transactions/${r.body.id}`, null, u4.accessToken)).status, 204);
  const final = (await s.api('GET', STATS, null, admin.accessToken)).body;
  assert.equal(final.transactions.total, antes.transactions.total);
  assert.equal(final.transactions.users_with_transactions, antes.transactions.users_with_transactions);
});

// ===========================================================================
// Servidor 2: A-04 y A-05 (cambian datos y borran cuentas; no deben afectar los conteos de arriba).
// ===========================================================================
let s2, ana, beto, ingestAna;
before(async () => {
  s2 = await startServer();
  ana = await s2.register('a-ana@test.com');
  beto = await s2.register('a-beto@test.com');
  ingestAna = (await s2.api('POST', '/v1/ingest-tokens', { label: 'Atajo Ana' }, ana.accessToken)).body.token;
});
after(() => s2.stop());

const ingest = async (merchant, token = ingestAna) => {
  const r = await s2.api('POST', '/v1/ingest', { merchant, amount: 25000 }, token);
  assert.equal(r.status, 201, `ingest de ${merchant}`);
  return r.body.id;
};
const categoriaDe = async (id, t = ana.accessToken) => (await s2.api('GET', `/v1/transactions/${id}`, null, t)).body.category;

// ===========================================================================
// A-04 · Categoría automática en el ingest
// ===========================================================================
test('A-04a ingest con comercio desconocido: la categoría queda en null', async () => {
  const id = await ingest(COMERCIO_DESCONOCIDO);
  assert.equal(await categoriaDe(id), null);
});

test('A-04b ingest con comercio conocido: se asigna la categoría',
  { todo: 'Pendiente de Wilches: el ingest todavía no categoriza por comercio (siempre guarda null)' }, async () => {
  const id = await ingest(COMERCIO_CONOCIDO.merchant);
  assert.equal(await categoriaDe(id), COMERCIO_CONOCIDO.category);
  // Sin importar mayúsculas ni espacios de más.
  const id2 = await ingest(`  ${COMERCIO_CONOCIDO.merchant.toUpperCase()} `);
  assert.equal(await categoriaDe(id2), COMERCIO_CONOCIDO.category);
});

test('A-04c la corrección del usuario se recuerda para el siguiente gasto del mismo comercio',
  { todo: 'Pendiente de Wilches: el ingest todavía no recuerda las categorías corregidas por el usuario' }, async () => {
  const comercio = 'Tienda de Barrio Q7';
  const primero = await ingest(comercio);
  assert.equal(await categoriaDe(primero), null, 'la primera vez no se conoce');

  // El usuario corrige la categoría a mano.
  const p = await s2.api('PATCH', `/v1/transactions/${primero}`, { category: 'mercado' }, ana.accessToken);
  assert.equal(p.status, 200);

  const segundo = await ingest(comercio);
  assert.equal(await categoriaDe(segundo), 'mercado', 'el segundo gasto del mismo comercio debe venir con la corrección');

  // La corrección es de Ana: no se le aplica a Beto.
  const ingestBeto = (await s2.api('POST', '/v1/ingest-tokens', { label: 'Atajo Beto' }, beto.accessToken)).body.token;
  const deBeto = await ingest(comercio, ingestBeto);
  assert.equal(await categoriaDe(deBeto, beto.accessToken), null, 'la corrección de un usuario no debe filtrarse a otro');
});

// ===========================================================================
// A-05 · Exportar mis datos y borrar mi cuenta
// ===========================================================================
test('A-05a GET /v1/me/export exporta solo lo propio',
  { todo: 'Pendiente de Wilches: GET /v1/me/export no existe todavía' }, async () => {
  const tx = await s2.api('POST', '/v1/transactions', { merchant: 'Export-Ana', amount: 11111 }, ana.accessToken);
  const goal = await s2.api('POST', '/v1/goals', { category: 'export-ana', limit: 50000 }, ana.accessToken);
  await s2.api('POST', '/v1/transactions', { merchant: 'Export-Beto', amount: 22222 }, beto.accessToken);

  const r = await s2.api('GET', '/v1/me/export', null, ana.accessToken);
  assert.equal(r.status, 200);
  const text = JSON.stringify(r.body);
  assert.ok(text.includes(tx.body.id) && text.includes('Export-Ana'), 'incluye los gastos de Ana');
  assert.ok(text.includes(goal.body.id), 'incluye las metas de Ana');
  assert.ok(!text.includes('Export-Beto'), 'no incluye datos de otro usuario');
  for (const campo of ['wrapped_dek', 'kdf_salt', 'totp', 'password', 'email_lookup', 'email_code']) {
    assert.ok(!text.includes(campo), `no expone el campo interno ${campo}`);
  }

  // Solo con sesión del propio usuario: sin token o con el token del Atajo, no.
  assert.equal((await s2.api('GET', '/v1/me/export')).status, 401);
  assert.equal((await s2.api('GET', '/v1/me/export', null, ingestAna)).status, 401);
});

test('A-05b DELETE /v1/me borra todo y el login deja de funcionar',
  { todo: 'Pendiente de Wilches: DELETE /v1/me no existe todavía' }, async () => {
  const email = 'a-borrar@test.com';
  const yo = await s2.register(email);
  await s2.api('POST', '/v1/transactions', { merchant: 'Borrar-1', amount: 1000 }, yo.accessToken);
  await s2.api('POST', '/v1/goals', { limit: 90000 }, yo.accessToken);
  const atajo = (await s2.api('POST', '/v1/ingest-tokens', { label: 'Atajo a borrar' }, yo.accessToken)).body.token;
  const txBeto = (await s2.api('GET', '/v1/transactions', null, beto.accessToken)).body.total;

  // Se envía la contraseña por si la ruta pide confirmarla.
  const r = await s2.api('DELETE', '/v1/me', { password: PW }, yo.accessToken);
  assert.ok([200, 204].includes(r.status), `DELETE /v1/me respondió ${r.status}`);

  // No queda nada del usuario en la base.
  for (const tabla of ['credentials', 'transactions', 'goals']) {
    assert.equal((await s2.db.get(`SELECT COUNT(*) n FROM ${tabla} WHERE user_id = $1`, [yo.user.id])).n, 0, `quedan filas en ${tabla}`);
  }
  assert.equal((await s2.db.get('SELECT COUNT(*) n FROM users WHERE id = $1', [yo.user.id])).n, 0, 'queda la fila del usuario');

  // Login, sesión, refresh y Atajo dejan de funcionar.
  assert.equal((await s2.api('POST', '/v1/auth/login', { email, password: PW })).status, 401);
  assert.equal((await s2.api('GET', '/v1/transactions', null, yo.accessToken)).status, 401);
  assert.equal((await s2.api('POST', '/v1/auth/refresh', { refreshToken: yo.refreshToken })).status, 401);
  assert.equal((await s2.api('POST', '/v1/ingest', { merchant: 'x', amount: 1 }, atajo)).status, 401);

  // El correo queda libre para registrarse de nuevo, y los datos de los demás siguen intactos.
  assert.equal((await s2.api('POST', '/v1/auth/register', { email, password: PW })).status, 201);
  assert.ok(mailer.lastCode(email));
  assert.equal((await s2.api('GET', '/v1/transactions', null, beto.accessToken)).body.total, txBeto);
});

test('A-05c DELETE /v1/me no se puede hacer sin sesión ni con el token del Atajo',
  { todo: 'Pendiente de Wilches: DELETE /v1/me no existe todavía' }, async () => {
  assert.equal((await s2.api('DELETE', '/v1/me', { password: PW })).status, 401);
  assert.equal((await s2.api('DELETE', '/v1/me', { password: PW }, ingestAna)).status, 401);
  assert.equal((await s2.db.get('SELECT COUNT(*) n FROM users WHERE id = $1', [ana.user.id])).n, 1, 'Ana sigue existiendo');
});