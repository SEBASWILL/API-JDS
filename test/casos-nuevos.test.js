// CASOS DE PRUEBA DE LAS FUNCIONES NUEVAS DE LA API
//
// Cada prueba lleva un código (GM = metas, RP = reportes, CT = categorías, SE = sesión,
// RC = recuperación) para poder citarla en el informe. Todo corre en local: servidor en memoria
// de proceso, base SQLite temporal y mailer falso (no se envía ningún correo real).
//
//   node --test test/casos-nuevos.test.js

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, totpFor } from './helpers.js';
import { dayKey, addDays, weekStart } from '../src/dates.js';

const TZ = 'America/Bogota'; // zona por defecto de la API
const PW = 'una-clave-larga-123';
const NUEVA = 'otra-clave-nueva-456';

let s;
before(async () => { s = await startServer(); });
after(() => s.stop());

const gasto = (t, body) => s.api('POST', '/v1/transactions', { merchant: 'Prueba', ...body }, t);
const avance = async (t) => (await s.api('GET', '/v1/goals/progress', null, t)).body;
const meta = (progress, category) => progress.goals.find((g) => g.category === category);

// ===========================================================================
// METAS
// ===========================================================================
test('GM-01 crear una meta: responde 201 con id, categoría y límite, y aparece en el listado', async () => {
  const { accessToken: t } = await s.register('gm01@test.com');
  const r = await s.api('POST', '/v1/goals', { category: 'comida', limit: 200000 }, t);
  assert.equal(r.status, 201);
  assert.ok(r.body.id, 'la meta debe tener id');
  assert.equal(r.body.category, 'comida');
  assert.equal(r.body.limit, 200000);
  assert.equal(r.body.currency, 'COP');

  const lista = await s.api('GET', '/v1/goals', null, t);
  assert.equal(lista.status, 200);
  assert.deepEqual(lista.body.map((g) => g.id), [r.body.id]);
});

test('GM-02 no deja crear dos metas para la misma categoría (409), pero sí para otra', async () => {
  const { accessToken: t } = await s.register('gm02@test.com');
  assert.equal((await s.api('POST', '/v1/goals', { category: 'comida', limit: 100000 }, t)).status, 201);

  const dup = await s.api('POST', '/v1/goals', { category: 'comida', limit: 50000 }, t);
  assert.equal(dup.status, 409, 'la segunda meta de "comida" debía rechazarse');
  assert.ok(dup.body.error, 'el 409 debe traer el campo error');

  assert.equal((await s.api('POST', '/v1/goals', { category: 'transporte', limit: 50000 }, t)).status, 201, 'otra categoría sí se permite');

  // También aplica a la meta sobre el gasto total (sin categoría): solo puede haber una.
  assert.equal((await s.api('POST', '/v1/goals', { limit: 900000 }, t)).status, 201);
  assert.equal((await s.api('POST', '/v1/goals', { limit: 800000 }, t)).status, 409, 'dos metas generales deben rechazarse');

  const lista = await s.api('GET', '/v1/goals', null, t);
  assert.equal(lista.body.length, 3, 'el intento duplicado no debió crear nada');
});

test('GM-03 el avance calcula porcentaje y estado: ok (<80 %), warning (80-99 %) y exceeded (>=100 %)', async () => {
  const { accessToken: t } = await s.register('gm03@test.com');
  // [categoría, límite, gastado, porcentaje esperado, estado esperado]
  const casos = [
    ['cero', 100000, 0, 0, 'ok'],
    ['mitad', 100000, 50000, 50, 'ok'],
    ['casi-warning', 100000, 79000, 79, 'ok'],       // justo debajo del umbral
    ['umbral', 100000, 80000, 80, 'warning'],         // el 80 % exacto ya es advertencia
    ['casi-limite', 100000, 99000, 99, 'warning'],
    ['limite', 100000, 100000, 100, 'exceeded'],      // el 100 % exacto ya cuenta como superado
    ['pasada', 100000, 150000, 150, 'exceeded'],
  ];
  for (const [category, limit] of casos) await s.api('POST', '/v1/goals', { category, limit }, t);
  for (const [category, , gastado] of casos) {
    if (gastado > 0) assert.equal((await gasto(t, { amount: gastado, category })).status, 201);
  }

  const p = await avance(t);
  for (const [category, limit, gastado, porcentaje, estado] of casos) {
    const g = meta(p, category);
    assert.ok(g, `no aparece la meta "${category}" en el avance`);
    assert.equal(g.spent, gastado, `${category}: gastado`);
    assert.equal(g.remaining, limit - gastado, `${category}: lo que queda`);
    assert.equal(g.percent, porcentaje, `${category}: porcentaje`);
    assert.equal(g.status, estado, `${category}: estado con ${porcentaje} %`);
  }
  assert.equal(meta(p, 'pasada').daily_allowance, 0, 'una meta superada no deja gasto diario disponible');
});

test('GM-04 el avance solo cuenta gastos aprobados o pendientes (no declinados ni reembolsados) y de la categoría', async () => {
  const { accessToken: t } = await s.register('gm04@test.com');
  await s.api('POST', '/v1/goals', { category: 'comida', limit: 100000 }, t);
  await s.api('POST', '/v1/goals', { limit: 1000000 }, t); // meta general
  await gasto(t, { amount: 10000, category: 'comida' });
  await gasto(t, { amount: 5000, category: 'comida', status: 'pending' });
  await gasto(t, { amount: 40000, category: 'comida', status: 'declined' });
  await gasto(t, { amount: 30000, category: 'comida', status: 'refunded' });
  await gasto(t, { amount: 20000, category: 'transporte' });

  const p = await avance(t);
  assert.equal(meta(p, 'comida').spent, 15000, 'solo cuentan la aprobada y la pendiente');
  assert.equal(meta(p, null).spent, 35000, 'la meta general suma todas las categorías que cuentan');
});

test('GM-05 borrar una meta: 204, deja de aparecer en el listado y en el avance, y borrarla otra vez da 404', async () => {
  const { accessToken: t } = await s.register('gm05@test.com');
  const g = await s.api('POST', '/v1/goals', { category: 'comida', limit: 100000 }, t);

  assert.equal((await s.api('DELETE', `/v1/goals/${g.body.id}`, null, t)).status, 204);
  assert.deepEqual((await s.api('GET', '/v1/goals', null, t)).body, []);
  assert.deepEqual((await avance(t)).goals, []);
  assert.equal((await s.api('DELETE', `/v1/goals/${g.body.id}`, null, t)).status, 404, 'ya no existe');

  // Al borrarla, la categoría queda libre para crear otra meta.
  assert.equal((await s.api('POST', '/v1/goals', { category: 'comida', limit: 70000 }, t)).status, 201);
});

// ===========================================================================
// REPORTES
// ===========================================================================
test('RP-01 reporte diario: trae todos los días del rango, también los de gasto 0', async () => {
  const { accessToken: t } = await s.register('rp01@test.com');
  const at = (d) => `${d}T17:00:00Z`; // mediodía en Bogotá
  await gasto(t, { amount: 12000, category: 'comida', occurred_at: at('2026-05-12') });
  await gasto(t, { amount: 8000, category: 'comida', occurred_at: at('2026-05-14') });

  const r = await s.api('GET', `/v1/reports/daily?tz=${TZ}&from=2026-05-10&to=2026-05-16`, null, t);
  assert.equal(r.status, 200);
  const { days, summary } = r.body;
  assert.equal(days.length, 7, 'del 10 al 16 son 7 días, con o sin gasto');
  assert.deepEqual(days.map((d) => d.date),
    ['2026-05-10', '2026-05-11', '2026-05-12', '2026-05-13', '2026-05-14', '2026-05-15', '2026-05-16']);
  assert.deepEqual(days.map((d) => d.total), [0, 0, 12000, 0, 8000, 0, 0]);

  const vacio = days[0];
  assert.equal(vacio.count, 0);
  assert.deepEqual(vacio.by_category, {});
  assert.deepEqual(vacio.by_type, { card: 0, cash: 0 });
  assert.equal(summary.total, 20000);
  assert.equal(summary.zero_days, 5, 'cinco de los siete días no tuvieron gasto');
});

test('RP-02 reporte diario sin parámetros: devuelve los últimos 30 días hasta hoy; un usuario sin gastos ve 30 días en 0', async () => {
  const { accessToken: t } = await s.register('rp02@test.com');
  const r = await s.api('GET', '/v1/reports/daily', null, t);
  assert.equal(r.status, 200);
  const hoy = dayKey(new Date(), TZ);
  assert.equal(r.body.days.length, 30);
  assert.equal(r.body.to, hoy);
  assert.equal(r.body.days.at(-1).date, hoy, 'el último día es hoy');
  assert.equal(r.body.days[0].date, addDays(hoy, -29));
  assert.ok(r.body.days.every((d) => d.total === 0 && d.count === 0), 'sin gastos, todos los días valen 0');
  assert.equal(r.body.summary.zero_days, 30);
  assert.equal(r.body.summary.total, 0);
});

test('RP-03 reporte semanal: trae todas las semanas pedidas (lunes a domingo), también las de gasto 0', async () => {
  const { accessToken: t } = await s.register('rp03@test.com');
  await gasto(t, { amount: 30000, category: 'comida' }); // hoy

  const r = await s.api('GET', '/v1/reports/weekly?weeks=6', null, t);
  assert.equal(r.status, 200);
  const { weeks, summary } = r.body;
  assert.equal(weeks.length, 6, 'se pidieron 6 semanas: deben venir las 6');

  const hoy = dayKey(new Date(), TZ);
  assert.equal(weeks.at(-1).start, weekStart(hoy), 'la última semana es la actual y empieza el lunes');
  weeks.forEach((w, i) => {
    assert.equal(w.end, addDays(w.start, 6), `semana ${i + 1}: debe durar 7 días`);
    if (i > 0) assert.equal(w.start, addDays(weeks[i - 1].start, 7), `semana ${i + 1}: debe seguir a la anterior sin huecos`);
  });

  assert.equal(weeks.at(-1).total, 30000);
  for (const w of weeks.slice(0, -1)) {
    assert.equal(w.total, 0, `la semana ${w.start} no tuvo gasto y debe valer 0`);
    assert.equal(w.count, 0);
  }
  assert.equal(weeks.at(-1).change_pct, null, 'sin gasto la semana anterior no hay variación que calcular');
  assert.equal(summary.total, 30000);
});

test('RP-04 reporte semanal: un usuario sin gastos recibe igualmente todas las semanas en 0', async () => {
  const { accessToken: t } = await s.register('rp04@test.com');
  for (const n of [1, 4, 12]) {
    const r = await s.api('GET', `/v1/reports/weekly?weeks=${n}`, null, t);
    assert.equal(r.body.weeks.length, n, `weeks=${n}`);
    assert.ok(r.body.weeks.every((w) => w.total === 0));
  }
  assert.equal((await s.api('GET', '/v1/reports/weekly', null, t)).body.weeks.length, 8, 'por defecto son 8 semanas');
});

// ===========================================================================
// CATEGORÍAS
// ===========================================================================
test('CT-01 un gasto guardado con categoría la devuelve al crearlo y al consultarlo', async () => {
  const { accessToken: t } = await s.register('ct01@test.com');
  const c = await gasto(t, { amount: 9000, category: 'comida' });
  assert.equal(c.status, 201);
  assert.equal(c.body.category, 'comida', 'la respuesta del POST ya trae la categoría');

  const r = await s.api('GET', `/v1/transactions/${c.body.id}`, null, t);
  assert.equal(r.body.category, 'comida', 'GET por id');
  const lista = await s.api('GET', '/v1/transactions', null, t);
  assert.equal(lista.body.items[0].category, 'comida', 'GET del listado');

  const sin = await gasto(t, { amount: 1000 });
  assert.equal(sin.body.category, null, 'sin categoría se guarda como null');

  const cambio = await s.api('PATCH', `/v1/transactions/${c.body.id}`, { category: 'transporte' }, t);
  assert.equal(cambio.body.category, 'transporte', 'la categoría se puede editar');
});

test('CT-02 el filtro por categoría devuelve solo los gastos de esa categoría', async () => {
  const { accessToken: t } = await s.register('ct02@test.com');
  await gasto(t, { amount: 1000, category: 'comida' });
  await gasto(t, { amount: 2000, category: 'comida' });
  await gasto(t, { amount: 3000, category: 'transporte' });
  await gasto(t, { amount: 4000 }); // sin categoría

  const comida = await s.api('GET', '/v1/transactions?category=comida', null, t);
  assert.equal(comida.status, 200);
  assert.equal(comida.body.total, 2);
  assert.deepEqual(comida.body.items.map((x) => x.amount).sort(), [1000, 2000]);
  assert.ok(comida.body.items.every((x) => x.category === 'comida'));

  const transporte = await s.api('GET', '/v1/transactions?category=transporte', null, t);
  assert.deepEqual(transporte.body.items.map((x) => x.amount), [3000]);

  const ninguna = await s.api('GET', '/v1/transactions?category=no-existe', null, t);
  assert.equal(ninguna.body.total, 0);
  assert.deepEqual(ninguna.body.items, []);

  assert.equal((await s.api('GET', '/v1/transactions', null, t)).body.total, 4, 'sin filtro vienen todos');

  const resumen = await s.api('GET', '/v1/transactions/summary', null, t);
  assert.deepEqual(resumen.body.by_category, { comida: 3000, transporte: 3000, sin_categoria: 4000 });
});

// ===========================================================================
// SESIÓN
// ===========================================================================
test('SE-01 refrescar con un refreshToken ya usado da 401; el par nuevo sí funciona', async () => {
  const reg = await s.register('se01@test.com');
  const primero = await s.api('POST', '/v1/auth/refresh', { refreshToken: reg.refreshToken });
  assert.equal(primero.status, 200);
  assert.ok(primero.body.accessToken && primero.body.refreshToken);
  assert.notEqual(primero.body.refreshToken, reg.refreshToken, 'el refresh debe rotar');

  const reuso = await s.api('POST', '/v1/auth/refresh', { refreshToken: reg.refreshToken });
  assert.equal(reuso.status, 401, 'un refreshToken es de un solo uso');
  assert.ok(reuso.body.error);

  assert.equal((await s.api('GET', '/v1/transactions', null, primero.body.accessToken)).status, 200, 'el accessToken nuevo funciona');
  assert.equal((await s.api('POST', '/v1/auth/refresh', { refreshToken: primero.body.refreshToken })).status, 200, 'el refreshToken nuevo también');
});

test('SE-02 cerrar sesión invalida el accessToken (401 en las rutas protegidas)', async () => {
  const reg = await s.register('se02@test.com');
  assert.equal((await s.api('GET', '/v1/transactions', null, reg.accessToken)).status, 200, 'antes de cerrar sesión funciona');

  const out = await s.api('POST', '/v1/auth/logout', {}, reg.accessToken);
  assert.equal(out.status, 204);

  for (const ruta of ['/v1/transactions', '/v1/goals', '/v1/reports/daily']) {
    assert.equal((await s.api('GET', ruta, null, reg.accessToken)).status, 401, `${ruta} aún acepta el token tras cerrar sesión`);
  }
});

// HALLAZGO ABIERTO: hoy POST /v1/auth/logout solo revoca el accessToken y el refreshToken de la
// sesión sigue funcionando (/auth/refresh responde 200). Esta prueba describe el comportamiento
// correcto, así que falla hasta que se corrija. Va marcada como `todo` para que no rompa
// `npm test` mientras tanto: cuando se arregle, QUITAR la opción `todo` para que vuelva a proteger.
test('SE-03 cerrar sesión también invalida el refreshToken: no se puede reabrir la sesión con él',
  { todo: 'Error conocido: el logout no revoca el refreshToken (ver descripción del PR)' }, async () => {
  const reg = await s.register('se03@test.com');
  await s.api('POST', '/v1/auth/logout', {}, reg.accessToken);
  const r = await s.api('POST', '/v1/auth/refresh', { refreshToken: reg.refreshToken });
  assert.equal(r.status, 401, 'tras cerrar sesión, el refreshToken de esa sesión debería dejar de servir');
});

test('SE-04 logout con { all: true } invalida todas las sesiones del usuario (access y refresh)', async () => {
  const a = await s.register('se04@test.com');
  // Segunda sesión (otro dispositivo): login + código del Authenticator.
  const l = await s.api('POST', '/v1/auth/login', { email: 'se04@test.com', password: PW });
  assert.equal(l.body.mfaRequired, true);
  const b = await s.api('POST', '/v1/auth/login/mfa', { mfaToken: l.body.mfaToken, code: totpFor(a.totpSecret, 1) });
  assert.equal(b.status, 200);
  assert.equal((await s.api('GET', '/v1/transactions', null, b.body.accessToken)).status, 200);

  assert.equal((await s.api('POST', '/v1/auth/logout', { all: true }, a.accessToken)).status, 204);

  assert.equal((await s.api('GET', '/v1/transactions', null, a.accessToken)).status, 401, 'sesión A (access)');
  assert.equal((await s.api('GET', '/v1/transactions', null, b.body.accessToken)).status, 401, 'sesión B (access)');
  assert.equal((await s.api('POST', '/v1/auth/refresh', { refreshToken: a.refreshToken })).status, 401, 'sesión A (refresh)');
  assert.equal((await s.api('POST', '/v1/auth/refresh', { refreshToken: b.body.refreshToken })).status, 401, 'sesión B (refresh)');
});

// ===========================================================================
// RECUPERACIÓN
// ===========================================================================
test('RC-01 /auth/recover cambia la contraseña: la anterior deja de servir y la nueva sí', async () => {
  const reg = await s.register('rc01@test.com');
  const r = await s.api('POST', '/v1/auth/recover', { email: 'rc01@test.com', recoveryKey: reg.recoveryKey, newPassword: NUEVA });
  assert.equal(r.status, 200);

  const vieja = await s.api('POST', '/v1/auth/login', { email: 'rc01@test.com', password: PW });
  assert.equal(vieja.status, 401, 'la contraseña anterior no debe iniciar sesión');
  const nueva = await s.api('POST', '/v1/auth/login', { email: 'rc01@test.com', password: NUEVA });
  assert.equal(nueva.status, 200, 'la contraseña nueva debe iniciar sesión');
});

test('RC-02 /auth/recover genera una llave de recuperación nueva y la anterior deja de servir', async () => {
  const reg = await s.register('rc02@test.com');
  const r = await s.api('POST', '/v1/auth/recover', { email: 'rc02@test.com', recoveryKey: reg.recoveryKey, newPassword: NUEVA });
  assert.equal(r.status, 200);

  assert.match(r.body.recoveryKey, /^([0-9a-f]{8}-){7}[0-9a-f]{8}$/, 'formato de la llave nueva');
  assert.notEqual(r.body.recoveryKey, reg.recoveryKey, 'debe ser una llave distinta');

  const vieja = await s.api('POST', '/v1/auth/recover', { email: 'rc02@test.com', recoveryKey: reg.recoveryKey, newPassword: 'tercera-clave-789' });
  assert.equal(vieja.status, 401, 'la llave anterior ya no sirve');

  const nueva = await s.api('POST', '/v1/auth/recover', { email: 'rc02@test.com', recoveryKey: r.body.recoveryKey, newPassword: 'tercera-clave-789' });
  assert.equal(nueva.status, 200, 'la llave nueva sí sirve');
  assert.notEqual(nueva.body.recoveryKey, r.body.recoveryKey, 'y cada recuperación vuelve a rotarla');
});

test('RC-03 tras recuperar, el MFA se reinicia: devuelve un QR nuevo, el Authenticator viejo no sirve y no hay sesión hasta confirmar', async () => {
  const reg = await s.register('rc03@test.com');
  const r = await s.api('POST', '/v1/auth/recover', { email: 'rc03@test.com', recoveryKey: reg.recoveryKey, newPassword: NUEVA });
  assert.equal(r.body.mfaSetupRequired, true);
  assert.ok(r.body.mfaToken && r.body.mfaSetup.qrCode && r.body.mfaSetup.secret);
  assert.equal(r.body.accessToken, undefined, 'recuperar no entrega sesión por sí solo');
  assert.notEqual(r.body.mfaSetup.secret, reg.totpSecret, 'el secreto del Authenticator es nuevo');

  const conViejo = await s.api('POST', '/v1/auth/mfa/setup/confirm', { mfaToken: r.body.mfaToken, code: totpFor(reg.totpSecret, 1) });
  assert.equal(conViejo.status, 401, 'el código del Authenticator anterior no debe servir');

  const conNuevo = await s.api('POST', '/v1/auth/mfa/setup/confirm', { mfaToken: r.body.mfaToken, code: totpFor(r.body.mfaSetup.secret) });
  assert.equal(conNuevo.status, 200);
  assert.ok(conNuevo.body.accessToken && conNuevo.body.refreshToken);
});

test('RC-04 recuperar cierra las sesiones abiertas (access y refresh anteriores dejan de servir)', async () => {
  const reg = await s.register('rc04@test.com');
  assert.equal((await s.api('GET', '/v1/transactions', null, reg.accessToken)).status, 200);

  await s.api('POST', '/v1/auth/recover', { email: 'rc04@test.com', recoveryKey: reg.recoveryKey, newPassword: NUEVA });
  assert.equal((await s.api('GET', '/v1/transactions', null, reg.accessToken)).status, 401);
  assert.equal((await s.api('POST', '/v1/auth/refresh', { refreshToken: reg.refreshToken })).status, 401);
});

test('RC-05 recuperar conserva los datos: los gastos y metas de antes se pueden leer con la contraseña nueva', async () => {
  const reg = await s.register('rc05@test.com');
  const g = await gasto(reg.accessToken, { merchant: 'Antes de recuperar', amount: 77000, category: 'comida' });
  await s.api('POST', '/v1/goals', { category: 'comida', limit: 300000 }, reg.accessToken);

  const r = await s.api('POST', '/v1/auth/recover', { email: 'rc05@test.com', recoveryKey: reg.recoveryKey, newPassword: NUEVA });
  const c = await s.api('POST', '/v1/auth/mfa/setup/confirm', { mfaToken: r.body.mfaToken, code: totpFor(r.body.mfaSetup.secret) });
  assert.equal(c.status, 200);

  const t = await s.api('GET', `/v1/transactions/${g.body.id}`, null, c.body.accessToken);
  assert.equal(t.status, 200);
  assert.equal(t.body.merchant, 'Antes de recuperar');
  assert.equal(t.body.amount, 77000);
  const metas = await s.api('GET', '/v1/goals', null, c.body.accessToken);
  assert.equal(metas.body.length, 1);
});

test('RC-06 datos inválidos en /auth/recover: llave o correo incorrectos dan 401; contraseña corta o campos de más, 400', async () => {
  const reg = await s.register('rc06@test.com');
  const base = { email: 'rc06@test.com', recoveryKey: reg.recoveryKey, newPassword: NUEVA };

  const mala = await s.api('POST', '/v1/auth/recover', { ...base, recoveryKey: '00000000-'.repeat(7) + '00000000' });
  assert.equal(mala.status, 401, 'llave incorrecta');
  const basura = await s.api('POST', '/v1/auth/recover', { ...base, recoveryKey: 'no-es-una-llave' });
  assert.equal(basura.status, 401, 'llave con formato inválido');
  const otroCorreo = await s.api('POST', '/v1/auth/recover', { ...base, email: 'nadie@test.com' });
  assert.equal(otroCorreo.status, 401, 'correo inexistente');
  assert.equal(otroCorreo.body.error, mala.body.error, 'mismo mensaje: no revela si el correo existe');

  assert.equal((await s.api('POST', '/v1/auth/recover', { ...base, newPassword: 'corta' })).status, 400, 'contraseña de menos de 10 caracteres');
  assert.equal((await s.api('POST', '/v1/auth/recover', { email: base.email })).status, 400, 'faltan campos');

  // Los intentos fallidos no gastan la llave: la correcta sigue funcionando.
  assert.equal((await s.api('POST', '/v1/auth/recover', base)).status, 200);
});