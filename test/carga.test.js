// Pruebas de CARGA y CONCURRENCIA: en vez de una petición a la vez (como en los otros archivos),
// aquí se disparan muchas peticiones AL MISMO TIEMPO con Promise.all, simulando varios usuarios
// usando la app simultáneamente. Es el mismo tipo de prueba que haría una herramienta como JMeter,
// pero escrita en el mismo lenguaje del proyecto para que corra junto a las demás con `npm test`.
//
// Qué se busca con esto, que una prueba "una petición a la vez" no puede detectar:
//   - Condiciones de carrera: dos peticiones que llegan juntas y podrían burlar una regla que,
//     una por una, siempre se cumple (ej.: "no se repite un correo", "no hay dos metas iguales").
//   - Escrituras perdidas: que bajo carga se "pierda" algún dato porque dos operaciones chocan.
//   - Cómo se comporta el tiempo de respuesta cuando crece la cantidad de peticiones simultáneas.
//
// USO:
//   node --test test/carga.test.js                 valores por defecto (rápido, SCRYPT_N bajo)
//   CARGA_N=200 node --test test/carga.test.js      sube la cantidad de peticiones simultáneas
//   CARGA_SCRYPT_N=32768 node --test test/carga.test.js   usa el costo REAL de scrypt (más lento,
//                                                          más realista; 32768 es el valor por
//                                                          defecto del servidor en producción)
//                                                          Acepta cualquier número: si no es
//                                                          potencia de 2 se usa la más cercana.
//
// Los números que se imprimen (tiempos, totales) son para que TÚ los leas e informes; las
// comprobaciones automáticas (assert) solo verifican que no se haya perdido ni duplicado nada.
//
// NOTA: el registro ahora exige verificar el correo antes de poder iniciar sesión. Estas pruebas
// usan el mailer falso de helpers.js (guarda los códigos en memoria, no envía correos reales).

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { loadConfig } from '../src/config.js';
import { openDb } from '../src/db.js';
import { createApp } from '../src/app.js';
import { emailLookup } from '../src/crypto.js';
import { registerWithMfa, mailer } from './helpers.js';

const N = Number(process.env.CARGA_N || 50);
// scrypt exige que su parámetro N sea una potencia de 2 (limitación de Node, no de la API).
// Para poder probar con cualquier número (1000, 10000, 100000...), el valor pedido en
// CARGA_SCRYPT_N se redondea a la potencia de 2 más cercana y se avisa cuál se usó.
function scryptNValido(pedido) {
  const n = Number(pedido);
  if (!Number.isFinite(n) || n <= 0) return 1024; // vacío o inválido: valor rápido por defecto
  return Math.max(2, 2 ** Math.round(Math.log2(n)));
}
const SCRYPT_PEDIDO = process.env.CARGA_SCRYPT_N;
const SCRYPT_N = String(scryptNValido(SCRYPT_PEDIDO));
if (SCRYPT_PEDIDO && SCRYPT_PEDIDO !== SCRYPT_N) {
  console.log(`   [aviso] CARGA_SCRYPT_N=${SCRYPT_PEDIDO} no es potencia de 2: se usa ${SCRYPT_N}, la más cercana`);
}
const PW = 'una-clave-larga-123';
const PEPPER = 'a'.repeat(64);

async function boot() {
  const env = { PEPPER, SCRYPT_N, AUTH_RATE_MAX: String(N * 10 + 1000), EMAIL_RESEND_COOLDOWN_SEC: '0' };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gastos-carga-'));
  const db = openDb(path.join(dir, 'test.db'));
  // El mailer falso guarda los códigos de verificación; sin él, registerWithMfa no puede
  // leer el código del correo y el registro nunca se completa.
  const app = createApp(db, loadConfig(env), { mailer });
  const server = await new Promise((ok) => { const x = app.listen(0, () => ok(x)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const api = async (method, url, body, token) => {
    const res = await fetch(base + url, {
      method,
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: body !== undefined && body !== null ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    let parsed = null;
    try { parsed = text ? JSON.parse(text) : null; } catch { parsed = text; }
    return { status: res.status, body: parsed };
  };
  const stop = () => { server.closeAllConnections?.(); server.close(); db.close(); fs.rmSync(dir, { recursive: true, force: true }); };
  return { api, db, stop };
}

// Cuántas conexiones abrir a la vez como máximo. Por defecto, todas (comportamiento "clásico" de
// esta prueba: Promise.all sin límite). Si tu máquina no aguanta tantas conexiones simultáneas
// (en Mac, el límite típico de archivos abiertos por proceso es 256: revísalo con `ulimit -n`),
// baja este número para enviarlas por tandas, como hace JMeter con su "ramp-up":
//   CARGA_CONCURRENCIA=200 CARGA_N=1000 node --test test/carga.test.js
const CONCURRENCIA = Number(process.env.CARGA_CONCURRENCIA || Infinity);

// Lanza las llamadas en tandas de hasta CONCURRENCIA a la vez, y mide cuánto tarda el total.
// Con CONCURRENCIA sin definir (Infinity), es una sola tanda: todas verdaderamente a la vez.
async function allAtOnce(fns) {
  const ini = Date.now();
  const resultados = [];
  for (let i = 0; i < fns.length; i += CONCURRENCIA) {
    const tanda = fns.slice(i, i + CONCURRENCIA);
    resultados.push(...await Promise.all(tanda.map((fn) => fn())));
  }
  return { resultados, ms: Date.now() - ini };
}
const contarPorEstado = (resultados) => resultados.reduce((acc, r) => {
  acc[r.status] = (acc[r.status] || 0) + 1;
  return acc;
}, {});

let s;
before(async () => { s = await boot(); });
after(() => s.stop());

test(`carga: ${N} registros con correos DISTINTOS, lanzados todos a la vez`, async () => {
  const emails = Array.from({ length: N }, (_, i) => `carga${i}@test.com`);
  const { resultados, ms } = await allAtOnce(
    emails.map((email) => () => s.api('POST', '/v1/auth/register', { email, password: PW })),
  );
  console.log(`   [${N} registros distintos] ${ms} ms en total, ${(ms / N).toFixed(1)} ms promedio por registro`);

  const estados = contarPorEstado(resultados);
  assert.deepEqual(estados, { 201: N }, `se esperaban ${N} códigos 201, salió ${JSON.stringify(estados)}`);

  // Se confirma contra la base: debe haber una fila por cada correo (se busca por su HMAC).
  const buscar = s.db.prepare('SELECT COUNT(*) n FROM users WHERE email_lookup = ?');
  const faltan = emails.filter((e) => buscar.get(emailLookup(e, Buffer.from(PEPPER, 'hex'))).n !== 1);
  assert.deepEqual(faltan, [], 'hay correos sin su fila en la tabla users: alguna escritura se perdió');
});

test('carga: muchos registros con el MISMO correo a la vez -> solo uno se crea (condición de carrera)', async () => {
  const email = 'mismo-correo@test.com';
  const { resultados, ms } = await allAtOnce(
    Array.from({ length: N }, () => () => s.api('POST', '/v1/auth/register', { email, password: PW })),
  );
  console.log(`   [${N} registros, mismo correo] ${ms} ms en total`);

  const estados = contarPorEstado(resultados);
  assert.equal(estados['201'], 1, `debía crearse exactamente 1 cuenta, se crearon ${estados['201'] || 0}`);
  assert.equal((estados['201'] || 0) + (estados['409'] || 0), N, `cada intento debía terminar en 201 o 409, salió ${JSON.stringify(estados)}`);

  // No basta con mirar los códigos de respuesta: se confirma también contra la base.
  const filas = s.db.prepare('SELECT COUNT(*) n FROM users WHERE email_lookup = ?')
    .get(emailLookup(email, Buffer.from(PEPPER, 'hex'))).n;
  assert.equal(filas, 1, `en la base quedaron ${filas} cuentas para el mismo correo`);
});

test('carga: varias transacciones simultáneas del mismo usuario se guardan todas y el resumen cuadra', async () => {
  const { accessToken } = await registerWithMfa(s.api, 'carga-tx@test.com');
  const montos = Array.from({ length: N }, (_, i) => 1000 + i); // montos distintos para poder rastrear pérdidas

  const { resultados, ms } = await allAtOnce(
    montos.map((amount) => () => s.api('POST', '/v1/transactions', { merchant: 'Carga', amount, category: 'prueba' }, accessToken)),
  );
  console.log(`   [${N} transacciones simultáneas] ${ms} ms en total, ${(ms / N).toFixed(1)} ms promedio`);

  const estados = contarPorEstado(resultados);
  assert.deepEqual(estados, { 201: N }, `se esperaban ${N} transacciones creadas, salió ${JSON.stringify(estados)}`);

  const ids = new Set(resultados.map((r) => r.body.id));
  assert.equal(ids.size, N, 'hay ids repetidos entre las transacciones creadas (colisión de ids)');

  // OJO con esto: /v1/transactions solo devuelve hasta 200 items por página (es una regla real
  // de la API, no un error). Para comprobar el TOTAL sin importar cuántos sean, se usa /summary,
  // que sí suma todas las transacciones del usuario sin paginar.
  const resumen = await s.api('GET', '/v1/transactions/summary', null, accessToken);
  assert.equal(resumen.body.count, N, `el resumen debía contar ${N} transacciones, contó ${resumen.body.count}`);

  const sumaEsperada = montos.reduce((a, b) => a + b, 0);
  assert.equal(resumen.body.total, sumaEsperada, 'la suma de los montos guardados no coincide: se perdió o se duplicó algo');
});

test('carga: varias metas con la MISMA categoría a la vez -> solo una se crea (condición de carrera)', async () => {
  const { accessToken } = await registerWithMfa(s.api, 'carga-metas@test.com');
  const { resultados, ms } = await allAtOnce(
    Array.from({ length: N }, () => () => s.api('POST', '/v1/goals', { category: 'comida', limit: 50000 }, accessToken)),
  );
  console.log(`   [${N} metas, misma categoría] ${ms} ms en total`);

  const estados = contarPorEstado(resultados);
  assert.equal(estados['201'], 1, `debía crearse exactamente 1 meta, se crearon ${estados['201'] || 0}`);
  assert.equal((estados['201'] || 0) + (estados['409'] || 0), N, `cada intento debía terminar en 201 o 409, salió ${JSON.stringify(estados)}`);

  const lista = await s.api('GET', '/v1/goals', null, accessToken);
  assert.equal(lista.body.filter((g) => g.category === 'comida').length, 1, 'quedó más de una meta para "comida"');
});

test('carga: muchos logins simultáneos (correctos e incorrectos mezclados) no rompen el servidor', async () => {
  const email = 'carga-login@test.com';
  const reg = await s.api('POST', '/v1/auth/register', { email, password: PW });
  assert.equal(reg.status, 201);
  // Sin verificar el correo, el login responde 403 aunque la contraseña sea correcta.
  const ver = await s.api('POST', '/v1/auth/verify-email', { email, code: mailer.lastCode(email) });
  assert.equal(ver.status, 200, 'no se pudo verificar el correo de prueba');

  const llamadas = Array.from({ length: N }, (_, i) =>
    () => s.api('POST', '/v1/auth/login', { email, password: i % 2 === 0 ? PW : 'incorrecta-123456789' }));
  const { resultados, ms } = await allAtOnce(llamadas);
  console.log(`   [${N} logins simultáneos] ${ms} ms en total, ${(ms / N).toFixed(1)} ms promedio`);

  const estados = contarPorEstado(resultados);
  assert.ok(Object.keys(estados).every((c) => Number(c) < 500), `hubo errores 500: ${JSON.stringify(estados)}`);
  // La mitad (los pares) debía entrar con la contraseña correcta.
  const correctos = resultados.filter((r) => r.status === 200 && (r.body.mfaSetupRequired || r.body.mfaRequired)).length;
  assert.equal(correctos, Math.ceil(N / 2), `se esperaban ${Math.ceil(N / 2)} logins correctos, hubo ${correctos}`);
});