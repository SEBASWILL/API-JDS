#!/usr/bin/env node
// Pobla la base de datos con ~2 semanas de transacciones y metas de DEMO para un usuario que
// YA existe (no crea usuarios, no toca su correo, contraseña, MFA ni sesiones).
//
// USO (desde la carpeta del proyecto):
//   node scripts/seed-demo.js tu-correo@ejemplo.com          pide la contraseña sin mostrarla
//   node scripts/seed-demo.js tu-correo@ejemplo.com --simular   muestra qué haría, sin escribir
//   node scripts/seed-demo.js tu-correo@ejemplo.com --limpiar    borra SOLO los datos de demo
//   --dias=N     cuántos días hacia atrás (por defecto 14)
//   --si         no pedir confirmación
//
// Variables de entorno (se leen de .env, igual que el servidor): PEPPER y DATABASE_URL.
// La escritura va en una sola transacción y solo toca filas con el prefijo de demo; para respaldos
// completos usa los backups de Supabase (Database -> Backups).
// Opcional: SEED_EMAIL, SEED_PASSWORD o SEED_RECOVERY_KEY (para no teclear la contraseña).
//
// POR QUÉ HACE FALTA LA CONTRASEÑA: todo el contenido (monto, comercio, categoría, metas) va
// cifrado con una llave del usuario (la DEK) que solo se abre con su contraseña o su llave de
// recuperación. El PEPPER por sí solo no basta. El script abre esa llave, cifra los datos con el
// mismo formato que usa la API y los inserta, así la web los lee con normalidad.
//
// Los datos de demo usan ids reconocibles (empiezan por 5eed0000-): volver a correr el script los
// reemplaza (no se duplican) y --limpiar los borra sin tocar nada de lo que el usuario registró.

import crypto from 'node:crypto';
import readline from 'node:readline';
import { loadConfig } from '../src/config.js';
import { openDb } from '../src/db.js';
import { emailLookup, encrypt, decrypt } from '../src/crypto.js';
import { unlockWithPassword, unlockWithRecovery } from '../src/keys.js';
import { sealTx, openTx, counts } from '../src/tx.js';
import { dayKey, addDays, weekStart } from '../src/dates.js';

const SEED_PREFIX = '5eed0000-';
const idTx = (i) => `${SEED_PREFIX}0000-4000-8000-${i.toString(16).padStart(12, '0')}`;
const idGoal = (i) => `${SEED_PREFIX}0000-4000-9000-${i.toString(16).padStart(12, '0')}`;

// ---------------------------------------------------------------- argumentos y utilidades
const args = process.argv.slice(2);
const flag = (n) => args.includes(n);
const opt = (n, d) => { const a = args.find((x) => x.startsWith(`${n}=`)); return a ? a.slice(n.length + 1) : d; };
const money = (n) => `$${Math.round(n).toLocaleString('es-CO')}`;
const fail = (msg) => { console.error(`\n✖ ${msg}\n`); process.exit(1); };

function preguntar(texto, { oculto = false } = {}) {
  return new Promise((ok) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: process.stdin.isTTY });
    let silenciar = false;
    const escribir = rl._writeToOutput?.bind(rl);
    if (oculto && escribir) rl._writeToOutput = (s) => { if (!silenciar) escribir(s); };
    rl.question(texto, (r) => { rl.close(); if (oculto) process.stdout.write('\n'); ok(r); });
    silenciar = oculto; // el texto de la pregunta ya se escribió; lo que se teclee no se muestra
  });
}

// Generador pseudoaleatorio con semilla: los mismos datos cada vez que se corre para el mismo usuario.
function mulberry32(a) {
  return () => {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// ---------------------------------------------------------------- catálogo de datos de demo
const CATS = {
  comida: {
    horas: [8, 21],
    tarjeta: [['Crepes & Waffles', 35000, 95000], ['Juan Valdez Café', 9000, 26000], ['Starbucks', 14000, 34000],
      ['El Corral', 28000, 68000], ['Frisby', 22000, 48000], ['Rappi', 24000, 72000], ['Subway', 17000, 32000], ['Presto', 24000, 52000]],
    efectivo: [['Almuerzo corrientazo', 12000, 18000], ['Tienda de barrio', 4000, 15000], ['Empanadas', 5000, 11000]],
  },
  mercado: {
    horas: [10, 19],
    tarjeta: [['Éxito', 45000, 170000], ['D1', 18000, 85000], ['Ara', 16000, 75000], ['Carulla', 60000, 190000], ['Olímpica', 30000, 120000]],
    efectivo: [['Plaza de mercado', 20000, 70000], ['Tienda de barrio', 6000, 22000]],
  },
  transporte: {
    horas: [6, 22],
    tarjeta: [['Uber', 9000, 38000], ['DiDi', 8000, 32000], ['Terpel', 60000, 140000], ['Recarga TuLlave', 20000, 50000], ['Parqueadero', 6000, 22000]],
    efectivo: [['Bus', 3000, 3500], ['Taxi', 8000, 25000]],
  },
  entretenimiento: {
    horas: [16, 22],
    tarjeta: [['Cine Colombia', 18000, 52000], ['Steam', 20000, 80000], ['Livepass', 55000, 140000], ['PlayStation Store', 20000, 90000]],
    efectivo: [['Bolera', 15000, 40000]],
  },
  salud: {
    horas: [9, 19],
    tarjeta: [['Farmatodo', 15000, 90000], ['Cruz Verde', 12000, 70000], ['Droguería La Rebaja', 9000, 45000]],
    efectivo: [['Droguería del barrio', 6000, 30000]],
  },
  ropa: {
    horas: [11, 20],
    tarjeta: [['Falabella', 70000, 240000], ['Arturo Calle', 80000, 230000], ['Zara', 80000, 220000], ['Decathlon', 40000, 180000]],
    efectivo: [],
  },
};
const PESOS_SEMANA = { comida: 40, transporte: 32, mercado: 10, salud: 6, entretenimiento: 6, ropa: 2, servicios: 0 };
const PESOS_FINDE = { comida: 36, entretenimiento: 26, mercado: 16, transporte: 12, ropa: 5, salud: 5, servicios: 0 };
const TARJETAS = ['Visa •••• 4242', 'Mastercard •••• 8810'];

// Hechos puntuales: [hace cuántos días, hora, comercio, monto, categoría, estado, descripción]
// "hace 0 días" = hoy. Si la hora cae en el futuro, el hecho se corre un día atrás.
const EVENTOS = [
  [11, 9, 'Netflix', 17900, 'entretenimiento', 'approved', 'Suscripción mensual'],
  [9, 10, 'Claro', 69900, 'servicios', 'approved', 'Plan de celular'],
  [6, 8, 'Spotify', 16900, 'entretenimiento', 'approved', 'Suscripción mensual'],
  [4, 11, 'Codensa', 118400, 'servicios', 'approved', 'Factura de energía'],
  [12, 15, 'Mercado Libre', 159900, 'ropa', 'declined', 'Tarjeta rechazada'],
  [7, 17, 'Falabella', 119900, 'ropa', 'refunded', 'Devolución de una compra'],
  [0, 12, 'Rappi', 38500, 'comida', 'pending', null],
];

// ---------------------------------------------------------------- generación
function generar({ dias, today, now, rng, tz }) {
  const entre = (a, b) => a + Math.floor(rng() * (b - a + 1));
  const elige = (arr) => arr[Math.floor(rng() * arr.length)];
  const aCientos = (n) => Math.round(n / 100) * 100;
  const elegirPonderado = (pesos) => {
    const total = Object.values(pesos).reduce((a, b) => a + b, 0);
    let x = rng() * total;
    for (const [k, p] of Object.entries(pesos)) { if ((x -= p) < 0) return k; }
    return Object.keys(pesos)[0];
  };
  // Bogotá no tiene horario de verano: siempre UTC-5.
  const instante = (dayStr, h, m) => new Date(`${dayStr}T${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:00-05:00`);

  const out = [];
  const agregar = (daysAgo, h, m, d) => {
    const fecha = instante(addDays(today, -daysAgo), h, m);
    if (fecha > now) return false;
    const iso = fecha.toISOString();
    out.push({
      type: d.type, merchant: d.merchant, amount: d.amount, currency: 'COP',
      card: d.type === 'cash' ? null : d.card ?? elige(TARJETAS),
      occurred_at: iso, description: d.description ?? null, status: d.status ?? 'approved',
      category: d.category, source: d.type === 'cash' ? 'manual' : (rng() < 0.7 ? 'ios-shortcut' : 'web'),
      created_at: iso, updated_at: iso,
    });
    return true;
  };

  const compra = (daysAgo, cat) => {
    const c = CATS[cat];
    const efectivo = c.efectivo.length > 0 && rng() < 0.14;
    const [merchant, min, max] = elige(efectivo ? c.efectivo : c.tarjeta);
    const amount = aCientos(min + rng() * (max - min));
    agregar(daysAgo, entre(c.horas[0], c.horas[1]), entre(0, 59), { type: efectivo ? 'cash' : 'card', merchant, amount, category: cat });
  };

  for (let daysAgo = dias - 1; daysAgo >= 0; daysAgo--) {
    const dia = addDays(today, -daysAgo);
    const dow = new Date(`${dia}T12:00:00Z`).getUTCDay(); // 0 = domingo
    const finde = dow === 0 || dow === 6;
    const n = finde ? entre(2, 4) : entre(1, 3);
    for (let k = 0; k < n; k++) compra(daysAgo, elegirPonderado(finde ? PESOS_FINDE : PESOS_SEMANA));
    // Rutina semanal: mercado grande los sábados y gasolina los viernes.
    if (dow === 6) agregar(daysAgo, entre(10, 13), entre(0, 59), { type: 'card', merchant: elige(['Éxito', 'Carulla']), amount: aCientos(110000 + rng() * 90000), category: 'mercado' });
    if (dow === 5) agregar(daysAgo, entre(17, 19), entre(0, 59), { type: 'card', merchant: 'Terpel', amount: aCientos(90000 + rng() * 50000), category: 'transporte' });
  }

  for (const [hace, hora, merchant, amount, category, status, description] of EVENTOS) {
    let d = hace;
    while (d < dias && !agregar(d, hora, entre(0, 59), { type: 'card', merchant, amount, category, status, description })) d++;
  }
  return out.sort((a, b) => (a.occurred_at < b.occurred_at ? -1 : 1));
}

// Calcula el límite de una meta para que su estado actual sea el deseado (ok / warning / exceeded).
function limiteParaEstado(gastado, estado) {
  const banda = { ok: [0.4, 0.7], warning: [0.84, 0.96], exceeded: [1.1, 1.3] }[estado];
  const medio = (banda[0] + banda[1]) / 2;
  for (const paso of [10000, 5000, 1000, 100]) {
    const limite = Math.max(paso, Math.round(gastado / medio / paso) * paso);
    const ratio = gastado / limite;
    if (ratio >= banda[0] && ratio < banda[1]) return limite;
  }
  return Math.max(100, Math.round(gastado / medio / 100) * 100);
}

const METAS = [ // categoría (null = gasto total del mes), estado deseado, límite si aún no hay gasto en el mes
  ['comida', 'ok', 450000], ['transporte', 'warning', 300000], ['entretenimiento', 'exceeded', 150000],
  ['mercado', 'ok', 700000], [null, 'ok', 2000000],
];

// ---------------------------------------------------------------- principal
const email = args.find((a) => !a.startsWith('--')) || process.env.SEED_EMAIL;

try { process.loadEnvFile(); } catch { /* sin .env: se usan las variables del sistema */ }
if (!email) fail('Falta el correo del usuario. Uso: node scripts/seed-demo.js correo@ejemplo.com');

let config;
try { config = loadConfig(); } catch (e) { fail(`${e.message}\n  Revisa que el archivo .env tenga PEPPER y DATABASE_URL.`); }

let db;
try { db = await openDb(config.databaseUrl); } catch (e) { fail(`No se pudo conectar a la base: ${e.message}\n  Revisa DATABASE_URL en .env.`); }
const host = config.databaseUrl.replace(/\/\/[^@]*@/, '//').replace(/\?.*/, ''); // sin usuario ni contraseña
const user = await db.get('SELECT * FROM users WHERE email_lookup = $1', [emailLookup(email, config.pepper)]);
if (!user) {
  const { n } = await db.get('SELECT COUNT(*) n FROM users');
  fail(`No se encontró al usuario ${email} en ${host} (la base tiene ${n} usuario(s)).\n` +
    '  Causas posibles: el correo está mal escrito, DATABASE_URL apunta a otra base, o el PEPPER\n' +
    '  no es el mismo con el que se creó la cuenta (el correo se guarda como un HMAC del PEPPER).');
}

console.log(`\nBase de datos : ${host}`);
console.log(`Usuario       : ${email}`);
console.log(`Correo verificado: ${user.email_verified_at ? 'sí' : 'NO'}   MFA activo: ${user.totp_enabled_at ? 'sí' : 'NO'}`);

// Abrir la DEK del usuario.
let dek;
if (process.env.SEED_RECOVERY_KEY) {
  dek = unlockWithRecovery(user, process.env.SEED_RECOVERY_KEY);
  if (!dek) fail('La llave de recuperación (SEED_RECOVERY_KEY) no es correcta.');
} else {
  const password = process.env.SEED_PASSWORD ?? await preguntar('Contraseña del usuario (no se muestra): ', { oculto: true });
  dek = await unlockWithPassword(user, password, config);
  if (!dek) fail('Contraseña incorrecta (o el PEPPER no coincide con el de la base).');
}
console.log('✔ Llave del usuario abierta\n');

const userId = user.id;
const seeded = (tabla) => db.all(`SELECT id FROM ${tabla} WHERE user_id = $1 AND id LIKE $2`, [userId, `${SEED_PREFIX}%`]);

if (flag('--limpiar')) {
  const tx = (await seeded('transactions')).length;
  const gl = (await seeded('goals')).length;
  if (!flag('--simular')) {
    await db.tx(async (t) => {
      await t.run('DELETE FROM transactions WHERE user_id = $1 AND id LIKE $2', [userId, `${SEED_PREFIX}%`]);
      await t.run('DELETE FROM goals WHERE user_id = $1 AND id LIKE $2', [userId, `${SEED_PREFIX}%`]);
    });
  }
  console.log(`${flag('--simular') ? '(simulación) ' : ''}Datos de demo borrados: ${tx} transacciones y ${gl} metas. Lo que el usuario registró no se tocó.`);
  await db.close();
  process.exit(0);
}

const dias = Math.min(60, Math.max(1, Number(opt('--dias', 14)) || 14));
const tz = config.defaultTz;
if (tz !== 'America/Bogota') console.log(`⚠ DEFAULT_TZ es ${tz}: las horas de demo se generan en hora de Bogotá (UTC-5).`);
const now = new Date();
const today = dayKey(now, tz);
const rng = mulberry32(parseInt(crypto.createHash('sha256').update(userId).digest('hex').slice(0, 8), 16));

const txs = generar({ dias, today, now, rng, tz });
const month = today.slice(0, 7);
const delMes = txs.filter(counts).filter((t) => dayKey(new Date(t.occurred_at), tz).startsWith(month));
const gastadoMes = (cat) => Math.round(delMes.filter((t) => cat === null || t.category === cat).reduce((a, t) => a + t.amount, 0));

// Metas: no se repite una categoría que el usuario ya tenga (la API no lo permite: 409).
const goalAad = (id) => `goal:${userId}:${id}`;
const existentes = (await db.all('SELECT * FROM goals WHERE user_id = $1 AND id NOT LIKE $2', [userId, `${SEED_PREFIX}%`]))
  .map((row) => { try { return JSON.parse(decrypt(dek, row.data, goalAad(row.id)).toString()); } catch { return null; } })
  .filter(Boolean);
const inicio = instante0(addDays(today, -(dias - 1)));
function instante0(d) { return new Date(`${d}T08:00:00-05:00`).toISOString(); }

const metas = [];
for (const [category, estado, porDefecto] of METAS) {
  if (existentes.some((g) => g.category === category)) { console.log(`• Meta "${category ?? 'total del mes'}" ya existe (creada por el usuario): se respeta y no se agrega otra.`); continue; }
  const gastado = gastadoMes(category);
  const limit = gastado >= 20000 ? limiteParaEstado(gastado, estado) : porDefecto;
  metas.push({ category, limit, currency: 'COP', created_at: inicio, updated_at: inicio });
}

// Resumen de lo que se va a escribir (mismas fórmulas que usa la API).
const porSemana = {};
for (const t of txs.filter(counts)) {
  const s = weekStart(dayKey(new Date(t.occurred_at), tz));
  porSemana[s] = (porSemana[s] ?? 0) + t.amount;
}
const porEstado = txs.reduce((a, t) => ({ ...a, [t.status]: (a[t.status] ?? 0) + 1 }), {});
console.log(`Ventana: ${addDays(today, -(dias - 1))} → ${today} (${dias} días)`);
console.log(`Transacciones a crear: ${txs.length}  (${Object.entries(porEstado).map(([k, v]) => `${v} ${k}`).join(', ')})`);
console.log(`Gasto total (aprobadas + pendientes): ${money(txs.filter(counts).reduce((a, t) => a + t.amount, 0))}`);
console.log('Por semana (lunes):');
for (const [s, v] of Object.entries(porSemana).sort()) console.log(`   ${s}  ${money(v).padStart(12)}`);
console.log(`Metas a crear: ${metas.length}   (avance del mes ${month}, lo que verá la web):`);
for (const g of metas) {
  const g2 = gastadoMes(g.category);
  const ratio = g2 / g.limit;
  const estado = ratio >= 1 ? 'exceeded' : ratio >= 0.8 ? 'warning' : 'ok';
  console.log(`   ${(g.category ?? 'TOTAL DEL MES').padEnd(16)} límite ${money(g.limit).padStart(11)}   gastado ${money(g2).padStart(11)}   ${String(Math.round(ratio * 100)).padStart(3)} %  ${estado}`);
}

if (flag('--simular')) { console.log('\n(simulación) No se escribió nada.'); await db.close(); process.exit(0); }

if (!flag('--si')) {
  const r = await preguntar(`\nSe escribirá en ${host} para ${email}. ¿Continuar? (s/N) `);
  if (!/^s/i.test(r.trim())) { console.log('Cancelado. No se escribió nada.'); await db.close(); process.exit(0); }
}

// Escritura: todo en una sola transacción (o se guarda todo o nada).
await db.tx(async (t) => {
  await t.run('DELETE FROM transactions WHERE user_id = $1 AND id LIKE $2', [userId, `${SEED_PREFIX}%`]);
  await t.run('DELETE FROM goals WHERE user_id = $1 AND id LIKE $2', [userId, `${SEED_PREFIX}%`]);
  for (const [i, tx] of txs.entries()) {
    const id = idTx(i);
    await t.run('INSERT INTO transactions (id,user_id,data) VALUES ($1,$2,$3)', [id, userId, sealTx(dek, userId, id, tx)]);
  }
  for (const [i, g] of metas.entries()) {
    const id = idGoal(i);
    await t.run('INSERT INTO goals (id,user_id,data) VALUES ($1,$2,$3)', [id, userId, encrypt(dek, Buffer.from(JSON.stringify(g)), goalAad(id))]);
  }
});

// Verificación: se vuelve a leer y descifrar todo lo escrito.
const filas = await db.all('SELECT * FROM transactions WHERE user_id = $1 AND id LIKE $2', [userId, `${SEED_PREFIX}%`]);
filas.forEach((row) => openTx(dek, row)); // lanza error si algo no descifra
const filasGl = await db.all('SELECT * FROM goals WHERE user_id = $1 AND id LIKE $2', [userId, `${SEED_PREFIX}%`]);
filasGl.forEach((row) => JSON.parse(decrypt(dek, row.data, goalAad(row.id)).toString()));
await db.close();
console.log(`\n✔ Listo: ${filas.length} transacciones y ${filasGl.length} metas guardadas y verificadas.`);
console.log('  Entra a la web con ese usuario para verlas. Para borrarlas: node scripts/seed-demo.js ' + email + ' --limpiar\n');
