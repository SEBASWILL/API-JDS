import postgres from 'postgres';

/**
 * Esquema en Postgres (Supabase). Todo el contenido sensible va cifrado en columnas bytea;
 * las fechas son milisegundos desde epoch (bigint), igual que antes en SQLite.
 *
 * RLS se activa SIN políticas: la API se conecta como "postgres" (que se salta RLS), pero la
 * Data API de Supabase (roles anon/authenticated, publishable key) no puede leer ni escribir nada.
 */
export const SCHEMA = `
  CREATE TABLE IF NOT EXISTS users (
    id                    text PRIMARY KEY,
    email_lookup          text NOT NULL UNIQUE,   -- HMAC(pepper, email), no el correo
    kdf_salt              bytea NOT NULL,
    kdf_n                 integer NOT NULL,
    wrapped_dek_pw        bytea NOT NULL,         -- DEK cifrada con llave derivada de la contraseña
    wrapped_dek_rec       bytea NOT NULL,         -- DEK cifrada con la llave de recuperación
    created_at            bigint NOT NULL,
    totp_enc              bytea,                  -- secreto del Authenticator cifrado con la DEK
    totp_enabled_at       bigint,                 -- NULL = aún no confirmó el QR
    totp_last_step        bigint,                 -- último paso usado (anti-reuso de códigos)
    email_verified_at     bigint,                 -- NULL = aún no confirmó el código del correo
    email_code_hash       bytea,                  -- HMAC del código de 6 dígitos (nunca el código)
    email_code_expires_at bigint,
    email_code_attempts   integer NOT NULL DEFAULT 0,
    email_code_sent_at    bigint
  );

  -- Sesiones (access/refresh), tokens de ingesta del Atajo y tokens temporales de MFA.
  -- El secreto del token nunca se guarda; solo la DEK envuelta con él.
  CREATE TABLE IF NOT EXISTS credentials (
    id           text PRIMARY KEY,
    user_id      text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind         text NOT NULL CHECK (kind IN ('access','refresh','ingest','mfa')),
    label_enc    bytea,
    wrapped_dek  bytea NOT NULL,
    created_at   bigint NOT NULL,
    expires_at   bigint,
    revoked_at   bigint,
    last_used_at bigint,
    attempts     integer NOT NULL DEFAULT 0  -- códigos MFA fallidos con este token
  );
  CREATE INDEX IF NOT EXISTS idx_cred_user ON credentials(user_id);

  -- Todo el contenido de la transacción va dentro de "data" (cifrado).
  CREATE TABLE IF NOT EXISTS transactions (
    id      text PRIMARY KEY,
    user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    data    bytea NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_tx_user ON transactions(user_id);

  -- Metas de gasto mensual: límite y categoría van cifrados dentro de "data".
  CREATE TABLE IF NOT EXISTS goals (
    id      text PRIMARY KEY,
    user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    data    bytea NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_goals_user ON goals(user_id);

  ALTER TABLE users        ENABLE ROW LEVEL SECURITY;
  ALTER TABLE credentials  ENABLE ROW LEVEL SECURITY;
  ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;
  ALTER TABLE goals        ENABLE ROW LEVEL SECURITY;
`;

/**
 * Abre la base y crea el esquema si falta. Interfaz común (todo async, placeholders $1, $2…):
 *   get(sql, params) -> fila | undefined     all(sql, params) -> filas
 *   run(sql, params) -> { changes }          exec(sql)        close()
 *   tx(async (t) => { await t.run(…) })      transacción (t tiene get/all/run)
 *
 * url:
 *   postgres://… / postgresql://…  -> Postgres real (Supabase). Producción.
 *   pglite: o pglite:<carpeta>      -> Postgres embebido (WASM) en memoria o en disco. Tests y desarrollo.
 */
export async function openDb(url) {
  if (!url) throw new Error('Falta DATABASE_URL (cadena de conexión de Supabase)');
  const db = url.startsWith('pglite:') ? await openPglite(url.slice(7)) : openPostgres(url);
  await db.exec(SCHEMA);
  return db;
}

/** Arma get/all/run a partir de una función query(sql, params) -> { rows, changes }. */
const api = (query) => ({
  get: async (q, p = []) => (await query(q, p)).rows[0],
  all: async (q, p = []) => (await query(q, p)).rows,
  run: async (q, p = []) => ({ changes: (await query(q, p)).changes }),
});

function openPostgres(url) {
  const sql = postgres(url, {
    ssl: /localhost|127\.0\.0\.1/.test(url) ? false : 'require',
    max: 10,
    prepare: false, // compatible también con el Transaction pooler de Supabase (puerto 6543)
    onnotice: () => {}, // silencia los "ya existe, se omite" de CREATE … IF NOT EXISTS
    types: { bigint: { to: 20, from: [20], serialize: String, parse: Number } }, // ms caben en Number
  });
  const queryOn = (conn) => async (q, p) => { const r = await conn.unsafe(q, p); return { rows: [...r], changes: r.count }; };
  return {
    kind: 'postgres',
    ...api(queryOn(sql)),
    exec: async (q) => { await sql.unsafe(q); },
    /** Ejecuta fn(tx) en una transacción: o se guarda todo o nada. */
    tx: (fn) => sql.begin((t) => fn(api(queryOn(t)))),
    close: () => sql.end({ timeout: 5 }),
  };
}

async function openPglite(dataDir) {
  // Solo se instala como devDependency: en producción no se carga.
  const { PGlite, types } = await import('@electric-sql/pglite');
  const pg = new PGlite(dataDir || undefined, { parsers: { [types.INT8]: Number } });
  // PGlite devuelve bytea como Uint8Array; el resto del código espera Buffer (igual que postgres.js).
  const fix = (row) => {
    for (const k in row) if (row[k] instanceof Uint8Array) row[k] = Buffer.from(row[k].buffer, row[k].byteOffset, row[k].length);
    return row;
  };
  const queryOn = (conn) => async (q, p) => { const r = await conn.query(q, p); return { rows: r.rows.map(fix), changes: r.affectedRows ?? 0 }; };
  return {
    kind: 'pglite',
    dataDir: dataDir || null,
    ...api(queryOn(pg)),
    exec: async (q) => { await pg.exec(q); },
    tx: (fn) => pg.transaction((t) => fn(api(queryOn(t)))),
    close: () => pg.close(),
  };
}
