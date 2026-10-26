import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';

export function openDb(file) {
  if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true });
  const db = new Database(file);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id              TEXT PRIMARY KEY,
      email_lookup    TEXT NOT NULL UNIQUE,   -- HMAC(pepper, email), no el correo
      kdf_salt        BLOB NOT NULL,
      kdf_n           INTEGER NOT NULL,
      wrapped_dek_pw  BLOB NOT NULL,          -- DEK cifrada con llave derivada de la contraseña
      wrapped_dek_rec BLOB NOT NULL,          -- DEK cifrada con la llave de recuperación
      created_at      INTEGER NOT NULL
    );

    -- Sesiones (access/refresh) y tokens de ingesta del Atajo.
    -- El secreto del token nunca se guarda; solo la DEK envuelta con él.
    CREATE TABLE IF NOT EXISTS credentials (
      id           TEXT PRIMARY KEY,
      user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      kind         TEXT NOT NULL CHECK (kind IN ('access','refresh','ingest')),
      label_enc    BLOB,
      wrapped_dek  BLOB NOT NULL,
      created_at   INTEGER NOT NULL,
      expires_at   INTEGER,
      revoked_at   INTEGER,
      last_used_at INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_cred_user ON credentials(user_id);

    -- Todo el contenido de la transacción va dentro de "data" (cifrado).
    CREATE TABLE IF NOT EXISTS transactions (
      id      TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      data    BLOB NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_tx_user ON transactions(user_id);
  `);
  return db;
}
