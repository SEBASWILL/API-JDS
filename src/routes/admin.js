import { Router } from 'express';
import { z } from 'zod';
import { ah, requireAuth } from '../middleware.js';
import { emailLookup } from '../crypto.js';
import { tzSchema, dayKey, addDays, daysBetween } from '../dates.js';

// Panel del administrador: SOLO metadatos. El admin no tiene la llave de nadie, así que no puede
// ver montos, comercios, categorías, correos ni la fecha de los gastos (todo sigue cifrado).
// Lo que sí ve: cuántas cuentas hay, su estado, cuántas transacciones y metas se registran y cuándo
// (created_at = momento en que llegó a la API), actividad de sesiones; y puede eliminar cuentas.

const dateKey = z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'usa el formato AAAA-MM-DD')
  .refine((s) => !Number.isNaN(Date.parse(s + 'T00:00:00Z')), 'fecha inválida');

/** Admin = la cuenta de ADMIN_EMAIL, con el correo verificado y el Authenticator activo. */
export const isAdmin = (config, u) =>
  Boolean(config.adminLookup && u && u.email_lookup === config.adminLookup && u.email_verified_at && u.totp_enabled_at);

const r2 = (n) => Math.round(n * 100) / 100;

export function adminRouter(db, config) {
  const r = Router();
  r.use(requireAuth(db));
  r.use(ah(async (req, res, next) => {
    const me = await db.get('SELECT * FROM users WHERE id = $1', [req.auth.userId]);
    if (!isAdmin(config, me)) return res.status(403).json({ error: 'Solo para el administrador' });
    next();
  }));

  /**
   * Estadísticas en un rango de días (en la zona horaria pedida). Por defecto, los últimos 30 días.
   * ?from=AAAA-MM-DD&to=AAAA-MM-DD&tz=America/Bogota
   */
  r.get('/stats', ah(async (req, res) => {
    const q = z.object({ tz: tzSchema, from: dateKey.optional(), to: dateKey.optional() }).parse(req.query);
    const tz = q.tz || config.defaultTz;
    const to = q.to || dayKey(new Date(), tz);
    const from = q.from || addDays(to, -29);
    const span = daysBetween(from, to) + 1;
    if (span < 1 || span > 366) {
      return res.status(400).json({ error: 'Rango inválido: from debe ser menor o igual a to y máximo 366 días' });
    }
    // Margen de un día a cada lado para cubrir cualquier zona horaria; luego se filtra exacto por día.
    const lo = Date.parse(addDays(from, -1) + 'T00:00:00Z');
    const hi = Date.parse(addDays(to, 2) + 'T00:00:00Z');
    const inRange = (ms) => { if (ms == null) return null; const k = dayKey(new Date(ms), tz); return k >= from && k <= to ? k : null; };
    const now = Date.now();

    const [users, txRows, goalRows, credRows, totals] = await Promise.all([
      db.all('SELECT id, created_at, email_verified_at, totp_enabled_at FROM users'),
      db.all('SELECT user_id, created_at FROM transactions WHERE created_at >= $1 AND created_at < $2', [lo, hi]),
      db.all('SELECT user_id, created_at FROM goals WHERE created_at >= $1 AND created_at < $2', [lo, hi]),
      db.all(`SELECT user_id, kind, created_at, last_used_at FROM credentials
              WHERE (created_at >= $1 AND created_at < $2) OR (last_used_at >= $1 AND last_used_at < $2)`, [lo, hi]),
      db.get(`SELECT
                (SELECT COUNT(*) FROM transactions) AS tx_total,
                (SELECT COUNT(*) FROM transactions WHERE created_at IS NULL) AS tx_sin_fecha,
                (SELECT COUNT(DISTINCT user_id) FROM transactions) AS tx_usuarios,
                (SELECT COUNT(*) FROM goals) AS goals_total,
                (SELECT COUNT(DISTINCT user_id) FROM goals) AS goals_usuarios,
                (SELECT COUNT(*) FROM credentials WHERE kind = 'ingest' AND revoked_at IS NULL) AS ingest_activos,
                (SELECT COUNT(DISTINCT user_id) FROM credentials
                   WHERE kind IN ('access','refresh') AND revoked_at IS NULL AND expires_at > $1) AS con_sesion_abierta`, [now]),
    ]);

    // Serie diaria con todos los días del rango, incluso los que no tuvieron movimiento.
    const days = new Map(Array.from({ length: span }, (_, i) => [addDays(from, i), { registros: 0, transacciones: 0, metas: 0, logins: 0 }]));
    const bump = (key, field) => { if (key) days.get(key)[field]++; };

    const nuevos = users.filter((u) => inRange(u.created_at));
    nuevos.forEach((u) => bump(inRange(u.created_at), 'registros'));

    const txEnRango = txRows.filter((t) => inRange(t.created_at));
    txEnRango.forEach((t) => bump(inRange(t.created_at), 'transacciones'));
    const porUsuario = new Map();
    for (const t of txEnRango) porUsuario.set(t.user_id, (porUsuario.get(t.user_id) ?? 0) + 1);

    goalRows.forEach((g) => bump(inRange(g.created_at), 'metas'));

    // Cada login con la contraseña correcta crea un mfaToken (luego viene el código del Authenticator).
    const logins =credRows.filter((c) => c.kind === 'mfa' && inRange(c.created_at));
    logins.forEach((c) => bump(inRange(c.created_at), 'logins'));
    const activos = new Set([
      ...credRows.filter((c) => inRange(c.last_used_at) || inRange(c.created_at)).map((c) => c.user_id),
      ...txEnRango.map((t) => t.user_id),
    ]);

    const serie = [...days].map(([date, d]) => ({ date, ...d }));
    const pico = serie.reduce((a, d) => (d.transacciones > a.transacciones ? d : a), serie[0]);

    res.json({
      range: { from, to, tz, days: span },
      users: {
        total: users.length,
        verified: users.filter((u) => u.email_verified_at).length,
        pending_verification: users.filter((u) => !u.email_verified_at).length,
        mfa_enabled: users.filter((u) => u.totp_enabled_at).length,
        new_in_range: nuevos.length,
        active_in_range: activos.size, // usaron la API o registraron algo en el rango
        with_open_session: totals.con_sesion_abierta,
      },
      transactions: {
        total: totals.tx_total,
        in_range: txEnRango.length,
        without_registration_date: totals.tx_sin_fecha, // creadas antes de existir created_at
        users_with_transactions: totals.tx_usuarios,
        users_with_transactions_in_range: porUsuario.size,
        avg_per_day: r2(txEnRango.length / span),
        avg_per_active_user: porUsuario.size ? r2(txEnRango.length / porUsuario.size) : 0,
        max_per_user_in_range: Math.max(0, ...porUsuario.values()),
        busiest_day: pico.transacciones ? { date: pico.date, count: pico.transacciones } : null,
      },
      goals: { total: totals.goals_total, users_with_goals: totals.goals_usuarios, in_range: serie.reduce((a, d) => a + d.metas, 0) },
      sessions: { logins_in_range: logins.length, active_ingest_tokens: totals.ingest_activos },
      daily: serie,
    });
  }));

  /** Cuentas (sin correo: solo se guarda su HMAC). ?email= busca una cuenta por su correo exacto. */
  r.get('/users', ah(async (req, res) => {
    const q = z.object({ email: z.string().email().max(254).optional() }).parse(req.query);
    const rows = await db.all(
      `SELECT u.id, u.email_lookup, u.created_at, u.email_verified_at, u.totp_enabled_at,
              (SELECT COUNT(*) FROM transactions t WHERE t.user_id = u.id) AS transactions,
              (SELECT COUNT(*) FROM goals g WHERE g.user_id = u.id) AS goals,
              (SELECT MAX(GREATEST(c.created_at, COALESCE(c.last_used_at, 0))) FROM credentials c WHERE c.user_id = u.id) AS last_activity_at
       FROM users u ${q.email ? 'WHERE u.email_lookup = $1' : ''} ORDER BY u.created_at DESC`,
      q.email ? [emailLookup(q.email, config.pepper)] : [],
    );
    res.json(rows.map((u) => ({
      id: u.id,
      is_admin: isAdmin(config, u),
      created_at: u.created_at,
      email_verified: Boolean(u.email_verified_at),
      mfa_enabled: Boolean(u.totp_enabled_at),
      transactions: u.transactions,
      goals: u.goals,
      last_activity_at: u.last_activity_at,
    })));
  }));

  /** Borra la cuenta y, en cascada, sus sesiones, tokens, transacciones y metas. */
  async function deleteUser(res, user) {
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
    if (isAdmin(config, user)) return res.status(400).json({ error: 'El administrador no puede eliminarse a sí mismo' });
    const counts = await db.get(`SELECT (SELECT COUNT(*) FROM transactions WHERE user_id = $1) AS transactions,
                                        (SELECT COUNT(*) FROM goals WHERE user_id = $1) AS goals`, [user.id]);
    await db.run('DELETE FROM users WHERE id = $1', [user.id]);
    res.json({ deleted: { id: user.id, created_at: user.created_at, ...counts } });
  }

  // Se declara antes de /users/:id para que "latest" no se tome como un id.
  r.delete('/users/latest', ah(async (req, res) => {
    const users = await db.all('SELECT * FROM users ORDER BY created_at DESC');
    await deleteUser(res, users.find((u) => !isAdmin(config, u)));
  }));

  r.delete('/users/:id', ah(async (req, res) => {
    await deleteUser(res, await db.get('SELECT * FROM users WHERE id = $1', [req.params.id]));
  }));

  return r;
}
