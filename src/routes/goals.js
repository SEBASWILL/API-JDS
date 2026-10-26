import { Router } from 'express';
import { z } from 'zod';
import { ah, requireAuth } from '../middleware.js';
import { newId, encrypt, decrypt } from '../crypto.js';
import { amountSchema, listTx, counts } from '../tx.js';
import { tzSchema, dayKey, daysInMonth } from '../dates.js';

const r2 = (n) => Math.round(n * 100) / 100;
// El monto límite y la categoría van dentro del bloque cifrado, igual que las transacciones.
const aad = (userId, id) => `goal:${userId}:${id}`;
const seal = (dek, userId, id, p) => encrypt(dek, Buffer.from(JSON.stringify(p)), aad(userId, id));
function open(dek, row) {
  try {
    return { id: row.id, ...JSON.parse(decrypt(dek, row.data, aad(row.user_id, row.id)).toString()) };
  } catch {
    const e = new Error('goal integrity');
    e.code = 'TX_INTEGRITY';
    throw e;
  }
}
const pub = (g) => ({ id: g.id, category: g.category, limit: g.limit, currency: g.currency, created_at: g.created_at, updated_at: g.updated_at });

// category vacía o ausente = meta sobre el gasto total del mes.
const shape = { category: z.string().trim().max(60).nullish().transform((v) => v || null), limit: amountSchema };
const createSchema = z.object(shape).strict();
const updateSchema = z.object(shape).partial().strict()
  .refine((o) => Object.keys(o).length > 0, { message: 'Envía al menos un campo' });

export function goalsRouter(db, config) {
  const r = Router();
  r.use(requireAuth(db));

  const all = (req) =>
    db.prepare('SELECT * FROM goals WHERE user_id = ?').all(req.auth.userId)
      .map((row) => open(req.auth.dek, row))
      .sort((a, b) => (a.created_at < b.created_at ? -1 : 1));
  const taken = (goals, category, exceptId) => goals.some((g) => g.category === category && g.id !== exceptId);

  r.post('/', ah(async (req, res) => {
    const b = createSchema.parse(req.body);
    const category = b.category ?? null;
    if (taken(all(req), category)) return res.status(409).json({ error: 'Ya tienes una meta para esa categoría' });
    const id = newId();
    const now = new Date().toISOString();
    const payload = { category, limit: b.limit, currency: 'COP', created_at: now, updated_at: now };
    db.prepare('INSERT INTO goals (id,user_id,data) VALUES (?,?,?)')
      .run(id, req.auth.userId, seal(req.auth.dek, req.auth.userId, id, payload));
    res.status(201).json(pub({ id, ...payload }));
  }));

  r.get('/', ah(async (req, res) => res.json(all(req).map(pub))));

  // Avance del mes en curso (en la zona horaria del usuario). Se declara antes de /:id.
  r.get('/progress', ah(async (req, res) => {
    const q = z.object({ tz: tzSchema }).parse(req.query);
    const tz = q.tz || config.defaultTz;
    const today = dayKey(new Date(), tz);
    const month = today.slice(0, 7);
    const [y, m, d] = today.split('-').map(Number);
    const dim = daysInMonth(y, m);
    const left = dim - d + 1; // incluye hoy

    const spentTx = listTx(db, req.auth.userId, req.auth.dek).filter(counts)
      .filter((t) => dayKey(new Date(t.occurred_at), tz).startsWith(month));

    const goals = all(req)
      .sort((a, b) => (a.category === null ? -1 : b.category === null ? 1 : a.category.localeCompare(b.category)))
      .map((g) => {
        const spent = r2(spentTx.reduce((a, t) => a + (g.category === null || t.category === g.category ? t.amount : 0), 0));
        const remaining = r2(g.limit - spent);
        const ratio = spent / g.limit;
        return {
          id: g.id, category: g.category, limit: g.limit, spent, remaining,
          percent: Math.round(ratio * 100),
          status: ratio >= 1 ? 'exceeded' : ratio >= 0.8 ? 'warning' : 'ok',
          daily_allowance: remaining > 0 ? Math.round(remaining / left) : 0,
          projected: Math.round((spent / d) * dim),
        };
      });
    res.json({ month, days_in_month: dim, days_elapsed: d, days_left: left, goals });
  }));

  r.patch('/:id', ah(async (req, res) => {
    const row = db.prepare('SELECT * FROM goals WHERE id = ? AND user_id = ?').get(req.params.id, req.auth.userId);
    if (!row) return res.status(404).json({ error: 'No encontrado' });
    const changes = updateSchema.parse(req.body);
    const { id, ...current } = open(req.auth.dek, row);
    const next = { ...current, updated_at: new Date().toISOString() };
    if ('limit' in changes) next.limit = changes.limit;
    if ('category' in changes) {
      next.category = changes.category ?? null;
      if (taken(all(req), next.category, id)) return res.status(409).json({ error: 'Ya tienes una meta para esa categoría' });
    }
    db.prepare('UPDATE goals SET data = ? WHERE id = ? AND user_id = ?')
      .run(seal(req.auth.dek, req.auth.userId, id, next), id, req.auth.userId);
    res.json(pub({ id, ...next }));
  }));

  r.delete('/:id', ah(async (req, res) => {
    const info = db.prepare('DELETE FROM goals WHERE id = ? AND user_id = ?').run(req.params.id, req.auth.userId);
    if (!info.changes) return res.status(404).json({ error: 'No encontrado' });
    res.status(204).end();
  }));

  return r;
}
