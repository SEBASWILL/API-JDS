import { Router } from 'express';
import { z } from 'zod';
import { ah, requireAuth } from '../middleware.js';
import { createSchema, updateSchema, sealTx, openTx, STATUSES } from '../tx.js';
import { newId } from '../crypto.js';

const listQuery = z.object({
  from: z.string().datetime({ offset: true }).optional(),
  to: z.string().datetime({ offset: true }).optional(),
  status: z.enum(STATUSES).optional(),
  type: z.enum(['card', 'cash']).optional(),
  category: z.string().max(60).optional(),
  q: z.string().max(100).optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
  offset: z.coerce.number().int().min(0).default(0),
});

export function transactionsRouter(db) {
  const r = Router();
  r.use(requireAuth(db));

  const rowsOf = (userId) => db.prepare('SELECT * FROM transactions WHERE user_id = ?').all(userId);
  const getRow = (id, userId) => db.prepare('SELECT * FROM transactions WHERE id = ? AND user_id = ?').get(id, userId);

  // Como todo está cifrado, el filtrado se hace en memoria tras descifrar (suficiente para uso personal).
  function filtered(req, q) {
    return rowsOf(req.auth.userId)
      .map((row) => openTx(req.auth.dek, row))
      .filter((t) =>
        (!q.from || t.occurred_at >= new Date(q.from).toISOString()) &&
        (!q.to || t.occurred_at <= new Date(q.to).toISOString()) &&
        (!q.status || t.status === q.status) &&
        (!q.type || t.type === q.type) &&
        (!q.category || t.category === q.category) &&
        (!q.q || t.merchant.toLowerCase().includes(q.q.toLowerCase())))
      .sort((a, b) => (a.occurred_at < b.occurred_at ? 1 : -1));
  }

  r.post('/', ah(async (req, res) => {
    const b = createSchema.parse(req.body);
    const id = newId();
    const now = new Date().toISOString();
    const payload = {
      ...b,
      card: b.type === 'cash' ? null : b.card ?? null,
      description: b.description ?? null,
      category: b.category ?? null,
      occurred_at: b.occurred_at ? new Date(b.occurred_at).toISOString() : now,
      created_at: now, updated_at: now,
    };
    db.prepare('INSERT INTO transactions (id,user_id,data) VALUES (?,?,?)')
      .run(id, req.auth.userId, sealTx(req.auth.dek, req.auth.userId, id, payload));
    res.status(201).json({ id, ...payload });
  }));

  r.get('/', ah(async (req, res) => {
    const q = listQuery.parse(req.query);
    const all = filtered(req, q);
    res.json({ total: all.length, limit: q.limit, offset: q.offset, items: all.slice(q.offset, q.offset + q.limit) });
  }));

  // Resumen para la web: no cuenta las declinadas ni las reembolsadas.
  r.get('/summary', ah(async (req, res) => {
    const q = listQuery.pick({ from: true, to: true }).parse(req.query);
    const all = filtered(req, q);
    const counted = all.filter((t) => t.status === 'approved' || t.status === 'pending');
    const sum = (list) => Math.round(list.reduce((a, t) => a + t.amount, 0) * 100) / 100;
    const group = (key) => {
      const out = {};
      for (const t of counted) out[t[key] ?? 'sin_categoria'] = Math.round(((out[t[key] ?? 'sin_categoria'] ?? 0) + t.amount) * 100) / 100;
      return out;
    };
    res.json({
      total: sum(counted), count: counted.length,
      declined_count: all.filter((t) => t.status === 'declined').length,
      by_category: group('category'), by_type: group('type'),
    });
  }));

  r.get('/:id', ah(async (req, res) => {
    const row = getRow(req.params.id, req.auth.userId);
    if (!row) return res.status(404).json({ error: 'No encontrado' });
    res.json(openTx(req.auth.dek, row));
  }));

  r.patch('/:id', ah(async (req, res) => {
    const row = getRow(req.params.id, req.auth.userId);
    if (!row) return res.status(404).json({ error: 'No encontrado' });
    const changes = updateSchema.parse(req.body);
    const { id, ...current } = openTx(req.auth.dek, row);
    const next = { ...current, ...changes, updated_at: new Date().toISOString() };
    if (changes.occurred_at) next.occurred_at = new Date(changes.occurred_at).toISOString();
    if (next.type === 'cash') next.card = null;
    db.prepare('UPDATE transactions SET data = ? WHERE id = ? AND user_id = ?')
      .run(sealTx(req.auth.dek, req.auth.userId, id, next), id, req.auth.userId);
    res.json({ id, ...next });
  }));

  r.delete('/:id', ah(async (req, res) => {
    const info = db.prepare('DELETE FROM transactions WHERE id = ? AND user_id = ?').run(req.params.id, req.auth.userId);
    if (!info.changes) return res.status(404).json({ error: 'No encontrado' });
    res.status(204).end();
  }));

  return r;
}
