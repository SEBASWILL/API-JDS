import { Router } from 'express';
import { z } from 'zod';
import { ah, requireAuth } from '../middleware.js';
import { issueCredential, revokeCredential, decryptLabel } from '../keys.js';

/** Tokens de ingesta: uno por dispositivo/Atajo. Solo pueden CREAR transacciones. */
export function tokensRouter(db) {
  const r = Router();
  r.use(requireAuth(db));

  r.post('/', ah(async (req, res) => {
    const { label } = z.object({ label: z.string().trim().min(1).max(60) }).strict().parse(req.body);
    const token = await issueCredential(db, { userId: req.auth.userId, dek: req.auth.dek, kind: 'ingest', label });
    res.status(201).json({ token, note: 'Guárdalo ahora: no se puede volver a ver.' });
  }));

  r.get('/', ah(async (req, res) => {
    const rows = await db.all(`SELECT * FROM credentials WHERE user_id=$1 AND kind='ingest' AND revoked_at IS NULL ORDER BY created_at`, [req.auth.userId]);
    res.json(rows.map((c) => ({
      id: c.id, label: decryptLabel(c, req.auth.dek), created_at: c.created_at, last_used_at: c.last_used_at,
    })));
  }));

  r.delete('/:id', ah(async (req, res) => {
    const c = await db.get(`SELECT id FROM credentials WHERE id=$1 AND user_id=$2 AND kind='ingest'`, [req.params.id, req.auth.userId]);
    if (!c) return res.status(404).json({ error: 'No encontrado' });
    await revokeCredential(db, c.id);
    res.status(204).end();
  }));

  return r;
}
