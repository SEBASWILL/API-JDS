import { ZodError } from 'zod';
import { authenticateToken } from './keys.js';

export const ah = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

export const requireAuth = (db, kinds = ['access']) => (req, res, next) => {
  const header = req.get('authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7).trim() : null;
  const auth = token && authenticateToken(db, token, kinds);
  if (!auth) return res.status(401).json({ error: 'No autorizado' });
  req.auth = auth;
  next();
};

export function errorHandler(err, req, res, _next) {
  if (err instanceof ZodError) {
    return res.status(400).json({
      error: 'Datos inválidos',
      details: err.issues.map((i) => ({ field: i.path.join('.'), message: i.message })),
    });
  }
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'JSON inválido' });
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Cuerpo demasiado grande' });
  if (err.code === 'TX_INTEGRITY') return res.status(500).json({ error: 'Integridad de datos comprometida' });
  console.error(err);
  res.status(500).json({ error: 'Error interno' });
}
