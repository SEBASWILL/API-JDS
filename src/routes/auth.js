import { Router } from 'express';
import { z } from 'zod';
import rateLimit from 'express-rate-limit';
import QRCode from 'qrcode';
import { ah, requireAuth } from '../middleware.js';
import { emailLookup, newId, deriveFromPassword, randomSalt } from '../crypto.js';
import {
  createUserKeys, unlockWithPassword, unlockWithRecovery, rewrapPassword, newRecoveryKey,
  issueSession, issueCredential, authenticateToken, revokeCredential, revokeAllSessions, failMfaAttempt,
} from '../keys.js';
import { newTotpSecret, sealTotp, openTotp, verifyTotp, otpauthUrl, base32Encode } from '../totp.js';

const password = z.string().min(10, 'mínimo 10 caracteres').max(200);
const email = z.string().email().max(254);
const mfaBody = z.object({
  mfaToken: z.string().max(200),
  code: z.string().max(20).transform((s) => s.replace(/\s/g, '')).pipe(z.string().regex(/^\d{6}$/, 'el código debe tener 6 dígitos')),
}).strict();

export function authRouter(db, config) {
  const r = Router();
  const limiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: config.authRateMax, standardHeaders: true, legacyHeaders: false });
  r.use(limiter);

  const findUser = (e) => db.prepare('SELECT * FROM users WHERE email_lookup = ?').get(emailLookup(e, config.pepper));
  const issueMfaToken = (userId, dek) => issueCredential(db, { userId, dek, kind: 'mfa', ttlSec: config.mfaTtlSec });

  /** Crea un secreto TOTP nuevo (sin activar) y devuelve el QR para escanearlo con el Authenticator. */
  async function startMfaSetup(userId, dek, account) {
    const secret = newTotpSecret();
    db.prepare('UPDATE users SET totp_enc=?, totp_enabled_at=NULL, totp_last_step=NULL WHERE id=?')
      .run(sealTotp(dek, userId, secret), userId);
    const url = otpauthUrl(secret, account.trim().toLowerCase(), config.mfaIssuer);
    return {
      mfaSetupRequired: true,
      mfaToken: issueMfaToken(userId, dek),
      mfaSetup: { qrCode: await QRCode.toDataURL(url), otpauthUrl: url, secret: base32Encode(secret) },
    };
  }

  /** Segundo paso: valida mfaToken + código del Authenticator y entrega la sesión. */
  const finishMfa = (enrolling) => ah(async (req, res) => {
    const body = mfaBody.parse(req.body);
    const auth = authenticateToken(db, body.mfaToken, ['mfa']);
    if (!auth) return res.status(401).json({ error: 'mfaToken inválido o vencido: inicia sesión de nuevo' });

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(auth.userId);
    if (!user.totp_enc || Boolean(user.totp_enabled_at) === enrolling) {
      return res.status(409).json({
        error: enrolling ? 'El MFA ya está activo: usa /auth/login/mfa' : 'Primero configura el MFA: usa /auth/mfa/setup/confirm',
      });
    }
    const step = verifyTotp(openTotp(auth.dek, user), body.code, user.totp_last_step);
    if (step === null) {
      failMfaAttempt(db, auth.credId, config.mfaMaxAttempts);
      return res.status(401).json({ error: 'Código incorrecto' });
    }
    revokeCredential(db, auth.credId); // el mfaToken es de un solo uso
    db.prepare('UPDATE users SET totp_last_step=?, totp_enabled_at=COALESCE(totp_enabled_at, ?) WHERE id=?')
      .run(step, Date.now(), user.id);
    res.json({ user: { id: user.id }, ...issueSession(db, user.id, auth.dek, config) });
  });

  // El registro no entrega sesión: primero hay que escanear el QR y confirmar un código.
  r.post('/register', ah(async (req, res) => {
    const body = z.object({ email, password }).strict().parse(req.body);
    if (findUser(body.email)) return res.status(409).json({ error: 'Ese correo ya está registrado' });

    const id = newId();
    const keys = await createUserKeys(id, body.password, config);
    try {
      db.prepare(`INSERT INTO users (id,email_lookup,kdf_salt,kdf_n,wrapped_dek_pw,wrapped_dek_rec,created_at)
                  VALUES (?,?,?,?,?,?,?)`)
        .run(id, emailLookup(body.email, config.pepper), keys.salt, keys.n, keys.wrappedPw, keys.wrappedRec, Date.now());
    } catch {
      return res.status(409).json({ error: 'Ese correo ya está registrado' });
    }
    res.status(201).json({
      user: { id },
      recoveryKey: keys.recoveryKey, // se muestra UNA sola vez
      ...(await startMfaSetup(id, keys.dek, body.email)),
    });
  }));

  r.post('/mfa/setup/confirm', finishMfa(true));

  // Primer paso del login: la contraseña correcta solo da un mfaToken, no la sesión.
  r.post('/login', ah(async (req, res) => {
    const body = z.object({ email, password: z.string().max(200) }).strict().parse(req.body);
    const user = findUser(body.email);
    if (!user) {
      // Trabajo equivalente para no revelar si el correo existe por tiempo de respuesta.
      await deriveFromPassword(body.password, randomSalt(), config.pepper, config.scryptN);
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }
    const dek = await unlockWithPassword(user, body.password, config);
    if (!dek) return res.status(401).json({ error: 'Credenciales inválidas' });
    // Quien aún no tiene el Authenticator configurado debe hacerlo antes de entrar.
    if (!user.totp_enabled_at) return res.json({ user: { id: user.id }, ...(await startMfaSetup(user.id, dek, body.email)) });
    res.json({ user: { id: user.id }, mfaRequired: true, mfaToken: issueMfaToken(user.id, dek) });
  }));

  r.post('/login/mfa', finishMfa(false));

  // Rotación: el refresh token se usa una vez y se cambia por un par nuevo.
  r.post('/refresh', ah(async (req, res) => {
    const { refreshToken } = z.object({ refreshToken: z.string() }).strict().parse(req.body);
    const auth = authenticateToken(db, refreshToken, ['refresh']);
    if (!auth) return res.status(401).json({ error: 'Refresh token inválido' });
    revokeCredential(db, auth.credId);
    res.json(issueSession(db, auth.userId, auth.dek, config));
  }));

  r.post('/logout', requireAuth(db), ah(async (req, res) => {
    const { all } = z.object({ all: z.boolean().optional() }).strict().parse(req.body ?? {});
    if (all) revokeAllSessions(db, req.auth.userId);
    else revokeCredential(db, req.auth.credId);
    res.status(204).end();
  }));

  r.post('/change-password', requireAuth(db), ah(async (req, res) => {
    const body = z.object({ currentPassword: z.string().max(200), newPassword: password }).strict().parse(req.body);
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.auth.userId);
    if (!(await unlockWithPassword(user, body.currentPassword, config))) {
      return res.status(401).json({ error: 'Contraseña actual incorrecta' });
    }
    const w = await rewrapPassword(user.id, req.auth.dek, body.newPassword, config);
    db.prepare('UPDATE users SET kdf_salt=?, kdf_n=?, wrapped_dek_pw=? WHERE id=?').run(w.salt, w.n, w.wrappedPw, user.id);
    revokeAllSessions(db, user.id);
    res.json({ user: { id: user.id }, ...issueSession(db, user.id, req.auth.dek, config) });
  }));

  // Olvidó la contraseña o perdió el celular: con la llave de recuperación se cambia la contraseña
  // y se vuelve a configurar el Authenticator (QR nuevo; el anterior deja de servir).
  r.post('/recover', ah(async (req, res) => {
    const body = z.object({ email, recoveryKey: z.string().max(100), newPassword: password }).strict().parse(req.body);
    const user = findUser(body.email);
    const dek = user && unlockWithRecovery(user, body.recoveryKey);
    if (!dek) return res.status(401).json({ error: 'Datos de recuperación inválidos' });

    const w = await rewrapPassword(user.id, dek, body.newPassword, config);
    const rec = newRecoveryKey(user.id, dek); // la anterior queda inválida
    db.prepare('UPDATE users SET kdf_salt=?, kdf_n=?, wrapped_dek_pw=?, wrapped_dek_rec=? WHERE id=?')
      .run(w.salt, w.n, w.wrappedPw, rec.wrappedRec, user.id);
    revokeAllSessions(db, user.id);
    res.json({ user: { id: user.id }, recoveryKey: rec.recoveryKey, ...(await startMfaSetup(user.id, dek, body.email)) });
  }));

  return r;
}
