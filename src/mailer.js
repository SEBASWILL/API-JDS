import nodemailer from 'nodemailer';

/**
 * Envío de correos con Gmail (contraseña de aplicación).
 * Sin GMAIL_USER / GMAIL_APP_PASSWORD (desarrollo) el código se imprime en consola.
 * Cualquier objeto con `sendVerificationCode(to, code)` sirve como mailer (las pruebas usan uno falso).
 */
export function createMailer(config) {
  if (!config.gmailUser || !config.gmailAppPassword) {
    console.warn('[mailer] GMAIL_USER / GMAIL_APP_PASSWORD no configurados: los códigos se mostrarán en consola');
    return {
      async sendVerificationCode(to, code) {
        console.log(`[mailer] código de verificación para ${to}: ${code}`);
      },
    };
  }

  const transport = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: config.gmailUser, pass: config.gmailAppPassword },
  });
  const from = config.mailFrom || `${config.mfaIssuer} <${config.gmailUser}>`;
  const minutes = Math.round(config.emailCodeTtlSec / 60);

  return {
    async sendVerificationCode(to, code) {
      await transport.sendMail({
        from,
        to,
        subject: `${code} es tu código de verificación de ${config.mfaIssuer}`,
        text: `Tu código de verificación es ${code}.\n\nVence en ${minutes} minutos. Si no creaste una cuenta, ignora este correo.`,
        html: `<p>Tu código de verificación es:</p>
<p style="font-size:28px;font-weight:bold;letter-spacing:6px;font-family:monospace">${code}</p>
<p>Vence en ${minutes} minutos. Si no creaste una cuenta, ignora este correo.</p>`,
      });
    },
  };
}
