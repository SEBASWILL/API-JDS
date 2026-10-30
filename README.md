# Gastos API

API en Node.js (Express + SQLite) con cifrado por usuario. Todo el contenido financiero
va cifrado; en la base de datos solo hay IDs y bytes aleatorios.

## Arranque
```bash
npm install
cp .env.example .env        # y pon PEPPER=$(openssl rand -hex 32)
npm test                    # 25 pruebas, incluidas las del dump de la BD y las del MFA
npm run dev
```
**PEPPER**: guárdalo fuera de la base de datos (variable de entorno del servidor / gestor de secretos).
Si lo pierdes, nadie puede iniciar sesión; si se filtra junto con la BD, pierdes esa capa extra.

## Cómo funciona el cifrado
- Cada usuario tiene una llave de datos (DEK) aleatoria de 256 bits. Cada transacción se cifra con
  AES-256-GCM usando su DEK (AAD = usuario + id, así no se pueden mover filas).
- La DEK nunca se guarda en claro. Se guarda **envuelta** de varias formas, cada una con una llave distinta:

  | Envoltura | Llave que la abre |
  |---|---|
  | Contraseña | scrypt(HMAC(PEPPER, contraseña)) |
  | Recuperación | llave aleatoria de 256 bits, mostrada una vez al registrarse |
  | Sesión (access/refresh) | secreto aleatorio del token (no se guarda) |
| MFA pendiente (`mfaToken`) | secreto aleatorio del token, vive 10 min |
  | Ingesta (Atajo) | secreto aleatorio del token (no se guarda) |

- El correo no se guarda: solo HMAC(PEPPER, correo).
- Cada usuario tiene una DEK distinta; con la de uno no se abre nada de otro.

## Endpoints (todos bajo /v1)
| Método | Ruta | Descripción |
|---|---|---|
| POST | /auth/register | `{email,password}` → `recoveryKey` (una sola vez) + `mfaToken` + QR. **Sin sesión.** |
| POST | /auth/mfa/setup/confirm | `{mfaToken,code}` → tokens (confirma que escaneó el QR) |
| POST | /auth/login | `{email,password}` → `{mfaRequired, mfaToken}` (o `mfaSetupRequired` + QR si no tiene MFA) |
| POST | /auth/login/mfa | `{mfaToken,code}` → tokens |
| POST | /auth/refresh | `{refreshToken}` → tokens nuevos (rotación) |
| POST | /auth/logout | `{all?}` |
| POST | /auth/change-password | `{currentPassword,newPassword}` |
| POST | /auth/recover | `{email,recoveryKey,newPassword}` → `recoveryKey` nueva + QR nuevo (hay que confirmarlo) |
| POST/GET/DELETE | /ingest-tokens | tokens para el Atajo (solo pueden crear transacciones) |
| POST | /ingest | lo llama el Atajo: `{merchant,amount,card,date,status?}` |
| POST/GET | /transactions | crear (tarjeta o `type:"cash"`) / listar con filtros |
| GET/PATCH/DELETE | /transactions/:id | leer, actualizar (p. ej. `status:"declined"`), borrar |
| GET | /transactions/summary | totales por categoría y tipo |
| GET | /reports/daily | `?tz&from&to` gasto por día (por defecto últimos 30), con promedio, día de mayor gasto, días sin gasto y top 5 comercios |
| GET | /reports/weekly | `?tz&weeks=8` gasto por semana (lunes a domingo) con variación frente a la semana anterior |
| POST/GET | /goals | crear (`{category?, limit}`; sin categoría = meta del total) / listar |
| GET | /goals/progress | `?tz` avance del mes: gastado, lo que queda, %, estado, gasto diario sugerido y proyección |
| PATCH/DELETE | /goals/:id | editar límite o categoría / borrar |

Estados: `approved`, `declined`, `pending`, `refunded`.
Listar admite `from,to,status,type,category,q,limit,offset`. Auth: `Authorization: Bearer <token>`.

## MFA (Microsoft Authenticator / Google Authenticator)
Obligatorio para todos. Es TOTP estándar (RFC 6238, códigos de 6 dígitos cada 30 s), así que sirve
cualquier app de autenticación; no hay que integrarse con Microsoft.

**Registro:** `POST /auth/register` responde
`{ user, recoveryKey, mfaSetupRequired: true, mfaToken, mfaSetup: { qrCode, otpauthUrl, secret } }`.
La app muestra `qrCode` (imagen PNG en `data:` URL, va directo en un `<img src>`) y el `secret` para quien
no pueda escanear. El usuario escribe el código → `POST /auth/mfa/setup/confirm` → sesión.

**Login:** `POST /auth/login` → `{ user, mfaRequired: true, mfaToken }` → el usuario escribe el código →
`POST /auth/login/mfa` → `{ user, accessToken, refreshToken, expiresIn }` (mismo formato de siempre).
Si la cuenta aún no tiene MFA, el login responde como el registro (`mfaSetupRequired` + QR).

- El `mfaToken` dura 10 minutos, es de un solo uso y se anula tras 5 códigos incorrectos. No sirve como token de acceso.
- Un código ya usado no se acepta otra vez; se tolera ±30 s de desfase de reloj.
- El secreto TOTP se guarda cifrado con la DEK del usuario (no aparece en un dump).
- `/refresh`, el resto de endpoints y los tokens de ingesta del Atajo **no** piden código.
- **Perdió el celular:** `/auth/recover` con la llave de recuperación cambia la contraseña y obliga a escanear un QR nuevo.
- `MFA_ISSUER` (opcional, por defecto `Gastos`) es el nombre que muestra la app Authenticator.

## Reportes y metas
- **Zona horaria:** los pagos se guardan en UTC. Los reportes y las metas agrupan por día con la zona que envíe el cliente en `?tz=` (por defecto `DEFAULT_TZ`, `America/Bogota`), así un pago a las 10:30 p. m. no cae en el día siguiente.
- Solo cuentan los gastos `approved` y `pending`; las declinadas y reembolsadas no suman.
- **Metas:** el límite y la categoría van cifrados igual que las transacciones (tabla `goals`). Una meta por categoría; sin categoría es la meta del total del mes. Se repiten cada mes.
- **Estado de una meta:** `ok` hasta 80 %, `warning` de 80 % a 100 %, `exceeded` al llegar al límite. `daily_allowance` = lo que queda ÷ días que faltan (contando hoy). `projected` = ritmo actual proyectado al fin de mes.
- La tabla `goals` se crea sola al arrancar: los usuarios y gastos existentes no se tocan.

## Atajo de iOS
Acción "Obtener contenido de URL": POST a `https://TU_API/v1/ingest`, encabezado
`Authorization: Bearer <token de ingesta>`, cuerpo JSON con `merchant`, `amount`, `card`, `date`
(fecha en ISO 8601 si se puede).

## Límites conocidos (decisiones del MVP)
- En la ingesta el servidor ve el dato en claro un instante (llega por HTTPS y se cifra al guardar). Es cifrado en reposo con llaves por usuario, no zero-knowledge puro.
- Filtros y sumas se hacen en memoria tras descifrar (bien para uso personal, no para millones de filas).
- Olvidar la contraseña **y** perder la llave de recuperación = datos irrecuperables (intencional).
- Pendiente para producción: HTTPS obligatorio, backups de la BD, migrar a Postgres si crece, deduplicar pagos repetidos.
