# Gastos API

API en Node.js (Express + SQLite) para registrar gastos con cifrado por usuario y MFA obligatorio
(Microsoft Authenticator, Google Authenticator o cualquier app TOTP). Todo el contenido financiero va
cifrado; en la base de datos solo hay IDs y bytes aleatorios.

**Contenido**
1. [Arranque](#arranque)
2. [Conceptos: tokens y autenticación](#conceptos-tokens-y-autenticación)
3. [Flujos paso a paso](#flujos-paso-a-paso)
4. [Tipos de datos](#tipos-de-datos)
5. [Errores](#errores)
6. [Referencia de endpoints](#referencia-de-endpoints)
7. [Cómo funciona el cifrado](#cómo-funciona-el-cifrado)
8. [Límites conocidos](#límites-conocidos)

---

## Arranque

Requiere Node.js 20.6 o superior (usa `--env-file`). Probado con Node 24.

```bash
npm install
# crea .env con al menos PEPPER (ver tabla de abajo)
npm test        # 25 pruebas: API, dump de la BD, reportes, metas y MFA
npm run dev     # recarga al guardar
npm start       # producción
```

### Variables de entorno (`.env`)

| Variable | Obligatoria | Por defecto | Qué hace |
|---|---|---|---|
| `PEPPER` | **sí** | — | 64 caracteres hex. Genera uno con `npm run gen-pepper` u `openssl rand -hex 32`. |
| `PORT` | no | `3000` | Puerto HTTP. |
| `DB_PATH` | no | `./data/gastos.db` | Archivo SQLite (la carpeta se crea sola). |
| `CORS_ORIGINS` | no | vacío | Orígenes permitidos separados por coma, o `*` para todos. |
| `TRUST_PROXY` | no | — | `1` si la API está detrás de un proxy (nginx, Render, etc.) para que el límite de intentos use la IP real. |
| `AUTH_RATE_MAX` | no | `20` | Peticiones por IP cada 15 min a **todas** las rutas `/v1/auth/*`. |
| `DEFAULT_TZ` | no | `America/Bogota` | Zona horaria de reportes y metas cuando el cliente no envía `?tz=`. |
| `MFA_ISSUER` | no | `Gastos` | Nombre que muestra la app Authenticator junto al correo. |
| `SCRYPT_N` | no | `32768` | Costo de scrypt al derivar la contraseña. No lo bajes en producción. |

**PEPPER**: guárdalo fuera de la base de datos (variable de entorno del servidor o gestor de secretos).
Si lo pierdes, nadie puede iniciar sesión; si se filtra junto con la BD, pierdes esa capa extra.

Al arrancar, la API crea las tablas que falten y migra una base anterior sin perder datos.

---

## Conceptos: tokens y autenticación

Todas las rutas van bajo `/v1`. Las protegidas llevan el encabezado:

```
Authorization: Bearer <token>
```

Todos los tokens tienen la forma `<prefijo>_<id>.<secreto>` y deben tratarse como texto opaco.

| Token | Prefijo | Dura | Para qué sirve | Cómo se obtiene |
|---|---|---|---|---|
| `accessToken` | `at_` | 1 hora (`expiresIn: 3600`) | Llamar a todas las rutas protegidas. | `login/mfa`, `mfa/setup/confirm`, `refresh`, `change-password` |
| `refreshToken` | `rt_` | 30 días | Pedir un par nuevo cuando el access vence. **Un solo uso.** | Junto con el `accessToken` |
| `mfaToken` | `mt_` | 10 min | Puente entre "contraseña correcta" y "código del Authenticator". **Un solo uso**, se anula tras 5 códigos incorrectos. No sirve en ninguna otra ruta. | `register`, `login`, `recover` |
| Token de ingesta | `it_` | No vence (hasta revocarlo) | Solo `POST /v1/ingest` (Atajo de iOS). No puede leer nada. | `POST /v1/ingest-tokens` |

Reglas importantes:

- **Nunca hay sesión sin MFA.** Registro, login y recuperación devuelven solo un `mfaToken`; la sesión
  (`accessToken` + `refreshToken`) llega después de enviar un código válido del Authenticator.
- El código es de **6 dígitos** y cambia cada 30 s. Se aceptan espacios (`"123 456"`). Se tolera ±30 s
  de desfase de reloj. **Un código ya usado no se acepta otra vez**, aunque siga vigente.
- `/refresh`, las rutas de datos y los tokens de ingesta **no** piden código.
- El límite de `AUTH_RATE_MAX` (20 por defecto) cuenta **todas** las rutas `/v1/auth/*` juntas,
  incluido `/refresh`. Al pasarlo, la API responde `429`.

---

## Flujos paso a paso

### 1. Registro (obligatorio escanear el QR)

```
App                                   API
 │ POST /v1/auth/register              │
 │ { email, password }  ──────────────▶│
 │◀──── 201 { recoveryKey, mfaToken,   │
 │            mfaSetup: { qrCode, … } }│
 │                                     │
 │ (muestra la llave de recuperación y el QR;
 │  el usuario escanea y escribe el código)
 │                                     │
 │ POST /v1/auth/mfa/setup/confirm     │
 │ { mfaToken, code }  ───────────────▶│
 │◀──── 200 { accessToken,             │
 │            refreshToken, expiresIn }│
```

1. Mostrar `recoveryKey` y pedir que la guarde: **no se vuelve a mostrar** y es la única forma de
   recuperar la cuenta si olvida la contraseña o pierde el celular.
2. Mostrar `mfaSetup.qrCode` en un `<img src="...">` (ya es una `data:` URL PNG). Mostrar también
   `mfaSetup.secret` para quien no pueda escanear (se escribe a mano en la app como "clave de configuración").
   En el celular, `mfaSetup.otpauthUrl` como enlace abre la app Authenticator directamente.
3. El usuario escribe el código → `POST /v1/auth/mfa/setup/confirm`. Si el código está mal (`401`)
   puede reintentar con el mismo `mfaToken` hasta 5 veces o hasta que pasen 10 min.
4. Si el `mfaToken` vence antes de confirmar, el usuario hace login normal: como su MFA no está
   activo, el login le devuelve un QR nuevo (paso siguiente).

### 2. Login

```
POST /v1/auth/login { email, password }
  ├─ 200 { mfaRequired: true, mfaToken }          → pedir el código
  │     POST /v1/auth/login/mfa { mfaToken, code }
  │       └─ 200 { accessToken, refreshToken, expiresIn }
  │
  ├─ 200 { mfaSetupRequired: true, mfaToken, mfaSetup }
  │     (la cuenta no terminó de configurar el MFA: mostrar QR como en el registro)
  │     POST /v1/auth/mfa/setup/confirm { mfaToken, code }
  │       └─ 200 { accessToken, refreshToken, expiresIn }
  │
  └─ 401 Credenciales inválidas
```

La app debe mirar **qué campo viene** en la respuesta de `/login` (`mfaRequired` o `mfaSetupRequired`),
no solo el código HTTP: ambos casos son `200`.

### 3. Mantener la sesión (refresh)

- El `accessToken` vence en 1 hora. Cuando una ruta responde `401`, llamar a `POST /v1/auth/refresh`
  con el `refreshToken`.
- La respuesta trae un **par nuevo**; el `refreshToken` anterior queda inválido. Guardar siempre los dos nuevos.
- Si `/refresh` responde `401` (vencido, ya usado o revocado), mandar al usuario a login.
- Evita lanzar dos refresh en paralelo con el mismo token: el segundo fallará.

### 4. Cerrar sesión

- `POST /v1/auth/logout` con el `accessToken` → cierra **esa** sesión.
- Con `{ "all": true }` → cierra todas las sesiones del usuario en todos los dispositivos.
  Los tokens de ingesta del Atajo **no** se tocan.

### 5. Cambiar contraseña (logueado)

`POST /v1/auth/change-password` → cierra **todas** las sesiones y devuelve una sesión nueva para el
dispositivo actual. El MFA no cambia.

### 6. Olvidó la contraseña o perdió el celular

`POST /v1/auth/recover` con el correo, la `recoveryKey` y una contraseña nueva:

- Cambia la contraseña, genera una **llave de recuperación nueva** (la anterior deja de servir) y
  **reinicia el MFA**: el Authenticator viejo deja de funcionar.
- Cierra todas las sesiones.
- Responde igual que el registro (`recoveryKey` + QR + `mfaToken`) → confirmar con
  `POST /v1/auth/mfa/setup/confirm`.

### 7. Atajo de iOS (Apple Pay)

1. Logueado, crear un token: `POST /v1/ingest-tokens { "label": "iPhone de Ana" }` → `{ token }`
   (solo se ve una vez).
2. En el Atajo, acción "Obtener contenido de URL":
   - Método `POST`, URL `https://TU_API/v1/ingest`
   - Encabezado `Authorization: Bearer <token de ingesta>`
   - Cuerpo JSON: `merchant`, `amount`, `card`, `date` (ISO 8601 si se puede).
3. El token de ingesta solo crea transacciones; no puede leer ni borrar nada, y no pide MFA.
4. Para desactivarlo: `DELETE /v1/ingest-tokens/:id`.

### Ejemplo de cliente (JavaScript)

```js
const API = 'https://TU_API/v1';
const post = (path, body, token) => fetch(API + path, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', ...(token && { Authorization: `Bearer ${token}` }) },
  body: JSON.stringify(body),
}).then(async (r) => ({ status: r.status, body: r.status === 204 ? null : await r.json() }));

// Paso 1: contraseña
const step1 = await post('/auth/login', { email, password });
if (step1.status !== 200) throw new Error(step1.body.error);

let session;
if (step1.body.mfaRequired) {
  const code = await pedirCodigoAlUsuario();
  session = await post('/auth/login/mfa', { mfaToken: step1.body.mfaToken, code });
} else if (step1.body.mfaSetupRequired) {
  mostrarQR(step1.body.mfaSetup.qrCode, step1.body.mfaSetup.secret);
  const code = await pedirCodigoAlUsuario();
  session = await post('/auth/mfa/setup/confirm', { mfaToken: step1.body.mfaToken, code });
}
// session.body = { user, accessToken, refreshToken, expiresIn }
```

---

## Tipos de datos

Notación estilo TypeScript. `?` = campo opcional; `| null` = puede venir `null`.

```ts
type ISODateTime = string;   // "2026-10-30T15:45:17.000Z" (las respuestas siempre en UTC)
type DateKey     = string;   // "2026-10-30" (AAAA-MM-DD)
type EpochMs     = number;   // milisegundos desde 1970 (ej. 1793461517000)
type Status      = 'approved' | 'declined' | 'pending' | 'refunded';

// ---------- Auth ----------
interface User { id: string }                       // UUID

interface Session {
  user?: User;                                      // no viene en /refresh
  accessToken: string;                              // "at_xxxx.yyyy"
  refreshToken: string;                             // "rt_xxxx.yyyy"
  expiresIn: number;                                // segundos de vida del accessToken (3600)
}

interface MfaSetup {
  qrCode: string;                                   // "data:image/png;base64,..." listo para <img src>
  otpauthUrl: string;                               // "otpauth://totp/Gastos%3Aana%40correo.com?secret=...&issuer=Gastos&algorithm=SHA1&digits=6&period=30"
  secret: string;                                   // base32 (A-Z, 2-7), para escribirlo a mano
}

interface MfaSetupRequired {                        // register (201), login sin MFA (200), recover (200)
  user: User;
  recoveryKey?: string;                             // solo register y recover: "xxxxxxxx-xxxxxxxx-..." (8 grupos hex)
  mfaSetupRequired: true;
  mfaToken: string;                                 // "mt_xxxx.yyyy"
  mfaSetup: MfaSetup;
}

interface MfaRequired {                             // login con MFA activo (200)
  user: User;
  mfaRequired: true;
  mfaToken: string;
}

// ---------- Transacciones ----------
interface Transaction {
  id: string;                                       // UUID
  type: 'card' | 'cash';
  merchant: string;
  amount: number;                                   // > 0, máximo 2 decimales
  currency: string;                                 // 3 letras en mayúscula, ej. "COP"
  card: string | null;                              // siempre null si type = 'cash'
  occurred_at: ISODateTime;                         // cuándo ocurrió el pago
  description: string | null;
  status: Status;
  category: string | null;
  source: 'manual' | 'web' | 'android' | 'ios-app' | 'ios-shortcut';
  created_at: ISODateTime;
  updated_at: ISODateTime;
}

// ---------- Metas ----------
interface Goal {
  id: string;
  category: string | null;                          // null = meta sobre el gasto total del mes
  limit: number;
  currency: 'COP';
  created_at: ISODateTime;
  updated_at: ISODateTime;
}

// ---------- Errores ----------
interface ApiError {
  error: string;                                    // mensaje en español, apto para mostrar
  details?: { field: string; message: string }[];   // solo en 400 de validación
}
```

### Montos (`amount`, `limit`)

Se aceptan como número o como texto. El texto se interpreta así:

| Entrada | Resultado |
|---|---|
| `25000` | `25000` |
| `"$25.000,00"` | `25000` |
| `"COP 25,000.00"` | `25000` |
| `"25.000"` | `25000` (un separador seguido de 3 dígitos = miles) |
| `"1.234.567"` | `1234567` |
| `"12,50"` | `12.5` |
| `"abc"`, `0`, `-5` | `400` monto inválido |

---

## Errores

Todas las respuestas de error son JSON con la forma `ApiError`, salvo el `429`.

| Código | Cuándo | Cuerpo |
|---|---|---|
| `400` | Datos inválidos (campo faltante, tipo incorrecto, campo no permitido) | `{ "error": "Datos inválidos", "details": [{ "field": "amount", "message": "monto inválido" }] }` |
| `400` | El cuerpo no es JSON válido | `{ "error": "JSON inválido" }` |
| `401` | Falta el token, está vencido, revocado o es de otro tipo; credenciales o código MFA incorrectos | `{ "error": "No autorizado" }` (u otro mensaje según la ruta) |
| `404` | El recurso no existe **o es de otro usuario** (nunca se distingue) | `{ "error": "No encontrado" }` |
| `404` | Ruta inexistente | `{ "error": "Ruta no encontrada" }` |
| `409` | Conflicto (correo ya registrado, meta duplicada, paso de MFA equivocado) | `{ "error": "..." }` |
| `413` | Cuerpo mayor a 20 KB | `{ "error": "Cuerpo demasiado grande" }` |
| `429` | Demasiados intentos en `/v1/auth/*` | Texto plano `Too many requests, please try again later.` Los encabezados `RateLimit-*` indican cuándo reintentar. |
| `500` | Un dato cifrado fue alterado o movido | `{ "error": "Integridad de datos comprometida" }` |
| `500` | Error inesperado | `{ "error": "Error interno" }` |

Los cuerpos de `POST`/`PATCH` son **estrictos**: un campo que no existe en la ruta produce `400`
(excepción: `/v1/ingest`, que ignora campos desconocidos).

---

## Referencia de endpoints

Leyenda de autenticación: **—** pública · **access** `accessToken` · **ingest** token de ingesta.

| Método | Ruta | Auth | Resumen |
|---|---|---|---|
| GET | `/health` | — | Estado del servidor |
| POST | `/v1/auth/register` | — | Crear cuenta → QR |
| POST | `/v1/auth/mfa/setup/confirm` | — (`mfaToken`) | Confirmar QR → sesión |
| POST | `/v1/auth/login` | — | Contraseña → `mfaToken` |
| POST | `/v1/auth/login/mfa` | — (`mfaToken`) | Código → sesión |
| POST | `/v1/auth/refresh` | — (`refreshToken`) | Rotar tokens |
| POST | `/v1/auth/logout` | access | Cerrar sesión |
| POST | `/v1/auth/change-password` | access | Cambiar contraseña |
| POST | `/v1/auth/recover` | — | Recuperar con la llave → QR nuevo |
| POST | `/v1/ingest-tokens` | access | Crear token del Atajo |
| GET | `/v1/ingest-tokens` | access | Listar tokens del Atajo |
| DELETE | `/v1/ingest-tokens/:id` | access | Revocar token del Atajo |
| POST | `/v1/ingest` | ingest | El Atajo registra un pago |
| POST | `/v1/transactions` | access | Crear transacción |
| GET | `/v1/transactions` | access | Listar con filtros |
| GET | `/v1/transactions/summary` | access | Totales |
| GET | `/v1/transactions/:id` | access | Ver una |
| PATCH | `/v1/transactions/:id` | access | Editar |
| DELETE | `/v1/transactions/:id` | access | Borrar |
| GET | `/v1/reports/daily` | access | Gasto por día |
| GET | `/v1/reports/weekly` | access | Gasto por semana |
| POST | `/v1/goals` | access | Crear meta mensual |
| GET | `/v1/goals` | access | Listar metas |
| GET | `/v1/goals/progress` | access | Avance del mes |
| PATCH | `/v1/goals/:id` | access | Editar meta |
| DELETE | `/v1/goals/:id` | access | Borrar meta |

### Salud

#### `GET /health`
**200** `{ "ok": true }`

---

### Autenticación

#### `POST /v1/auth/register`
Crea la cuenta. **No entrega sesión**: hay que confirmar el QR.

```ts
// Request
{ email: string;      // correo válido, máx. 254
  password: string }  // 10 a 200 caracteres
```
**201** `MfaSetupRequired` (incluye `recoveryKey`)
```json
{
  "user": { "id": "3f6c1a2e-...-9b1d" },
  "recoveryKey": "1a2b3c4d-5e6f7a8b-...-9c0d1e2f",
  "mfaSetupRequired": true,
  "mfaToken": "mt_Qk3x....Zr8",
  "mfaSetup": {
    "qrCode": "data:image/png;base64,iVBORw0KGgo...",
    "otpauthUrl": "otpauth://totp/Gastos%3Aana%40correo.com?secret=JBSWY3DP...&issuer=Gastos&algorithm=SHA1&digits=6&period=30",
    "secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
  }
}
```
Errores: `400` validación · `409` "Ese correo ya está registrado".

#### `POST /v1/auth/mfa/setup/confirm`
Confirma que el usuario escaneó el QR y activa el MFA.

```ts
{ mfaToken: string;  // el de register, login (mfaSetupRequired) o recover
  code: string }     // 6 dígitos; se ignoran los espacios
```
**200** `Session` (con `user`)
```json
{ "user": { "id": "3f6c..." }, "accessToken": "at_...", "refreshToken": "rt_...", "expiresIn": 3600 }
```
Errores:
- `400` el código no tiene 6 dígitos
- `401` "mfaToken inválido o vencido: inicia sesión de nuevo" → volver a login
- `401` "Código incorrecto" → reintentar (máx. 5 por `mfaToken`)
- `409` "El MFA ya está activo: usa /auth/login/mfa"

#### `POST /v1/auth/login`
Primer paso: valida la contraseña. **Nunca devuelve la sesión directamente.**

```ts
{ email: string; password: string }
```
**200** una de dos formas:
```json
{ "user": { "id": "3f6c..." }, "mfaRequired": true, "mfaToken": "mt_..." }
```
→ pedir el código y llamar a `/v1/auth/login/mfa`.

```json
{ "user": { "id": "3f6c..." }, "mfaSetupRequired": true, "mfaToken": "mt_...", "mfaSetup": { "qrCode": "...", "otpauthUrl": "...", "secret": "..." } }
```
→ la cuenta no tiene el MFA activo: mostrar el QR y llamar a `/v1/auth/mfa/setup/confirm`.
Cada vez que pasa esto se genera un QR nuevo y los anteriores sin confirmar dejan de servir.

Errores: `400` validación · `401` "Credenciales inválidas" (no indica si el correo existe).

#### `POST /v1/auth/login/mfa`
Segundo paso del login.

```ts
{ mfaToken: string; code: string }
```
**200** `Session` (con `user`).

Errores:
- `400` el código no tiene 6 dígitos
- `401` "mfaToken inválido o vencido: inicia sesión de nuevo"
- `401` "Código incorrecto" (también si el código ya se usó); tras 5 fallos el `mfaToken` se anula
- `409` "Primero configura el MFA: usa /auth/mfa/setup/confirm"

#### `POST /v1/auth/refresh`
```ts
{ refreshToken: string }
```
**200** `Session` **sin** `user`:
```json
{ "accessToken": "at_...", "refreshToken": "rt_...", "expiresIn": 3600 }
```
Errores: `401` "Refresh token inválido" (vencido, ya usado o revocado) → volver a login.

#### `POST /v1/auth/logout` · access
```ts
{ all?: boolean }   // true = cerrar todas las sesiones; el cuerpo puede ir vacío
```
**204** sin cuerpo.

#### `POST /v1/auth/change-password` · access
```ts
{ currentPassword: string;
  newPassword: string }   // 10 a 200 caracteres
```
**200** `Session` (con `user`). Todas las demás sesiones quedan cerradas.

Errores: `400` validación · `401` "Contraseña actual incorrecta".

#### `POST /v1/auth/recover`
```ts
{ email: string;
  recoveryKey: string;    // la guardada al registrarse (o la última que dio /recover)
  newPassword: string }   // 10 a 200 caracteres
```
**200** `MfaSetupRequired` (incluye la `recoveryKey` **nueva**). Hay que confirmar el QR nuevo con
`/v1/auth/mfa/setup/confirm` para obtener sesión.

Errores: `400` validación · `401` "Datos de recuperación inválidos".

---

### Tokens del Atajo de iOS

#### `POST /v1/ingest-tokens` · access
```ts
{ label: string }   // 1 a 60 caracteres, ej. "iPhone de Ana"
```
**201**
```json
{ "token": "it_Ab12....Xy9", "note": "Guárdalo ahora: no se puede volver a ver." }
```

#### `GET /v1/ingest-tokens` · access
**200** solo los activos, del más viejo al más nuevo:
```ts
{ id: string;                 // "it_Ab12..." (sin el secreto)
  label: string | null;
  created_at: EpochMs;
  last_used_at: EpochMs | null }[]
```

#### `DELETE /v1/ingest-tokens/:id` · access
**204**. Errores: `404`.

#### `POST /v1/ingest` · ingest
Lo llama el Atajo. Es permisivo: ignora campos desconocidos.

```ts
{ merchant: string;              // 1 a 200
  amount: number | string;       // ver "Montos"
  currency?: string;             // 3 letras, por defecto "COP"
  card?: string | null;          // máx. 60
  date?: string;                 // cualquier fecha que Date.parse entienda; si no, se usa la hora actual
  status?: Status;               // por defecto "approved"
  description?: string | null }  // máx. 1000
```
**201** `{ "id": "uuid" }`. La transacción queda con `type: "card"`, `source: "ios-shortcut"` y `category: null`.

Errores: `400` validación · `401` el token no es de ingesta (un `accessToken` tampoco sirve aquí).

---

### Transacciones

#### `POST /v1/transactions` · access
```ts
{ merchant: string;                       // 1 a 200
  amount: number | string;                // ver "Montos"
  type?: 'card' | 'cash';                 // por defecto 'card'
  currency?: string;                      // 3 letras, por defecto "COP"
  card?: string | null;                   // máx. 60; se descarta si type = 'cash'
  occurred_at?: ISODateTime;              // con zona: "2026-10-30T10:30:00-05:00" o "...Z"; por defecto ahora
  description?: string | null;            // máx. 1000
  status?: Status;                        // por defecto 'approved'
  category?: string | null;               // máx. 60
  source?: 'manual' | 'web' | 'android' | 'ios-app' }  // por defecto 'manual'
```
**201** `Transaction`
```json
{
  "id": "b7e1...", "type": "card", "merchant": "Éxito", "amount": 45900, "currency": "COP",
  "card": "Visa 1234", "occurred_at": "2026-10-30T15:30:00.000Z", "description": "mercado",
  "status": "approved", "category": null, "source": "manual",
  "created_at": "2026-10-30T15:30:01.120Z", "updated_at": "2026-10-30T15:30:01.120Z"
}
```

#### `GET /v1/transactions` · access
Query (todos opcionales):

| Parámetro | Tipo | Descripción |
|---|---|---|
| `from`, `to` | ISODateTime con zona | Rango sobre `occurred_at` (inclusivo) |
| `status` | `Status` | |
| `type` | `card` \| `cash` | |
| `category` | string | Coincidencia exacta |
| `q` | string | Busca dentro de `merchant` (sin distinguir mayúsculas) |
| `limit` | 1–200 | Por defecto 50 |
| `offset` | ≥ 0 | Por defecto 0 |

**200** ordenado de la más reciente a la más vieja:
```ts
{ total: number;       // total que cumple los filtros (para paginar)
  limit: number;
  offset: number;
  items: Transaction[] }
```

#### `GET /v1/transactions/summary` · access
Query opcional: `from`, `to` (como arriba). Solo suman `approved` y `pending`.

**200**
```ts
{ total: number;                          // suma de montos
  count: number;                          // transacciones que suman
  declined_count: number;
  by_category: Record<string, number>;    // las sin categoría van en "sin_categoria"
  by_type: { card?: number; cash?: number } }  // solo aparecen los tipos que tienen gasto
```

#### `GET /v1/transactions/:id` · access
**200** `Transaction`. Errores: `404`.

#### `PATCH /v1/transactions/:id` · access
Mismos campos que el `POST` (todos opcionales, al menos uno), **excepto `source`**. Solo cambia lo que envíes.
Si `type` queda en `cash`, `card` pasa a `null`.

**200** `Transaction` actualizada. Errores: `400` (cuerpo vacío o inválido) · `404`.

#### `DELETE /v1/transactions/:id` · access
**204**. Errores: `404`.

---

### Reportes

Los pagos se guardan en UTC; los reportes agrupan por día **en la zona horaria del cliente** (`?tz=`,
nombre IANA como `America/Bogota`; por defecto `DEFAULT_TZ`). Así un pago a las 10:30 p. m. en Bogotá
no cae en el día siguiente. Solo cuentan `approved` y `pending`.

#### `GET /v1/reports/daily` · access
Query: `tz?`, `from?: DateKey`, `to?: DateKey`. Por defecto, los últimos 30 días hasta hoy. Rango máximo 366 días.

**200**
```ts
{ tz: string;
  from: DateKey;
  to: DateKey;
  days: {                                  // TODOS los días del rango, también los de gasto 0
    date: DateKey;
    total: number;
    count: number;
    by_category: Record<string, number>;
    by_type: { card: number; cash: number };
  }[];
  summary: {
    total: number;
    avg_per_day: number;                   // total ÷ días del rango
    max_day: { date: DateKey; total: number };
    zero_days: number;                     // días sin gasto
    top_merchants: { merchant: string; total: number; count: number }[];  // máx. 5
  } }
```
Errores: `400` fecha mal formada, zona horaria inválida, o `from` > `to` / más de 366 días.

#### `GET /v1/reports/weekly` · access
Query: `tz?`, `weeks?: 1–52` (por defecto 8). Semanas de lunes a domingo, de la más vieja a la actual.

**200**
```ts
{ tz: string;
  weeks: {
    start: DateKey;                        // lunes
    end: DateKey;                          // domingo
    total: number;
    count: number;
    avg_per_day: number;                   // en la semana actual divide solo por los días transcurridos
    change_pct: number | null;             // % frente a la semana anterior; null si la anterior fue 0
    by_category: Record<string, number>;
  }[];
  summary: { total: number; avg_per_week: number } }
```

---

### Metas mensuales

Un límite de gasto que se repite cada mes. Una meta por categoría; sin categoría (`null`) es la meta
del gasto total. El límite y la categoría van cifrados.

#### `POST /v1/goals` · access
```ts
{ limit: number | string;         // ver "Montos"
  category?: string | null }      // máx. 60; vacío o ausente = meta del total
```
**201** `Goal`. Errores: `400` · `409` "Ya tienes una meta para esa categoría".

#### `GET /v1/goals` · access
**200** `Goal[]` (en orden de creación).

#### `GET /v1/goals/progress` · access
Query: `tz?`. Avance del mes en curso.

**200**
```ts
{ month: string;                  // "2026-10"
  days_in_month: number;
  days_elapsed: number;           // día del mes de hoy
  days_left: number;              // incluye hoy
  goals: {                        // primero la meta del total, luego por categoría (A-Z)
    id: string;
    category: string | null;
    limit: number;
    spent: number;
    remaining: number;            // negativo si se pasó
    percent: number;              // entero, puede pasar de 100
    status: 'ok' | 'warning' | 'exceeded';   // < 80 % · 80–99 % · ≥ 100 %
    daily_allowance: number;      // lo que queda ÷ días que faltan (0 si ya no queda)
    projected: number;            // gasto proyectado a fin de mes al ritmo actual
  }[] }
```

#### `PATCH /v1/goals/:id` · access
```ts
{ limit?: number | string; category?: string | null }   // al menos uno
```
**200** `Goal`. Errores: `400` · `404` · `409` (ya existe otra meta con esa categoría).

#### `DELETE /v1/goals/:id` · access
**204**. Errores: `404`.

---

## Cómo funciona el cifrado

- Cada usuario tiene una llave de datos (DEK) aleatoria de 256 bits. Cada transacción y cada meta se
  cifran con AES-256-GCM usando su DEK (AAD = usuario + id, así no se pueden mover filas).
- La DEK nunca se guarda en claro. Se guarda **envuelta** de varias formas, cada una con una llave distinta:

  | Envoltura | Llave que la abre |
  |---|---|
  | Contraseña | scrypt(HMAC(PEPPER, contraseña)) |
  | Recuperación | llave aleatoria de 256 bits, mostrada una vez |
  | Sesión (access/refresh) | secreto aleatorio del token (no se guarda) |
  | MFA pendiente (`mfaToken`) | secreto aleatorio del token, vive 10 min |
  | Ingesta (Atajo) | secreto aleatorio del token (no se guarda) |

- El secreto del Authenticator (TOTP) se guarda cifrado con la DEK: no aparece en un dump.
- El correo no se guarda: solo HMAC(PEPPER, correo).
- Cada usuario tiene una DEK distinta; con la de uno no se abre nada de otro.
- El MFA es TOTP estándar (RFC 6238: SHA-1, 6 dígitos, 30 s), compatible con cualquier app de autenticación.

## Límites conocidos

- En la ingesta el servidor ve el dato en claro un instante (llega por HTTPS y se cifra al guardar).
  Es cifrado en reposo con llaves por usuario, no zero-knowledge puro.
- Filtros y sumas se hacen en memoria tras descifrar (bien para uso personal, no para millones de filas).
- Olvidar la contraseña **y** perder la llave de recuperación = datos irrecuperables (intencional).
- Quien tenga la llave de recuperación y el correo puede cambiar la contraseña y el MFA: debe guardarse bien.
- Aún no hay ruta para cambiar de celular estando logueado; hoy se hace con `/auth/recover`.
- Pendiente para producción: HTTPS obligatorio, backups de la BD, migrar a Postgres si crece,
  deduplicar pagos repetidos.
