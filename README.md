# Gastos API

API en Node.js (Express + SQLite) con cifrado por usuario. Todo el contenido financiero
va cifrado; en la base de datos solo hay IDs y bytes aleatorios.

## Arranque
```bash
npm install
cp .env.example .env        # y pon PEPPER=$(openssl rand -hex 32)
npm test                    # 9 pruebas, incluida la del dump de la BD
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
  | Ingesta (Atajo) | secreto aleatorio del token (no se guarda) |

- El correo no se guarda: solo HMAC(PEPPER, correo).
- Cada usuario tiene una DEK distinta; con la de uno no se abre nada de otro.

## Endpoints (todos bajo /v1)
| Método | Ruta | Descripción |
|---|---|---|
| POST | /auth/register | `{email,password}` → tokens + `recoveryKey` (una sola vez) |
| POST | /auth/login | `{email,password}` → tokens |
| POST | /auth/refresh | `{refreshToken}` → tokens nuevos (rotación) |
| POST | /auth/logout | `{all?}` |
| POST | /auth/change-password | `{currentPassword,newPassword}` |
| POST | /auth/recover | `{email,recoveryKey,newPassword}` |
| POST/GET/DELETE | /ingest-tokens | tokens para el Atajo (solo pueden crear transacciones) |
| POST | /ingest | lo llama el Atajo: `{merchant,amount,card,date,status?}` |
| POST/GET | /transactions | crear (tarjeta o `type:"cash"`) / listar con filtros |
| GET/PATCH/DELETE | /transactions/:id | leer, actualizar (p. ej. `status:"declined"`), borrar |
| GET | /transactions/summary | totales por categoría y tipo |

Estados: `approved`, `declined`, `pending`, `refunded`.
Listar admite `from,to,status,type,category,q,limit,offset`. Auth: `Authorization: Bearer <token>`.

## Atajo de iOS
Acción "Obtener contenido de URL": POST a `https://TU_API/v1/ingest`, encabezado
`Authorization: Bearer <token de ingesta>`, cuerpo JSON con `merchant`, `amount`, `card`, `date`
(fecha en ISO 8601 si se puede).

## Límites conocidos (decisiones del MVP)
- En la ingesta el servidor ve el dato en claro un instante (llega por HTTPS y se cifra al guardar). Es cifrado en reposo con llaves por usuario, no zero-knowledge puro.
- Filtros y sumas se hacen en memoria tras descifrar (bien para uso personal, no para millones de filas).
- Olvidar la contraseña **y** perder la llave de recuperación = datos irrecuperables (intencional).
- Pendiente para producción: HTTPS obligatorio, backups de la BD, migrar a Postgres si crece, deduplicar pagos repetidos.
