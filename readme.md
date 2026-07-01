# usermgt — Auth API

A self-contained authentication service built with Fastify 5, Prisma, and PostgreSQL. Designed to be deployed once and shared across multiple apps.

## Quickstart

```bash
cp .env.example .env          # fill in secrets
docker compose up --build     # starts postgres + api on :3000
```

The API is available at `http://localhost:3000/v1`.  
Swagger UI is available at `http://localhost:3000/docs` (non-production only).

---

## Token Flows

### Register and verify email

```
POST /v1/auth/register
  → 201 { accessToken, refreshToken }
  → verification email sent to user

POST /v1/auth/verify-email  { token: "<from email>" }
  → 200 { message: "Email verified" }
```

### Login and refresh

```
POST /v1/auth/login  { email, password }
  → 200 { accessToken, refreshToken }

  ... accessToken expires (default 15 min) ...

POST /v1/auth/refresh  { refreshToken }
  → 200 { accessToken, refreshToken }   ← old refreshToken is immediately invalidated
```

Each refresh rotates the token — the old one is revoked on use. Store the latest `refreshToken` and replace it every time you call `/refresh`.

### Password reset

```
POST /v1/auth/forgot-password  { email }
  → 200 (always, regardless of whether email exists)
  → reset email sent if account found

POST /v1/auth/reset-password  { token: "<from email>", password: "<new>" }
  → 200 { message }
  → all existing sessions revoked
```

---

## Token Revocation

Access tokens are stateless JWTs — once issued they remain valid until expiry, even if the user is deactivated. This is the standard JWT trade-off. There are two ways to handle it:

### 1. Accept the TTL window (standard routes)

For most routes, verify the JWT locally. A deactivated user's token will expire within `ACCESS_TOKEN_TTL_MINUTES` (default 15 min). This is acceptable for low-sensitivity operations.

```js
// consuming app — verify locally
const payload = jwt.verify(token, JWT_ACCESS_SECRET, { audience: JWT_AUDIENCE });
const { sub: userId, role } = payload;
```

### 2. Introspect for sensitive routes (health data access)

For routes that touch sensitive data, call `POST /v1/auth/introspect` first. This checks the token's signature *and* confirms the user is still active in real time.

```js
// consuming app — sensitive route
const r = await fetch('https://auth.example.com/v1/auth/introspect', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ token: accessToken }),
});
const { active, role, isEmailVerified } = await r.json();
if (!active) return res.status(401).json({ message: 'Unauthorized' });
```

`isEmailVerified` is included so you can also gate access on email confirmation in one call.

**Revocation guarantee:** When a user is deactivated (or deletes their account), `POST /v1/auth/introspect` returns `{ active: false }` immediately. Consuming apps using introspection get near-real-time revocation with no shared database required.

---

## Endpoints

All endpoints are prefixed with `/v1`. Authenticated endpoints require `Authorization: Bearer <accessToken>`.

### Auth

#### `POST /v1/auth/register`
Create a new account. Sends a verification email.

**Body:** `{ email, password, displayName? }`  
**Response 201:** `{ accessToken, refreshToken }`  
**Errors:** 400 validation, 409 email already registered  
**Rate limit:** 5 requests / minute

```bash
curl -X POST http://localhost:3000/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@example.com","password":"secret1234"}'
```

---

#### `POST /v1/auth/login`
Authenticate and receive tokens.

**Body:** `{ email, password }`  
**Response 200:** `{ accessToken, refreshToken }`  
**Errors:** 401 invalid credentials  
**Rate limit:** 10 requests / minute

```bash
curl -X POST http://localhost:3000/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@example.com","password":"secret1234"}'
```

---

#### `POST /v1/auth/refresh`
Exchange a refresh token for a new access + refresh token pair. The old refresh token is immediately revoked.

**Body:** `{ refreshToken }`  
**Response 200:** `{ accessToken, refreshToken }`  
**Errors:** 401 invalid/expired/revoked token  
**Rate limit:** 30 requests / minute

---

#### `POST /v1/auth/logout`
Revoke a refresh token.

**Body:** `{ refreshToken }`  
**Response 204**

---

#### `POST /v1/auth/verify-email`
Mark email as verified using the token from the verification email.

**Body:** `{ token }`  
**Response 200:** `{ message }`  
**Errors:** 400 invalid or expired token

---

#### `POST /v1/auth/forgot-password`
Request a password reset email. Always returns 200 to prevent user enumeration.

**Body:** `{ email }`  
**Response 200:** `{ message }`  
**Rate limit:** 5 requests / 15 minutes

---

#### `POST /v1/auth/reset-password`
Set a new password using the token from the reset email. Revokes all existing sessions.

**Body:** `{ token, password }`  
**Response 200:** `{ message }`  
**Errors:** 400 invalid/expired token  
**Rate limit:** 10 requests / 15 minutes

---

#### `POST /v1/auth/introspect`
Check whether an access token is currently valid — verifies the signature and confirms the user is still active in the database. Returns `active: false` for any invalid, expired, or deactivated token without revealing why. Use this on sensitive routes instead of local-only verification.

**Body:** `{ token }`  
**Response 200 (active):**
```json
{ "active": true, "sub": "...", "role": "USER", "sessionId": "...", "isEmailVerified": false, "exp": 1700000900 }
```
**Response 200 (inactive/invalid):**
```json
{ "active": false }
```
**Errors:** 400 missing token field  
**Rate limit:** 30 requests / minute

```bash
curl -X POST http://localhost:3000/v1/auth/introspect \
  -H 'Content-Type: application/json' \
  -d '{"token":"<accessToken>"}'
```

---

### User (authenticated)

#### `GET /v1/me`
Get the current user's profile.

**Response 200:**
```json
{
  "id": "cuid",
  "email": "user@example.com",
  "role": "USER",
  "displayName": "Jane",
  "isActive": true,
  "isEmailVerified": false,
  "createdAt": "2024-01-01T00:00:00.000Z",
  "updatedAt": "2024-01-01T00:00:00.000Z",
  "lastLoginAt": "2024-01-02T00:00:00.000Z"
}
```

---

#### `PATCH /v1/me`
Update profile fields. Send `null` to clear `displayName`.

**Body:** `{ displayName?: string | null }`  
**Response 200:** `{ id, email, displayName, updatedAt }`

```bash
curl -X PATCH http://localhost:3000/v1/me \
  -H 'Authorization: Bearer <accessToken>' \
  -H 'Content-Type: application/json' \
  -d '{"displayName":"Jane Smith"}'
```

---

#### `POST /v1/me/password`
Change password. Keeps the current session active, revokes all other sessions.

**Body:** `{ currentPassword, newPassword }`  
**Response 200:** `{ message }`  
**Errors:** 401 wrong current password, 400 new password too weak

---

#### `DELETE /v1/me/sessions`
Revoke all active sessions, forcing re-login on all devices.

**Response 204**

---

#### `DELETE /v1/me`
Permanently delete the account. Requires password confirmation. All sessions and tokens are deleted via cascade.

**Body:** `{ password }`  
**Response 204**  
**Errors:** 401 wrong password

---

### Health

#### `GET /health`
Database connectivity check. Does not require authentication.

**Response 200:** `{ ok: true }` / **503:** `{ ok: false, error: "Database unavailable" }`

---

## Validation Rules

| Field | Constraints |
|---|---|
| `email` | Valid email format, max 320 characters, stored lowercase |
| `password` (register / reset / change new) | Min 8 characters, max 200 characters |
| `password` (login / change current / delete) | Min 1 character, max 200 characters |
| `displayName` | Max 120 characters, optional, nullable |
| `refreshToken` / `token` | Min 10 characters |

---

## Error Responses

All errors return JSON with a `message` field.

**Validation error (400):**
```json
{
  "message": "Validation error",
  "errors": [
    { "path": "password", "message": "String must contain at least 8 character(s)" }
  ]
}
```

**All other errors:**
```json
{
  "message": "Invalid credentials"
}
```

HTTP status codes used: 400 validation, 401 unauthenticated/wrong credentials, 404 not found, 409 conflict, 429 rate limited, 500 server error.

---

## JWT Claims

Access tokens are short-lived JWTs (default 15 min) signed with HS256. The payload:

```json
{
  "sub": "<userId>",
  "role": "USER",
  "sessionId": "<sessionId>",
  "aud": "<JWT_AUDIENCE>",
  "iat": 1700000000,
  "exp": 1700000900
}
```

- `sub` — user ID (CUID)
- `role` — `USER` or `ADMIN`; safe to use for authorization decisions in consuming apps
- `sessionId` — ID of the refresh session this access token belongs to
- `aud` — must match `JWT_AUDIENCE`; consuming apps should reject tokens with a different audience

---

## Integrating with a Consuming App

Verify the access token in your app using the same secret (`JWT_ACCESS_SECRET`) and audience (`JWT_AUDIENCE`).

**Node.js (jsonwebtoken):**
```js
import jwt from 'jsonwebtoken';

function verifyToken(token) {
  return jwt.verify(token, process.env.JWT_ACCESS_SECRET, {
    audience: process.env.JWT_AUDIENCE,
    algorithms: ['HS256'],
  });
  // returns { sub, role, sessionId, aud, iat, exp }
}
```

**Node.js (@fastify/jwt):**
```js
fastify.register(jwt, {
  secret: process.env.JWT_ACCESS_SECRET,
  verify: { allowedAud: process.env.JWT_AUDIENCE },
});

// in a route preHandler:
await request.jwtVerify();
const { sub: userId, role } = request.user;
```

**Python (PyJWT):**
```python
import jwt

payload = jwt.decode(
    token,
    key=JWT_ACCESS_SECRET,
    algorithms=["HS256"],
    audience=JWT_AUDIENCE,
)
user_id = payload["sub"]
role = payload["role"]
```

---

## Roles

| Role | Description |
|---|---|
| `USER` | Default role assigned at registration |
| `ADMIN` | Elevated role; assign directly in the database (`UPDATE "User" SET role = 'ADMIN' WHERE email = '...'`) |

The role is embedded in the JWT so consuming apps can gate access without a database lookup.

---

## Security Notes

- **Passwords** are hashed with bcrypt (cost 12).
- **Refresh tokens** are opaque random values (48 bytes). Only the SHA-256 hash is stored in the database.
- **Refresh rotation** — each `/refresh` call issues a new token and immediately revokes the previous one. Presenting a session's old token (indicating possible theft) immediately revokes that session.
- **Reset/verify tokens** are single-use. Consumption is atomic (`updateMany` with `usedAt: null` guard) to prevent race conditions.
- **Rate limiting** is applied per-IP on sensitive endpoints (see endpoint docs above).
- **Account lockout** — per-account soft lockout on repeated login failures: 5 failures triggers a 15-minute lock; 10 cumulative failures triggers a 1-hour lock. The lock expires automatically (no admin action needed). The same error message is returned whether credentials are wrong or the account is locked, to prevent enumeration of lockout state.
- **User enumeration** is prevented on login (same error for unknown email, wrong password, or locked account) and on forgot-password (always 200).
- **`isActive` flag** — deactivating a user in the database immediately blocks login and all authenticated endpoints. In-flight JWTs remain cryptographically valid until expiry (default 15 min); use `/introspect` for immediate revocation on sensitive routes.
- **Password reset revokes all sessions**, ensuring stolen session tokens are invalidated immediately.
- **Token introspection** — `POST /v1/auth/introspect` provides real-time token validity checks including user active status. Recommended for routes that access sensitive or personal data.

---

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `JWT_ACCESS_SECRET` | yes | — | Secret for signing access tokens — use a random string of at least 32 characters |
| `JWT_AUDIENCE` | yes | — | Audience claim in every JWT; consuming apps must set the same value when verifying |
| `DATABASE_URL` | yes | — | PostgreSQL connection string |
| `APP_URL` | yes | — | Base URL for email links, e.g. `https://auth.example.com` (no trailing slash) |
| `CORS_ORIGINS` | no | `false` (disabled) | Comma-separated list of allowed origins, e.g. `https://app.com,https://admin.com` |
| `ACCESS_TOKEN_TTL_MINUTES` | no | `15` | Access token lifetime in minutes |
| `REFRESH_TOKEN_TTL_DAYS` | no | `30` | Refresh token lifetime in days |
| `SMTP_HOST` | no | — | SMTP server hostname |
| `SMTP_PORT` | no | `587` | SMTP port |
| `SMTP_SECURE` | no | `false` | `true` to use TLS (port 465), `false` for STARTTLS |
| `SMTP_USER` | no | — | SMTP username |
| `SMTP_PASS` | no | — | SMTP password |
| `SMTP_FROM` | no | — | From address, e.g. `"Auth Service" <no-reply@example.com>` |
| `PORT` | no | `3000` | HTTP port |

---

## Deployment

### Production checklist

- [ ] `JWT_ACCESS_SECRET` is at least 32 random characters and kept secret
- [ ] `JWT_AUDIENCE` is set to a value unique to your deployment (e.g. `myapp-prod`)
- [ ] `CORS_ORIGINS` is set to your frontend domain(s)
- [ ] SMTP variables are configured — email verification and password reset will silently fail without them
- [ ] `APP_URL` points to the public URL of this service (used in email links)
- [ ] Database is accessible from the API container

### Running migrations

Migrations must be applied before the API starts. In CI/CD, run:

```bash
npx prisma migrate deploy
```

In Docker Compose, add a one-shot init container or run it as part of the build process. The included `docker-compose.yml` does not run migrations automatically — run them manually after first deploy:

```bash
docker compose exec api npx prisma migrate deploy
```

### Docker Compose

The `docker-compose.yml` loads secrets from a `.env` file via `env_file`. Copy `.env.example` to `.env` and fill in the required values before starting:

```bash
cp .env.example .env
# edit .env
docker compose up -d --build
docker compose exec api npx prisma migrate deploy
```

---

## Development

```bash
cd api
npm install
npx prisma migrate deploy   # apply migrations against local postgres
npm run dev                  # watch mode (ts-node-dev)
npm test                     # integration tests — requires postgres on localhost:5432
```

Tests use a real database (no mocks for the DB layer). The test database is wiped before each test file runs. Run Docker Compose to get a local postgres instance:

```bash
docker compose up -d db
cd api && npm test
```
