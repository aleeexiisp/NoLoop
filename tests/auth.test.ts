import { after, before, beforeEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import jwt from 'jsonwebtoken';
import type { Server } from 'node:http';

import { app } from '../src/infra/server.js';
import { sqlite } from '../src/infra/db.js';
import { userRepository } from '../src/adapters/db/userRepo.drizzle.js';
import { signAccessToken } from '../src/infra/auth.js';
import { SECRET_JWT_KEY, REFRESH_TTL_SEC } from '../config/config.js';

const strongPassword = 'Stronger#1234';

const schemaSql = `
DROP TABLE IF EXISTS password_reset_tokens;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE refresh_tokens (
  jti TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  expires_at INTEGER NOT NULL
);

CREATE TABLE password_reset_tokens (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  expires_at INTEGER NOT NULL,
  used_at INTEGER
);
`;

const truncateSql = `
DELETE FROM refresh_tokens;
DELETE FROM password_reset_tokens;
DELETE FROM users;
`;

class TestClient {
  #cookies = new Map<string, string>();
  constructor(private readonly baseUrl: string) {}

  async request(path: string, options: {
    method?: string;
    json?: Record<string, unknown>;
    headers?: Record<string, string>;
  } = {}) {
    const headers = new Headers(options.headers ?? {});
    let body: string | undefined;

    if (options.json !== undefined) {
      body = JSON.stringify(options.json);
      headers.set('content-type', 'application/json');
    }

    if (this.#cookies.size > 0) {
      const cookieHeader = Array.from(this.#cookies.entries())
        .map(([name, value]) => `${name}=${value}`)
        .join('; ');
      headers.set('cookie', cookieHeader);
    }

    const res = await fetch(new URL(path, this.baseUrl), {
      method: options.method ?? (options.json ? 'POST' : 'GET'),
      headers,
      body,
      redirect: 'manual',
    });

    const setCookie = res.headers.getSetCookie();
    if (setCookie.length > 0) {
      this.#updateCookies(setCookie);
    }

    let parsedBody: any = null;
    const contentType = res.headers.get('content-type') ?? '';
    if (contentType.includes('application/json')) {
      parsedBody = await res.json();
    } else if (contentType) {
      parsedBody = await res.text();
    }

    return { res, cookies: setCookie, body: parsedBody };
  }

  getCookieValue(name: string): string | undefined {
    return this.#cookies.get(name);
  }

  #updateCookies(cookies: string[]) {
    for (const raw of cookies) {
      const [pair, ...attributes] = raw.split(';');
      const [name, value] = pair.split('=');
      if (!name) continue;

      const expiresAttr = attributes.find((attr) => attr.trim().toLowerCase().startsWith('expires='));
      const shouldRemove = value === '' || (expiresAttr && new Date(expiresAttr.split('=')[1]).getTime() <= Date.now());
      if (shouldRemove) {
        this.#cookies.delete(name);
      } else {
        this.#cookies.set(name, value);
      }
    }
  }
}

let baseUrl: string;
let server: Server;

before(async () => {
  sqlite.exec(schemaSql);
  server = app.listen(0);
  await once(server, 'listening');
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  baseUrl = `http://127.0.0.1:${address.port}`;
});

beforeEach(() => {
  sqlite.exec(truncateSql);
});

after(async () => {
  await new Promise<void>((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
  sqlite.close();
});

function getCookie(cookies: string[], name: string): string | undefined {
  for (const raw of cookies) {
    const [pair] = raw.split(';');
    const [cookieName, value] = pair.split('=');
    if (cookieName === name) return value;
  }
  return undefined;
}

describe('Database connection', () => {
  it('allows executing basic queries', () => {
    const row = sqlite.prepare('SELECT 1 as value').get();
    assert.strictEqual(row.value, 1);
  });
});

describe('User repository authentication flow', () => {
  it('registers and logs in a user with hashed password', async () => {
    const username = 'user_repo_1';
    const id = await userRepository.create({ username, password: strongPassword });
    assert.strictEqual(typeof id, 'string');

    const user = await userRepository.login({ username, password: strongPassword });
    assert.strictEqual(user.id, id);
    assert.strictEqual(user.username, username);
  });

  it('prevents duplicated usernames and invalid credentials', async () => {
    const username = 'user_repo_2';
    await userRepository.create({ username, password: strongPassword });

    await assert.rejects(
      userRepository.create({ username, password: strongPassword }),
      /ya existe/i,
    );

    await assert.rejects(
      userRepository.login({ username, password: 'Wrong#12345' }),
      /incorrecta/i,
    );
  });

  it('rotates refresh tokens securely', async () => {
    const username = 'user_repo_3';
    const id = await userRepository.create({ username, password: strongPassword });

    const issued = await userRepository.issueRefresh(id);
    assert.strictEqual(issued.token.split('.').length, 2);
    assert.ok(issued.expiresAt > Math.floor(Date.now() / 1000));

    const stored = sqlite.prepare('SELECT token_hash AS tokenHash, revoked FROM refresh_tokens WHERE jti = ?').get(issued.jti);
    assert.strictEqual(stored.revoked, 0);
    assert.notStrictEqual(stored.tokenHash, issued.token.split('.')[1]);

    const rotated = await userRepository.rotateRefresh(issued.token);
    assert.notStrictEqual(rotated.refresh.token, issued.token);

    const old = sqlite.prepare('SELECT revoked FROM refresh_tokens WHERE jti = ?').get(issued.jti);
    assert.strictEqual(old.revoked, 1);
  });

  it('detects refresh token reuse and invalidates the entire family', async () => {
    const username = 'user_repo_reuse';
    const id = await userRepository.create({ username, password: strongPassword });

    const { token } = await userRepository.issueRefresh(id);

    const [first, second] = await Promise.allSettled([
      userRepository.rotateRefresh(token),
      userRepository.rotateRefresh(token),
    ]);

    let success: any;
    let failure: unknown;
    for (const outcome of [first, second]) {
      if (outcome.status === 'fulfilled') success = outcome.value;
      else failure = outcome.reason;
    }

    assert.ok(success);
    assert.ok(failure instanceof Error);
    assert.match((failure as Error).message, /reuse/i);

    const reuseAttempt = success.refresh.token;
    await assert.rejects(userRepository.rotateRefresh(reuseAttempt), /reuse|invalid/i);

    const stored = sqlite.prepare('SELECT revoked FROM refresh_tokens WHERE user_id = ?').all(id) as Array<{ revoked: number }>;
    assert.ok(stored.length >= 2);
    assert.ok(stored.every((row) => row.revoked === 1));
  });

  it('revokes refresh tokens individually and in bulk', async () => {
    const username = 'user_repo_4';
    const id = await userRepository.create({ username, password: strongPassword });

    const first = await userRepository.issueRefresh(id);
    const second = await userRepository.issueRefresh(id);

    await userRepository.revokeRefresh(first.token);
    const storedFirst = sqlite.prepare('SELECT revoked FROM refresh_tokens WHERE jti = ?').get(first.jti);
    assert.strictEqual(storedFirst.revoked, 1);

    await userRepository.revokeAllRefresh(id);
    const storedSecond = sqlite.prepare('SELECT revoked FROM refresh_tokens WHERE jti = ?').get(second.jti);
    assert.strictEqual(storedSecond.revoked, 1);
  });

  it('validates refresh token input strictly', async () => {
    await assert.rejects(
      userRepository.rotateRefresh('invalid'),
      /invalid refresh token/i,
    );
  });

  it('rejects refresh tokens with tampered secrets', async () => {
    const username = 'user_repo_6';
    const id = await userRepository.create({ username, password: strongPassword });
    const { token } = await userRepository.issueRefresh(id);
    const [jti] = token.split('.');

    await assert.rejects(
      userRepository.rotateRefresh(`${jti}.tampered`),
      /invalid refresh token/i,
    );
  });

  it('changes passwords and invalidates old credentials', async () => {
    const username = 'user_repo_5';
    const id = await userRepository.create({ username, password: strongPassword });

    await userRepository.changePassword({ userId: id, currentPassword: strongPassword, newPassword: 'Different#1234' });

    await assert.rejects(
      userRepository.login({ username, password: strongPassword }),
      /incorrecta/i,
    );

    const user = await userRepository.login({ username, password: 'Different#1234' });
    assert.strictEqual(user.id, id);
  });
});

describe('JWT helpers', () => {
  it('creates signed tokens with expected payload and expiry', () => {
    const token = signAccessToken({ id: '123', username: 'jwt-user' });
    const decoded = jwt.verify(token, SECRET_JWT_KEY) as jwt.JwtPayload;
    assert.strictEqual(decoded.id, '123');
    assert.strictEqual(decoded.username, 'jwt-user');
    assert.strictEqual(typeof decoded.exp, 'number');
  });
});

describe('HTTP authentication endpoints', () => {
  it('registers, logs in and accesses protected routes', async () => {
    const client = new TestClient(baseUrl);
    const username = 'http_user_1';

    const register = await client.request('/register', { json: { username, password: strongPassword } });
    assert.strictEqual(register.res.status, 201);

    const login = await client.request('/login', { json: { username, password: strongPassword } });
    assert.strictEqual(login.res.status, 200);
    assert.ok(getCookie(login.cookies, 'access_token'));
    assert.ok(getCookie(login.cookies, 'refresh_token'));

    const me = await client.request('/api/v1/me');
    assert.strictEqual(me.res.status, 200);
    assert.strictEqual(me.body.user.username, username);

    const protectedRes = await client.request('/protected', { method: 'POST' });
    assert.strictEqual(protectedRes.res.status, 200);
    assert.strictEqual(protectedRes.body.user.username, username);
  });

  it('rejects unauthenticated access', async () => {
    const res = await fetch(new URL('/api/v1/me', baseUrl));
    assert.strictEqual(res.status, 401);
  });

  it('refreshes tokens and rotates refresh secrets', async () => {
    const client = new TestClient(baseUrl);
    const username = 'http_user_2';

    await client.request('/register', { json: { username, password: strongPassword } });
    const login = await client.request('/login', { json: { username, password: strongPassword } });
    const initialRefresh = getCookie(login.cookies, 'refresh_token');
    assert.ok(initialRefresh);

    const refresh = await client.request('/auth/refresh', { method: 'POST' });
    assert.strictEqual(refresh.res.status, 200);
    const newRefresh = getCookie(refresh.cookies, 'refresh_token');
    assert.ok(newRefresh);
    assert.notStrictEqual(newRefresh, initialRefresh);
  });

  it('prevents refresh with invalid or revoked tokens', async () => {
    const malformed = await fetch(new URL('/auth/refresh', baseUrl), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ refresh_token: 'malformed' }),
    });
    assert.strictEqual(malformed.status, 401);

    const client = new TestClient(baseUrl);
    const username = 'http_user_3';
    await client.request('/register', { json: { username, password: strongPassword } });
    const login = await client.request('/login', { json: { username, password: strongPassword } });
    const refreshToken = getCookie(login.cookies, 'refresh_token');
    assert.ok(refreshToken);

    await userRepository.revokeRefresh(refreshToken);
    const revoked = await fetch(new URL('/auth/refresh', baseUrl), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    assert.strictEqual(revoked.status, 401);
  });

  it('logs out users and clears cookies', async () => {
    const client = new TestClient(baseUrl);
    const username = 'http_user_4';

    await client.request('/register', { json: { username, password: strongPassword } });
    const login = await client.request('/login', { json: { username, password: strongPassword } });
    const refreshToken = getCookie(login.cookies, 'refresh_token');
    assert.ok(refreshToken);

    const logout = await client.request('/auth/logout', { method: 'POST' });
    assert.strictEqual(logout.res.status, 200);
    assert.strictEqual(getCookie(logout.cookies, 'access_token'), '');
    assert.strictEqual(getCookie(logout.cookies, 'refresh_token'), '');

    const refreshAttempt = await fetch(new URL('/auth/refresh', baseUrl), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    assert.strictEqual(refreshAttempt.status, 401);
  });

  it('forces re-login after password change', async () => {
    const client = new TestClient(baseUrl);
    const username = 'http_user_5';

    await client.request('/register', { json: { username, password: strongPassword } });
    await client.request('/login', { json: { username, password: strongPassword } });

    const change = await client.request('/change-password', {
      method: 'POST',
      json: { currentPassword: strongPassword, newPassword: 'BrandNew#12345' },
    });

    assert.strictEqual(change.res.status, 200);
    assert.strictEqual(getCookie(change.cookies, 'access_token'), '');
    assert.strictEqual(getCookie(change.cookies, 'refresh_token'), '');

    const meAfter = await client.request('/api/v1/me');
    assert.strictEqual(meAfter.res.status, 401);

    const oldLogin = await client.request('/login', { json: { username, password: strongPassword } });
    assert.strictEqual(oldLogin.res.status, 401);

    const newLogin = await fetch(new URL('/login', baseUrl), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username, password: 'BrandNew#12345' }),
    });
    assert.strictEqual(newLogin.status, 200);
  });

  it('sets authentication cookies with the expected attributes in development', async () => {
    const client = new TestClient(baseUrl);
    const username = 'http_cookie_1';

    await client.request('/register', { json: { username, password: strongPassword } });
    const login = await client.request('/login', { json: { username, password: strongPassword } });

    const accessCookie = login.cookies.find((cookie) => cookie.startsWith('access_token='));
    const refreshCookie = login.cookies.find((cookie) => cookie.startsWith('refresh_token='));

    assert.ok(accessCookie, 'access cookie should be set');
    assert.ok(refreshCookie, 'refresh cookie should be set');

    assert.ok(accessCookie!.includes('HttpOnly'));
    assert.ok(accessCookie!.includes('SameSite=Lax'));
    assert.ok(accessCookie!.includes('Path=/'));
    assert.match(accessCookie!, /Max-Age=\d+/);
    assert.ok(!accessCookie!.includes('Secure'));
    assert.ok(!accessCookie!.includes('Domain='));

    assert.ok(refreshCookie!.includes('HttpOnly'));
    assert.ok(refreshCookie!.includes('SameSite=Lax'));
    assert.ok(refreshCookie!.includes('Path=/auth'));
    assert.match(refreshCookie!, /Max-Age=\d+/);
    assert.ok(!refreshCookie!.includes('Secure'));
    assert.ok(!refreshCookie!.includes('Domain='));
  });

  it('rejects forged access tokens', async () => {
    const forged = jwt.sign({ id: 'attacker', username: 'evil' }, 'wrong-secret');
    const res = await fetch(new URL('/api/v1/me', baseUrl), {
      headers: { cookie: `access_token=${forged}` },
    });
    assert.strictEqual(res.status, 401);
  });
});

it('uses configurable refresh expirations', async () => {
  const username = 'config_user_1';
  const id = await userRepository.create({ username, password: strongPassword });
  const refresh = await userRepository.issueRefresh(id);
  const now = Math.floor(Date.now() / 1000);
  assert.ok(refresh.expiresAt > now);
  assert.ok(refresh.expiresAt - now > 0);
  assert.ok(refresh.expiresAt - now <= Number(REFRESH_TTL_SEC));
});
