import 'dotenv/config';

type SameSiteOption = 'strict' | 'lax' | 'none';

function parseNumber(value: string | undefined, fallback: number): number {
  const parsed = value !== undefined ? Number(value) : NaN;
  return Number.isFinite(parsed) ? parsed : fallback;
}

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  if (value === '1' || value.toLowerCase() === 'true') return true;
  if (value === '0' || value.toLowerCase() === 'false') return false;
  return fallback;
}

function parseSameSite(value: string | undefined, fallback: SameSiteOption): SameSiteOption {
  if (!value) return fallback;
  const normalized = value.toLowerCase();
  if (normalized === 'strict' || normalized === 'lax' || normalized === 'none') {
    return normalized;
  }
  return fallback;
}

export const PORT = parseNumber(process.env.PORT, 3000);
export const SECRET_JWT_KEY = process.env.SECRET_JWT_KEY ?? 'change-me-in-prod';
export const ACCESS_EXPIRES_IN = process.env.ACCESS_EXPIRES_IN ?? '15m';
export const REFRESH_TTL_SEC = parseNumber(process.env.REFRESH_TTL_SEC, 60 * 60 * 24 * 30);
export const SALT_ROUNDS = parseNumber(process.env.SALT_ROUNDS, 10);

export const COOKIE_SECURE = parseBoolean(process.env.COOKIE_SECURE, false);
export const COOKIE_SAMESITE = parseSameSite(process.env.COOKIE_SAMESITE, 'lax');
export const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN ?? undefined;

export const SQLITE_PATH = process.env.SQLITE_PATH ?? './db/noloop.db';
