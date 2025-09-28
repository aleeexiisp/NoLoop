import jwt from "jsonwebtoken";
import { SECRET_JWT_KEY, ACCESS_EXPIRES_IN, COOKIE_SECURE, COOKIE_SAMESITE, COOKIE_DOMAIN } from "../../config/config.js";


// Genera access token (JWT) corto
export function signAccessToken(payload: { id: string; username: string }) {
  return jwt.sign(payload, SECRET_JWT_KEY, { expiresIn: ACCESS_EXPIRES_IN });
}

// helper simple para  "15m", "1h", 900, etc.
function expiresInToMs(v: string | number): number {
  if (typeof v === "number") return v * 1000; // si te llega en segundos
  const m = /^(\d+)\s*([smhd])$/.exec(v.trim());
  if (!m) return 60 * 60 * 1000; // fallback 1h
  const n = Number(m[1]);
  const unit = m[2];
  const mult = unit === 's' ? 1000 : unit === 'm' ? 60_000 : unit === 'h' ? 3_600_000 : 86_400_000;
  return n * mult;
}

export function setAccessCookie(res: any, token: string) {
  res.cookie("access_token", token, {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: COOKIE_SAMESITE,
    maxAge: expiresInToMs(ACCESS_EXPIRES_IN),  // <- alineado con el JWT
    domain: COOKIE_DOMAIN,
    path: "/",
  });
}

export function setRefreshCookie(res: any, refreshToken: string, ttlSec: number) {
  res.cookie("refresh_token", refreshToken, {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: COOKIE_SAMESITE,
    maxAge: 1000 * ttlSec,
    domain: COOKIE_DOMAIN,
    path: "/auth", // opcional: restringe el path a /auth
  });
}

export function clearAuthCookies(res: any) {
  res.clearCookie("access_token", { path: "/" });
  res.clearCookie("refresh_token", { path: "/auth" });
}
