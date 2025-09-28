import jwt from "jsonwebtoken";
import { SECRET_JWT_KEY, ACCESS_EXPIRES_IN, COOKIE_SECURE, COOKIE_SAMESITE, COOKIE_DOMAIN } from "../../config/config.js";


// Genera access token (JWT) corto
export function signAccessToken(payload: { id: string; username: string }) {
  return jwt.sign(payload, SECRET_JWT_KEY, { expiresIn: ACCESS_EXPIRES_IN });
}

// Setters de cookies
export function setAccessCookie(res: any, token: string) {
  res.cookie("access_token", token, {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: COOKIE_SAMESITE,
    maxAge: 1000 * 60 * 60, // 15 min (opcional: en línea con ACCESS_EXPIRES_IN)
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
