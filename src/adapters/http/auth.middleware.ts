// adapters/http/auth.middleware.ts
import type { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { SECRET_JWT_KEY } from "../../../config/config.js";

export interface JwtPayload { id: string; username: string; iat?: number; exp?: number }

declare global {
  namespace Express {
    interface Request { user?: JwtPayload | null }
  }
}

export function attachUser(req: Request, _res: Response, next: NextFunction) {
  req.user = null;
  const raw = req.cookies?.access_token || req.header("Authorization")?.replace("Bearer ", "");
  if (!raw) return next();
  try {
    req.user = jwt.verify(raw, SECRET_JWT_KEY) as JwtPayload;
  } catch { /* token inválido/expirado */ }
  next();
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  if (!req.user) return res.status(401).json({ error: "Unauthorized" });
  next();
}
