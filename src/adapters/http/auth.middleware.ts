import type { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

export const requireAuth = (req: Request, res: Response, next: NextFunction) => {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing Bearer token' });
  }
  const token = header.slice(7);
  try {
    const secret = process.env.JWT_SECRET!;
    const payload = jwt.verify(token, secret) as { sub?: string };
    if (!payload.sub) throw new Error('Missing sub');
    (req as any).user = { id: payload.sub };
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};
