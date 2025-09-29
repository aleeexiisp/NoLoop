import helmet from "helmet";
import 'dotenv/config';
import express from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import rateLimit from "express-rate-limit";
import { signAccessToken, setAccessCookie, setRefreshCookie, clearAuthCookies } from './auth.js';

import { PORT } from '../../config/config.js';
import { userRepository } from '../adapters/db/userRepo.drizzle.js';
import { attachUser, requireAuth } from "../adapters/http/auth.middleware.js";

declare global {
  namespace Express {
    interface UserPayload { id: string; username: string; iat?: number; exp?: number }
    interface Request { user?: UserPayload | null }
  }
}

/********************************
 * 
 *  CONFIGURACIÓN DEL SERVIDOR
 * 
 ********************************/

export const app = express();

app.use(helmet());
app.use(cors({
  origin: 'http://localhost:8000', // your frontend origin
  credentials: true,               // allow cookies to be sent
}));
app.set('view engine', 'ejs');
app.use(express.json());
app.use(cookieParser());
app.use(attachUser)

/********************************
 * 
 *    CHECK HEALTH & ROUTES
 * 
 ********************************/

app.get('/health', (_req, res) => res.json({ ok: true }));
app.get('/api/v1/ping', (req, res) => res.json({ pong: true, user: req.user }));
app.get('/api/v1/me', requireAuth, (req, res) => res.json({ user: req.user }));

/********************************
 * 
 *  ENDPOINTS DE AUTENTICACIÓN
 * 
 ********************************/

const rateLimiter: express.RequestHandler = process.env.NODE_ENV === 'test'
  ? (_req, _res, next) => next()
  : rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });

app.get('/', (req, res) => {
  const user = req.user ?? null;
  //res.render('index', { user });
  res.json({ message: 'Welcome to the API', user });
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const id = await userRepository.create({ username, password });
    return res.status(201).json({ id });
  } catch (error: any) {
    const status = error?.statusCode ?? 400;
    return res.status(status).json({ error: error.message });
  }
});

app.post('/login', rateLimiter, async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await userRepository.login({ username, password });

    const access = signAccessToken({ id: user.id, username: user.username });
    setAccessCookie(res, access); // si tu helper acepta ms opcional, puedes pasar 15*60*1000

    const { token: refresh, expiresAt } = await userRepository.issueRefresh(user.id);
    const ttlSec = Math.max(1, expiresAt - Math.floor(Date.now() / 1000));
    setRefreshCookie(res, refresh, ttlSec);

    return res.json({ user });
  } catch (error) {
    return res.status(401).json({ error: (error as any).message });
  }
});


app.post('/change-password', rateLimiter, requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user!.id; // ← del JWT, sin fallback

    await userRepository.changePassword({ userId, currentPassword, newPassword });
    await userRepository.revokeAllRefresh(req.user!.id)
    clearAuthCookies(res);
    
    return res.json({ ok: true, message: 'Password changed successfully, please login again.' });
  } catch (error) {
    return res.status(401).json({ error: (error as any).message });
  }
});


app.post('/auth/logout', rateLimiter, async (req, res) => {
  const rt = req.cookies?.refresh_token || req.body?.refresh_token;
  if (rt) await userRepository.revokeRefresh(rt);

  clearAuthCookies(res); 

  return res.json({ ok: true, message: 'User logged out successfully' });
});


app.post('/logout-all', rateLimiter, requireAuth, async (req, res) => {
  await userRepository.revokeAllRefresh(req.user!.id);
  clearAuthCookies(res);
  return res.json({ ok: true });
});


app.post("/auth/refresh", rateLimiter, async (req, res) => {
  try {
    const rt = req.cookies?.refresh_token || req.body?.refresh_token;
    if (!rt) return res.status(401).json({ error: 'No refresh token' });

    const { user, refresh } = await userRepository.rotateRefresh(rt);

    const access = signAccessToken(user);
    setAccessCookie(res, access);

    // refresh.expiresAt es number (epoch seconds)
    const secondsUntil = (expSec: number) => Math.max(1, expSec - Math.floor(Date.now()/1000));
    setRefreshCookie(res, refresh.token, secondsUntil(refresh.expiresAt));

    return res.json({ ok: true });
  } catch (error) {
    return res.status(401).json({ error: (error as any).message });
  }
});

app.post('/protected', rateLimiter, requireAuth, (req, res) => {
  const user = req.user ?? null;
  if (!user) return res.status(403).json({ error: 'Unauthorised user' });

  //res.render('protected', user);
  res.json({ message: 'This is protected data.', user });
});

// Error handler
app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error(err);
  const status = err?.statusCode ?? (err?.name === 'ZodError' ? 400 : 500);
  res.status(status).json({ error: err?.message ?? 'Internal Server Error' });
});

if (process.env.NODE_ENV !== 'test') {
  app.listen(PORT, () => {
    console.log(`[noloop] listening on http://localhost:${PORT}`);
  });
}
