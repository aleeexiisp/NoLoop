import helmet from "helmet";
import 'dotenv/config';
import express from 'express';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import rateLimit from "express-rate-limit";

import { PORT, SECRET_JWT_KEY } from '../../config/config.js';
import { userRepository } from '../adapters/db/userRepo.drizzle.js';
import { attachUser, requireAuth } from "../adapters/http/auth.middleware.js";

declare global {
  namespace Express {
    interface UserPayload { id: string; username: string; iat?: number; exp?: number }
    interface Request { user?: UserPayload | null }
  }
}

const app = express();

app.use(helmet());
app.use(cors({
  origin: 'http://localhost:8000', // your frontend origin
  credentials: true,               // allow cookies to be sent
}));
app.set('view engine', 'ejs');
app.use(express.json());
app.use(cookieParser());
app.use(attachUser)

// Check server
app.get('/health', (_req, res) => res.json({ ok: true }));
app.get('/api/v1/ping', (req, res) => res.json({ pong: true, user: req.user }));
app.get('/api/v1/me', requireAuth, (req, res) => res.json({ user: req.user }));


app.get('/', (req, res) => {
  const user = req.user ?? null;
  //res.render('index', { user });
  res.json({ message: 'Welcome to the API', user });
});

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });

app.post('/login', loginLimiter, async(req, res) => {
  const { username, password } = req.body;
  try {
    const user = await userRepository.login({ username, password });
    const token = jwt.sign(
      { id: user.id, username: user.username }, 
      SECRET_JWT_KEY, 
      { 
        expiresIn: '1h' 
      });
    res
      .cookie('access_token', token, { 
        httpOnly: true, // not accessible from JS
        secure: process.env.NODE_ENV === 'production', // only over HTTPS
        sameSite: 'lax', // CSRF protection
        maxAge: 3600000, // 1 hour
      })
      .json({ user, token });
  } catch (error) {
    res.status(401).json({ error: (error as any).message });
  }

});

app.post('/change-password', loginLimiter, requireAuth, async(req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user!.id ?? {};

    await userRepository.changePassword({ userId, currentPassword, newPassword });
    
    return res.json({ ok: true, message: 'Password changed successfully' });
  } catch (error) {
    res.status(401).json({ error: (error as any).message });
  }

});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  
  try {
    const id = await userRepository.create({ username, password });
    res.json({ id });
  } catch (error) {
    res.status(400).json({ error: (error as any).message });
  }

});

app.post('/logout', (_req, res) => {
  res
    .clearCookie('access_token')
    .json({ message: "Used logged out successfully" });
});

app.post('/protected', requireAuth, (req, res) => {
  const user = req.user ?? null;
  if (!user) return res.status(403).json({ error: 'Unauthorised user' });

  //res.render('protected', user);
  res.json({ message: 'This is protected data.', user });
});

// Error handler
app.use((err: any, _req: any, res: any, _next: any) => {
  console.error(err);
  res.status(400).json({ error: err?.message || 'Bad Request' });
});

app.listen(PORT, () => {
  console.log(`[noloop] listening on http://localhost:${PORT}`);
});
