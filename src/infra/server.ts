import 'dotenv/config';
import express from 'express';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import cors from 'cors';

import { PORT, SECRET_JWT_KEY } from './config.js';
import { userRepository } from '../adapters/db/userRepo.js';

declare global {
  namespace Express {
    interface Request {
      session?: { user: any | null };
    }
  }
}

const app = express();

app.use(cors({
  origin: 'http://localhost:8000', // your frontend origin
  credentials: true,               // allow cookies to be sent
}));

app.set('view engine', 'ejs');

app.use(express.json());
app.use(cookieParser());
app.use((req, _res, next) => {
  const token = req.cookies.access_token;

  req.session = { user: null };
  try {
    const data = jwt.verify(token, SECRET_JWT_KEY);
    req.session.user = data
  } catch {}
  next(); // continue to the next middleware or route handler
})

// Health
app.get('/health', (_req, res) => res.json({ ok: true }));


app.get('/', (req, res) => {
  const user = req.session?.user ?? null;
  res.render('index', { user });
});

app.post('/login', async(req, res) => {
  const { username, password } = req.body;
  try {
    const user = await userRepository.login({ username, password });
    const token = jwt.sign(
      { id: user._id, username: user.username }, 
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

app.post('/protected', (req, res) => {
  const user = req.session?.user ?? null;
  if (!user) return res.status(403).json({ error: 'Unauthorised user' });

  res.render('protected', user);
});

// Error handler
app.use((err: any, _req: any, res: any, _next: any) => {
  console.error(err);
  res.status(400).json({ error: err?.message || 'Bad Request' });
});

app.listen(PORT, () => {
  console.log(`[noloop] listening on http://localhost:${PORT}`);
});
