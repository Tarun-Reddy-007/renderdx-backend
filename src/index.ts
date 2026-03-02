import 'dotenv/config';

import bcrypt from 'bcryptjs';
import cookieParser from 'cookie-parser';
import express from 'express';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import { z } from 'zod';

const prisma = new PrismaClient();
const app = express();

app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());

const PORT = Number(process.env.PORT ?? 3001);
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error('Missing JWT_SECRET in environment');
}
const JWT_SECRET_VALUE: string = JWT_SECRET;

const emailSchema = z.string().trim().toLowerCase().email();

function isStrongPassword(password: string) {
  // min 8 chars, at least 1 uppercase, 1 number, 1 special char
  return /^(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/.test(password);
}

function signSession(user: { id: string; email: string }) {
  return jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET_VALUE, { expiresIn: '30d' });
}

function setSessionCookie(res: express.Response, token: string) {
  res.cookie('renderdx_session', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: false,
    path: '/',
    maxAge: 30 * 24 * 60 * 60 * 1000,
  });
}

app.post('/api/auth/check-email', async (req: express.Request, res: express.Response) => {
  const parsed = z.object({ email: emailSchema }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid email' });

  const email = parsed.data.email;
  const user = await prisma.user.findUnique({ where: { email }, select: { id: true } });
  res.json({ exists: Boolean(user) });
});

app.post('/api/auth/signup', async (req: express.Request, res: express.Response) => {
  const parsed = z
    .object({
      email: emailSchema,
      fullName: z.string().trim().min(1),
      password: z.string().min(1),
    })
    .safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid input' });

  const { email, fullName, password } = parsed.data;
  if (!isStrongPassword(password)) {
    return res.status(400).json({
      error: 'Password must be at least 8 characters and include 1 uppercase letter, 1 number, and 1 special character.',
    });
  }

  const existing = await prisma.user.findUnique({ where: { email }, select: { id: true } });
  if (existing) return res.status(409).json({ error: 'Email already exists' });

  const passwordHash = await bcrypt.hash(password, 10);
  const user = await prisma.user.create({
    data: { email, fullName, passwordHash },
    select: { id: true, email: true, fullName: true, createdAt: true },
  });

  const token = signSession({ id: user.id, email: user.email });
  setSessionCookie(res, token);

  res.json({ user });
});

app.post('/api/auth/login', async (req: express.Request, res: express.Response) => {
  const parsed = z.object({ email: emailSchema, password: z.string().min(1) }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid input' });

  const { email, password } = parsed.data;
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid email or password' });

  const token = signSession({ id: user.id, email: user.email });
  setSessionCookie(res, token);

  res.json({ user: { id: user.id, email: user.email, fullName: user.fullName } });
});

app.get('/api/health', (_req: express.Request, res: express.Response) => {
  res.json({ ok: true });
});

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`renderdx-backend listening on http://localhost:${PORT}`);
});
