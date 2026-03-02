# renderdx-backend (Express + Prisma + PostgreSQL)

## Setup

1. Create a Postgres database (local, Docker, or hosted)
2. Copy env file:
   - `cp .env.example .env` (PowerShell: `Copy-Item .env.example .env`)
3. Set `DATABASE_URL` and `JWT_SECRET` in `.env`

## Install

- `npm install`

## Migrate + run

- `npm run prisma:migrate`
- `npm run dev`

Backend runs on `http://localhost:3001`.

## API

- `POST /api/auth/check-email` { email }
- `POST /api/auth/login` { email, password }
- `POST /api/auth/signup` { email, fullName, password }
