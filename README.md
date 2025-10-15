# Bug Bash Registration

Node/Express app that serves the Bug Bash marketing pages and exposes the APIs powering the registration flow in `register.html`. Registrations are stored in Firestore, and optional integrations cover GitHub OAuth, Google reCAPTCHA, and transactional email.

## Features
- Static marketing pages (`index.html`, `register.html`, `admin.html`) hosted from Express.
- Firestore-backed registration API with form validation, duplicate blocking, and CSV export.
- GitHub OAuth helper that pre-fills form fields and signs session payloads with HMAC.
- Optional Google reCAPTCHA v3 enforcement to limit automated submissions.
- Nodemailer integration for confirmation emails triggered after successful registration.
- Admin APIs protected by a static admin token and short-lived in-memory sessions.
- Organizer-only team dashboard (`/team`) for assigning tasks, logging progress, and tracking upcoming events.
- Task claiming workflow so organizers can self-assign work with department-specific highlights.

## Prerequisites
- Node.js 18+ and npm
- Firebase project with a service account that can write to Cloud Firestore
- (Optional) GitHub OAuth app, SMTP credentials, and a reCAPTCHA v3 key pair

## Getting Started
1. Install dependencies:
   ```sh
   npm install
   ```
2. Create a `.env` file alongside `server.js`. At minimum you need Firebase credentials and an admin token:
   ```env
   FIREBASE_SERVICE_ACCOUNT='{"type":"service_account",...}'
   ADMIN_TOKEN=choose-a-long-random-string
   PORT=3000
   REGISTRATION_OPEN=true
   ```
   You can also point `GOOGLE_APPLICATION_CREDENTIALS` to a JSON key file instead of using `FIREBASE_SERVICE_ACCOUNT`.
3. Start the server:
   ```sh
   npm run dev
   ```
   The site is then served from http://localhost:3000 with `index.html` and `register.html` available directly.

### Admin access
The admin page is served from http://localhost:3000/admin. Sign in with the `ADMIN_TOKEN` using the client-side prompt; the backend exchanges that for a short-lived session token so you do not resend the static key on every request.

## Environment Variables
| Name | Purpose |
| --- | --- |
| `FIREBASE_SERVICE_ACCOUNT` / `GOOGLE_APPLICATION_CREDENTIALS` | Required. Supplies credentials for Firebase Admin SDK so registrations can be persisted in Firestore. |
| `FIREBASE_REGISTRATIONS_COLLECTION` | Optional. Firestore collection name (defaults to `registrations`). |
| `ADMIN_TOKEN` / `ADMIN_KEY` | Static token for protecting admin-only APIs. |
| `ADMIN_SESSION_TTL_MS` | Milliseconds before an admin session expires (default 6h). |
| `REGISTRATION_OPEN` | Set to `false` to temporarily close sign-ups. |
| `RECAPTCHA_SITE_KEY` / `RECAPTCHA_SECRET` | Enable Google reCAPTCHA verification for the public form. |
| `RECAPTCHA_MIN_SCORE` | Minimum accepted score when reCAPTCHA is enabled (default 0.5). |
| `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` | Configure GitHub OAuth login to pre-fill profile details. |
| `GITHUB_REDIRECT_URI` | Optional. Override callback URL used in production. |
| `GITHUB_TOKEN_SECRET` / `SESSION_SECRET` | Secret for signing GitHub state/session tokens. |
| `GITHUB_STATE_TTL_MS`, `GITHUB_PROFILE_TTL_MS` | Lifetimes for OAuth state and cached profiles. |
| `SITE_URL` | Base URL used by sitemap/robots responses (default `https://bugbash.me`). |
| `GOOGLE_SITE_VERIFICATION` / `GOOGLE_SITE_VERIFICATION_HTML` | Surface Google Search Console verification tags. |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `EMAIL_FROM` | Enable confirmation emails via nodemailer. |
| `PORT` | HTTP port when running locally (default 3000). |
| `TEAM_DASHBOARD_ENABLED` | Toggle the `/team` dashboard (`true` by default; set to `false` to disable). |
| `TEAM_SESSION_TTL_MS` | Milliseconds before organizer dashboard sessions expire (default 4h). |
| `TEAM_LOGIN_CODES` | JSON map of email → access code (optional override for the built-in demo codes). |
| `TEAM_SESSION_SECRET` | HMAC secret for signing team-session tokens (defaults to `ADMIN_TOKEN` if unset). |
| `FIREBASE_TEAM_DEPARTMENTS_COLLECTION` | Firestore collection name for team departments (`team_departments` by default). |
| `FIREBASE_TEAM_MEMBERS_COLLECTION` | Firestore collection for organizer accounts (`team_members` by default). |
| `FIREBASE_TEAM_TASKS_COLLECTION` | Firestore collection for task documents (`team_tasks` by default). |
| `FIREBASE_TEAM_TASK_UPDATES_COLLECTION` | Firestore collection for task updates (`team_task_updates` by default). |
| `FIREBASE_TEAM_EVENTS_COLLECTION` | Firestore collection for team events (`team_events` by default). |

## API Overview
| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `GET` | `/api/health` | None | Lightweight health check used by uptime monitors. |
| `POST` | `/api/register` | None | Accepts registration payloads, validates inputs, verifies reCAPTCHA, writes to Firestore, and triggers confirmation email. |
| `GET` | `/env.js` | None | Serves runtime configuration for the static front-end (`window.__APP_CONFIG__`). |
| `POST` | `/api/admin/login` | Admin token | Exchanges the static admin token for a short-lived session token. |
| `POST` | `/api/admin/logout` | Session token | Clears in-memory admin session. |
| `GET` | `/api/admin/registrations` | Session token / admin header | Returns JSON list of registrations ordered by creation time. |
| `GET` | `/api/registrations.csv` | Session token / admin header | Streams all registrations as CSV for spreadsheet workflows. |
| `POST` | `/api/team/login` | Name/login + access code | Starts an organizer session and returns profile context. |
| `POST` | `/api/team/logout` | Team session | Invalidates the current organizer session. |
| `GET` | `/api/team/me` | Team session | Returns member profile, department summary, and dashboard stats. |
| `GET` | `/api/team/tasks` | Team session | Lists tasks with optional filters (`status`, `mine`, `owner`, `department`). |
| `POST` | `/api/team/tasks` | Team session (lead) | Creates a new task within the selected department. |
| `PATCH` | `/api/team/tasks/:id` | Team session (lead/owner) | Updates task status, owners, due date, or checklist. |
| `POST` | `/api/team/tasks/:id/updates` | Team session (owner/lead) | Appends a progress note and optional status change. |
| `GET` | `/api/team/tasks/:id/updates` | Team session | Fetches the chronological update log for a task. |
| `POST` | `/api/team/tasks/:id/claim` | Team session (owner/lead) | Self-assign or release a task; leads can override existing assignees. |
| `GET` | `/api/team/events` | Team session | Lists upcoming events/meetings with host info. |
| `POST` | `/api/team/events` | Team session (lead) | Creates a new event or timeline entry. |
| `GET` | `/api/team/departments` | Team session | Returns department metadata for filters and ownership. |

All admin endpoints accept either:
- `Authorization: Bearer <sessionToken>` returned by `/api/admin/login`, or
- `X-Admin-Token: <ADMIN_TOKEN>` (suitable for scripts or CLI usage).

Team dashboard endpoints expect `Authorization: Bearer <teamSession>` returned by `/api/team/login` (or `X-Team-Token` when scripting).

## Available Scripts
- `npm run dev` – start the Express server with development defaults.
- `npm start` – start the server in production mode.
- `npm test` – placeholder; currently exits with a non-zero status.

## Data Model
Registrations are written to the Firestore collection defined by `FIREBASE_REGISTRATIONS_COLLECTION`. Each document contains:
- `leader_name`, `leader_email`, `leader_email_lower`
- `phone` (normalized to `+91XXXXXXXXXX`), `dob`
- `tshirt_size`, `heard_from`, `notes`, `profile_link`
- `github_login`, `github_profile_url`, `github_avatar`
- Metadata: `ip`, `created_at` ISO string, `created_at_ts` server timestamp, and optional GitHub metadata (`github_connected_at`)

Use the provided CSV endpoint when you need a spreadsheet-friendly export. Each row mirrors the fields returned by `mapRegistration` in `server.js`.

## Team Dashboard Data
- Organizer-facing routes now read/write Firestore collections. Create the following documents before going live:
  - `team_departments`: `{ name, description, lead_member_ids: string[], channels: { slack, whatsapp? } }`
  - `team_members`: `{ display_name, login_id, access_code, role, department_id, active?, identifiers?: string[] }`
  - `team_tasks`: `{ title, description, department_id, owner_ids: string[], status, priority, due_at }` (fields like `last_update_*` and `updates_count` are maintained automatically).
  - `team_task_updates`: `{ task_id, member_id, note, status_after, created_at }`.
  - `team_events`: `{ title, description, start_at, end_at, location, link, hosts: string[], department_ids: string[] }`.
- Store `login_id`/`display_name`/any aliases in lowercase inside the `identifiers` array so organizers can sign in with their name (e.g. `identifiers: ["anant"]`).
- Sessions for organizers are tracked in-memory with a four-hour TTL (`TEAM_SESSION_TTL_MS`). Increase the value or switch to persistent storage if you need long-lived access.
- Each task keeps `owner_ids` and works with the `/api/team/tasks/:id/claim` endpoint for self-assignment; the API updates the task document with `updates_count` and the latest note so cards can show progress without extra queries.
- For quick seeding, you can adapt the sample objects in `team-data.js` into batch writes for the collections above.
- Firestore will prompt for composite indexes the first time you hit the `/api/team/tasks/:id/updates` query (`task_id` + `created_at_ts`). Approve the suggested index in the Firebase console so update history loads instantly.
- To seed a fresh environment with the sample data under `team-data.js`, run `npm run seed:team` after configuring your service account; this script writes the departments/members/tasks/updates/events into the configured collections.

## Email Customization
The confirmation email template lives inline in `server.js`. Update the plain-text and HTML bodies together to keep content in sync. The `EMAIL_FROM` environment variable controls the sender header. If SMTP credentials are absent, the registration flow still succeeds but no email is sent.

## Project Layout
- `index.html` – landing page served from the Express static middleware.
- `register.html` – registration form that calls `/api/register`.
- `team.html` – organizer dashboard UI for tasks, updates, and events.
- `server.js` – Express app with API routes, Firestore integration, and GitHub/SMTP helpers.
- `assets/` – shared static assets (logos, images).
- `api/index.js` – Vercel edge handler that proxies to the main server when deployed serverlessly.
- `team-data.js` – optional seed sample you can adapt for populating Firestore collections during testing.
- `docs/team-dashboard.md` – product spec outlining long-term dashboard goals and API expectations.

## Deployment Notes
- The app reads configuration exclusively from environment variables, making it suitable for platforms like Vercel, Render, or any Node-friendly host.
- Ensure the environment allows outbound HTTPS requests to GitHub, Google reCAPTCHA, and your SMTP provider if those features are enabled.
- For Vercel, keep `vercel.json` in sync with any new routes you expose under `/api`.

## Troubleshooting
- **Firebase credential errors**: Confirm `FIREBASE_SERVICE_ACCOUNT` contains valid JSON or base64 JSON, or set `GOOGLE_APPLICATION_CREDENTIALS` to an accessible file path.
- **reCAPTCHA failures**: Lower `RECAPTCHA_MIN_SCORE` temporarily while testing, and make sure the front-end is configured with a matching `RECAPTCHA_SITE_KEY`.
- **Admin login invalid**: Verify the request body includes `token` that exactly matches `ADMIN_TOKEN`; tokens are case sensitive.
- **Emails not sending**: Check SMTP credentials and that the chosen port aligns with your provider (`465` generally requires `secure: true` which is auto-detected).

## Contributing
Issues and pull requests are welcome. Please lint and manually test the registration flow before submitting changes; automated tests are not yet in place.
