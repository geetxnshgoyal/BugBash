# Team Operations Dashboard

Internal workspace for NST’s Bug Bash organizing team. The goal is to replace ad-hoc meeting notes with a shared dashboard where organizers can track department ownership, action items, progress updates, and upcoming events.

## Audience & Access
- **Users:** NST core committee, department leads, on-ground volunteers. Participants do not see this page.
- **Access control:** Require named accounts for each organizer. Reuse the existing admin session/token scaffolding so the dashboard stays private, but extend it to issue per-user sessions instead of a single shared admin key.

## Core Use Cases
1. **Department overview:** Team members see their assigned department and shared responsibilities.
2. **Task management:** Create, assign, prioritize, and set deadlines on tasks. Users can filter by department, owner, status, and due date.
3. **Progress logging:** Before marking a task complete, add a short progress report (text, optional links, attachments later).
4. **New task intake:** Leads can create follow-up tasks for any member and set reminders.
5. **Events timeline:** Upcoming meetings, campus visits, dry runs, etc., visible with ownership and preparation checklists.
6. **Historical accountability:** Post-event, NST can review individual contributions and reuse insights for future clubs or events.
7. **Self-assignment:** Volunteers can claim or release tasks so ownership is obvious and conflicts are avoided.

## Data Model (Firestore)
| Collection | Purpose | Sample Fields |
| --- | --- | --- |
| `team_members` | Organizer accounts & preferences | `display_name`, `login_id`, `identifiers[]`, `access_code`, `role` (`lead`, `volunteer`, etc.), `department_id`, `photo_url`, `active` |
| `departments` | Departments or working groups | `name`, `description`, `lead_member_ids`, `channels` (Slack/WhatsApp link) |
| `tasks` | Work items tied to departments | `title`, `description`, `department_id`, `owner_ids`, `status`, `priority`, `due_at`, `created_by`, `created_at`, `checklist[]`, `updates_count`, `last_update_*` |
| `task_updates` | Progress log entries for tasks | `task_id`, `member_id`, `note`, `status_after`, `created_at`, `attachments[]` |
| `events` | Meetings, rehearsals, deadlines | `title`, `description`, `start_at`, `end_at`, `location`, `link`, `hosts`, `department_ids` |
| `session_tokens` | Short-lived login sessions | `token`, `member_id`, `expires_at`, `created_at`, `ip` |

> Store task counters/aggregates via Firestore triggers or query-time aggregations as needed (e.g., incomplete task count per department).

## API Outline
| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/api/team/login` | Name/login + one-time code. Returns session token. |
| `POST` | `/api/team/logout` | Invalidates the current session token. |
| `GET` | `/api/team/me` | Returns member profile, department info, and default filters. |
| `GET` | `/api/team/tasks` | Paginated task list filtered by department/owner/status. |
| `POST` | `/api/team/tasks` | Create a new task (lead-only by default). |
| `PATCH` | `/api/team/tasks/:id` | Update metadata (status, owners, due date). |
| `POST` | `/api/team/tasks/:id/updates` | Add progress note; optionally mark complete. |
| `GET` | `/api/team/tasks/:id/updates` | Fetch update history for the task. |
| `POST` | `/api/team/tasks/:id/claim` | Claim or release a task; leads can override owners. |
| `GET` | `/api/team/events` | List upcoming events/meetings with optional filters. |
| `POST` | `/api/team/events` | Create or edit events (restrict to leads/admins). |
| `GET` | `/api/team/departments` | Reference data for UI filters/dropdowns. |

All endpoints require a valid organizer session (`Authorization: Bearer <token>`). Reuse the existing timing-safe checks (`safeCompare`, `createSignedGithubToken`) to sign JSON Web Token-like payloads scoped to team users.

## Front-End Experience
- **Route:** `/team`
- **Layout:** Dashboard with a left rail (department & filters), main content (task list / calendar), right rail (upcoming deadlines, meeting reminders).
- **Components:**
  - Department summary card (lead, members, open tasks count).
  - Task board view with quick actions (update status, assign member, add note).
  - Modal for logging progress (textarea + “blocked” toggle).
  - Event list with ICS download link and “prep checklist” reference.
  - Notification banner for overdue tasks or approaching deadlines.
- **State management:** Fetch `me`, `tasks`, and `events` on load; use optimistic updates for task status changes and note submissions.
- **Security:** Hide the page unless authenticated. Redirect to login if session missing/expired.

## Implementation Phases
1. **Foundation**
   - Create Firestore collections and indexes.
   - Build `/api/team/login` issuing signed session tokens (passwordless or admin-seeded credentials).
   - Protect new routes with middleware similar to `adminAuth`.
   - Wire Express handlers to Firestore reads/writes (members, departments, tasks, updates, events).
   - Use HMAC-signed JWTs (`TEAM_SESSION_SECRET`) for organizer sessions so stateless deployments work.
2. **MVP Dashboard**
   - Add `/team` page with login form.
   - Implement task list + progress updates + event feed.
   - Enable task claiming/unclaiming so ownership stays visible without meetings.
   - Seed initial data for departments and members.
3. **Enhancements**
   - Notifications (email/push) for upcoming deadlines.
   - Attachment support for updates.
   - Slack/Teams integration for automatic reminders.
   - CSV export for contribution reports.

## Next Steps
- Align with NST leads on required roles, authentication method (email OTP vs. password vs. Google/GitHub), and any data retention policies.
- Convert the API outline into issues/user stories so development can be parallelized (auth, tasks, events, UI).
- Once confirmed, scaffold the backend routes in `server.js` (or split into `/team` module) and create the new `team.html` / React component if you migrate the dashboard to a framework.
