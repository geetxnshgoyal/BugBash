import dotenv from 'dotenv';
import path from 'path';
import express from 'express';
import cors from 'cors';
import Database from 'better-sqlite3';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || process.env.ADMIN_KEY || '';
const SESSION_TTL_MS = Number(process.env.ADMIN_SESSION_TTL_MS || 1000 * 60 * 60 * 6);
const adminSessions = new Map();

const createSession = (username) => {
  const token = crypto.randomBytes(32).toString('hex');
  adminSessions.set(token, { username, createdAt: Date.now() });
  return token;
};

const touchSession = (token) => {
  const record = adminSessions.get(token);
  if (!record) return false;
  if (Date.now() - record.createdAt > SESSION_TTL_MS) {
    adminSessions.delete(token);
    return false;
  }
  adminSessions.set(token, { ...record, createdAt: Date.now() });
  return true;
};

const getTokenFromRequest = (req) => {
  const authHeader = req.headers['authorization'];
  if (authHeader && typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7).trim();
  }
  const headerToken = req.headers['x-admin-token'];
  return typeof headerToken === 'string' ? headerToken.trim() : '';
};

const cleanupSessions = () => {
  const now = Date.now();
  for (const [token, session] of adminSessions.entries()) {
    if (now - session.createdAt > SESSION_TTL_MS) {
      adminSessions.delete(token);
    }
  }
};

setInterval(cleanupSessions, SESSION_TTL_MS).unref?.();

// --- DB ---
const db = new Database(path.join(__dirname, 'bugbash.db'));
db.pragma('journal_mode = WAL');
db.prepare(`
  CREATE TABLE IF NOT EXISTS registrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team_name TEXT NOT NULL,
    leader_name TEXT NOT NULL,
    leader_email TEXT NOT NULL,
    members_text TEXT NOT NULL,
    track TEXT NOT NULL,
    idea TEXT,
    project_title TEXT,
    problem TEXT,
    solution TEXT,
    tech_stack TEXT,
    project_link TEXT,
    notes TEXT,
    ip TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  )
`).run();

const ensureColumn = (column, type = 'TEXT') => {
  try {
    db.prepare(`ALTER TABLE registrations ADD COLUMN ${column} ${type}`).run();
  } catch (err) {
    if (!String(err.message).includes('duplicate column name')) throw err;
  }
};
['project_title','problem','solution','tech_stack','project_link','notes'].forEach(col => ensureColumn(col));

// --- Middleware ---
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// static
app.use('/assets', express.static(path.join(__dirname, 'assets'), { extensions: ['png','jpg','jpeg','gif'] }));
app.use(express.static(__dirname, { extensions: ['html'] }));

// health
app.get('/api/health', (_req, res) => res.json({ ok: true }));

// register
app.post('/api/register', (req, res) => {
  const payload = req.body || {};

  const leader_name = String(
    payload.full_name ??
    payload.name ??
    payload.leader_name ??
    (typeof payload.leader === 'string' ? payload.leader.split(/[-•|]/)[0] : '') ??
    ''
  ).trim();

  let leaderEmailRaw = String(
    payload.email ??
    payload.leader_email ??
    ''
  ).trim();
  if (!leaderEmailRaw && typeof payload.leader === 'string') {
    const parts = payload.leader.split(/[-•|]/);
    if (parts.length >= 2) leaderEmailRaw = parts[1].trim();
  }

  const trackValue = String(payload.track ?? payload.preferred_track ?? '').trim();
  const projectTitle = String(payload.project_title ?? payload.team_name ?? payload.project ?? '').trim();
  let problemStatement = String(payload.problem ?? payload.idea ?? '').trim();
  const solutionOverview = String(payload.solution ?? '').trim();
  const techStack = String(payload.tech_stack ?? payload.members ?? '').trim();
  const notesRaw = String(payload.notes ?? payload.additional_notes ?? '').trim();
  const linkInput = String(payload.project_link ?? payload.link ?? '').trim();
  const link = linkInput && !/^https?:\/\//i.test(linkInput) ? `https://${linkInput}` : linkInput;

  if (!leader_name || !leaderEmailRaw || !trackValue || !projectTitle) {
    return res.status(400).json({ ok: false, error: 'missing_fields' });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(leaderEmailRaw)) {
    return res.status(400).json({ ok: false, error: 'invalid_email' });
  }

  const leaderEmailNormalized = leaderEmailRaw.toLowerCase();
  const existing = db.prepare(`SELECT id FROM registrations WHERE lower(leader_email) = ?`).get(leaderEmailNormalized);
  if (existing) {
    return res.status(409).json({ ok: false, error: 'email_exists' });
  }

  if (!problemStatement) problemStatement = 'Not specified yet';

  const ideaParts = [`Problem: ${problemStatement}`];
  if (solutionOverview) ideaParts.push(`Solution: ${solutionOverview}`);
  const ideaCombined = ideaParts.join('\n');
  const membersText = [
    techStack ? `Tech stack: ${techStack}` : '',
    notesRaw ? `Notes: ${notesRaw}` : ''
  ].filter(Boolean).join('\n') || 'Not provided';

  const stmt = db.prepare(`
    INSERT INTO registrations (
      team_name,
      leader_name,
      leader_email,
      members_text,
      track,
      idea,
      ip,
      project_title,
      problem,
      solution,
      tech_stack,
      project_link,
      notes
    ) VALUES (
      @project_title,
      @leader_name,
      @leader_email,
      @members_text,
      @track,
      @idea,
      @ip,
      @project_title,
      @problem,
      @solution,
      @tech_stack,
      @project_link,
      @notes
    )
  `);

  const info = stmt.run({
    project_title: projectTitle,
    leader_name,
    leader_email: leaderEmailRaw,
    members_text: membersText,
    track: trackValue,
    idea: ideaCombined,
    ip: req.headers['x-forwarded-for']?.toString() || req.socket.remoteAddress || '',
    problem: problemStatement,
    solution: solutionOverview,
    tech_stack: techStack,
    project_link: link,
    notes: notesRaw
  });

  return res.status(201).json({ ok: true, id: info.lastInsertRowid });
});

// CSV
app.get('/api/registrations.csv', adminAuth, (_req, res) => {
  const rows = db.prepare(`SELECT * FROM registrations ORDER BY created_at DESC`).all();
  const headers = [
    'id','created_at','project_title','team_name','leader_name','leader_email','track',
    'problem','solution','tech_stack','project_link','notes','members_text','idea','ip'
  ];
  const esc = v => `"${String(v ?? '').replace(/"/g,'""')}"`;
  const csv = [headers.join(',')].concat(rows.map(r => headers.map(h => esc(r[h])).join(','))).join('\n');
  res.setHeader('Content-Type','text/csv; charset=utf-8');
  res.setHeader('Content-Disposition','attachment; filename="registrations.csv"');
  res.send(csv);
});

// --- Admin API (header key) ---
function adminAuth(req, res, next){
  const bearerToken = getTokenFromRequest(req);
  if (bearerToken && touchSession(bearerToken)) {
    req.adminToken = bearerToken;
    return next();
  }

  if (ADMIN_TOKEN) {
    const headerToken = req.headers['x-admin-token'] || req.headers['x-admin-key'] || '';
    if (headerToken === ADMIN_TOKEN) {
      return next();
    }
    if (bearerToken === ADMIN_TOKEN) {
      return next();
    }
    return res.status(401).json({ ok:false, error:'unauthorized' });
  }

  return res.status(501).json({ ok:false, error:'admin_credentials_not_set' });
}

app.post('/api/admin/login', (req, res) => {
  if (!ADMIN_TOKEN) {
    return res.status(501).json({ ok:false, error:'admin_credentials_not_set' });
  }

  const { token: providedToken } = req.body || {};
  if (!providedToken) {
    return res.status(400).json({ ok:false, error:'missing_token' });
  }

  if (providedToken !== ADMIN_TOKEN) {
    return res.status(401).json({ ok:false, error:'invalid_token' });
  }

  const sessionToken = createSession('admin');
  res.json({ ok:true, token: sessionToken, expires_in: SESSION_TTL_MS });
});

app.post('/api/admin/logout', (req, res) => {
  const token = getTokenFromRequest(req);
  if (token) {
    adminSessions.delete(token);
  }
  res.json({ ok:true });
});
app.get('/api/admin/registrations', adminAuth, (_req, res) => {
  const rows = db.prepare(`SELECT * FROM registrations ORDER BY created_at DESC`).all();
  res.json(rows);
});

// --- Admin page and index fallback ---
app.get('/admin', (_req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.get('/register', (_req, res) => res.sendFile(path.join(__dirname, 'register.html')));
app.use((_req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// --- Start ---
app.listen(PORT, () => console.log(`Bug Bash server listening on :${PORT}`));
