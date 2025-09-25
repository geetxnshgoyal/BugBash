import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';
import express from 'express';
import cors from 'cors';
import admin from 'firebase-admin';
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

// --- Firebase ---
const resolveServiceAccount = () => {
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT?.trim();
  if (raw) {
    try {
      return JSON.parse(raw);
    } catch (err) {
      try {
        const decoded = Buffer.from(raw, 'base64').toString('utf8');
        return JSON.parse(decoded);
      } catch (decodeErr) {
        throw new Error('FIREBASE_SERVICE_ACCOUNT is not valid JSON or base64 JSON');
      }
    }
  }

  const credentialsPath = process.env.GOOGLE_APPLICATION_CREDENTIALS?.trim();
  if (credentialsPath) {
    const resolved = path.isAbsolute(credentialsPath) ? credentialsPath : path.join(__dirname, credentialsPath);
    const fileContents = fs.readFileSync(resolved, 'utf8');
    return JSON.parse(fileContents);
  }

  return null;
};

const initializeFirebase = () => {
  if (admin.apps.length) return admin.app();
  const serviceAccount = resolveServiceAccount();
  if (serviceAccount) {
    return admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
  }
  if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
    return admin.initializeApp({ credential: admin.credential.applicationDefault() });
  }
  throw new Error('Firebase credentials not configured. Set FIREBASE_SERVICE_ACCOUNT or GOOGLE_APPLICATION_CREDENTIALS.');
};

let firestore;
try {
  firestore = initializeFirebase().firestore();
} catch (err) {
  console.error('Failed to initialize Firebase Admin SDK');
  console.error(err);
  process.exit(1);
}

const FieldValue = admin.firestore.FieldValue;
const registrationsCollection = firestore.collection(process.env.FIREBASE_REGISTRATIONS_COLLECTION || 'registrations');

const mapRegistration = (doc) => {
  const data = doc.data() || {};
  const createdAt = data.created_at || (data.created_at_ts?.toDate ? data.created_at_ts.toDate().toISOString() : '');
  return {
    id: doc.id,
    created_at: createdAt,
    project_title: data.project_title || data.team_name || '',
    team_name: data.team_name || '',
    leader_name: data.leader_name || '',
    leader_email: data.leader_email || '',
    track: data.track || '',
    problem: data.problem || '',
    solution: data.solution || '',
    tech_stack: data.tech_stack || '',
    project_link: data.project_link || '',
    notes: data.notes || '',
    members_text: data.members_text || '',
    idea: data.idea || '',
    ip: data.ip || '',
    phone: data.phone || '',
    dob: data.dob || '',
    tshirt_size: data.tshirt_size || data.size || '',
    heard_from: data.heard_from || ''
  };
};

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
app.post('/api/register', async (req, res) => {
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
  const phoneRaw = String(payload.phone ?? '').trim();
  const normalizedPhone = phoneRaw.replace(/[^\d+]/g,'').replace(/(?!^)[+]/g,'');
  const dobRaw = String(payload.dob ?? '').trim();
  const tshirtRaw = String(payload.size ?? payload.tshirt_size ?? '').trim().toUpperCase().replace(/\s+/g,'');
  const allowedSizes = new Set(['XS','S','M','L','XL','XXL']);
  const tshirtSize = allowedSizes.has(tshirtRaw) ? tshirtRaw : '';
  const heardFrom = String(payload.heard_from ?? payload.referral ?? payload.problem ?? '').trim();

  if (!leader_name || !leaderEmailRaw || !trackValue || !projectTitle) {
    return res.status(400).json({ ok: false, error: 'missing_fields' });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(leaderEmailRaw)) {
    return res.status(400).json({ ok: false, error: 'invalid_email' });
  }

  const leaderEmailNormalized = leaderEmailRaw.toLowerCase();
  try {
    const existingSnap = await registrationsCollection
      .where('leader_email_lower', '==', leaderEmailNormalized)
      .limit(1)
      .get();
    if (!existingSnap.empty) {
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

    const docRef = registrationsCollection.doc();
    const createdAtIso = new Date().toISOString();
    await docRef.set({
      team_name: projectTitle,
      leader_name,
      leader_email: leaderEmailRaw,
      leader_email_lower: leaderEmailNormalized,
      members_text: membersText,
      track: trackValue,
      idea: ideaCombined,
      ip: req.headers['x-forwarded-for']?.toString() || req.socket.remoteAddress || '',
      project_title: projectTitle,
      problem: problemStatement,
      solution: solutionOverview,
      tech_stack: techStack,
      project_link: link,
      notes: notesRaw,
      phone: normalizedPhone,
      dob: dobRaw,
      tshirt_size: tshirtSize,
      heard_from: heardFrom,
      created_at: createdAtIso,
      created_at_ts: FieldValue.serverTimestamp()
    });

    return res.status(201).json({ ok: true, id: docRef.id });
  } catch (err) {
    console.error('Failed to save registration', err);
    return res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// CSV
app.get('/api/registrations.csv', adminAuth, async (_req, res) => {
  try {
    const snapshot = await registrationsCollection.orderBy('created_at', 'desc').get();
    const rows = snapshot.docs.map(mapRegistration);
    const headers = [
      'id','created_at','project_title','team_name','leader_name','leader_email','phone','dob','tshirt_size','heard_from','track',
      'problem','solution','tech_stack','project_link','notes','members_text','idea','ip'
    ];
    const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
    const csv = [headers.join(',')]
      .concat(rows.map((row) => headers.map((h) => esc(row[h])).join(',')))
      .join('\n');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="registrations.csv"');
    res.send(csv);
  } catch (err) {
    console.error('Failed to produce registrations CSV', err);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
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
app.get('/api/admin/registrations', adminAuth, async (_req, res) => {
  try {
    const snapshot = await registrationsCollection.orderBy('created_at', 'desc').get();
    const rows = snapshot.docs.map(mapRegistration);
    res.json(rows);
  } catch (err) {
    console.error('Failed to load registrations for admin', err);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// --- Admin page and index fallback ---
app.get('/admin', (_req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.get('/register', (_req, res) => res.sendFile(path.join(__dirname, 'register.html')));
app.use((_req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// --- Start ---
app.listen(PORT, () => console.log(`Bug Bash server listening on :${PORT}`));
