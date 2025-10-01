import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';
import express from 'express';
import cors from 'cors';
import admin from 'firebase-admin';
import crypto from 'crypto';
import fetch from 'node-fetch';
import { fileURLToPath } from 'url';

dotenv.config();

if (typeof globalThis.fetch !== 'function') {
  globalThis.fetch = fetch;
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || process.env.ADMIN_KEY || '';
const SESSION_TTL_MS = Number(process.env.ADMIN_SESSION_TTL_MS || 1000 * 60 * 60 * 6);
const REGISTRATION_OPEN = process.env.REGISTRATION_OPEN !== 'false';
const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET?.trim() || '';
const RECAPTCHA_MIN_SCORE = Number(process.env.RECAPTCHA_MIN_SCORE || '0.5');
const adminSessions = new Map();
const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID?.trim() || '';
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET?.trim() || '';
const GITHUB_REDIRECT_URI = process.env.GITHUB_REDIRECT_URI?.trim();
const GITHUB_STATE_TTL_MS = Number(process.env.GITHUB_STATE_TTL_MS || 1000 * 60 * 10);
const GITHUB_PROFILE_TTL_MS = Number(process.env.GITHUB_PROFILE_TTL_MS || 1000 * 60 * 5);
const githubStates = new Map();
const githubProfiles = new Map();
const githubSessions = new Map();
const EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}$/;
const INDIAN_MOBILE_REGEX = /^[6-9][0-9]{9}$/;

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

const sanitizeReturnTo = (value) => {
  if (typeof value !== 'string') return '/register.html';
  const trimmed = value.trim();
  if (!trimmed) return '/register.html';
  if (/^https?:\/\//i.test(trimmed)) {
    try {
      const url = new URL(trimmed);
      return `${url.pathname}${url.search}${url.hash}` || '/register.html';
    } catch {
      return '/register.html';
    }
  }
  if (trimmed.startsWith('//')) return '/register.html';
  if (!trimmed.startsWith('/')) {
    const normalized = trimmed.replace(/^\/+/, '');
    return `/${normalized}`;
  }
  return trimmed;
};

const cleanupGithubArtifacts = () => {
  const now = Date.now();
  for (const [state, record] of githubStates.entries()) {
    if (now - record.createdAt > GITHUB_STATE_TTL_MS) {
      githubStates.delete(state);
    }
  }
  for (const [token, record] of githubProfiles.entries()) {
    if (now - record.createdAt > GITHUB_PROFILE_TTL_MS) {
      githubProfiles.delete(token);
    }
  }
  for (const [sessionToken, record] of githubSessions.entries()) {
    if (now - record.createdAt > GITHUB_PROFILE_TTL_MS) {
      githubSessions.delete(sessionToken);
    }
  }
};

if (GITHUB_CLIENT_ID && GITHUB_CLIENT_SECRET) {
  const interval = Math.max(30000, Math.min(GITHUB_STATE_TTL_MS, GITHUB_PROFILE_TTL_MS));
  setInterval(cleanupGithubArtifacts, interval).unref?.();
}

const resolveGithubRedirectUri = (req) => {
  if (GITHUB_REDIRECT_URI) return GITHUB_REDIRECT_URI;
  const forwardedProto = req.headers['x-forwarded-proto']?.split(',')[0]?.trim();
  const proto = forwardedProto || req.protocol || 'https';
  const forwardedHost = req.headers['x-forwarded-host']?.split(',')[0]?.trim();
  const host = forwardedHost || req.get('host');
  return `${proto}://${host}/api/auth/github/callback`;
};

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
    leader_name: data.leader_name || '',
    leader_email: data.leader_email || '',
    problem: data.problem || '',
    solution: data.solution || '',
    tech_stack: data.tech_stack || '',
    profile_link: data.profile_link || data.project_link || '',
    github_login: data.github_login || '',
    github_profile_url: data.github_profile_url || data.profile_link || '',
    notes: data.notes || '',
    members_text: data.members_text || '',
    idea: data.idea || '',
    ip: data.ip || '',
    phone: data.phone || '',
    dob: data.dob || '',
    tshirt_size: data.tshirt_size || data.size || '',
    heard_from: data.heard_from || data.problem || ''
  };
};

// --- Middleware ---
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// static
app.get('/env.js', (_req, res) => {
  const payload = {
    recaptchaSiteKey: process.env.RECAPTCHA_SITE_KEY || '',
    registrationsOpen: REGISTRATION_OPEN,
    githubAuthEnabled: Boolean(GITHUB_CLIENT_ID && GITHUB_CLIENT_SECRET)
  };
  res.type('application/javascript').send(`window.__APP_CONFIG__=${JSON.stringify(payload)};`);
});

app.use('/assets', express.static(path.join(__dirname, 'assets'), { extensions: ['png','jpg','jpeg','gif'] }));
app.use(express.static(__dirname, { extensions: ['html'] }));

// health
app.get('/api/health', (_req, res) => res.json({ ok: true }));

// --- GitHub OAuth ---
const githubConfigured = () => Boolean(GITHUB_CLIENT_ID && GITHUB_CLIENT_SECRET);

app.get('/api/auth/github/start', (req, res) => {
  if (!githubConfigured()) {
    return res.status(501).json({ ok: false, error: 'github_not_configured' });
  }

  const state = crypto.randomBytes(16).toString('hex');
  const returnTo = sanitizeReturnTo(req.query.returnTo || '/register.html');
  githubStates.set(state, { createdAt: Date.now(), returnTo });

  const params = new URLSearchParams({
    client_id: GITHUB_CLIENT_ID,
    redirect_uri: resolveGithubRedirectUri(req),
    scope: 'read:user user:email',
    state
  });

  res.redirect(`https://github.com/login/oauth/authorize?${params.toString()}`);
});

const fetchGithubJson = async (url, token) => {
  const response = await fetch(url, {
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${token}`,
      'User-Agent': 'BugBash-App'
    }
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`github_fetch_failed:${response.status}:${text}`);
  }
  return response.json();
};

app.get('/api/auth/github/callback', async (req, res) => {
  if (!githubConfigured()) {
    return res.status(501).send('GitHub integration is not configured.');
  }

  const { code = '', state = '' } = req.query || {};
  const stateRecord = githubStates.get(state);
  if (!state || !stateRecord) {
    return res.status(400).send('Invalid or expired state. Please try again.');
  }
  githubStates.delete(state);

  const params = new URLSearchParams({
    client_id: GITHUB_CLIENT_ID,
    client_secret: GITHUB_CLIENT_SECRET,
    code: String(code || ''),
    redirect_uri: resolveGithubRedirectUri(req)
  });

  let tokenResponse;
  try {
    const response = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { Accept: 'application/json' },
      body: params
    });
    tokenResponse = await response.json();
  } catch (err) {
    console.error('GitHub token exchange failed', err);
    return res.status(502).send('Could not connect to GitHub. Please try again.');
  }

  if (!tokenResponse || tokenResponse.error || !tokenResponse.access_token) {
    console.error('GitHub token response error', tokenResponse);
    return res.status(400).send('GitHub authorization failed. Please try again.');
  }

  const accessToken = tokenResponse.access_token;

  try {
    const [profile, emails] = await Promise.all([
      fetchGithubJson('https://api.github.com/user', accessToken),
      fetchGithubJson('https://api.github.com/user/emails', accessToken).catch(() => [])
    ]);

    const emailFromProfile = typeof profile.email === 'string' ? profile.email.trim() : '';
    let selectedEmail = emailFromProfile;
    if ((!selectedEmail || selectedEmail.length === 0) && Array.isArray(emails)) {
      const primary = emails.find((item) => item.primary && item.verified && item.email);
      const fallback = emails.find((item) => item.verified && item.email);
      selectedEmail = (primary || fallback || emails[0] || {}).email || '';
    }

    const profileData = {
      name: (profile.name || profile.login || '').trim(),
      email: selectedEmail?.trim() || '',
      login: profile.login || '',
      avatar: profile.avatar_url || '',
      profileUrl: profile.html_url || ''
    };

    let alreadyRegistered = false;
    try {
      const candidateEmail = profileData.email ? profileData.email.toLowerCase() : '';
      if (candidateEmail) {
        const existingByEmail = await registrationsCollection
          .where('leader_email_lower', '==', candidateEmail)
          .limit(1)
          .get();
        alreadyRegistered = !existingByEmail.empty;
      }
      if (!alreadyRegistered) {
        const githubLogin = (profileData.login || '').trim();
        if (githubLogin) {
          const existingByGithub = await registrationsCollection
            .where('github_login', '==', githubLogin)
            .limit(1)
            .get();
          alreadyRegistered = !existingByGithub.empty;
        }
      }
    } catch (lookupErr) {
      console.error('Failed to check existing GitHub registration', lookupErr);
    }

    const profileToken = crypto.randomBytes(24).toString('hex');
    githubProfiles.set(profileToken, { createdAt: Date.now(), profile: profileData, alreadyRegistered });

    const target = sanitizeReturnTo(stateRecord.returnTo || '/register.html');
    const separator = target.includes('?') ? '&' : '?';
    res.redirect(`${target}${separator}github_token=${profileToken}`);
  } catch (err) {
    console.error('GitHub profile fetch failed', err);
    res.status(502).send('Failed to fetch your GitHub profile. Please try again.');
  }
});

app.get('/api/auth/github/profile/:token', (req, res) => {
  if (!githubConfigured()) {
    return res.status(404).json({ ok: false, error: 'github_not_available' });
  }
  const token = req.params.token?.trim();
  if (!token || !githubProfiles.has(token)) {
    return res.status(404).json({ ok: false, error: 'profile_not_found' });
  }
  const record = githubProfiles.get(token);
  githubProfiles.delete(token);
  const sessionToken = crypto.randomBytes(24).toString('hex');
  githubSessions.set(sessionToken, { createdAt: Date.now(), profile: record.profile, alreadyRegistered: record.alreadyRegistered });
  res.json({ ok: true, profile: record.profile, sessionToken, alreadyRegistered: Boolean(record.alreadyRegistered) });
});

// register
app.post('/api/register', async (req, res) => {
  const payload = req.body || {};

  if (!REGISTRATION_OPEN) {
    return res.status(503).json({ ok: false, error: 'registrations_closed' });
  }

  const githubSessionTokenRaw = payload.github_session;
  const githubSessionToken = typeof githubSessionTokenRaw === 'string' ? githubSessionTokenRaw.trim() : '';
  if (!githubSessionToken) {
    return res.status(400).json({ ok: false, error: 'github_required' });
  }
  const githubSession = githubSessions.get(githubSessionToken);
  if (!githubSession || (Date.now() - githubSession.createdAt > GITHUB_PROFILE_TTL_MS)) {
    githubSessions.delete(githubSessionToken);
    return res.status(400).json({ ok: false, error: 'github_required' });
  }
  githubSessions.delete(githubSessionToken);
  const githubProfile = githubSession.profile || {};
  const githubLogin = (githubProfile.login || '').trim();
  const githubProfileUrl = (githubProfile.profileUrl || '').trim();
  const githubAvatar = (githubProfile.avatar || '').trim();
  const githubEmail = (githubProfile.email || '').trim();
  delete payload.github_session;

  let leader_name = String(
    payload.full_name ??
    payload.name ??
    payload.leader_name ??
    (typeof payload.leader === 'string' ? payload.leader.split(/[-•|]/)[0] : '') ??
    ''
  ).trim();
  if (!leader_name && githubProfile.name) {
    leader_name = String(githubProfile.name).trim();
  }

  let leaderEmailRaw = String(
    payload.email ??
    payload.leader_email ??
    ''
  ).trim();
  if (!leaderEmailRaw && githubEmail) {
    leaderEmailRaw = githubEmail;
  }
  if (!leaderEmailRaw && typeof payload.leader === 'string') {
    const parts = payload.leader.split(/[-•|]/);
    if (parts.length >= 2) leaderEmailRaw = parts[1].trim();
  }

  let problemStatement = String(payload.problem ?? payload.idea ?? '').trim();
  const solutionOverview = String(payload.solution ?? '').trim();
  const techStack = String(payload.tech_stack ?? payload.members ?? '').trim();
  const notesRaw = String(payload.notes ?? payload.additional_notes ?? '').trim();
  const linkInput = String(payload.profile_link ?? payload.project_link ?? payload.link ?? '').trim();
  let link = linkInput && !/^https?:\/\//i.test(linkInput) ? `https://${linkInput}` : linkInput;
  if (!link && githubProfileUrl) {
    link = githubProfileUrl;
  }
  const phoneRaw = String(payload.phone ?? '').trim();
  const normalizeIndianPhone = (input) => {
    if (!input) return null;
    const digits = input.replace(/\D/g, '');
    const ensureValidTen = (ten) => (INDIAN_MOBILE_REGEX.test(ten) ? ten : null);
    if (digits.length === 10) {
      const ten = ensureValidTen(digits);
      return ten ? `+91${ten}` : null;
    }
    if (digits.length === 11 && digits.startsWith('0')) {
      const ten = ensureValidTen(digits.slice(1));
      return ten ? `+91${ten}` : null;
    }
    if (digits.length === 12 && digits.startsWith('91')) {
      const ten = ensureValidTen(digits.slice(2));
      return ten ? `+${digits}` : null;
    }
    if (digits.length === 13 && digits.startsWith('091')) {
      const candidate = digits.slice(1);
      const ten = ensureValidTen(candidate.slice(2));
      return ten ? `+${candidate}` : null;
    }
    return null;
  };
  const normalizedPhone = normalizeIndianPhone(phoneRaw);
  const dobRaw = String(payload.dob ?? '').trim();
  const tshirtRaw = String(payload.size ?? payload.tshirt_size ?? '').trim().toUpperCase().replace(/\s+/g,'');
  const allowedSizes = new Set(['XS','S','M','L','XL','XXL']);
  const tshirtSize = allowedSizes.has(tshirtRaw) ? tshirtRaw : '';
  const heardFrom = String(payload.heard_from ?? payload.referral ?? payload.problem ?? '').trim();
  const captchaToken = String(payload.captchaToken ?? payload['g-recaptcha-response'] ?? '').trim();
  delete payload.captchaToken;
  delete payload['g-recaptcha-response'];
  if (!problemStatement && heardFrom) {
    problemStatement = heardFrom;
  }
  if (!problemStatement) {
    problemStatement = 'Not specified yet';
  }

  if (!leader_name || !leaderEmailRaw) {
    return res.status(400).json({ ok: false, error: 'missing_fields' });
  }

  if (!EMAIL_REGEX.test(leaderEmailRaw)) {
    return res.status(400).json({ ok: false, error: 'invalid_email' });
  }

  if (!normalizedPhone) {
    return res.status(400).json({ ok: false, error: 'invalid_phone' });
  }

  if (RECAPTCHA_SECRET) {
    if (!captchaToken) {
      return res.status(400).json({ ok: false, error: 'invalid_captcha' });
    }
    try {
      const verifyResponse = await fetch('https://www.google.com/recaptcha/api/siteverify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          secret: RECAPTCHA_SECRET,
          response: captchaToken
        }).toString()
      });
      const verifyPayload = await verifyResponse.json();
      const scoreOk = typeof verifyPayload.score !== 'number' || verifyPayload.score >= RECAPTCHA_MIN_SCORE;
      if (!verifyPayload.success || !scoreOk) {
        return res.status(400).json({ ok: false, error: 'captcha_failed' });
      }
    } catch (captchaErr) {
      console.error('reCAPTCHA verification failed', captchaErr);
      return res.status(400).json({ ok: false, error: 'captcha_failed' });
    }
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

    const ideaParts = [];
    if (heardFrom) ideaParts.push(`Heard via: ${heardFrom}`);
    if (solutionOverview) ideaParts.push(`Solution: ${solutionOverview}`);
    if (techStack) ideaParts.push(`Tech stack: ${techStack}`);
    const ideaCombined = ideaParts.join('\n') || problemStatement;
    const membersText = techStack ? `Tech stack: ${techStack}` : 'Not provided';

    const docRef = registrationsCollection.doc();
    const createdAtIso = new Date().toISOString();
    await docRef.set({
      leader_name,
      leader_email: leaderEmailRaw,
      leader_email_lower: leaderEmailNormalized,
      github_login: githubLogin,
      github_profile_url: githubProfileUrl,
      github_avatar: githubAvatar,
      github_connected_at: FieldValue.serverTimestamp(),
      members_text: membersText,
      idea: ideaCombined,
      ip: req.headers['x-forwarded-for']?.toString() || req.socket.remoteAddress || '',
      problem: problemStatement,
      solution: solutionOverview,
      tech_stack: techStack,
      profile_link: link,
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
    const columns = [
      { key: 'id', label: 'id' },
      { key: 'created_at', label: 'created_at' },
      { key: 'leader_name', label: 'name' },
      { key: 'leader_email', label: 'email' },
      { key: 'phone', label: 'phone' },
      { key: 'dob', label: 'dob' },
      { key: 'tshirt_size', label: 'tshirt_size' },
      { key: 'heard_from', label: 'heard_from' },
      { key: 'notes', label: 'notes' },
      { key: 'profile_link', label: 'profile_link' },
      { key: 'github_login', label: 'github_login' },
      { key: 'github_profile_url', label: 'github_profile_url' },
      { key: 'ip', label: 'ip' }
    ];
    const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
    const csv = [columns.map((c) => esc(c.label)).join(',')]
      .concat(rows.map((row) => columns.map((c) => esc(row[c.key])).join(',')))
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
