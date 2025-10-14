import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';
import express from 'express';
import cors from 'cors';
import admin from 'firebase-admin';
import crypto from 'crypto';
import fetch from 'node-fetch';
import nodemailer from 'nodemailer';
import { fileURLToPath } from 'url';

dotenv.config();

if (typeof globalThis.fetch !== 'function') {
  globalThis.fetch = fetch;
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
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
const SITE_URL = (process.env.SITE_URL?.trim() || 'https://bugbash.me').replace(/\/+$/, '');
const GOOGLE_SITE_VERIFICATION_META = process.env.GOOGLE_SITE_VERIFICATION?.trim();
const GOOGLE_SITE_VERIFICATION_HTML = process.env.GOOGLE_SITE_VERIFICATION_HTML?.trim();
const rawGithubTokenSecret =
  process.env.GITHUB_TOKEN_SECRET?.trim() ||
  process.env.SESSION_SECRET?.trim() ||
  (GITHUB_CLIENT_SECRET ? `${GITHUB_CLIENT_SECRET}:${process.env.GITHUB_CLIENT_ID || ''}` : '') ||
  ADMIN_TOKEN;
const GITHUB_TOKEN_SECRET = rawGithubTokenSecret?.trim() || '';
const EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}$/;
const INDIAN_MOBILE_REGEX = /^[6-9][0-9]{9}$/;
const SMTP_HOST = process.env.SMTP_HOST?.trim();
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_USER = process.env.SMTP_USERNAME?.trim();
const SMTP_PASS = process.env.SMTP_PASSWORD;
const EMAIL_FROM = process.env.EMAIL_FROM?.trim() || 'Bug Bash <updates@bugbash.me>';

let mailTransporter = null;
if (SMTP_HOST && SMTP_USER && SMTP_PASS) {
  try {
    mailTransporter = nodemailer.createTransport({
      host: SMTP_HOST,
      port: SMTP_PORT,
      secure: SMTP_PORT === 465,
      auth: { user: SMTP_USER, pass: SMTP_PASS }
    });
  } catch (mailErr) {
    console.error('Failed to configure mail transporter', mailErr);
  }
}

const sendConfirmationEmail = async ({ to, name, tshirtSize, profileLink, heardFrom }) => {
  if (!mailTransporter || !to) return;
  const firstName = (name || '').split(' ')[0] || 'there';
  const safeSize = tshirtSize || 'Will be confirmed at check-in';
  const safeHeard = heardFrom || 'Not shared';
  const safeProfile = profileLink || 'Not provided';

  const message = {
    from: EMAIL_FROM,
    to,
    subject: 'Bug Bash 2025 - registration confirmed 🎉',
    text: `Hi ${firstName},\n\nThanks for registering for Bug Bash 2025!\n\nEvent: 14–15 March 2025, SVYASA Bengaluru\nT-shirt size: ${safeSize}\nHow you heard about us: ${safeHeard}\nPortfolio: ${safeProfile}\n\nWe will follow up soon with teams, the detailed schedule, and logistics.\nIf you need anything in the meantime, reply to this email or write to contact@bugbash.me.\n\nSee you at the kickoff!\n- Bug Bash team`,
    html: `
      <p>Hi ${firstName},</p>
      <p>Thanks for signing up for <strong>Bug Bash 2025</strong>! We'll share teams, the detailed schedule, and logistics soon.</p>
      <p><strong>Event:</strong> 14–15 March 2025 · SVYASA Bengaluru</p>
      <table style="border-collapse:collapse;margin:18px 0 22px;width:100%;max-width:520px;font-size:14px;color:#cfd7e1;">
        <tbody>
          <tr>
            <td style="padding:8px 12px;border:1px solid rgba(255,255,255,0.1);background:rgba(255,255,255,0.03);">T-shirt size</td>
            <td style="padding:8px 12px;border:1px solid rgba(255,255,255,0.1);">${safeSize}</td>
          </tr>
          <tr>
            <td style="padding:8px 12px;border:1px solid rgba(255,255,255,0.1);background:rgba(255,255,255,0.03);">How you heard about us</td>
            <td style="padding:8px 12px;border:1px solid rgba(255,255,255,0.1);">${safeHeard}</td>
          </tr>
          <tr>
            <td style="padding:8px 12px;border:1px solid rgba(255,255,255,0.1);background:rgba(255,255,255,0.03);">Portfolio / GitHub</td>
            <td style="padding:8px 12px;border:1px solid rgba(255,255,255,0.1);">${profileLink ? `<a style="color:#7be04a;" href="${profileLink}">${profileLink}</a>` : 'Not provided'}</td>
          </tr>
        </tbody>
      </table>
      <p>If you have any questions, just reply to this email or write to <a href="mailto:contact@bugbash.me">contact@bugbash.me</a>.</p>
      <p>See you at the kickoff!<br/>- Bug Bash team</p>
    `
  };

  try {
    await mailTransporter.sendMail(message);
  } catch (err) {
    console.error('Confirmation email failed', err);
  }
};

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

const encodeBase64Url = (buffer) => buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');

const decodeBase64Url = (value) => {
  if (typeof value !== 'string' || !value.trim()) return null;
  let normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padding = normalized.length % 4;
  if (padding) {
    normalized += '='.repeat(4 - padding);
  }
  try {
    return Buffer.from(normalized, 'base64');
  } catch {
    return null;
  }
};

const safeCompare = (a, b) => {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const aBuffer = Buffer.from(a);
  const bBuffer = Buffer.from(b);
  if (aBuffer.length !== bBuffer.length) return false;
  return crypto.timingSafeEqual(aBuffer, bBuffer);
};

const createSignedGithubToken = (payload) => {
  if (!GITHUB_TOKEN_SECRET) {
    throw new Error('GitHub token secret not configured. Set GITHUB_TOKEN_SECRET or SESSION_SECRET.');
  }
  const body = encodeBase64Url(Buffer.from(JSON.stringify(payload), 'utf8'));
  const signature = encodeBase64Url(crypto.createHmac('sha256', GITHUB_TOKEN_SECRET).update(body).digest());
  return `${body}.${signature}`;
};

const verifySignedGithubToken = (token) => {
  if (!GITHUB_TOKEN_SECRET) return null;
  if (!token || typeof token !== 'string') return null;
  const parts = token.trim().split('.');
  if (parts.length !== 2) return null;
  const [body, signature] = parts;
  if (!body || !signature) return null;

  const expectedSignature = encodeBase64Url(crypto.createHmac('sha256', GITHUB_TOKEN_SECRET).update(body).digest());
  if (!safeCompare(signature, expectedSignature)) return null;

  const raw = decodeBase64Url(body);
  if (!raw) return null;
  try {
    const payload = JSON.parse(raw.toString('utf8'));
    if (!payload || typeof payload !== 'object') return null;
    if (typeof payload.exp === 'number' && Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
};

const isLocalHost = (host) => {
  if (!host) return false;
  const base = host.toLowerCase().split(':')[0];
  return base === 'localhost' || base === '127.0.0.1';
};

const resolveGithubRedirectUri = (req) => {
  const forwardedHost = req.headers['x-forwarded-host']?.split(',')[0]?.trim();
  const host = forwardedHost || req.get('host') || '';
  if (GITHUB_REDIRECT_URI && !isLocalHost(host)) {
    return GITHUB_REDIRECT_URI;
  }
  const forwardedProto = req.headers['x-forwarded-proto']?.split(',')[0]?.trim();
  const proto = forwardedProto || req.protocol || 'http';
  const effectiveHost = host || `localhost:${req.socket?.localPort || PORT || 3000}`;
  return `${proto}://${effectiveHost}/api/auth/github/callback`;
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
    profile_link: data.profile_link || '',
    github_login: data.github_login || '',
    github_profile_url: data.github_profile_url || data.profile_link || '',
    notes: data.notes || '',
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
app.use((req, res, next) => {
  res.setHeader('X-Robots-Tag', 'index, follow');
  if (GOOGLE_SITE_VERIFICATION_META) {
    res.setHeader('X-Goog-Verification', GOOGLE_SITE_VERIFICATION_META);
  }
  next();
});

// static
app.get('/favicon.ico', (_req, res) => {
  res.type('image/png').sendFile(path.join(__dirname, 'assets', 'bugbash_logo.png'));
});

app.get('/robots.txt', (_req, res) => {
  const lines = [
    'User-agent: *',
    'Allow: /',
    '',
    `Sitemap: ${SITE_URL}/sitemap.xml`
  ];
  res.type('text/plain').send(lines.join('\n'));
});

app.get('/sitemap.xml', (_req, res) => {
  const pages = [
    { loc: SITE_URL, changefreq: 'daily', priority: '1.0' },
    { loc: `${SITE_URL}/register`, changefreq: 'weekly', priority: '0.8' }
  ];
  const now = new Date().toISOString();
  const xml = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    ...pages.map((page) => [
      '  <url>',
      `    <loc>${page.loc}</loc>`,
      `    <lastmod>${now}</lastmod>`,
      page.changefreq ? `    <changefreq>${page.changefreq}</changefreq>` : '',
      page.priority ? `    <priority>${page.priority}</priority>` : '',
      '  </url>'
    ].filter(Boolean).join('\n')),
    '</urlset>'
  ].join('\n');
  res.type('application/xml').send(xml);
});

if (GOOGLE_SITE_VERIFICATION_HTML) {
  const sanitized = GOOGLE_SITE_VERIFICATION_HTML.replace(/^\/+/, '').replace(/[^a-zA-Z0-9._-]/g, '');
  if (sanitized) {
    app.get(`/${sanitized}`, (_req, res) => {
      res.type('text/html').send(`google-site-verification: ${sanitized}`);
    });
  }
}

app.get('/env.js', (_req, res) => {
  const payload = {
    recaptchaSiteKey: process.env.RECAPTCHA_SITE_KEY || '',
    registrationsOpen: REGISTRATION_OPEN,
    githubAuthEnabled: githubConfigured()
  };
  res.type('application/javascript').send(`window.__APP_CONFIG__=${JSON.stringify(payload)};`);
});

app.use('/assets', express.static(path.join(__dirname, 'assets'), { extensions: ['png','jpg','jpeg','gif'] }));
app.use(express.static(__dirname, { extensions: ['html'] }));

// health
app.get('/api/health', (_req, res) => res.json({ ok: true }));

// --- GitHub OAuth ---
const githubConfigured = () => Boolean(GITHUB_CLIENT_ID && GITHUB_CLIENT_SECRET && GITHUB_TOKEN_SECRET);

app.get('/api/auth/github/start', (req, res) => {
  if (!githubConfigured()) {
    return res.status(501).json({ ok: false, error: 'github_not_configured' });
  }

  const returnTo = sanitizeReturnTo(req.query.returnTo || '/register.html');
  let stateToken;
  try {
    stateToken = createSignedGithubToken({
      type: 'state',
      nonce: crypto.randomBytes(16).toString('hex'),
      returnTo,
      iat: Date.now(),
      exp: Date.now() + GITHUB_STATE_TTL_MS
    });
  } catch (err) {
    console.error('Failed to create GitHub state token', err);
    return res.status(500).json({ ok: false, error: 'github_state_failed' });
  }

  const params = new URLSearchParams({
    client_id: GITHUB_CLIENT_ID,
    redirect_uri: resolveGithubRedirectUri(req),
    scope: 'read:user user:email',
    state: stateToken
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
  const statePayload = verifySignedGithubToken(typeof state === 'string' ? state : '');
  if (!statePayload || statePayload.type !== 'state' || !statePayload.returnTo) {
    return res.status(400).send('Invalid or expired state. Please try again.');
  }
  const returnTo = sanitizeReturnTo(statePayload.returnTo || '/register.html');

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

    const issuedAt = Date.now();
    let profileToken;
    try {
      profileToken = createSignedGithubToken({
        type: 'profile',
        profile: profileData,
        alreadyRegistered,
        iat: issuedAt,
        exp: issuedAt + GITHUB_PROFILE_TTL_MS
      });
    } catch (err) {
      console.error('Failed to create GitHub profile token', err);
      return res.status(500).send('Could not create GitHub session. Please try again.');
    }

    const target = returnTo;
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
  const profileRecord = verifySignedGithubToken(token || '');
  if (!profileRecord || profileRecord.type !== 'profile' || !profileRecord.profile) {
    return res.status(404).json({ ok: false, error: 'profile_not_found' });
  }
  const issuedAt = Date.now();
  let sessionToken;
  try {
    sessionToken = createSignedGithubToken({
      type: 'session',
      profile: profileRecord.profile,
      alreadyRegistered: Boolean(profileRecord.alreadyRegistered),
      iat: issuedAt,
      exp: issuedAt + GITHUB_PROFILE_TTL_MS
    });
  } catch (err) {
    console.error('Failed to issue GitHub session token', err);
    return res.status(500).json({ ok: false, error: 'session_creation_failed' });
  }

  res.json({
    ok: true,
    profile: profileRecord.profile,
    sessionToken,
    alreadyRegistered: Boolean(profileRecord.alreadyRegistered)
  });
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
  const githubSession = verifySignedGithubToken(githubSessionToken);
  if (!githubSession || githubSession.type !== 'session' || !githubSession.profile) {

    return res.status(400).json({ ok: false, error: 'github_required' });
  }
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
      ip: req.headers['x-forwarded-for']?.toString() || req.socket.remoteAddress || '',
      profile_link: link,
      notes: notesRaw,
      phone: normalizedPhone,
      dob: dobRaw,
      tshirt_size: tshirtSize,
      heard_from: heardFrom,
      created_at: createdAtIso,
      created_at_ts: FieldValue.serverTimestamp()
    });

    sendConfirmationEmail({
      to: leaderEmailRaw,
      name: leader_name || githubProfile?.name || githubProfile?.login || '',
      tshirtSize,
      profileLink: link,
      heardFrom
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

const PORT = Number(process.env.PORT || 3000);

if (import.meta.url === `file://${__filename}`) {
  app.listen(PORT, () => {
    const base = SITE_URL || `http://localhost:${PORT}`;
    console.log(`Bug Bash server ready on port ${PORT} → ${base}`);
  });
}

export default app;

