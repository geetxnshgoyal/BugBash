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
const SLACK_WEBHOOK_URL = process.env.SLACK_WEBHOOK_URL?.trim() || '';
const SLACK_FALLBACK_CHANNEL = process.env.SLACK_FALLBACK_CHANNEL?.trim() || '';
const GITHUB_TOKEN_SECRET = rawGithubTokenSecret?.trim() || '';
const EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}$/;
const INDIAN_MOBILE_REGEX = /^[6-9][0-9]{9}$/;
const SMTP_HOST = process.env.SMTP_HOST?.trim();
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_USER = process.env.SMTP_USERNAME?.trim();
const SMTP_PASS = process.env.SMTP_PASSWORD;
const EMAIL_FROM = process.env.EMAIL_FROM?.trim() || 'Bug Bash <updates@bugbash.me>';

const TEAM_DASHBOARD_ENABLED = process.env.TEAM_DASHBOARD_ENABLED !== 'false';
const TEAM_SESSION_TTL_MS = Number(process.env.TEAM_SESSION_TTL_MS || 1000 * 60 * 60 * 4);
const TEAM_ALLOWED_STATUSES = new Set(['todo', 'in_progress', 'blocked', 'done']);

const teamLoginOverrides = new Map();
const rawTeamLoginCodes = process.env.TEAM_LOGIN_CODES?.trim();
if (rawTeamLoginCodes) {
  try {
    const parsedOverrides = JSON.parse(rawTeamLoginCodes);
    if (parsedOverrides && typeof parsedOverrides === 'object') {
      for (const [emailKey, value] of Object.entries(parsedOverrides)) {
        if (!emailKey || typeof emailKey !== 'string') continue;
        const normalizedEmail = emailKey.trim().toLowerCase();
        if (!normalizedEmail) continue;
        if (typeof value === 'string' && value.trim()) {
          teamLoginOverrides.set(normalizedEmail, { code: value.trim() });
        } else if (value && typeof value === 'object') {
          const overrideCode =
            typeof value.code === 'string' && value.code.trim() ? value.code.trim() : '';
          if (overrideCode) {
            teamLoginOverrides.set(normalizedEmail, {
              code: overrideCode,
              memberId:
                typeof value.memberId === 'string' && value.memberId.trim()
                  ? value.memberId.trim()
                  : undefined,
              member:
                value.member && typeof value.member === 'object'
                  ? {
                      id:
                        typeof value.member.id === 'string' && value.member.id.trim()
                          ? value.member.id.trim()
                          : undefined,
                      displayName:
                        typeof value.member.displayName === 'string'
                          ? value.member.displayName.trim()
                          : undefined,
                      role:
                        typeof value.member.role === 'string'
                          ? value.member.role.trim()
                          : undefined,
                      departmentId:
                        typeof value.member.departmentId === 'string'
                          ? value.member.departmentId.trim()
                          : undefined
                    }
                  : undefined
            });
          }
        }
      }
    }
  } catch (teamLoginErr) {
    console.error('Failed to parse TEAM_LOGIN_CODES. Expected JSON object.', teamLoginErr);
  }
}

const teamMembersById = new Map();
const teamMemberIdentifiers = new Map();
const normalizeKey = (value) =>
  typeof value === 'string' && value.trim() ? value.trim().toLowerCase() : '';
const registerMemberAlias = (alias, member) => {
  const key = normalizeKey(alias);
  if (key && !teamMemberIdentifiers.has(key)) {
    teamMemberIdentifiers.set(key, member);
  }
};

const toIsoString = (value) => {
  if (!value) return '';
  if (typeof value === 'string') return value;
  if (value instanceof Date) {
    try {
      return value.toISOString();
    } catch {
      return '';
    }
  }
  if (value.toDate) {
    try {
      return value.toDate().toISOString();
    } catch {
      return '';
    }
  }
  if (typeof value === 'number') {
    try {
      return new Date(value).toISOString();
    } catch {
      return '';
    }
  }
  return '';
};

const slackEscape = (value = '') =>
  String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

const formatSlackLabel = (value = '') => {
  const normalized = String(value || '')
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  if (!normalized) return '';
  return slackEscape(normalized.replace(/\b\w/g, (char) => char.toUpperCase()));
};

const formatSlackDate = (value) => {
  if (!value) return slackEscape('No due date');
  try {
    const date = new Date(value);
    if (!Number.isNaN(date.getTime())) {
      return slackEscape(
        date.toLocaleDateString('en-IN', {
          day: '2-digit',
          month: 'long',
          year: 'numeric'
        })
      );
    }
  } catch {
    // ignore formatting errors
  }
  return slackEscape(String(value));
};

const getSlackChannelForDepartment = (department) => {
  if (department && typeof department === 'object') {
    const departmentChannel = department.channels?.slack;
    if (typeof departmentChannel === 'string' && departmentChannel.trim()) {
      return departmentChannel.trim();
    }
  }
  return SLACK_FALLBACK_CHANNEL;
};

const notifySlack = async ({ text, channel, blocks }) => {
  if (!SLACK_WEBHOOK_URL) return;
  const payload = {
    text: text || ''
  };
  if (channel) {
    payload.channel = channel;
  }
  if (Array.isArray(blocks) && blocks.length) {
    payload.blocks = blocks;
  }
  try {
    const response = await fetch(SLACK_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!response.ok) {
      const responseText = await response.text().catch(() => '');
      console.error('Slack webhook error', response.status, responseText);
    }
  } catch (err) {
    console.error('Failed to dispatch Slack notification', err);
  }
};

const getMemberDisplayName = (member) => {
  if (!member || typeof member !== 'object') return 'A teammate';
  const candidates = [member.displayName, member.name, member.loginId, member.id, member.email];
  for (const candidate of candidates) {
    if (typeof candidate === 'string' && candidate.trim()) {
      return candidate.trim();
    }
  }
  return 'A teammate';
};

const safeSlackUserId = (value) => {
  if (typeof value !== 'string') return '';
  const trimmed = value.trim();
  if (!trimmed) return '';
  return /^[A-Za-z0-9]+$/.test(trimmed) ? trimmed : '';
};

const formatSlackMention = (member) => {
  if (!member || typeof member !== 'object') return slackEscape('A teammate');
  const slackId =
    safeSlackUserId(member.slackUserId) ||
    safeSlackUserId(member.raw?.slack_user_id) ||
    '';
  if (slackId) {
    return `<@${slackId}>`;
  }
  return slackEscape(getMemberDisplayName(member));
};


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

const TEAM_SESSION_SECRET =
  process.env.TEAM_SESSION_SECRET?.trim() ||
  process.env.TEAM_LOGIN_MASTER_KEY?.trim() ||
  ADMIN_TOKEN ||
  process.env.SESSION_SECRET?.trim() ||
  '';

const createSignedToken = (payload, secret) => {
  if (!secret) {
    throw new Error('Team session secret not configured. Set TEAM_SESSION_SECRET or ADMIN_TOKEN.');
  }
  const body = encodeBase64Url(Buffer.from(JSON.stringify(payload), 'utf8'));
  const signature = encodeBase64Url(crypto.createHmac('sha256', secret).update(body).digest());
  return `${body}.${signature}`;
};

const verifySignedToken = (token, secret) => {
  if (!secret) return null;
  if (!token || typeof token !== 'string') return null;
  const parts = token.trim().split('.');
  if (parts.length !== 2) return null;
  const [body, signature] = parts;
  if (!body || !signature) return null;
  const expectedSignature = encodeBase64Url(
    crypto.createHmac('sha256', secret).update(body).digest()
  );
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

const createTeamSession = (memberId) =>
  createSignedToken(
    {
      memberId,
      iat: Date.now(),
      exp: Date.now() + TEAM_SESSION_TTL_MS
    },
    TEAM_SESSION_SECRET
  );

const touchTeamSession = (token) => {
  const payload = verifySignedToken(token, TEAM_SESSION_SECRET);
  if (!payload || !payload.memberId) return null;
  if (typeof payload.exp === 'number' && Date.now() > payload.exp) return null;
  return payload.memberId;
};

const ensureMembersLoaded = async () => {
  if (!teamMembersById.size) {
    await fetchTeamMembers();
  }
};

const resolveLoginMember = async (identifierNormalized) => {
  await ensureMembersLoaded();
  const override = teamLoginOverrides.get(identifierNormalized);
  let member = teamMemberIdentifiers.get(identifierNormalized);
  if (!member && override?.memberId) {
    member = await fetchTeamMemberById(override.memberId);
  }
  if (!member && override?.member) {
    const generatedId =
      override.member.id ||
      `override-${Buffer.from(identifierNormalized).toString('hex').slice(0, 12)}`;
    member = {
      id: generatedId,
      displayName: override.member.displayName || identifierNormalized,
      role: override.member.role || 'volunteer',
      departmentId: override.member.departmentId || '',
      email: `${identifierNormalized}`,
      loginId: override.member.loginId || identifierNormalized,
      loginIdNormalized: identifierNormalized,
      identifiers: [identifierNormalized]
    };
    teamMembersById.set(member.id, member);
    registerMemberAlias(identifierNormalized, member);
  }
  if (!member) {
    member = await fetchTeamMemberById(identifierNormalized);
    if (member) {
      registerMemberAlias(identifierNormalized, member);
    }
  }
  return { member, override };
};

const resolveTeamAccessCode = ({ member, override, identifierNormalized }) => {
  const overrideCode = override?.code;
  if (overrideCode) {
    return overrideCode;
  }
  if (member?.accessCode) {
    return member.accessCode;
  }
  if (member && override && !overrideCode) {
    return '';
  }
  const fallback = teamLoginOverrides.get(identifierNormalized);
  return fallback?.code || '';
};

const sanitizeTeamMember = (member) => {
  if (!member || typeof member !== 'object') return null;
  return {
    id: member.id,
    displayName: member.displayName || '',
    email: member.email || '',
    role: member.role || '',
    roleNormalized: member.roleNormalized || normalizeRole(member.role),
    loginId: member.loginId || '',
    departmentId: member.departmentId || '',
    slackUserId:
      typeof member.slackUserId === 'string' && member.slackUserId.trim()
        ? member.slackUserId.trim()
        : typeof member.raw?.slack_user_id === 'string' && member.raw.slack_user_id.trim()
        ? member.raw.slack_user_id.trim()
        : ''
  };
};

const sanitizeTeamDepartment = (department) => {
  if (!department || typeof department !== 'object') return null;
  return {
    id: department.id,
    name: department.name || '',
    description: department.description || '',
    leadMemberIds: Array.isArray(department.leadMemberIds) ? department.leadMemberIds : [],
    channels: department.channels && typeof department.channels === 'object' ? department.channels : {}
  };
};

const getTaskUpdates = (taskId) =>
  teamTaskUpdates
    .filter((update) => update.taskId === taskId)
    .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));

const sanitizeTeamTask = (
  task,
  { departmentMap, memberMap, departmentColors, currentMemberId, currentMemberRole }
) => {
  if (!task || typeof task !== 'object') return null;
  const currentRoleNormalized = normalizeRole(currentMemberRole);
  const department = departmentMap.get(task.departmentId);
  const owners = Array.isArray(task.ownerIds) ? task.ownerIds : [];
  const ownerSummaries = owners.map((ownerId) => {
    const member = memberMap.get(ownerId);
    return (
      sanitizeTeamMember(
        member || { id: ownerId, displayName: ownerId, role: '', departmentId: task.departmentId }
      ) || { id: ownerId, displayName: ownerId }
    );
  });
  const departmentColor = departmentColors.get(task.departmentId) || '#7be04a';
  const isMine = Boolean(currentMemberId && owners.includes(currentMemberId));
  const isElevated = currentRoleNormalized === 'lead' || currentRoleNormalized === 'mentor';
  const hasOwners = owners.length > 0;
  const canClaim = Boolean(currentMemberId && !isMine && (!hasOwners || isElevated));
  const canUnclaim = Boolean(currentMemberId && (isMine || isElevated));
  const restrictedRoles = Array.isArray(task.restrictedRoles) ? task.restrictedRoles : [];
  const allowedMemberIds = Array.isArray(task.allowedMemberIds) ? task.allowedMemberIds : [];
  const isRestricted = restrictedRoles.length > 0;
  const isCreator = Boolean(currentMemberId && task.createdBy && task.createdBy === currentMemberId);
  const canManage = isElevated;
  const lastUpdateMember =
    task.lastUpdate?.memberId && memberMap.has(task.lastUpdate.memberId)
      ? sanitizeTeamMember(memberMap.get(task.lastUpdate.memberId))
      : null;
  return {
    id: task.id,
    title: task.title || '',
    description: task.description || '',
    departmentId: task.departmentId || '',
    departmentName: department?.name || '',
    departmentColor,
    ownerIds: owners,
    owners: ownerSummaries,
    status: task.status || 'todo',
    priority: task.priority || 'medium',
    dueAt: task.dueAt || '',
    createdBy: task.createdBy || '',
    createdAt: task.createdAt || '',
    checklist: Array.isArray(task.checklist) ? task.checklist : [],
    restrictedRoles,
    allowedMemberIds,
    isRestricted,
    isCreator,
    updatesCount: typeof task.updatesCount === 'number' ? task.updatesCount : 0,
    lastUpdateAt: task.lastUpdate?.createdAt || task.createdAt || '',
    lastUpdate: task.lastUpdate
      ? {
          id: task.lastUpdate.id || '',
          memberId: task.lastUpdate.memberId || '',
          note: task.lastUpdate.note || '',
          statusAfter: task.lastUpdate.statusAfter || '',
          createdAt: task.lastUpdate.createdAt || '',
          member: lastUpdateMember
        }
      : null,
    isMine,
    canClaim,
    canUnclaim,
    hasOwners,
    canEdit: canManage,
    canDelete: canManage,
    canUpdateDeadline: canManage,
    canManage
  };
};

const canMemberViewTask = (task, member) => {
  if (!task) return false;
  const restrictedRoles = Array.isArray(task.restrictedRoles) ? task.restrictedRoles : [];
  if (!restrictedRoles.length) {
    return true;
  }
  const memberRole = member?.roleNormalized || normalizeRole(member?.role);
  if (restrictedRoles.includes(memberRole)) {
    return true;
  }
  const allowedMemberIds = Array.isArray(task.allowedMemberIds) ? task.allowedMemberIds : [];
  if (member?.id && allowedMemberIds.includes(member.id)) {
    return true;
  }
  return false;
};

const sanitizeTeamTaskUpdate = (update, memberMap) => {
  if (!update || typeof update !== 'object') return null;
  const member = memberMap?.get(update.memberId);
  return {
    id: update.id,
    taskId: update.taskId,
    memberId: update.memberId,
    note: update.note || '',
    statusAfter: update.statusAfter || '',
    createdAt: update.createdAt || '',
    member:
      sanitizeTeamMember(member) ||
      {
        id: update.memberId,
        displayName: update.memberId || '',
        email: '',
        role: '',
        departmentId: ''
      }
  };
};

const sanitizeTeamEvent = (event, memberMap) => {
  if (!event || typeof event !== 'object') return null;
  const hosts = Array.isArray(event.hosts) ? event.hosts : [];
  const hostMembers = hosts
    .map((hostId) => sanitizeTeamMember(memberMap.get(hostId)))
    .filter(Boolean);
  return {
    id: event.id,
    title: event.title || '',
    description: event.description || '',
    startAt: event.startAt || '',
    endAt: event.endAt || '',
    location: event.location || '',
    link: event.link || '',
    hosts,
    hostMembers,
    departmentIds: Array.isArray(event.departmentIds) ? event.departmentIds : []
  };
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

const TEAM_DEPARTMENTS_COLLECTION =
  process.env.FIREBASE_TEAM_DEPARTMENTS_COLLECTION || 'team_departments';
const TEAM_MEMBERS_COLLECTION =
  process.env.FIREBASE_TEAM_MEMBERS_COLLECTION || 'team_members';
const TEAM_TASKS_COLLECTION =
  process.env.FIREBASE_TEAM_TASKS_COLLECTION || 'team_tasks';
const TEAM_TASK_UPDATES_COLLECTION =
  process.env.FIREBASE_TEAM_TASK_UPDATES_COLLECTION || 'team_task_updates';
const TEAM_EVENTS_COLLECTION =
  process.env.FIREBASE_TEAM_EVENTS_COLLECTION || 'team_events';

const teamDepartmentsCollection = firestore.collection(TEAM_DEPARTMENTS_COLLECTION);
const teamMembersCollection = firestore.collection(TEAM_MEMBERS_COLLECTION);
const teamTasksCollection = firestore.collection(TEAM_TASKS_COLLECTION);
const teamTaskUpdatesCollection = firestore.collection(TEAM_TASK_UPDATES_COLLECTION);
const teamEventsCollection = firestore.collection(TEAM_EVENTS_COLLECTION);

const DEPARTMENT_COLOR_PALETTE = [
  '#7be04a',
  '#38bdf8',
  '#f97316',
  '#f472b6',
  '#a855f7',
  '#22c55e',
  '#facc15',
  '#fb7185',
  '#2dd4bf',
  '#c084fc'
];

const buildDepartmentColorMap = (departments) => {
  const map = new Map();
  departments.forEach((dept, index) => {
    map.set(dept.id, DEPARTMENT_COLOR_PALETTE[index % DEPARTMENT_COLOR_PALETTE.length]);
  });
  return map;
};

const normalizeRole = (role) =>
  typeof role === 'string' && role.trim() ? role.trim().toLowerCase() : '';

const hasRole = (member, roles = []) => {
  if (!member) return false;
  const normalized = member.roleNormalized || normalizeRole(member.role);
  return roles.includes(normalized);
};

const isLeadOrMentor = (member) => hasRole(member, ['lead', 'mentor']);

const mapTeamDepartmentDoc = (doc) => {
  const data = doc.data() || {};
  return {
    id: doc.id,
    name: data.name || data.display_name || '',
    description: data.description || '',
    leadMemberIds: Array.isArray(data.lead_member_ids) ? data.lead_member_ids : [],
    channels: data.channels && typeof data.channels === 'object' ? data.channels : {}
  };
};

const mapTeamMemberDoc = (doc) => {
  const data = doc.data() || {};
  const loginId = data.login_id || data.login || doc.id;
  const displayName = data.display_name || data.name || loginId || doc.id;
  const rawRole = typeof data.role === 'string' ? data.role.trim() : data.role || '';
  const normalizedRole = normalizeRole(rawRole);
  const explicitIdentifiers = Array.isArray(data.identifiers) ? data.identifiers : [];
  const identifierSet = new Set(
    [
      loginId,
      data.login_id_lower,
      displayName,
      data.display_name_lower,
      data.email,
      ...explicitIdentifiers
    ]
      .map(normalizeKey)
      .filter(Boolean)
  );
  const identifiers = Array.from(identifierSet);
  const normalizedLoginId = normalizeKey(loginId);
  const member = {
    id: doc.id,
    displayName,
    loginId,
    loginIdNormalized: normalizedLoginId,
    displayNameNormalized: normalizeKey(displayName),
    accessCode: data.access_code || '',
    role: rawRole,
    roleNormalized: normalizedRole,
    departmentId: data.department_id || '',
    email: data.email || '',
    slackUserId:
      typeof data.slack_user_id === 'string'
        ? data.slack_user_id.trim()
        : typeof data.slackUserId === 'string'
        ? data.slackUserId.trim()
        : '',
    active: data.active !== false,
    identifiers,
    raw: data
  };
  registerMemberAlias(loginId, member);
  registerMemberAlias(displayName, member);
  registerMemberAlias(data.email, member);
  identifiers.forEach((alias) => registerMemberAlias(alias, member));
  teamMembersById.set(member.id, member);
  return member;
};

const mapTeamTaskDoc = (doc) => {
  const data = doc.data() || {};
  const restrictedRoles = Array.isArray(data.restricted_roles)
    ? Array.from(
        new Set(
          data.restricted_roles
            .map((value) => normalizeRole(value))
            .filter(Boolean)
        )
      )
    : [];
  const allowedMemberIds = Array.isArray(data.allowed_member_ids)
    ? Array.from(
        new Set(
          data.allowed_member_ids
            .map((value) => (typeof value === 'string' ? value.trim() : ''))
            .filter(Boolean)
        )
      )
    : [];
  return {
    id: doc.id,
    title: data.title || '',
    description: data.description || '',
    departmentId: data.department_id || '',
    ownerIds: Array.isArray(data.owner_ids) ? data.owner_ids : [],
    status: data.status || 'todo',
    priority: data.priority || 'medium',
    dueAt: toIsoString(data.due_at || data.due_at_ts),
    createdBy: data.created_by || '',
    createdAt: toIsoString(data.created_at || data.created_at_ts),
    checklist: Array.isArray(data.checklist) ? data.checklist : [],
    restrictedRoles,
    allowedMemberIds,
    updatesCount: typeof data.updates_count === 'number' ? data.updates_count : 0,
    lastUpdate: data.last_update_id
      ? {
          id: data.last_update_id,
          memberId: data.last_update_member_id || '',
          note: data.last_update_note || '',
          statusAfter: data.last_update_status || '',
          createdAt: toIsoString(data.last_update_at),
          createdAtTs: data.last_update_at_ts
        }
      : null
  };
};

const mapTeamTaskUpdateDoc = (doc) => {
  const data = doc.data() || {};
  return {
    id: doc.id,
    taskId: data.task_id || '',
    memberId: data.member_id || '',
    note: data.note || '',
    statusAfter: data.status_after || '',
    createdAt: toIsoString(data.created_at || data.created_at_ts),
    createdAtTs: data.created_at_ts
  };
};

const mapTeamEventDoc = (doc) => {
  const data = doc.data() || {};
  return {
    id: doc.id,
    title: data.title || '',
    description: data.description || '',
    startAt: toIsoString(data.start_at || data.start_at_ts),
    endAt: toIsoString(data.end_at || data.end_at_ts),
    location: data.location || '',
    link: data.link || '',
    hosts: Array.isArray(data.hosts) ? data.hosts : [],
    departmentIds: Array.isArray(data.department_ids) ? data.department_ids : [],
    createdAt: toIsoString(data.created_at || data.created_at_ts)
  };
};

const fetchTeamDepartments = async () => {
  const snapshot = await teamDepartmentsCollection.get();
  return snapshot.docs.map(mapTeamDepartmentDoc);
};

const resetTeamMemberCaches = () => {
  teamMembersById.clear();
  teamMemberIdentifiers.clear();
};

const fetchTeamMembers = async () => {
  resetTeamMemberCaches();
  const snapshot = await teamMembersCollection.get();
  return snapshot.docs.map(mapTeamMemberDoc).filter((member) => member.active);
};

const fetchTeamMembersMap = async () => {
  const members = await fetchTeamMembers();
  const map = new Map(members.map((member) => [member.id, member]));
  return { members, map };
};

const fetchTeamMemberById = async (id) => {
  if (!id) return null;
  if (teamMembersById.has(id)) return teamMembersById.get(id);
  const doc = await teamMembersCollection.doc(id).get();
  if (!doc.exists) return null;
  return mapTeamMemberDoc(doc);
};

const fetchTeamTasks = async () => {
  const snapshot = await teamTasksCollection.get();
  return snapshot.docs.map(mapTeamTaskDoc);
};

const fetchTaskUpdates = async (taskId) => {
  const snapshot = await teamTaskUpdatesCollection.where('task_id', '==', taskId).get();
  return snapshot.docs
    .map(mapTeamTaskUpdateDoc)
    .sort(
      (a, b) =>
        new Date(b.createdAt || 0).getTime() - new Date(a.createdAt || 0).getTime()
    );
};

const deleteTaskUpdates = async (taskId) => {
  const snapshot = await teamTaskUpdatesCollection.where('task_id', '==', taskId).get();
  if (snapshot.empty) return;
  const batch = firestore.batch();
  snapshot.docs.forEach((doc) => {
    batch.delete(doc.ref);
  });
  await batch.commit();
};

const fetchTeamEvents = async () => {
  const snapshot = await teamEventsCollection.get();
  return snapshot.docs.map(mapTeamEventDoc);
};

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

// --- Team Dashboard API ---
const getTeamTokenFromRequest = (req) => {
  const authHeader = req.headers['authorization'];
  if (authHeader && typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7).trim();
  }
  const headerToken = req.headers['x-team-token'];
  return typeof headerToken === 'string' ? headerToken.trim() : '';
};

const ensureTeamEnabled = (res) => {
  if (!TEAM_DASHBOARD_ENABLED) {
    res.status(503).json({ ok: false, error: 'team_dashboard_disabled' });
    return false;
  }
  return true;
};

const teamAuth = async (req, res, next) => {
  if (!ensureTeamEnabled(res)) return;
  const token = getTeamTokenFromRequest(req);
  if (!token) {
    return res.status(401).json({ ok: false, error: 'unauthorized' });
  }
  const memberId = touchTeamSession(token);
  if (!memberId) {
    return res.status(401).json({ ok: false, error: 'invalid_session' });
  }
  let member = teamMembersById.get(memberId);
  if (!member) {
    try {
      member = await fetchTeamMemberById(memberId);
    } catch (err) {
      console.error('Failed to load member during auth', err);
    }
    if (!member) {
      return res.status(401).json({ ok: false, error: 'invalid_session' });
    }
  }
  req.teamMember = member;
  if (!req.teamMember.roleNormalized) {
    req.teamMember.roleNormalized = normalizeRole(req.teamMember.role);
  }
  req.teamSessionToken = token;
  next();
};

app.post('/api/team/login', async (req, res) => {
  if (!ensureTeamEnabled(res)) return;
  const { email = '', code = '' } = req.body || {};
  const normalizedIdentifier = normalizeKey(email);
  const providedCode = typeof code === 'string' ? code.trim() : '';
  if (!normalizedIdentifier || !providedCode) {
    return res.status(400).json({ ok: false, error: 'missing_credentials' });
  }
  const { member, override } = await resolveLoginMember(normalizedIdentifier);
  if (!member) {
    return res.status(404).json({ ok: false, error: 'member_not_found' });
  }
  const expectedCode = resolveTeamAccessCode({ member, override, identifierNormalized: normalizedIdentifier });
  if (!expectedCode) {
    return res.status(403).json({ ok: false, error: 'access_not_configured' });
  }
  if (!safeCompare(expectedCode, providedCode)) {
    return res.status(401).json({ ok: false, error: 'invalid_credentials' });
  }
  const sessionToken = createTeamSession(member.id);
  try {
    const [departments, tasks] = await Promise.all([fetchTeamDepartments(), fetchTeamTasks()]);
    const departmentMap = new Map(departments.map((dept) => [dept.id, dept]));
    const department = sanitizeTeamDepartment(departmentMap.get(member.departmentId));
    const myOpenTasks = tasks.filter(
      (task) => Array.isArray(task.ownerIds) && task.ownerIds.includes(member.id) && task.status !== 'done'
    ).length;
    res.json({
      ok: true,
      token: sessionToken,
      expires_in: TEAM_SESSION_TTL_MS,
      member: sanitizeTeamMember(member),
      department,
      stats: {
        myOpenTasks
      }
    });
  } catch (err) {
    console.error('Failed to load team context during login', err);
    res.json({
      ok: true,
      token: sessionToken,
      expires_in: TEAM_SESSION_TTL_MS,
      member: sanitizeTeamMember(member),
      department: null,
      stats: {
        myOpenTasks: 0
      }
    });
  }
});

app.post('/api/team/logout', teamAuth, (req, res) => {
  const token = req.teamSessionToken;
  res.json({ ok: true });
});

app.get('/api/team/me', teamAuth, async (req, res) => {
  try {
    const [departments, { members, map: memberMap }, tasks, events] = await Promise.all([
      fetchTeamDepartments(),
      fetchTeamMembersMap(),
      fetchTeamTasks(),
      fetchTeamEvents()
    ]);
    const departmentMap = new Map(departments.map((dept) => [dept.id, dept]));
    const member = await fetchTeamMemberById(req.teamMember.id);
    const department = sanitizeTeamDepartment(departmentMap.get(member?.departmentId || req.teamMember.departmentId));
    const myTasks = tasks.filter(
      (task) => Array.isArray(task.ownerIds) && task.ownerIds.includes(req.teamMember.id)
    );
    const upcomingEvents = events.filter((event) => {
      if (!event.startAt) return false;
      const eventTime = new Date(event.startAt).getTime();
      return Number.isFinite(eventTime) && eventTime >= Date.now() - 1000 * 60 * 60 * 24;
    });
    res.json({
      ok: true,
      member: sanitizeTeamMember(member || req.teamMember),
      department,
      departments: departments.map(sanitizeTeamDepartment).filter(Boolean),
      members: members.map(sanitizeTeamMember).filter(Boolean),
      stats: {
        myOpenTasks: myTasks.filter((task) => task.status !== 'done').length,
        myBlockedTasks: myTasks.filter((task) => task.status === 'blocked').length,
        upcomingEvents: upcomingEvents.length
      }
    });
  } catch (err) {
    console.error('Failed to load team profile', err);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

app.get('/api/team/departments', teamAuth, async (_req, res) => {
  try {
    const departments = await fetchTeamDepartments();
    res.json({ ok: true, departments: departments.map(sanitizeTeamDepartment).filter(Boolean) });
  } catch (err) {
    console.error('Failed to load team departments', err);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

app.get('/api/team/tasks', teamAuth, async (req, res) => {
  try {
    const { department, status, mine, owner } = req.query || {};
    const [departments, { map: memberMap }, tasks] = await Promise.all([
      fetchTeamDepartments(),
      fetchTeamMembersMap(),
      fetchTeamTasks()
    ]);
    const departmentMap = new Map(departments.map((dept) => [dept.id, dept]));
    const departmentColors = buildDepartmentColorMap(departments);
    const requester = req.teamMember;
    let results = tasks.filter((task) => canMemberViewTask(task, requester));
    if (department && typeof department === 'string') {
      const departmentIds = department
        .split(',')
        .map((value) => value.trim())
        .filter(Boolean);
      if (departmentIds.length) {
        results = results.filter((task) => departmentIds.includes(task.departmentId));
      }
    }
    if (status && typeof status === 'string' && status.trim() !== 'all') {
      const normalizedStatus = status.trim().toLowerCase();
      results = results.filter((task) => task.status === normalizedStatus);
    }
    if (owner && typeof owner === 'string') {
      const normalizedOwner = owner.trim();
      results = results.filter(
        (task) => Array.isArray(task.ownerIds) && task.ownerIds.includes(normalizedOwner)
      );
    }
    if (mine === 'true') {
      results = results.filter(
        (task) =>
          Array.isArray(task.ownerIds) && task.ownerIds.includes(req.teamMember.id)
      );
    }
    const context = {
      departmentMap,
      memberMap,
      departmentColors,
      currentMemberId: req.teamMember.id,
      currentMemberRole: req.teamMember.role || '',
      currentMemberRoleNormalized: req.teamMember.roleNormalized || normalizeRole(req.teamMember.role)
    };
    const payload = results
      .map((task) => sanitizeTeamTask(task, context))
      .filter(Boolean);
    res.json({ ok: true, tasks: payload });
  } catch (err) {
    console.error('Failed to load team tasks', err);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

app.get('/api/team/tasks/:id/updates', teamAuth, async (req, res) => {
  const taskId = req.params.id?.trim();
  if (!taskId) {
    return res.status(400).json({ ok: false, error: 'missing_task_id' });
  }
  try {
    const taskSnap = await teamTasksCollection.doc(taskId).get();
    if (!taskSnap.exists) {
      return res.status(404).json({ ok: false, error: 'task_not_found' });
    }
    const task = mapTeamTaskDoc(taskSnap);
    if (!canMemberViewTask(task, req.teamMember)) {
      return res.status(403).json({ ok: false, error: 'forbidden' });
    }
    const [updates, { map: memberMap }] = await Promise.all([
      fetchTaskUpdates(taskId),
      fetchTeamMembersMap()
    ]);
    res.json({
      ok: true,
      updates: updates.map((update) => sanitizeTeamTaskUpdate(update, memberMap)).filter(Boolean)
    });
  } catch (err) {
    console.error('Failed to load task updates', err);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

app.post('/api/team/tasks/:id/updates', teamAuth, async (req, res) => {
  const taskId = req.params.id?.trim();
  if (!taskId) {
    return res.status(400).json({ ok: false, error: 'missing_task_id' });
  }
  try {
    const taskRef = teamTasksCollection.doc(taskId);
    const [taskSnap, departments, { map: memberMap }] = await Promise.all([
      taskRef.get(),
      fetchTeamDepartments(),
      fetchTeamMembersMap()
    ]);
    if (!taskSnap.exists) {
      return res.status(404).json({ ok: false, error: 'task_not_found' });
    }
    const departmentMap = new Map(departments.map((dept) => [dept.id, dept]));
    const departmentColors = buildDepartmentColorMap(departments);
    const task = mapTeamTaskDoc(taskSnap);
    if (!canMemberViewTask(task, req.teamMember)) {
      return res.status(403).json({ ok: false, error: 'forbidden' });
    }
    const { note = '', status } = req.body || {};
    const trimmedNote = typeof note === 'string' ? note.trim() : '';
    if (!trimmedNote) {
      return res.status(400).json({ ok: false, error: 'missing_note' });
    }
    const normalizedStatus =
      typeof status === 'string' && status.trim() ? status.trim().toLowerCase() : '';
    if (normalizedStatus && !TEAM_ALLOWED_STATUSES.has(normalizedStatus)) {
      return res.status(400).json({ ok: false, error: 'invalid_status' });
    }
    const isOwner = Array.isArray(task.ownerIds) && task.ownerIds.includes(req.teamMember.id);
    const isElevated = isLeadOrMentor(req.teamMember);
    if (!isOwner && !isElevated) {
      return res.status(403).json({ ok: false, error: 'forbidden' });
    }
    const createdAtIso = new Date().toISOString();
    const updateRef = teamTaskUpdatesCollection.doc();
    const statusAfter = normalizedStatus || task.status || 'todo';
    await updateRef.set({
      task_id: taskId,
      member_id: req.teamMember.id,
      note: trimmedNote,
      status_after: statusAfter,
      created_at: createdAtIso,
      created_at_ts: FieldValue.serverTimestamp()
    });
    const taskUpdatePayload = {
      last_update_id: updateRef.id,
      last_update_member_id: req.teamMember.id,
      last_update_note: trimmedNote,
      last_update_status: statusAfter,
      last_update_at: createdAtIso,
      last_update_at_ts: FieldValue.serverTimestamp(),
      updates_count: FieldValue.increment(1),
      updated_at: FieldValue.serverTimestamp()
    };
    if (normalizedStatus && normalizedStatus !== task.status) {
      taskUpdatePayload.status = normalizedStatus;
    }
    await taskRef.update(taskUpdatePayload);
    const [updatedTaskSnap, updateSnap] = await Promise.all([taskRef.get(), updateRef.get()]);
    const updatedTask = mapTeamTaskDoc(updatedTaskSnap);
    const updateRecord = mapTeamTaskUpdateDoc(updateSnap);
    const department = departmentMap.get(task.departmentId);
    const context = {
      departmentMap,
      memberMap,
      departmentColors,
      currentMemberId: req.teamMember.id,
      currentMemberRole: req.teamMember.role || '',
      currentMemberRoleNormalized: req.teamMember.roleNormalized || normalizeRole(req.teamMember.role)
    };
    const sanitizedUpdate = sanitizeTeamTaskUpdate(updateRecord, memberMap);
    const sanitizedTask = sanitizeTeamTask(updatedTask, context);
    res.status(201).json({
      ok: true,
      update: sanitizedUpdate,
      task: sanitizedTask
    });
    if (sanitizedTask && sanitizedUpdate) {
      const updaterMember = sanitizedUpdate.member || req.teamMember;
      const updaterNameRaw = getMemberDisplayName(updaterMember);
      const updaterMention = formatSlackMention(updaterMember);
      const noteTextRaw = sanitizedUpdate.note || '';
      const notePreviewFull = noteTextRaw.replace(/\s+/g, ' ').trim();
      const notePreview =
        notePreviewFull.length > 180 ? `${notePreviewFull.slice(0, 177)}…` : notePreviewFull;
      const noteText = noteTextRaw ? slackEscape(noteTextRaw) : '_Update submitted._';
      const departmentNameRaw = department?.name || sanitizedTask.departmentName || 'General';
      const departmentName = slackEscape(departmentNameRaw);
      const statusLabel =
        formatSlackLabel(sanitizedUpdate.statusAfter || '') ||
        formatSlackLabel(sanitizedTask.status || '');
      const taskTitleRaw = sanitizedTask.title || '';
      const taskTitle = slackEscape(taskTitleRaw);
      const contextElements = [
        { type: 'mrkdwn', text: `*Team:* ${departmentName}` }
      ];
      if (statusLabel) {
        contextElements.push({ type: 'mrkdwn', text: `*Status:* ${statusLabel}` });
      }
      contextElements.push({ type: 'mrkdwn', text: `From ${updaterMention}` });
      notifySlack({
        text: notePreview
          ? `✏️ ${updaterNameRaw} updated "${taskTitleRaw}": ${notePreview}`
          : `✏️ ${updaterNameRaw} updated "${taskTitleRaw}".`,
        channel: getSlackChannelForDepartment(department),
        blocks: [
          {
            type: 'section',
            text: {
              type: 'mrkdwn',
              text: `*${taskTitle}*\n${noteText}`
            }
          },
          {
            type: 'context',
            elements: contextElements
          }
        ]
      });
    }
  } catch (err) {
    console.error('Failed to append task update', err);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

app.post('/api/team/tasks', teamAuth, async (req, res) => {
  const requester = req.teamMember;
  const requesterRole = requester.roleNormalized || normalizeRole(requester.role);
  const isElevated = requesterRole === 'lead' || requesterRole === 'mentor';
  if (!isElevated && requesterRole !== 'member') {
    return res.status(403).json({ ok: false, error: 'forbidden' });
  }
  const { title = '', description = '', departmentId = '', ownerIds, dueAt, priority } =
    req.body || {};
  const trimmedTitle = typeof title === 'string' ? title.trim() : '';
  const trimmedDescription = typeof description === 'string' ? description.trim() : '';
  if (!trimmedTitle) {
    return res.status(400).json({ ok: false, error: 'missing_title' });
  }
  try {
    const [departments, { map: memberMap }] = await Promise.all([
      fetchTeamDepartments(),
      fetchTeamMembersMap()
    ]);
    const departmentMap = new Map(departments.map((dept) => [dept.id, dept]));
    const department =
      typeof departmentId === 'string' && departmentId.trim()
        ? departmentMap.get(departmentId.trim())
        : departmentMap.get(requester.departmentId);
    if (!department) {
      return res.status(400).json({ ok: false, error: 'invalid_department' });
    }
    let normalizedOwnerIds;
    if (Array.isArray(ownerIds) && ownerIds.length) {
      normalizedOwnerIds = ownerIds
        .map((value) => (typeof value === 'string' ? value.trim() : ''))
        .filter(Boolean);
    } else if (isElevated) {
      normalizedOwnerIds = [requester.id];
    } else {
      normalizedOwnerIds = [];
    }
    const missingOwners = normalizedOwnerIds.filter((ownerId) => !memberMap.has(ownerId));
    if (missingOwners.length) {
      return res.status(400).json({ ok: false, error: 'invalid_owner' });
    }
    const nowIso = new Date().toISOString();
    const dueAtIso = dueAt ? toIsoString(new Date(dueAt)) || '' : '';
    const taskRef = teamTasksCollection.doc();
    const restrictedRoles = [];
    const allowedMemberIds = [];
    await taskRef.set({
      title: trimmedTitle,
      description: trimmedDescription,
      department_id: department.id,
      owner_ids: normalizedOwnerIds,
      status: 'todo',
      priority: typeof priority === 'string' && priority.trim() ? priority.trim() : 'medium',
      due_at: dueAtIso,
      due_at_ts: dueAtIso ? new Date(dueAtIso) : null,
      created_by: requester.id,
      created_at: nowIso,
      created_at_ts: FieldValue.serverTimestamp(),
      checklist: [],
      updates_count: 0,
      restricted_roles: restrictedRoles,
      allowed_member_ids: allowedMemberIds
    });
    const createdTaskSnap = await taskRef.get();
    const createdTask = mapTeamTaskDoc(createdTaskSnap);
    const departmentColors = buildDepartmentColorMap(departments);
    const context = {
      departmentMap,
      memberMap,
      departmentColors,
      currentMemberId: requester.id,
      currentMemberRole: requester.role || '',
      currentMemberRoleNormalized: requester.roleNormalized || normalizeRole(requester.role)
    };
    const sanitizedTask = sanitizeTeamTask(createdTask, context);
    res.status(201).json({
      ok: true,
      task: sanitizedTask
    });
    if (sanitizedTask) {
      const departmentNameRaw = department?.name || sanitizedTask.departmentName || 'General';
      const departmentName = slackEscape(departmentNameRaw);
      const ownersMentions =
        Array.isArray(sanitizedTask.owners) && sanitizedTask.owners.length
          ? sanitizedTask.owners.map((owner) => formatSlackMention(owner)).join(', ')
          : slackEscape('Unassigned');
      const dueText = formatSlackDate(sanitizedTask.dueAt);
      const priorityLabel =
        formatSlackLabel(sanitizedTask.priority || '') || slackEscape('Medium');
      const descriptionText = sanitizedTask.description
        ? slackEscape(sanitizedTask.description)
        : '_No description provided._';
      const creatorNameRaw = getMemberDisplayName(requester);
      const creatorMention = formatSlackMention(requester);
      const taskTitleRaw = sanitizedTask.title || '';
      const taskTitle = slackEscape(taskTitleRaw);
      notifySlack({
        text: `🆕 ${creatorNameRaw} created "${taskTitleRaw}" in ${departmentNameRaw}.`,
        channel: getSlackChannelForDepartment(department),
        blocks: [
          {
            type: 'section',
            text: {
              type: 'mrkdwn',
              text: `*${taskTitle}*\n${descriptionText}`
            }
          },
          {
            type: 'context',
            elements: [
              { type: 'mrkdwn', text: `*Team:* ${departmentName}` },
              { type: 'mrkdwn', text: `*Priority:* ${priorityLabel}` },
              { type: 'mrkdwn', text: `*Due:* ${dueText}` },
              { type: 'mrkdwn', text: `*Owners:* ${ownersMentions}` }
            ]
          },
          {
            type: 'context',
            elements: [{ type: 'mrkdwn', text: `Created by ${creatorMention}` }]
          }
        ]
      });
    }
  } catch (err) {
    console.error('Failed to create team task', err);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

app.patch('/api/team/tasks/:id', teamAuth, async (req, res) => {
  const taskId = req.params.id?.trim();
  if (!taskId) {
    return res.status(400).json({ ok: false, error: 'missing_task_id' });
  }
  try {
    const taskRef = teamTasksCollection.doc(taskId);
    const [taskSnap, departments, { map: memberMap }] = await Promise.all([
      taskRef.get(),
      fetchTeamDepartments(),
      fetchTeamMembersMap()
    ]);
    if (!taskSnap.exists) {
      return res.status(404).json({ ok: false, error: 'task_not_found' });
    }
    const task = mapTeamTaskDoc(taskSnap);
    const requester = req.teamMember;
    if (!canMemberViewTask(task, requester)) {
      return res.status(403).json({ ok: false, error: 'forbidden' });
    }
    const isElevated = isLeadOrMentor(requester);
    const isOwner = Array.isArray(task.ownerIds) && task.ownerIds.includes(requester.id);
    const allowedFields = ['status'];
    const bodyKeys = Object.keys(req.body || {});
    if (!isElevated) {
      if (!isOwner || bodyKeys.some((key) => !allowedFields.includes(key))) {
        return res.status(403).json({ ok: false, error: 'forbidden' });
      }
    }
    const updates = {};
    if (req.body?.status) {
      const normalizedStatus =
        typeof req.body.status === 'string' ? req.body.status.trim().toLowerCase() : '';
      if (!TEAM_ALLOWED_STATUSES.has(normalizedStatus)) {
        return res.status(400).json({ ok: false, error: 'invalid_status' });
      }
      updates.status = normalizedStatus;
    }
    if (isElevated && Array.isArray(req.body?.ownerIds)) {
      const normalizedOwnerIds = req.body.ownerIds
        .map((value) => (typeof value === 'string' ? value.trim() : ''))
        .filter(Boolean);
      const missingOwners = normalizedOwnerIds.filter((ownerId) => !memberMap.has(ownerId));
      if (missingOwners.length) {
        return res.status(400).json({ ok: false, error: 'invalid_owner' });
      }
      updates.owner_ids = normalizedOwnerIds;
    }
    if (isElevated && typeof req.body?.departmentId === 'string') {
      const trimmedDepartment = req.body.departmentId.trim();
      if (trimmedDepartment) {
        if (!departmentMap.has(trimmedDepartment)) {
          return res.status(400).json({ ok: false, error: 'invalid_department' });
        }
        updates.department_id = trimmedDepartment;
      }
    }
    if (isElevated && typeof req.body?.priority === 'string' && req.body.priority.trim()) {
      updates.priority = req.body.priority.trim();
    }
    if (isElevated && typeof req.body?.dueAt === 'string') {
      const dueAtIso = req.body.dueAt.trim()
        ? toIsoString(new Date(req.body.dueAt.trim())) || ''
        : '';
      updates.due_at = dueAtIso;
      updates.due_at_ts = dueAtIso ? new Date(dueAtIso) : null;
    }
    if (isElevated && Array.isArray(req.body?.checklist)) {
      updates.checklist = req.body.checklist
        .map((item) => (typeof item === 'string' ? item.trim() : ''))
        .filter(Boolean);
    }
    if (isElevated && typeof req.body?.title === 'string') {
      const trimmedTitle = req.body.title.trim();
      if (!trimmedTitle) {
        return res.status(400).json({ ok: false, error: 'missing_title' });
      }
      updates.title = trimmedTitle;
    }
    if (isElevated && typeof req.body?.description === 'string') {
      updates.description = req.body.description.trim();
    }
    if (!Object.keys(updates).length) {
      const context = {
        departmentMap,
        memberMap,
        departmentColors,
        currentMemberId: requester.id,
        currentMemberRole: requester.role
      };
      return res.json({
        ok: true,
        task: sanitizeTeamTask(task, context)
      });
    }
    updates.updated_at = FieldValue.serverTimestamp();
    await taskRef.update(updates);
    const updatedTaskSnap = await taskRef.get();
    const updatedTask = mapTeamTaskDoc(updatedTaskSnap);
    const context = {
      departmentMap,
      memberMap,
      departmentColors,
      currentMemberId: requester.id,
      currentMemberRole: requester.role
    };
    res.json({
      ok: true,
      task: sanitizeTeamTask(updatedTask, context)
    });
  } catch (err) {
    console.error('Failed to update team task', err);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

app.delete('/api/team/tasks/:id', teamAuth, async (req, res) => {
  const taskId = req.params.id?.trim();
  if (!taskId) {
    return res.status(400).json({ ok: false, error: 'missing_task_id' });
  }
  try {
    const requester = req.teamMember;
    if (!isLeadOrMentor(requester)) {
      return res.status(403).json({ ok: false, error: 'forbidden' });
    }
    const taskRef = teamTasksCollection.doc(taskId);
    const taskSnap = await taskRef.get();
    if (!taskSnap.exists) {
      return res.status(404).json({ ok: false, error: 'task_not_found' });
    }
    const task = mapTeamTaskDoc(taskSnap);
    if (!canMemberViewTask(task, requester)) {
      return res.status(403).json({ ok: false, error: 'forbidden' });
    }
    await deleteTaskUpdates(taskId);
    await taskRef.delete();
    res.json({ ok: true, deleted: true });
  } catch (err) {
    console.error('Failed to delete team task', err);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

app.post('/api/team/tasks/:id/reminders', teamAuth, async (req, res) => {
  const taskId = req.params.id?.trim();
  if (!taskId) {
    return res.status(400).json({ ok: false, error: 'missing_task_id' });
  }
  try {
    const [taskSnap, departments, { map: memberMap }] = await Promise.all([
      teamTasksCollection.doc(taskId).get(),
      fetchTeamDepartments(),
      fetchTeamMembersMap()
    ]);
    if (!taskSnap.exists) {
      return res.status(404).json({ ok: false, error: 'task_not_found' });
    }
    const task = mapTeamTaskDoc(taskSnap);
    if (!canMemberViewTask(task, req.teamMember)) {
      return res.status(403).json({ ok: false, error: 'forbidden' });
    }
    if (!isLeadOrMentor(req.teamMember)) {
      return res.status(403).json({ ok: false, error: 'forbidden' });
    }
    const departmentMap = new Map(departments.map((dept) => [dept.id, dept]));
    const department = departmentMap.get(task.departmentId);
    const scope = typeof req.body?.scope === 'string' ? req.body.scope.trim().toLowerCase() : 'owners';
    const message = typeof req.body?.message === 'string' ? req.body.message.trim() : '';
    let recipients = [];
    if (scope === 'member') {
      const memberId = typeof req.body?.memberId === 'string' ? req.body.memberId.trim() : '';
      if (!memberId) {
        return res.status(400).json({ ok: false, error: 'missing_member' });
      }
      const member = memberMap.get(memberId);
      if (!member) {
        return res.status(400).json({ ok: false, error: 'invalid_member' });
      }
      recipients = [member];
    } else {
      const ownerIds = Array.isArray(task.ownerIds) ? task.ownerIds : [];
      recipients = ownerIds.map((ownerId) => memberMap.get(ownerId)).filter(Boolean);
      if (!recipients.length) {
        return res.status(400).json({ ok: false, error: 'no_assignees' });
      }
    }
    const sanitizedRecipients = recipients.map((member) => sanitizeTeamMember(member)).filter(Boolean);
    const mentionList = sanitizedRecipients.map((member) => formatSlackMention(member)).join(' ');
    const textMentionList = sanitizedRecipients
      .map((member) => {
        const slackId = safeSlackUserId(member.slackUserId);
        if (slackId) return `<@${slackId}>`;
        return member.displayName || member.loginId || member.id || 'teammate';
      })
      .join(' ');
    const requesterMention = formatSlackMention(req.teamMember);
    const taskTitle = task.title || 'Untitled task';
    const dueLabel = formatSlackDate(task.dueAt || '');
    const priorityLabel = formatSlackLabel(task.priority || 'medium') || 'Medium';
    const statusLabel = formatSlackLabel(task.status || 'todo') || 'To do';
    const customLine = message ? slackEscape(message) : `Please take the next step on *${slackEscape(taskTitle)}*.`;
    const departmentName = department?.name || task.departmentName || task.departmentId || 'General';

    notifySlack({
      text: `${textMentionList || 'Team'} — reminder for "${taskTitle}"`,
      channel: getSlackChannelForDepartment(department),
      blocks: [
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `${mentionList || 'Team'}
${customLine}`
          }
        },
        {
          type: 'context',
          elements: [
            { type: 'mrkdwn', text: `*Task:* ${slackEscape(taskTitle)}` },
            { type: 'mrkdwn', text: `*Team:* ${slackEscape(departmentName)}` },
            { type: 'mrkdwn', text: `*Status:* ${statusLabel}` },
            { type: 'mrkdwn', text: `*Priority:* ${priorityLabel}` },
            { type: 'mrkdwn', text: `*Due:* ${dueLabel}` }
          ]
        },
        {
          type: 'context',
          elements: [{ type: 'mrkdwn', text: `Requested by ${requesterMention}` }]
        }
      ]
    });

    res.status(201).json({ ok: true });
  } catch (err) {
    console.error('Failed to send reminder', err);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

app.post('/api/team/tasks/:id/claim', teamAuth, async (req, res) => {
  const taskId = req.params.id?.trim();
  if (!taskId) {
    return res.status(400).json({ ok: false, error: 'missing_task_id' });
  }
  try {
    const taskRef = teamTasksCollection.doc(taskId);
    const [taskSnap, departments, { map: memberMap }] = await Promise.all([
      taskRef.get(),
      fetchTeamDepartments(),
      fetchTeamMembersMap()
    ]);
    if (!taskSnap.exists) {
      return res.status(404).json({ ok: false, error: 'task_not_found' });
    }
    const task = mapTeamTaskDoc(taskSnap);
    const requester = req.teamMember;
    if (!canMemberViewTask(task, requester)) {
      return res.status(403).json({ ok: false, error: 'forbidden' });
    }
    const isElevated = isLeadOrMentor(requester);
    const action =
      typeof req.body?.action === 'string' ? req.body.action.trim().toLowerCase() : 'claim';
    const requestedMemberIdRaw =
      typeof req.body?.memberId === 'string' ? req.body.memberId.trim() : '';
    const targetMemberId =
      requestedMemberIdRaw && isElevated ? requestedMemberIdRaw : requester.id;
    if (!memberMap.has(targetMemberId)) {
      return res.status(404).json({ ok: false, error: 'member_not_found' });
    }

    const owners = Array.isArray(task.ownerIds) ? [...task.ownerIds] : [];
    const isTargetOwner = owners.includes(targetMemberId);

    if (action === 'claim') {
      if (isTargetOwner) {
        const departmentMap = new Map(departments.map((dept) => [dept.id, dept]));
        const departmentColors = buildDepartmentColorMap(departments);
        const context = {
          departmentMap,
          memberMap,
          departmentColors,
          currentMemberId: requester.id,
          currentMemberRole: requester.role || '',
          currentMemberRoleNormalized: requester.roleNormalized || normalizeRole(requester.role)
        };
        return res.json({ ok: true, task: sanitizeTeamTask(task, context) });
      }
      if (owners.length && !isElevated) {
        return res.status(409).json({ ok: false, error: 'already_claimed' });
      }
      owners.push(targetMemberId);
    } else if (action === 'unclaim') {
      if (!isTargetOwner) {
        return res.status(404).json({ ok: false, error: 'not_assigned' });
      }
      if (targetMemberId !== requester.id && !isElevated) {
        return res.status(403).json({ ok: false, error: 'forbidden' });
      }
      const index = owners.indexOf(targetMemberId);
      if (index >= 0) {
        owners.splice(index, 1);
      }
    } else {
      return res.status(400).json({ ok: false, error: 'unknown_action' });
    }

    await taskRef.update({
      owner_ids: owners,
      updated_at: FieldValue.serverTimestamp()
    });
    const updatedTaskSnap = await taskRef.get();
    const updatedTask = mapTeamTaskDoc(updatedTaskSnap);
    const departmentMap = new Map(departments.map((dept) => [dept.id, dept]));
    const departmentColors = buildDepartmentColorMap(departments);
    const context = {
      departmentMap,
      memberMap,
      departmentColors,
      currentMemberId: requester.id,
      currentMemberRole: requester.role || '',
      currentMemberRoleNormalized: requester.roleNormalized || normalizeRole(requester.role)
    };
    res.json({
      ok: true,
      task: sanitizeTeamTask(updatedTask, context)
    });
  } catch (err) {
    console.error('Failed to update task assignment', err);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

app.get('/api/team/events', teamAuth, async (req, res) => {
  const { department, upcoming } = req.query || {};
  try {
    const [events, { map: memberMap }] = await Promise.all([
      fetchTeamEvents(),
      fetchTeamMembersMap()
    ]);
    let results = [...events];
    if (department && typeof department === 'string') {
      const trimmed = department.trim();
      results = results.filter(
        (event) =>
          Array.isArray(event.departmentIds) && event.departmentIds.includes(trimmed)
      );
    }
    if (upcoming !== 'false') {
      const now = Date.now();
      results = results.filter((event) => {
        if (!event.startAt) return false;
        const startTs = new Date(event.startAt).getTime();
        return Number.isFinite(startTs) && startTs >= now - 1000 * 60 * 60 * 24;
      });
    }
    results.sort((a, b) => new Date(a.startAt || 0) - new Date(b.startAt || 0));
    res.json({
      ok: true,
      events: results.map((event) => sanitizeTeamEvent(event, memberMap)).filter(Boolean)
    });
  } catch (err) {
    console.error('Failed to load team events', err);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

app.post('/api/team/events', teamAuth, async (req, res) => {
  const requester = req.teamMember;
  if (requester.role !== 'lead') {
    return res.status(403).json({ ok: false, error: 'forbidden' });
  }
  const {
    title = '',
    description = '',
    startAt = '',
    endAt = '',
    location = '',
    link = '',
    hosts,
    departmentIds
  } = req.body || {};
  const trimmedTitle = typeof title === 'string' ? title.trim() : '';
  if (!trimmedTitle) {
    return res.status(400).json({ ok: false, error: 'missing_title' });
  }
  const normalizedStart = typeof startAt === 'string' ? startAt.trim() : '';
  if (!normalizedStart) {
    return res.status(400).json({ ok: false, error: 'missing_start' });
  }
  try {
    const [departments, { map: memberMap }] = await Promise.all([
      fetchTeamDepartments(),
      fetchTeamMembersMap()
    ]);
    const departmentMap = new Map(departments.map((dept) => [dept.id, dept]));
    const normalizedHosts = Array.isArray(hosts)
      ? hosts.map((value) => (typeof value === 'string' ? value.trim() : '')).filter(Boolean)
      : [requester.id];
    const missingHosts = normalizedHosts.filter((hostId) => !memberMap.has(hostId));
    if (missingHosts.length) {
      return res.status(400).json({ ok: false, error: 'invalid_host' });
    }
    const normalizedDepartments = Array.isArray(departmentIds)
      ? departmentIds.map((value) => (typeof value === 'string' ? value.trim() : '')).filter(Boolean)
      : requester.departmentId
      ? [requester.departmentId]
      : [];
    const invalidDepartments = normalizedDepartments.filter((deptId) => !departmentMap.has(deptId));
    if (invalidDepartments.length) {
      return res.status(400).json({ ok: false, error: 'invalid_department' });
    }
    const startIso = toIsoString(new Date(normalizedStart)) || normalizedStart;
    const endIso = typeof endAt === 'string' && endAt.trim()
      ? toIsoString(new Date(endAt.trim())) || endAt.trim()
      : '';
    const eventRef = teamEventsCollection.doc();
    const nowIso = new Date().toISOString();
    await eventRef.set({
      title: trimmedTitle,
      description: typeof description === 'string' ? description.trim() : '',
      start_at: startIso,
      start_at_ts: startIso ? new Date(startIso) : null,
      end_at: endIso,
      end_at_ts: endIso ? new Date(endIso) : null,
      location: typeof location === 'string' ? location.trim() : '',
      link: typeof link === 'string' ? link.trim() : '',
      hosts: normalizedHosts,
      department_ids: normalizedDepartments,
      created_at: nowIso,
      created_at_ts: FieldValue.serverTimestamp()
    });
    const eventSnap = await eventRef.get();
    const event = mapTeamEventDoc(eventSnap);
    res.status(201).json({ ok: true, event: sanitizeTeamEvent(event, memberMap) });
  } catch (err) {
    console.error('Failed to create team event', err);
    res.status(500).json({ ok: false, error: 'server_error' });
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
app.get('/team', (_req, res) => res.sendFile(path.join(__dirname, 'team.html')));
app.use((_req, res) => res.sendFile(path.join(__dirname, 'index.html')));

const PORT = Number(process.env.PORT || 3000);

if (import.meta.url === `file://${__filename}`) {
  app.listen(PORT, () => {
    const base = SITE_URL || `http://localhost:${PORT}`;
    console.log(`Bug Bash server ready on port ${PORT} → ${base}`);
  });
}

export default app;
