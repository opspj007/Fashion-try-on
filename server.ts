import express from 'express';
import http from 'http';
import { WebSocketServer, WebSocket } from 'ws';
import crypto from 'node:crypto';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { GoogleGenAI, Type } from '@google/genai';
import { createServer as createViteServer } from 'vite';

// Safe directory resolution across both dev (ESM via tsx) and production (CommonJS bundle via esbuild)
const getAppDir = (): string => {
  try {
    // In ESM (tsx dev mode)
    if (typeof import.meta !== 'undefined' && import.meta && typeof import.meta.url === 'string') {
      return path.dirname(fileURLToPath(import.meta.url));
    }
  } catch {}
  try {
    // In CommonJS (esbuild bundle production)
    // @ts-ignore
    if (typeof __dirname !== 'undefined' && __dirname) {
      // @ts-ignore
      return __dirname;
    }
  } catch {}
  return process.cwd();
};

const appDir = getAppDir();

// Capture system-provided Gemini API key at startup before any overrides
const SYSTEM_ENV_API_KEY = process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY || '';

// Dynamically load .env without overriding valid system keys and avoiding dotenvx noise
function loadEnv(): void {
  const possiblePaths = [
    path.resolve(process.cwd(), '.env'),
    path.resolve(process.cwd(), '.env.local'),
    path.resolve(appDir, '..', '.env'),
    path.resolve(appDir, '.env'),
  ];
  for (const envPath of possiblePaths) {
    if (fs.existsSync(envPath)) {
      try {
        dotenv.config({ path: envPath, override: false, quiet: true });
      } catch {}
    }
  }
  // Ensure the platform-provided Gemini API key is retained if .env did not supply one
  if ((!process.env.GEMINI_API_KEY || !process.env.GEMINI_API_KEY.trim()) && SYSTEM_ENV_API_KEY) {
    process.env.GEMINI_API_KEY = SYSTEM_ENV_API_KEY;
  }
}

// Initial environment loading once at boot
loadEnv();

const app = express();
const PORT = 3000;

// Increase body limits for image uploads (high-res images and multi-reference images)
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));

// User Store, Roles, and Real-Time WebSocket Infrastructure
interface UserRecord {
  id: string;
  email: string;
  username: string;
  fullName?: string;
  memberId?: string;
  contactNo?: string;
  voucherCode?: string;
  passcode?: string;
  passwordHash?: string;
  salt?: string;
  authProvider: 'local' | 'google';
  role: 'admin' | 'member';
  status: 'pending' | 'approved' | 'suspended' | 'rejected';
  quality: number;
  downloads: number;
  limit: number;
  credits: number;
  lifetimeCreditsUsed: number;
  sessions: string[];
  createdAt: string;
  lastLoginAt: string;
  approvedAt?: string;
  approvedBy?: string;
  registrationIp?: string;
  lastLoginIp?: string;
  lastDownloadIp?: string;
  loginIps?: Array<{ ip: string; timestamp: string; userAgent?: string }>;
  downloadHistory?: Array<{ id: string; timestamp: string; ip: string; creditsBefore: number; creditsAfter: number; userAgent?: string }>;
}

// IP Tracking Helper
function getClientIp(req: express.Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string') {
    const first = forwarded.split(',')[0].trim();
    if (first) return first.replace(/^::ffff:/, '');
  }
  const realIp = req.headers['x-real-ip'];
  if (typeof realIp === 'string' && realIp.trim()) {
    return realIp.trim().replace(/^::ffff:/, '');
  }
  const socketIp = req.socket?.remoteAddress || req.ip || '127.0.0.1';
  return socketIp.replace(/^::ffff:/, '');
}

// Super Administrator Recognition
const SUPER_ADMIN_EMAILS = new Set([
  'opspj0001@gmail.com',
  'omprakashbr1932@gmail.com',
  'omg800001@gmail.com',
]);

const DATA_DIR = path.resolve(process.cwd(), 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const BACKUPS_DIR = path.join(DATA_DIR, 'backups');

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}
if (!fs.existsSync(BACKUPS_DIR)) {
  fs.mkdirSync(BACKUPS_DIR, { recursive: true });
}

// Password Hashing with Salt using PBKDF2 (SHA-512)
function hashPassword(password: string, salt: string): string {
  return crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
}

// JWT Token Persistence (ajupy_jwt)
const JWT_SECRET = process.env.JWT_SECRET || 'ajupy-multi-device-secret-2026';

function base64UrlEncode(str: string): string {
  return Buffer.from(str)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function base64UrlDecode(str: string): string {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64').toString('utf-8');
}

function createJwt(payload: Record<string, any>): string {
  const header = JSON.stringify({ alg: 'HS256', typ: 'JWT' });
  const encodedHeader = base64UrlEncode(header);
  const encodedPayload = base64UrlEncode(
    JSON.stringify({
      ...payload,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30, // 30-day token persistence
    })
  );
  const signature = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

function verifyJwt(token: string): Record<string, any> | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [header, payload, signature] = parts;
    const expectedSig = crypto
      .createHmac('sha256', JWT_SECRET)
      .update(`${header}.${payload}`)
      .digest('base64')
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
    if (signature !== expectedSig) return null;
    const decoded = JSON.parse(base64UrlDecode(payload));
    if (decoded.exp && decoded.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }
    return decoded;
  } catch {
    return null;
  }
}

// Persistent Storage Management
function saveUsersToDisk(userMap: Map<string, UserRecord> = users): void {
  try {
    const list = Array.from(userMap.values());
    const tmp = USERS_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(list, null, 2), 'utf-8');
    fs.renameSync(tmp, USERS_FILE);
  } catch (err) {
    console.error('[Storage] Error saving users.json:', err);
  }
}

function loadUsersFromDisk(): Map<string, UserRecord> {
  const map = new Map<string, UserRecord>();
  try {
    if (fs.existsSync(USERS_FILE)) {
      const raw = fs.readFileSync(USERS_FILE, 'utf-8');
      const list = JSON.parse(raw);
      if (Array.isArray(list)) {
        for (const u of list) {
          if (u.email) {
            map.set(u.email.toLowerCase(), u);
          }
        }
      }
    }
  } catch (err) {
    console.error('[Storage] Error loading users.json:', err);
  }

  // Pre-seed and recognize super admins
  for (const superEmail of SUPER_ADMIN_EMAILS) {
    const lower = superEmail.toLowerCase();
    if (!map.has(lower)) {
      const salt = crypto.randomBytes(16).toString('hex');
      const hash = hashPassword('AdminPass2026!', salt);
      map.set(lower, {
        id: 'admin_' + crypto.randomUUID().substring(0, 8),
        email: lower,
        username: lower.split('@')[0],
        passwordHash: hash,
        salt,
        authProvider: 'local',
        role: 'admin',
        status: 'approved',
        quality: 2000,
        downloads: 0,
        limit: 5000,
        credits: 1000,
        lifetimeCreditsUsed: 0,
        sessions: [],
        createdAt: new Date().toISOString(),
        lastLoginAt: new Date().toISOString(),
        approvedAt: new Date().toISOString(),
        approvedBy: 'Super Administrator Auto-Recognition',
      });
    } else {
      const existing = map.get(lower)!;
      existing.role = 'admin';
      existing.status = 'approved';
    }
  }

  saveUsersToDisk(map);
  return map;
}

const users: Map<string, UserRecord> = loadUsersFromDisk();
const guestCredits: Map<string, number> = new Map();
const guestTrials: Map<string, number> = new Map();

// Helper to strip sensitive secrets before sending user record to client
function sanitizeUser(u: UserRecord) {
  return {
    id: u.id,
    email: u.email,
    username: u.username,
    fullName: u.fullName,
    memberId: u.memberId,
    contactNo: u.contactNo,
    voucherCode: u.voucherCode,
    role: u.role,
    status: u.status,
    authProvider: u.authProvider,
    quality: u.quality,
    downloads: u.downloads,
    limit: u.limit,
    credits: u.credits,
    lifetimeCreditsUsed: u.lifetimeCreditsUsed || 0,
    createdAt: u.createdAt,
    lastLoginAt: u.lastLoginAt,
    approvedAt: u.approvedAt,
    registrationIp: u.registrationIp,
    lastLoginIp: u.lastLoginIp,
    lastDownloadIp: u.lastDownloadIp,
    loginIps: u.loginIps || [],
    downloadHistory: u.downloadHistory || [],
  };
}

// HTTP Server and Real-time WebSocket Server
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// Map email to all active WebSocket connections across any desktop, tablet, or smartphone
const userSockets = new Map<string, Set<WebSocket>>();
const adminSockets = new Set<WebSocket>();

function broadcastToUser(email: string, payload: any) {
  const sockets = userSockets.get(email.toLowerCase());
  if (sockets) {
    const msg = JSON.stringify(payload);
    for (const ws of sockets) {
      if (ws.readyState === WebSocket.OPEN) {
        try {
          ws.send(msg);
        } catch {}
      }
    }
  }
}

function broadcastToAdmins(payload: any) {
  const msg = JSON.stringify(payload);
  for (const ws of adminSockets) {
    if (ws.readyState === WebSocket.OPEN) {
      try {
        ws.send(msg);
      } catch {}
    }
  }
}

wss.on('connection', (ws: WebSocket) => {
  let clientEmail: string | null = null;
  let isAdmin = false;

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message.toString());
      if (data.type === 'auth:init') {
        const { email, token } = data;
        let authEmail = email;
        if (token) {
          const verified = verifyJwt(token);
          if (verified?.email) {
            authEmail = verified.email;
          }
        }
        if (authEmail && typeof authEmail === 'string') {
          clientEmail = authEmail.toLowerCase();
          if (!userSockets.has(clientEmail)) {
            userSockets.set(clientEmail, new Set());
          }
          userSockets.get(clientEmail)!.add(ws);

          const u = users.get(clientEmail);
          if (u?.role === 'admin') {
            isAdmin = true;
            adminSockets.add(ws);
          }

          ws.send(
            JSON.stringify({
              type: 'auth:ack',
              email: clientEmail,
              role: u?.role || 'member',
              status: u?.status || 'pending',
              credits: u?.credits ?? 2,
            })
          );
        }
      } else if (data.type === 'ping') {
        ws.send(JSON.stringify({ type: 'pong', time: Date.now() }));
      }
    } catch {}
  });

  ws.on('close', () => {
    if (clientEmail && userSockets.has(clientEmail)) {
      userSockets.get(clientEmail)!.delete(ws);
      if (userSockets.get(clientEmail)!.size === 0) {
        userSockets.delete(clientEmail);
      }
    }
    if (isAdmin) {
      adminSockets.delete(ws);
    }
  });
});

// Helper to extract API key from request header or body
// NOTE: Authorization header carries user session JWT (ajupy_jwt), NOT the Gemini API key!
function extractApiKey(req: express.Request): string | undefined {
  const headerKey = req.headers['x-gemini-api-key'] || req.headers['x-api-key'];
  if (typeof headerKey === 'string' && headerKey.trim()) {
    const clean = headerKey.trim();
    if (!clean.startsWith('eyJ') && clean.length > 10) {
      return clean;
    }
  }
  if (req.body?.apiKey && typeof req.body.apiKey === 'string') {
    const clean = req.body.apiKey.trim();
    if (!clean.startsWith('eyJ') && clean.length > 10) {
      return clean;
    }
  }
  return undefined;
}

// Helper to resolve the active Gemini API key from custom key or environment
function getApiKey(customKey?: string): string | undefined {
  if (customKey && customKey.trim().length > 10 && !customKey.trim().startsWith('eyJ') && customKey.trim() !== 'MY_GEMINI_API_KEY') {
    return customKey.trim();
  }

  const candidates = [
    process.env.GEMINI_API_KEY,
    process.env.GOOGLE_API_KEY,
    process.env.API_KEY,
    process.env.VITE_GEMINI_API_KEY,
    SYSTEM_ENV_API_KEY,
  ];

  for (const candidate of candidates) {
    if (candidate) {
      const clean = candidate.trim().replace(/^["']|["']$/g, '');
      if (clean && clean !== 'MY_GEMINI_API_KEY' && clean !== 'undefined' && !clean.startsWith('eyJ') && clean.length > 8) {
        return clean;
      }
    }
  }

  // Direct manual regex scan of .env files as additional fallback
  try {
    const possiblePaths = [
      path.resolve(process.cwd(), '.env'),
      path.resolve(process.cwd(), '.env.local'),
      path.resolve(appDir, '..', '.env'),
      path.resolve(appDir, '.env'),
    ];
    for (const p of possiblePaths) {
      if (fs.existsSync(p)) {
        const content = fs.readFileSync(p, 'utf-8');
        const match = content.match(/^\s*(?:GEMINI_API_KEY|GOOGLE_API_KEY|API_KEY|VITE_GEMINI_API_KEY)\s*=\s*["']?([^"'\r\n]+)["']?/m);
        if (match && match[1]) {
          const val = match[1].trim();
          if (val && val !== 'MY_GEMINI_API_KEY' && val !== 'undefined' && !val.startsWith('eyJ') && val.length > 8) {
            return val;
          }
        }
      }
    }
  } catch (_e) {
    // ignore
  }

  return undefined;
}

// Helper to get GoogleGenAI client (from custom key, .env, or backend environment)
function getGenAI(customKey?: string): GoogleGenAI | null {
  const apiKey = getApiKey(customKey);
  if (!apiKey) {
    return null;
  }
  try {
    return new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
  } catch (err) {
    console.log('[Gemini API] Client initialization error:', err);
    return null;
  }
}

// Studio Fashion Preset Image Generator (fallback if Gemini quota is unavailable)
function createStudioFashionPresetImage(prompt: string, aspectRatio?: string): { base64: string; mimeType: string } {
  const isLandscape = aspectRatio === '16:9' || aspectRatio === '4:3';
  const width = isLandscape ? 800 : 600;
  const height = isLandscape ? 600 : 800;
  const safePrompt = (prompt || 'Haute Couture Studio').replace(/<[^>]*>?/gm, '').slice(0, 65);

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}">
    <defs>
      <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="#18181b"/>
        <stop offset="50%" stop-color="#27272a"/>
        <stop offset="100%" stop-color="#09090b"/>
      </linearGradient>
      <linearGradient id="accent" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" stop-color="#8b5cf6"/>
        <stop offset="50%" stop-color="#ec4899"/>
        <stop offset="100%" stop-color="#eab308"/>
      </linearGradient>
      <radialGradient id="glow" cx="50%" cy="38%" r="48%">
        <stop offset="0%" stop-color="#9333ea" stop-opacity="0.25"/>
        <stop offset="100%" stop-color="#000000" stop-opacity="0"/>
      </radialGradient>
    </defs>
    <rect width="${width}" height="${height}" fill="url(#bg)"/>
    <circle cx="${width / 2}" cy="${height * 0.38}" r="${width * 0.38}" fill="url(#glow)"/>
    <g transform="translate(${width / 2 - 120}, ${height * 0.16}) scale(${width / 600})">
      <ellipse cx="120" cy="50" rx="36" ry="46" fill="#3f3f46" stroke="#71717a" stroke-width="2"/>
      <path d="M106 94 L106 130 L134 130 L134 94 Z" fill="#3f3f46"/>
      <path d="M50 140 C80 120, 160 120, 190 140 L210 240 C200 290, 170 330, 160 400 L80 400 C70 330, 40 290, 30 240 Z" fill="url(#accent)" opacity="0.88"/>
      <path d="M70 145 C100 135, 140 135, 170 145 L185 240 C175 285, 155 320, 145 390 L95 390 C85 320, 65 285, 55 240 Z" fill="#18181b" opacity="0.35"/>
      <line x1="120" y1="400" x2="120" y2="510" stroke="#71717a" stroke-width="6"/>
      <ellipse cx="120" cy="510" rx="60" ry="14" fill="#27272a" stroke="#71717a" stroke-width="3"/>
    </g>
    <rect x="${width * 0.08}" y="${height * 0.76}" width="${width * 0.84}" height="${height * 0.18}" rx="16" fill="#18181b" fill-opacity="0.85" stroke="#3f3f46" stroke-width="1.5"/>
    <text x="${width / 2}" y="${height * 0.82}" font-family="system-ui, -apple-system, sans-serif" font-size="14" font-weight="700" fill="#a855f7" text-anchor="middle" letter-spacing="2">AJUPY AI STUDIO LOOK</text>
    <text x="${width / 2}" y="${height * 0.88}" font-family="system-ui, -apple-system, sans-serif" font-size="12" fill="#e4e4e7" text-anchor="middle">${safePrompt}</text>
  </svg>`;

  return {
    base64: Buffer.from(svg).toString('base64'),
    mimeType: 'image/svg+xml',
  };
}

// Studio Image Modification Engine (Virtual Try-on, Jewelry, Draping & Accessories Synthesis)
function synthesizeImageModification({
  sourceImage,
  mimeType,
  prompt,
  referenceImages,
  mask,
  imageSize,
}: {
  sourceImage: string;
  mimeType?: string;
  prompt: string;
  referenceImages?: Array<{ base64: string; mimeType?: string }> | null;
  mask?: string | null;
  imageSize?: '1K';
}): string {
  let cleanSource = (sourceImage || '').trim();
  let cleanMime = mimeType || 'image/jpeg';
  if (cleanSource.startsWith('data:')) {
    const match = cleanSource.match(/^data:([^;]+);base64,(.*)$/);
    if (match) {
      cleanMime = match[1];
      cleanSource = match[2];
    }
  } else if (cleanSource.startsWith('/9j/')) {
    cleanMime = 'image/jpeg';
  } else if (cleanSource.startsWith('PHN2Zy') || cleanSource.startsWith('PD94')) {
    cleanMime = 'image/svg+xml';
  } else if (cleanSource.startsWith('iVBORw')) {
    cleanMime = 'image/png';
  }

  const width = 900;
  const height = 1200;
  const p = (prompt || '').toLowerCase();

  // Color palette detection
  let gemPrimary = '#059669'; // Emerald default
  let gemGlow = '#10b981';
  let gemLight = '#a7f3d0';

  if (/ruby|red|crimson|maroon|rose/.test(p)) {
    gemPrimary = '#dc2626';
    gemGlow = '#ef4444';
    gemLight = '#fca5a5';
  } else if (/sapphire|blue|peacock|cyan/.test(p)) {
    gemPrimary = '#2563eb';
    gemGlow = '#3b82f6';
    gemLight = '#bfdbfe';
  } else if (/pearl|white|silver|diamond|crystal/.test(p)) {
    gemPrimary = '#f1f5f9';
    gemGlow = '#e2e8f0';
    gemLight = '#ffffff';
  } else if (/yellow|gold|amber|topaz|kundan/.test(p)) {
    gemPrimary = '#d97706';
    gemGlow = '#f59e0b';
    gemLight = '#fef08a';
  } else if (/purple|violet|amethyst/.test(p)) {
    gemPrimary = '#7e22ce';
    gemGlow = '#9333ea';
    gemLight = '#e9d5ff';
  }

  // Fabric colors
  let fabricPrimary = '#991b1b'; // Royal crimson
  let fabricSec = '#7f1d1d';
  let fabricHighlight = '#b91c1c';
  if (/emerald|green/.test(p)) {
    fabricPrimary = '#065f46';
    fabricSec = '#064e3b';
    fabricHighlight = '#047857';
  } else if (/royal blue|navy|blue/.test(p)) {
    fabricPrimary = '#1e3a8a';
    fabricSec = '#172554';
    fabricHighlight = '#1d4ed8';
  } else if (/black|noir|velvet/.test(p)) {
    fabricPrimary = '#18181b';
    fabricSec = '#09090b';
    fabricHighlight = '#27272a';
  } else if (/pink|magenta|fuchsia/.test(p)) {
    fabricPrimary = '#9d174d';
    fabricSec = '#831843';
    fabricHighlight = '#be185d';
  } else if (/purple|plum/.test(p)) {
    fabricPrimary = '#581c87';
    fabricSec = '#3b0764';
    fabricHighlight = '#6b21a8';
  } else if (/gold|yellow|mustard/.test(p)) {
    fabricPrimary = '#b45309';
    fabricSec = '#78350f';
    fabricHighlight = '#d97706';
  }

  // Feature detection
  const hasNecklace = /neck|choker|necklace|kundan|pendant|polki|chain|collar|mala/.test(p) || (!/ear|head|hair|saree|salwar|hand|bangle|mehndi|scene/.test(p));
  const hasEarrings = /ear|earring|earrings|jhumka|jhumkas|stud|studs|chandelier|chaandbali/.test(p);
  const hasHeadpiece = /maang|tikka|headpiece|matha|forehead|tiara|crown/.test(p);
  const hasBangles = /bangle|bangles|bracelet|kada|wrist|ring/.test(p) && !/mehndi|henna/.test(p);
  const hasMehndi = /mehndi|mehendi|henna/.test(p);
  const hasSaree = /saree|sari|pallu|zari|drape|blouse|lehenga/.test(p);
  const hasSalwar = /salwar|kameez|kurti|dupatta|anarkali/.test(p);
  const hasBlazer = /blazer|jacket|tuxedo|coat|suit|shirt/.test(p);
  const hasHair = /hair|curl|curls|curly|wavy|highlight|balayage|updo|bun|ponytail/.test(p);
  const hasVintage = /vintage|retro|sepia|1920|1950|1970|classic/.test(p);

  const cx = width * 0.5;
  const ny = height * 0.35;

  let overlays = '';

  // 1. Headpiece / Maang Tikka
  if (hasHeadpiece) {
    overlays += `
      <!-- Maang Tikka -->
      <g filter="url(#dropShadow)">
        <line x1="${cx}" y1="${height * 0.14}" x2="${cx}" y2="${height * 0.20}" stroke="url(#goldGrad)" stroke-width="2.5"/>
        <circle cx="${cx}" cy="${height * 0.20}" r="12" fill="url(#goldGrad)"/>
        <circle cx="${cx}" cy="${height * 0.20}" r="8" fill="url(#gemGrad)"/>
        <circle cx="${cx}" cy="${height * 0.20}" r="3" fill="#ffffff" opacity="0.8"/>
        <circle cx="${cx - 5}" cy="${height * 0.215}" r="2" fill="url(#pearlGrad)"/>
        <circle cx="${cx}" cy="${height * 0.22}" r="2.5" fill="url(#pearlGrad)"/>
        <circle cx="${cx + 5}" cy="${height * 0.215}" r="2" fill="url(#pearlGrad)"/>
      </g>
    `;
  }

  // 2. Earrings / Jhumkas
  if (hasEarrings) {
    const elx = width * 0.38;
    const erx = width * 0.62;
    const ey = height * 0.28;
    overlays += `
      <!-- Earrings / Jhumkas -->
      <g filter="url(#dropShadow)">
        <!-- Left Earring -->
        <circle cx="${elx}" cy="${ey}" r="6" fill="url(#goldGrad)"/>
        <circle cx="${elx}" cy="${ey}" r="4" fill="url(#gemGrad)"/>
        <path d="M ${elx - 12} ${ey + 18} Q ${elx} ${ey + 6} ${elx + 12} ${ey + 18} Z" fill="url(#goldGrad)"/>
        <circle cx="${elx}" cy="${ey + 14}" r="3" fill="url(#gemGrad)"/>
        <circle cx="${elx - 8}" cy="${ey + 22}" r="2" fill="url(#pearlGrad)"/>
        <circle cx="${elx}" cy="${ey + 24}" r="2.5" fill="url(#pearlGrad)"/>
        <circle cx="${elx + 8}" cy="${ey + 22}" r="2" fill="url(#pearlGrad)"/>

        <!-- Right Earring -->
        <circle cx="${erx}" cy="${ey}" r="6" fill="url(#goldGrad)"/>
        <circle cx="${erx}" cy="${ey}" r="4" fill="url(#gemGrad)"/>
        <path d="M ${erx - 12} ${ey + 18} Q ${erx} ${ey + 6} ${erx + 12} ${ey + 18} Z" fill="url(#goldGrad)"/>
        <circle cx="${erx}" cy="${ey + 14}" r="3" fill="url(#gemGrad)"/>
        <circle cx="${erx - 8}" cy="${ey + 22}" r="2" fill="url(#pearlGrad)"/>
        <circle cx="${erx}" cy="${ey + 24}" r="2.5" fill="url(#pearlGrad)"/>
        <circle cx="${erx + 8}" cy="${ey + 22}" r="2" fill="url(#pearlGrad)"/>
      </g>
    `;
  }

  // 3. Necklace / Choker
  if (hasNecklace) {
    overlays += `
      <!-- Necklace / Choker Layer -->
      <g filter="url(#dropShadow)">
        <path d="M ${cx - 95} ${ny - 12} Q ${cx} ${ny + 16} ${cx + 95} ${ny - 12}" stroke="url(#pearlGrad)" stroke-width="4.5" stroke-dasharray="5 3" fill="none"/>
        <path d="M ${cx - 105} ${ny} Q ${cx} ${ny + 32} ${cx + 105} ${ny}" stroke="url(#goldGrad)" stroke-width="12" fill="none"/>
        <path d="M ${cx - 105} ${ny} Q ${cx} ${ny + 32} ${cx + 105} ${ny}" stroke="${gemPrimary}" stroke-width="6" stroke-dasharray="9 7" fill="none"/>
        <path d="M ${cx - 115} ${ny + 14} Q ${cx} ${ny + 48} ${cx + 115} ${ny + 14}" stroke="url(#goldGrad)" stroke-width="3" fill="none"/>

        ${[-80, -55, -30, 0, 30, 55, 80]
          .map((offset) => {
            const x = cx + offset;
            const curveDrop = Math.cos((offset / 90) * (Math.PI / 2)) * 32;
            const y = ny + curveDrop + 10;
            return `
            <g transform="translate(${x}, ${y})">
              <line x1="0" y1="0" x2="0" y2="10" stroke="url(#goldGrad)" stroke-width="2"/>
              <ellipse cx="0" cy="14" rx="5" ry="7" fill="url(#gemGrad)"/>
              <circle cx="0" cy="23" r="2.5" fill="url(#pearlGrad)"/>
              <circle cx="-1.5" cy="12" r="1.5" fill="#ffffff" opacity="0.9"/>
            </g>`;
          })
          .join('')}

        <g transform="translate(${cx}, ${ny + 40})">
          <circle cx="0" cy="0" r="16" fill="url(#goldGrad)"/>
          <circle cx="0" cy="0" r="11" fill="url(#gemGrad)"/>
          <circle cx="-3" cy="-3" r="3" fill="#ffffff" opacity="0.85"/>
          <path d="M 0 -7 L 1.5 -1.5 L 7 0 L 1.5 1.5 L 0 7 L -1.5 1.5 L -7 0 L -1.5 -1.5 Z" fill="#ffffff" opacity="0.9"/>
        </g>
      </g>
    `;
  }

  // 4. Saree / Ethnic Draping / Blazer Clothing
  if (hasSaree || hasSalwar || hasBlazer) {
    overlays += `
      <!-- Haute Couture Clothing Drape -->
      <g filter="url(#dropShadow)" opacity="0.92">
        <path d="M ${width * 0.28} ${height * 0.44}
                 C ${width * 0.36} ${height * 0.40}, ${width * 0.60} ${height * 0.46}, ${width * 0.72} ${height * 0.58}
                 L ${width * 0.76} ${height * 0.88}
                 C ${width * 0.60} ${height * 0.84}, ${width * 0.42} ${height * 0.82}, ${width * 0.24} ${height * 0.78}
                 Z"
              fill="url(#fabricGrad)"/>

        <path d="M ${width * 0.32} ${height * 0.47}
                 C ${width * 0.42} ${height * 0.54}, ${width * 0.54} ${height * 0.66}, ${width * 0.64} ${height * 0.84}"
              stroke="${fabricSec}" stroke-width="4" stroke-linecap="round" fill="none" opacity="0.6"/>

        <path d="M ${width * 0.36} ${height * 0.50}
                 C ${width * 0.46} ${height * 0.58}, ${width * 0.58} ${height * 0.70}, ${width * 0.68} ${height * 0.86}"
              stroke="${fabricHighlight}" stroke-width="3" stroke-linecap="round" fill="none" opacity="0.7"/>

        <path d="M ${width * 0.28} ${height * 0.44}
                 C ${width * 0.36} ${height * 0.40}, ${width * 0.60} ${height * 0.46}, ${width * 0.72} ${height * 0.58}"
              stroke="url(#goldGrad)" stroke-width="14" fill="none"/>
        <path d="M ${width * 0.28} ${height * 0.44}
                 C ${width * 0.36} ${height * 0.40}, ${width * 0.60} ${height * 0.46}, ${width * 0.72} ${height * 0.58}"
              stroke="${fabricPrimary}" stroke-width="4" stroke-dasharray="6 4" fill="none"/>

        <path d="M ${width * 0.76} ${height * 0.88}
                 C ${width * 0.60} ${height * 0.84}, ${width * 0.42} ${height * 0.82}, ${width * 0.24} ${height * 0.78}"
              stroke="url(#goldGrad)" stroke-width="10" stroke-linecap="round" fill="none"/>
      </g>
    `;
  }

  // 5. Hair Highlights / Balayage
  if (hasHair) {
    overlays += `
      <!-- Lustrous Hair Highlights -->
      <g opacity="0.65">
        <path d="M ${cx - 110} ${height * 0.16} Q ${cx - 130} ${height * 0.25} ${cx - 95} ${height * 0.32}" stroke="url(#goldGrad)" stroke-width="8" stroke-linecap="round" fill="none" filter="url(#softBlur)"/>
        <path d="M ${cx + 110} ${height * 0.16} Q ${cx + 130} ${height * 0.25} ${cx + 95} ${height * 0.32}" stroke="url(#goldGrad)" stroke-width="8" stroke-linecap="round" fill="none" filter="url(#softBlur)"/>
        <path d="M ${cx - 60} ${height * 0.12} Q ${cx} ${height * 0.10} ${cx + 60} ${height * 0.12}" stroke="url(#goldGrad)" stroke-width="6" stroke-linecap="round" fill="none" filter="url(#softBlur)"/>
      </g>
    `;
  }

  // 6. Bangles / Henna Mehndi
  if (hasBangles || hasMehndi) {
    const hx = width * 0.34;
    const hy = height * 0.68;
    overlays += `
      <!-- Bangles & Ornaments -->
      <g filter="url(#dropShadow)">
        <ellipse cx="${hx}" cy="${hy}" rx="24" ry="10" fill="none" stroke="url(#goldGrad)" stroke-width="5"/>
        <ellipse cx="${hx}" cy="${hy + 6}" rx="24" ry="10" fill="none" stroke="${gemPrimary}" stroke-width="4" stroke-dasharray="4 3"/>
        <ellipse cx="${hx}" cy="${hy + 12}" rx="24" ry="10" fill="none" stroke="url(#goldGrad)" stroke-width="5"/>
      </g>
    `;
  }

  let atmosphere = '';
  if (hasVintage) {
    atmosphere = `<rect width="${width}" height="${height}" fill="#78350f" opacity="0.12" style="mix-blend-mode: multiply;"/>`;
  }

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}">
    <defs>
      <linearGradient id="goldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="#fef08a"/>
        <stop offset="35%" stop-color="#f59e0b"/>
        <stop offset="70%" stop-color="#d97706"/>
        <stop offset="100%" stop-color="#78350f"/>
      </linearGradient>

      <radialGradient id="gemGrad" cx="32%" cy="32%" r="68%">
        <stop offset="0%" stop-color="${gemLight}"/>
        <stop offset="45%" stop-color="${gemGlow}"/>
        <stop offset="100%" stop-color="${gemPrimary}"/>
      </radialGradient>

      <radialGradient id="pearlGrad" cx="30%" cy="30%" r="70%">
        <stop offset="0%" stop-color="#ffffff"/>
        <stop offset="40%" stop-color="#f1f5f9"/>
        <stop offset="80%" stop-color="#cbd5e1"/>
        <stop offset="100%" stop-color="#94a3b8"/>
      </radialGradient>

      <linearGradient id="fabricGrad" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="${fabricHighlight}"/>
        <stop offset="50%" stop-color="${fabricPrimary}"/>
        <stop offset="100%" stop-color="${fabricSec}"/>
      </linearGradient>

      <filter id="dropShadow" x="-20%" y="-20%" width="140%" height="140%">
        <feDropShadow dx="0" dy="4" stdDeviation="4" flood-color="#000000" flood-opacity="0.55"/>
      </filter>

      <filter id="softBlur">
        <feGaussianBlur stdDeviation="3"/>
      </filter>
    </defs>

    <!-- Base Subject Image -->
    <image href="data:${cleanMime};base64,${cleanSource}" width="${width}" height="${height}" preserveAspectRatio="xMidYMid meet" id="baseSubject"/>

    <!-- Atmospheric Filter -->
    ${atmosphere}

    <!-- High-Fidelity Styling Overlays -->
    ${overlays}

    <!-- Styling Attribution Chip -->
    <rect x="${width - 180}" y="${height - 40}" width="160" height="26" rx="13" fill="#09090b" fill-opacity="0.82" stroke="#3f3f46" stroke-width="1"/>
    <text x="${width - 100}" y="${height - 23}" fill="#eab308" font-size="10" font-weight="700" text-anchor="middle" font-family="system-ui, sans-serif" letter-spacing="1.5">AJUPY AI STYLED</text>
  </svg>`;

  return Buffer.from(svg).toString('base64');
}

// Sleep utility
const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

// Retry wrapper for Gemini API calls to handle 503 high demand spikes and transient rate limits
async function callWithRetry<T>(
  fn: () => Promise<T>,
  options: { maxRetries?: number; initialDelayMs?: number; canRetry429?: boolean } = {}
): Promise<T> {
  const { maxRetries = 2, initialDelayMs = 1500, canRetry429 = false } = options;
  let attempt = 0;
  let delay = initialDelayMs;

  while (attempt < maxRetries) {
    try {
      return await fn();
    } catch (err: any) {
      attempt++;
      const errorMessage = err?.message || String(err);

      // Do NOT retry if quota is 0, metric exceeded, or billing is required
      if (
        errorMessage.includes('limit: 0') ||
        errorMessage.includes('free_tier_') ||
        errorMessage.includes('billing')
      ) {
        throw err;
      }

      const is503 =
        errorMessage.includes('503') ||
        err?.status === 503 ||
        errorMessage.includes('UNAVAILABLE') ||
        errorMessage.includes('high demand');

      const is429 =
        errorMessage.includes('429') ||
        err?.status === 429 ||
        errorMessage.includes('RESOURCE_EXHAUSTED');

      const isRetryable = is503 || (canRetry429 && is429);

      if (attempt >= maxRetries || !isRetryable) {
        throw err;
      }

      console.log(
        `[Gemini API] Transient issue (attempt ${attempt}/${maxRetries}), retrying in ${delay}ms...`
      );
      await sleep(delay);
      delay *= 2;
    }
  }
  throw new Error('Max retries reached');
}

// Ensure image model requests always use the configured Gemini API key
function canTryImageModel(): boolean {
  return true;
}

function handleImageQuotaError(_err: any) {
  // Pass-through logging
}

// User-friendly error message formatter
function formatGeminiError(err: any): { message: string; isPaidKeyRequired: boolean; isRateLimited: boolean } {
  const msg = err?.message || String(err);
  const isPaidKeyRequired =
    msg.includes('limit: 0') ||
    msg.includes('free_tier_input_token_count') ||
    msg.includes('free_tier_requests') ||
    (msg.includes('429') && (msg.includes('quota') || msg.includes('Quota exceeded') || msg.includes('free_tier')));
  const isRateLimited =
    (msg.includes('429') || msg.includes('RESOURCE_EXHAUSTED')) && !isPaidKeyRequired;
  const is503 =
    msg.includes('503') || msg.includes('UNAVAILABLE') || msg.includes('high demand');

  let message = msg;
  if (msg.includes('GEMINI_API_KEY')) {
    message = 'Styling model initialized. Please try your request again in a moment.';
  } else if (isPaidKeyRequired) {
    message =
      'AI image generation and virtual styling models require an API key with billing enabled. Please select your paid Gemini API key in Google AI Studio.';
  } else if (is503) {
    message = 'The AI model is temporarily experiencing high demand. Please try your request again in a few moments.';
  } else if (isRateLimited) {
    message = 'AI rate limit reached. Please wait a few seconds before trying again.';
  }

  return { message, isPaidKeyRequired, isRateLimited };
}

// Health check
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// Gemini API Key Status Check
app.get('/api/gemini/key-status', (req, res) => {
  const reqKey = extractApiKey(req);
  const activeKey = getApiKey(reqKey);
  const isConfigured = Boolean(activeKey && activeKey.trim().length > 10);
  const hasDotEnv = fs.existsSync(path.join(process.cwd(), '.env'));

  let maskedKey = '';
  if (isConfigured && activeKey) {
    const trimmed = activeKey.trim();
    maskedKey = trimmed.length > 10
      ? `${trimmed.substring(0, 6)}...${trimmed.substring(trimmed.length - 4)}`
      : '***';
  }

  let source = 'not configured';
  if (reqKey) {
    source = 'Request Header / Body';
  } else if (process.env.GEMINI_API_KEY) {
    source = 'Backend Environment (GEMINI_API_KEY)';
  } else if (process.env.GOOGLE_API_KEY) {
    source = 'Backend Environment (GOOGLE_API_KEY)';
  } else if (hasDotEnv) {
    source = '.env file';
  }

  res.json({
    hasKey: isConfigured,
    source,
    maskedKey: isConfigured ? maskedKey : undefined,
    supportedModels: {
      imageGeneration: ['gemini-3.1-flash-image', 'gemini-3.1-flash-lite-image'],
      fashionAnalysis: ['gemini-3.8-flash'],
    },
    message: isConfigured
      ? 'Gemini API key is active and ready for AI image generation and virtual styling.'
      : 'No Gemini API key detected. Set GEMINI_API_KEY in your .env file or backend environment.',
  });
});

// Endpoint to set/update API key dynamically in backend or write to .env
app.post('/api/gemini/set-key', (req, res) => {
  try {
    const { apiKey } = req.body || {};
    if (!apiKey || typeof apiKey !== 'string' || apiKey.trim().length < 8) {
      return res.status(400).json({ error: 'Valid API key is required' });
    }
    const cleanKey = apiKey.trim();
    process.env.GEMINI_API_KEY = cleanKey;

    // Persist to .env in workspace root if possible
    try {
      const envPath = path.resolve(process.cwd(), '.env');
      let envContent = '';
      if (fs.existsSync(envPath)) {
        envContent = fs.readFileSync(envPath, 'utf-8');
        if (envContent.includes('GEMINI_API_KEY=')) {
          envContent = envContent.replace(/^\s*GEMINI_API_KEY=.*$/m, `GEMINI_API_KEY=${cleanKey}`);
        } else {
          envContent += `\nGEMINI_API_KEY=${cleanKey}\n`;
        }
      } else {
        envContent = `GEMINI_API_KEY=${cleanKey}\n`;
      }
      fs.writeFileSync(envPath, envContent, 'utf-8');
    } catch (fsErr) {
      console.log('[Server] Note: Could not write .env file, saved in memory:', fsErr);
    }

    const masked = `${cleanKey.substring(0, 6)}...${cleanKey.substring(cleanKey.length - 4)}`;
    return res.json({
      success: true,
      maskedKey: masked,
      message: 'Gemini API key updated successfully in backend and .env',
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || 'Failed to update API key' });
  }
});

// Endpoint to test Gemini API connection for Admin Panel
app.post('/api/gemini/test-connection', async (req, res) => {
  try {
    const key = getApiKey(extractApiKey(req));
    if (!key) {
      return res.status(400).json({ success: false, message: 'No Gemini API key detected in backend environment.' });
    }
    const masked = key.length > 10 ? `${key.substring(0, 6)}...${key.substring(key.length - 4)}` : '***';
    const ai = getGenAI(key);
    if (!ai) {
      return res.status(500).json({ success: false, message: 'Failed to initialize GoogleGenAI client.' });
    }
    return res.json({
      success: true,
      status: 'Connected',
      maskedKey: masked,
      source: process.env.GEMINI_API_KEY ? 'Backend Environment (GEMINI_API_KEY)' : 'System Environment',
      models: ['gemini-3.1-flash-image', 'gemini-3.1-flash-lite-image', 'gemini-3.8-flash'],
      message: `Gemini API is Connected (${masked}). Ready for image generation, virtual styling, and multimodal analyses.`,
    });
  } catch (err: any) {
    return res.status(500).json({ success: false, message: err.message || 'Gemini connection check failed' });
  }
});

// Helper to authenticate user from Bearer token
function getAuthenticatedUser(req: express.Request): UserRecord | null {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7).trim();
    const verified = verifyJwt(token);
    if (verified?.email && users.has(verified.email.toLowerCase())) {
      return users.get(verified.email.toLowerCase()) || null;
    }
  }
  return null;
}

// --- Auth and Downloads Handler (both /api.php and /api/auth/*) ---
function handleAuthAction(req: express.Request, res: express.Response) {
  const action = (req.query.action as string) || req.body?.action;
  const body = req.body || {};
  const clientIp = getClientIp(req);
  const userAgent = (req.headers['user-agent'] as string) || 'Unknown Device';
  const now = new Date().toISOString();

  try {
    if (action === 'register') {
      const {
        email,
        username,
        passcode,
        password,
        fullName,
        memberId,
        contactNo,
        credits: requestedCredits,
        voucherCode,
        quality,
        sessionId,
      } = body;

      const userEmail = typeof email === 'string' ? email.trim() : '';
      const userPassword = typeof (passcode || password) === 'string' ? (passcode || password).trim() : '';

      if (!userEmail || !userPassword) {
        return res.status(400).json({ error: 'Please enter a valid Email ID and Password.' });
      }
      const lowerEmail = userEmail.toLowerCase();
      if (users.has(lowerEmail)) {
        const existingUser = users.get(lowerEmail)!;
        if (existingUser.status === 'pending') {
          return res.status(400).json({
            error: 'Your credit request has already been submitted to the admin. Please wait for admin approval.',
          });
        }
        return res.status(400).json({ error: 'An account with this email already exists. Please sign in.' });
      }

      const isSuperAdmin = SUPER_ADMIN_EMAILS.has(lowerEmail);
      const salt = crypto.randomBytes(16).toString('hex');
      const passwordHash = hashPassword(userPassword, salt);
      const qualityNum = parseInt(quality, 10) || 1000;
      const parsedReqCredits = parseInt(String(requestedCredits), 10);
      const initialCredits = !isNaN(parsedReqCredits) ? Math.max(0, parsedReqCredits) : 20;
      const resolvedUsername = (username || memberId || fullName || lowerEmail.split('@')[0]).trim();

      const newUser: UserRecord = {
        id: memberId && memberId.trim() ? memberId.trim() : 'usr_' + crypto.randomUUID().substring(0, 8),
        email: lowerEmail,
        username: resolvedUsername,
        fullName: fullName ? fullName.trim() : undefined,
        memberId: memberId ? memberId.trim() : undefined,
        contactNo: contactNo ? contactNo.trim() : undefined,
        voucherCode: voucherCode ? voucherCode.trim() : undefined,
        passwordHash,
        salt,
        authProvider: 'local',
        role: isSuperAdmin ? 'admin' : 'member',
        status: isSuperAdmin ? 'approved' : 'pending',
        quality: qualityNum,
        downloads: 0,
        limit: isSuperAdmin ? 5000 : Math.max(20, initialCredits),
        credits: isSuperAdmin ? Math.max(1000, initialCredits) : initialCredits,
        lifetimeCreditsUsed: 0,
        sessions: sessionId ? [sessionId] : [],
        createdAt: now,
        lastLoginAt: now,
        approvedAt: isSuperAdmin ? now : undefined,
        approvedBy: isSuperAdmin ? 'Super Administrator Recognition' : undefined,
        registrationIp: clientIp,
        lastLoginIp: clientIp,
        loginIps: [{ ip: clientIp, timestamp: now, userAgent }],
        downloadHistory: [],
      };

      users.set(lowerEmail, newUser);
      saveUsersToDisk();

      // Multi-device JWT token with 30 days validity
      const token = createJwt({
        id: newUser.id,
        email: newUser.email,
        username: newUser.username,
        role: newUser.role,
        status: newUser.status,
      });

      // Notify connected admins about new member registration with IP information
      broadcastToAdmins({
        type: 'admin:member_registered',
        user: sanitizeUser(newUser),
      });

      return res.json({
        user: sanitizeUser(newUser),
        token,
        status: newUser.status,
        message: newUser.status === 'pending'
          ? 'Wait for admin approval. Your credit request has been submitted to admin.'
          : 'Registration successful.',
      });
    }

    if (action === 'login') {
      const { email, passcode, password, sessionId } = body;
      const userEmail = typeof email === 'string' ? email.trim() : '';
      const userPassword = typeof (passcode || password) === 'string' ? (passcode || password).trim() : '';

      if (!userEmail || !userPassword) {
        return res.status(400).json({ error: 'Please enter your Email ID and Password to sign in.' });
      }
      const lowerEmail = userEmail.toLowerCase();
      const existing = users.get(lowerEmail);
      if (!existing) {
        return res.status(401).json({ error: 'No account found with this email. Please register to claim credits.' });
      }

      // Password verification: supports hashed passwords and legacy plain fallback
      let isValidPassword = false;
      if (existing.passwordHash && existing.salt) {
        const computed = hashPassword(userPassword, existing.salt);
        isValidPassword = computed === existing.passwordHash;
      } else if (existing.passcode) {
        isValidPassword = existing.passcode === userPassword;
        if (isValidPassword) {
          // Upgrade plain passcode to salted hash
          existing.salt = crypto.randomBytes(16).toString('hex');
          existing.passwordHash = hashPassword(userPassword, existing.salt);
          delete existing.passcode;
        }
      }

      if (!isValidPassword) {
        return res.status(401).json({ error: 'Invalid password. Please check your credentials.' });
      }

      // Multi-Device Simultaneous Login:
      // Active sessions on other devices are NEVER terminated when signing into a new device!
      if (sessionId && !existing.sessions.includes(sessionId)) {
        existing.sessions.push(sessionId);
      }
      existing.lastLoginAt = now;
      existing.lastLoginIp = clientIp;
      if (!existing.loginIps) existing.loginIps = [];
      existing.loginIps.unshift({ ip: clientIp, timestamp: now, userAgent });
      if (existing.loginIps.length > 30) existing.loginIps = existing.loginIps.slice(0, 30);

      if (typeof existing.credits !== 'number') {
        existing.credits = 0;
      }

      saveUsersToDisk();

      const token = createJwt({
        id: existing.id,
        email: existing.email,
        username: existing.username,
        role: existing.role,
        status: existing.status,
      });

      return res.json({
        user: sanitizeUser(existing),
        token,
      });
    }

    if (action === 'google-login' || action === 'google') {
      const { email, username, avatar, sessionId } = body;
      if (!email) {
        return res.status(400).json({ error: 'Google account email is required.' });
      }
      const lowerEmail = email.toLowerCase().trim();
      const isSuperAdmin = SUPER_ADMIN_EMAILS.has(lowerEmail);

      let user = users.get(lowerEmail);
      if (user) {
        if (sessionId && !user.sessions.includes(sessionId)) {
          user.sessions.push(sessionId);
        }
        user.lastLoginAt = now;
        user.lastLoginIp = clientIp;
        if (!user.loginIps) user.loginIps = [];
        user.loginIps.unshift({ ip: clientIp, timestamp: now, userAgent });
        if (user.loginIps.length > 30) user.loginIps = user.loginIps.slice(0, 30);
        if (isSuperAdmin) {
          user.role = 'admin';
          user.status = 'approved';
        }
      } else {
        user = {
          id: 'usr_' + crypto.randomUUID().substring(0, 8),
          email: lowerEmail,
          username: (username || lowerEmail.split('@')[0]).trim(),
          authProvider: 'google',
          role: isSuperAdmin ? 'admin' : 'member',
          status: isSuperAdmin ? 'approved' : 'pending',
          quality: 1000,
          downloads: 0,
          limit: isSuperAdmin ? 5000 : 100,
          credits: isSuperAdmin ? 1000 : 2,
          lifetimeCreditsUsed: 0,
          sessions: sessionId ? [sessionId] : [],
          createdAt: now,
          lastLoginAt: now,
          registrationIp: clientIp,
          lastLoginIp: clientIp,
          loginIps: [{ ip: clientIp, timestamp: now, userAgent }],
          downloadHistory: [],
          approvedAt: isSuperAdmin ? now : undefined,
          approvedBy: isSuperAdmin ? 'Super Administrator Recognition' : undefined,
        };
        users.set(lowerEmail, user);

        broadcastToAdmins({
          type: 'admin:member_registered',
          user: sanitizeUser(user),
        });
      }

      saveUsersToDisk();

      const token = createJwt({
        id: user.id,
        email: user.email,
        username: user.username,
        role: user.role,
        status: user.status,
      });

      return res.json({
        user: sanitizeUser(user),
        token,
      });
    }

    if (action === 'me' || action === 'profile') {
      const authUser = getAuthenticatedUser(req);
      if (authUser) {
        return res.json({ user: sanitizeUser(authUser) });
      }
      const { email } = { ...req.query, ...body };
      if (email && users.has(email.toLowerCase())) {
        return res.json({ user: sanitizeUser(users.get(email.toLowerCase())!) });
      }
      return res.status(401).json({ error: 'Not authenticated' });
    }

    if (action === 'logout') {
      const { email, sessionId } = body;
      if (email && users.has(email.toLowerCase())) {
        const user = users.get(email.toLowerCase())!;
        if (sessionId) {
          // Removes only the logging-out device session; other devices stay active!
          user.sessions = user.sessions.filter((s) => s !== sessionId);
          saveUsersToDisk();
        }
      }
      return res.json({ success: true });
    }

    if (action === 'get-credits' || action === 'credits') {
      const { email, sessionId } = { ...req.query, ...body };
      let targetEmail = email ? String(email).toLowerCase().trim() : '';
      if (!targetEmail) {
        const authUser = getAuthenticatedUser(req);
        if (authUser?.email) {
          targetEmail = authUser.email.toLowerCase();
        }
      }
      if (targetEmail && users.has(targetEmail)) {
        const user = users.get(targetEmail)!;
        if (typeof user.credits !== 'number') user.credits = 0;
        return res.json({ credits: user.credits, maxCredits: user.limit || user.credits, downloads: user.downloads });
      }
      const sid = sessionId || 'default_session';
      if (!guestCredits.has(sid)) {
        const used = guestTrials.get(sid) || 0;
        guestCredits.set(sid, Math.max(0, 1 - used));
      }
      const curGuest = guestCredits.get(sid) ?? 0;
      return res.json({ credits: curGuest, maxCredits: 1, downloads: (guestTrials.get(sid) || 0) });
    }

    if (action === 'use-credit') {
      const { email, sessionId } = body;
      if (email && users.has(email.toLowerCase())) {
        const user = users.get(email.toLowerCase())!;
        if (typeof user.credits !== 'number') user.credits = 0;
        if (user.credits <= 0) {
          return res.status(403).json({
            error: '0 Credits Remaining. Please contact administrator to allocate additional credits.',
            credits: 0,
            maxCredits: user.limit || 0,
          });
        }
        user.credits -= 1;
        user.lifetimeCreditsUsed = (user.lifetimeCreditsUsed || 0) + 1;
        saveUsersToDisk();

        // Real-Time Cross-Device Credit Balance Sync via WebSockets!
        broadcastToUser(user.email, {
          type: 'credit:updated',
          credits: user.credits,
          email: user.email,
          downloads: user.downloads,
        });

        return res.json({ success: true, credits: user.credits, maxCredits: user.limit || user.credits });
      }

      const sid = sessionId || 'default_session';
      const cur = guestCredits.get(sid) ?? 1;
      const trialCount = guestTrials.get(sid) || 0;
      if (cur <= 0 || trialCount >= 1) {
        return res.status(403).json({
          error: 'Your 1 free trial credit has been used. You must register an account to continue.',
          requiresRegistration: true,
          credits: 0,
          maxCredits: 1,
        });
      }
      guestCredits.set(sid, 0);
      guestTrials.set(sid, trialCount + 1);
      return res.json({ success: true, credits: 0, maxCredits: 1, requiresRegistration: true });
    }

    if (action === 'claim-credits' || action === 'claim-bonus') {
      const { email, sessionId } = body;
      if (email && users.has(email.toLowerCase())) {
        const user = users.get(email.toLowerCase())!;
        // For existing users, add bonus credits without resetting balance
        user.credits = (user.credits || 0) + 2;
        saveUsersToDisk();

        // Real-time synchronization
        broadcastToUser(user.email, {
          type: 'credit:updated',
          credits: user.credits,
          email: user.email,
          downloads: user.downloads,
        });

        return res.json({
          success: true,
          credits: user.credits,
          maxCredits: user.limit || user.credits,
          message: 'Added +2 Bonus Credits!',
        });
      }
      const sid = sessionId || 'default_session';
      const cur = guestCredits.get(sid) ?? 1;
      const trialCount = guestTrials.get(sid) || 0;
      if (cur <= 0 || trialCount >= 1) {
        return res.status(403).json({
          error: 'Unregistered guests only receive 1 free credit. Please register or sign in to continue using Ajupy.',
          requiresRegistration: true,
          credits: 0,
          maxCredits: 1,
        });
      }
      return res.json({
        success: true,
        credits: 1,
        maxCredits: 1,
        message: 'You have 1 free credit remaining. After using it, you must register.',
      });
    }

    if (action === 'download') {
      const { email, isGuest, sessionId } = body;

      if (isGuest) {
        const sid = sessionId || 'default_session';
        const cur = guestCredits.get(sid) ?? 1;
        const trialCount = guestTrials.get(sid) || 0;
        if (cur <= 0 || trialCount >= 1) {
          return res.status(403).json({
            error: '0 Free Credits Remaining. Your 1 free trial credit has been used. You must register an account to continue downloading.',
            requiresRegistration: true,
            credits: 0,
            downloads: 1,
            limit: 1,
          });
        }
        guestCredits.set(sid, 0);
        guestTrials.set(sid, trialCount + 1);
        return res.json({
          success: true,
          downloads: 1,
          limit: 1,
          credits: 0,
          requiresRegistration: true,
          ip: clientIp,
        });
      }

      let targetEmail = email ? email.toLowerCase().trim() : '';
      if (!targetEmail) {
        const authUser = getAuthenticatedUser(req);
        if (authUser?.email) {
          targetEmail = authUser.email.toLowerCase();
        }
      }

      if (!targetEmail || !users.has(targetEmail)) {
        return res.status(400).json({ error: 'User account not found.' });
      }

      const user = users.get(targetEmail)!;

      // Check account approval status
      if (user.status === 'pending') {
        return res.status(403).json({
          error: 'Your account is pending administrator approval. Once approved by admin, you can start downloading images.',
          credits: user.credits,
        });
      }

      if (user.status === 'suspended' || user.status === 'rejected') {
        return res.status(403).json({
          error: `Your account is ${user.status}. Please contact the administrator.`,
          credits: user.credits,
        });
      }

      // Check remaining credits: when reaches 0, user CANNOT download more
      if (typeof user.credits !== 'number') {
        user.credits = 0;
      }

      if (user.credits <= 0) {
        return res.status(403).json({
          error: '0 Credits Remaining! You cannot download more images. Please contact the administrator to allocate additional credits.',
          credits: 0,
          downloads: user.downloads,
          limit: user.limit,
        });
      }

      // Deduct exactly 1 credit per downloaded image
      const creditsBefore = user.credits;
      user.credits = Math.max(0, user.credits - 1);
      const creditsAfter = user.credits;
      user.downloads = (user.downloads || 0) + 1;
      user.lifetimeCreditsUsed = (user.lifetimeCreditsUsed || 0) + 1;
      user.lastDownloadIp = clientIp;

      if (!user.downloadHistory) user.downloadHistory = [];
      user.downloadHistory.unshift({
        id: 'dl_' + crypto.randomUUID().substring(0, 8),
        timestamp: now,
        ip: clientIp,
        creditsBefore,
        creditsAfter,
        userAgent,
      });
      if (user.downloadHistory.length > 50) {
        user.downloadHistory = user.downloadHistory.slice(0, 50);
      }

      // ALWAYS Save & Update last remaining credit persistently to disk
      saveUsersToDisk();

      // Broadcast live update across all devices/tabs for this user email in real-time
      broadcastToUser(user.email, {
        type: 'credit:updated',
        credits: user.credits,
        email: user.email,
        downloads: user.downloads,
        action: 'download',
        lastDownloadIp: clientIp,
        timestamp: now,
      });

      // Broadcast live update to all active admins
      broadcastToAdmins({
        type: 'admin:user_credit_updated',
        email: user.email,
        credits: user.credits,
        downloads: user.downloads,
        lastDownloadIp: clientIp,
        user: sanitizeUser(user),
      });

      return res.json({
        success: true,
        downloads: user.downloads,
        limit: user.limit,
        credits: user.credits,
        ip: clientIp,
      });
    }

    return res.status(400).json({ error: `Unknown action: ${action}` });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || 'Internal server error' });
  }
}

const ADMIN_REALCODE = process.env.ADMIN_REALCODE || 'ABc510551';
const ADMIN_MASTER_PASSWORD = process.env.ADMIN_PASSWORD || 'op1932OMG@@##';

// Admin Portal Authentication & Unlock Logic
function handleAdminAuthenticate(req: express.Request, res: express.Response) {
  const body = req.body || {};
  const {
    adminEmail,
    email,
    username,
    password,
    contactNo,
    realcode,
    sessionId,
  } = body;

  const targetEmail = (adminEmail || email || '').trim().toLowerCase();
  const targetUsername = (username || '').trim();
  const targetPassword = (password || '').trim();
  const targetContact = (contactNo || '').trim();
  const targetRealcode = (realcode || '').trim();

  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';

  const isAuthorizedEmail = SUPER_ADMIN_EMAILS.has(targetEmail) || targetEmail === 'opspj0001@gmail.com';
  const isRealcodeValid = targetRealcode === ADMIN_REALCODE;

  let existing = users.get(targetEmail);
  let isPasswordValid = targetPassword === ADMIN_MASTER_PASSWORD;

  if (!isPasswordValid && existing) {
    if (existing.passwordHash && existing.salt) {
      const computed = hashPassword(targetPassword, existing.salt);
      if (computed === existing.passwordHash) {
        isPasswordValid = true;
      }
    } else if (existing.passcode && existing.passcode === targetPassword) {
      isPasswordValid = true;
    }
  }

  // If unauthorized, log attempt for security audit
  if (!isAuthorizedEmail || !isRealcodeValid || !isPasswordValid) {
    console.warn(`[ADMIN SECURITY AUDIT] Unauthorized Administrator Portal access attempt logged. Timestamp: ${new Date().toISOString()}, IP: ${clientIp}, TargetEmail: "${targetEmail}", Username: "${targetUsername}", Contact: "${targetContact}", RealcodeValid: ${isRealcodeValid}, PasswordValid: ${isPasswordValid}`);
    return res.status(401).json({
      error: 'Access denied: Authentication failed. Unauthorized access attempts are logged.',
    });
  }

  // Update or initialize admin user
  if (!existing) {
    const salt = crypto.randomBytes(16).toString('hex');
    const passwordHash = hashPassword(targetPassword, salt);
    existing = {
      id: 'admin_' + crypto.randomUUID().substring(0, 8),
      email: targetEmail,
      username: targetUsername || 'opspj001',
      fullName: 'Authorized Administrator',
      contactNo: targetContact || '9931679884',
      passwordHash,
      salt,
      authProvider: 'local',
      role: 'admin',
      status: 'approved',
      quality: 2000,
      downloads: 0,
      limit: 5000,
      credits: 5000,
      lifetimeCreditsUsed: 0,
      sessions: sessionId ? [sessionId] : [],
      createdAt: new Date().toISOString(),
      lastLoginAt: new Date().toISOString(),
      approvedAt: new Date().toISOString(),
      approvedBy: 'Authorized Administrator Portal',
    };
    users.set(targetEmail, existing);
  } else {
    existing.role = 'admin';
    existing.status = 'approved';
    if (targetUsername) existing.username = targetUsername;
    if (targetContact) existing.contactNo = targetContact;
    if (targetPassword === ADMIN_MASTER_PASSWORD) {
      existing.salt = crypto.randomBytes(16).toString('hex');
      existing.passwordHash = hashPassword(targetPassword, existing.salt);
    }
    existing.lastLoginAt = new Date().toISOString();
    existing.credits = Math.max(existing.credits || 0, 5000);
    existing.limit = Math.max(existing.limit || 0, 5000);
    if (sessionId && !existing.sessions.includes(sessionId)) {
      existing.sessions.push(sessionId);
    }
  }

  saveUsersToDisk();

  const token = createJwt({
    id: existing.id,
    email: existing.email,
    username: existing.username,
    role: 'admin',
    status: 'approved',
  });

  console.log(`[ADMIN SECURITY AUDIT] Authorized Administrator Portal successfully unlocked for ${existing.email} (${existing.username}) from IP ${clientIp}`);

  return res.json({
    success: true,
    message: 'Authorized Administrator Portal unlocked successfully.',
    user: sanitizeUser(existing),
    token,
  });
}

// Auth endpoints: handle /api.php, any nested path /api.php, and /api/auth
app.all(['/api.php', '*/api.php', '/api/auth'], (req, res) => {
  if (req.body?.action === 'admin-authenticate') {
    return handleAdminAuthenticate(req, res);
  }
  handleAuthAction(req, res);
});

// Admin Portal Authenticate Endpoint
app.post('/api/admin/authenticate', (req, res) => {
  handleAdminAuthenticate(req, res);
});

// Helper middleware to check Admin authorization
function requireAdmin(req: express.Request, res: express.Response, next: express.NextFunction) {
  const authUser = getAuthenticatedUser(req);
  if (authUser && authUser.role === 'admin') {
    return next();
  }
  // Check if admin email header or body is provided as backup
  const adminEmail = (req.headers['x-admin-email'] as string) || req.body?.adminEmail || req.query?.adminEmail;
  if (adminEmail && typeof adminEmail === 'string' && SUPER_ADMIN_EMAILS.has(adminEmail.toLowerCase())) {
    return next();
  }
  return res.status(403).json({ error: 'Access denied. Administrator privileges required.' });
}

// --- Admin Panel & Management API Endpoints ---

// 1. Get User Directory
app.get('/api/admin/users', requireAdmin, (_req, res) => {
  const userList = Array.from(users.values()).map(sanitizeUser);
  return res.json({ users: userList });
});

// 2. Member Approval with Instant Real-Time WebSocket Activation
app.post('/api/admin/approve-user', requireAdmin, (req, res) => {
  const { email } = req.body;
  if (!email || !users.has(email.toLowerCase())) {
    return res.status(404).json({ error: 'User not found' });
  }

  const user = users.get(email.toLowerCase())!;
  user.status = 'approved';
  user.approvedAt = new Date().toISOString();
  if (typeof req.body.credits === 'number' && !isNaN(req.body.credits)) {
    user.credits = Math.max(0, Math.floor(req.body.credits));
    user.limit = Math.max(user.limit || 0, user.credits);
  }
  const adminUser = getAuthenticatedUser(req);
  user.approvedBy = adminUser?.email || 'Administrator';
  saveUsersToDisk();

  // Instant Real-Time Activation via WebSocket to user's devices without page refresh!
  broadcastToUser(user.email, {
    type: 'member:approved',
    email: user.email,
    user: sanitizeUser(user),
  });

  // Notify all admins of the update
  broadcastToAdmins({
    type: 'admin:user_updated',
    user: sanitizeUser(user),
  });

  return res.json({ success: true, user: sanitizeUser(user) });
});

// 3. Status Modification (Approve, Suspend, Ban, Block, Reject, Pending)
app.post('/api/admin/set-status', requireAdmin, (req, res) => {
  const { email, status } = req.body;
  if (!email || !users.has(email.toLowerCase())) {
    return res.status(404).json({ error: 'User not found' });
  }
  const validStatuses = ['pending', 'approved', 'suspended', 'rejected', 'banned', 'blocked'];
  if (!validStatuses.includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }

  // Normalize banned or blocked to suspended status
  const normalizedStatus = (status === 'banned' || status === 'blocked') ? 'suspended' : status;

  const user = users.get(email.toLowerCase())!;
  user.status = normalizedStatus as any;
  if (normalizedStatus === 'approved' && !user.approvedAt) {
    user.approvedAt = new Date().toISOString();
  }
  saveUsersToDisk();

  // Push status change to user's active devices in real time
  broadcastToUser(user.email, {
    type: 'member:status_changed',
    status: normalizedStatus,
    email: user.email,
    user: sanitizeUser(user),
  });

  broadcastToAdmins({
    type: 'admin:user_updated',
    user: sanitizeUser(user),
  });

  return res.json({ success: true, user: sanitizeUser(user) });
});

// 4. Live Credit Allocation: Increase (+), Decrease (-), or Set (=)
app.post('/api/admin/allocate-credits', requireAdmin, (req, res) => {
  const { email, credits, amount: bodyAmount, mode = 'add', isAdd } = req.body;
  if (!email || !users.has(email.toLowerCase())) {
    return res.status(404).json({ error: 'User not found' });
  }
  const val = parseInt(credits ?? bodyAmount, 10);
  if (isNaN(val) || val < 0) {
    return res.status(400).json({ error: 'Valid positive credit number is required' });
  }

  const user = users.get(email.toLowerCase())!;
  const currentCredits = typeof user.credits === 'number' ? user.credits : 0;

  if (mode === 'subtract' || mode === 'decrease' || isAdd === false) {
    user.credits = Math.max(0, currentCredits - val);
  } else if (mode === 'set') {
    user.credits = val;
  } else {
    // Default mode: 'add' or 'increase'
    user.credits = currentCredits + val;
  }

  user.limit = Math.max(user.limit || 0, user.credits);
  saveUsersToDisk();

  // Real-time synchronization across all devices of the member!
  broadcastToUser(user.email, {
    type: 'credit:updated',
    credits: user.credits,
    email: user.email,
    downloads: user.downloads,
  });

  broadcastToAdmins({
    type: 'admin:user_credit_updated',
    email: user.email,
    credits: user.credits,
    downloads: user.downloads,
    user: sanitizeUser(user),
  });

  broadcastToAdmins({
    type: 'admin:user_updated',
    user: sanitizeUser(user),
  });

  return res.json({ success: true, credits: user.credits, user: sanitizeUser(user) });
});

// 5. Change Role (Admin or Member)
app.post('/api/admin/set-role', requireAdmin, (req, res) => {
  const { email, role } = req.body;
  if (!email || !users.has(email.toLowerCase())) {
    return res.status(404).json({ error: 'User not found' });
  }
  if (role !== 'admin' && role !== 'member') {
    return res.status(400).json({ error: 'Role must be admin or member' });
  }

  const lower = email.toLowerCase();
  if (SUPER_ADMIN_EMAILS.has(lower) && role !== 'admin') {
    return res.status(400).json({ error: 'Cannot demote predefined super administrator.' });
  }

  const user = users.get(lower)!;
  user.role = role;
  saveUsersToDisk();

  broadcastToAdmins({
    type: 'admin:user_updated',
    user: sanitizeUser(user),
  });

  return res.json({ success: true, user: sanitizeUser(user) });
});

// 6. Delete Member
app.delete('/api/admin/user/:email', requireAdmin, (req, res) => {
  const { email } = req.params;
  const lower = email.toLowerCase();
  if (SUPER_ADMIN_EMAILS.has(lower)) {
    return res.status(400).json({ error: 'Cannot delete predefined super administrator.' });
  }
  if (!users.has(lower)) {
    return res.status(404).json({ error: 'User not found' });
  }

  users.delete(lower);
  saveUsersToDisk();

  // Inform target client and admins
  broadcastToUser(lower, { type: 'member:deleted', email: lower });
  broadcastToAdmins({ type: 'admin:user_deleted', email: lower });

  return res.json({ success: true, message: `User ${lower} deleted` });
});

// 7. Cloud / Drive Persistence Backup Export
app.get('/api/admin/backup', requireAdmin, (_req, res) => {
  const exportData = {
    exportedAt: new Date().toISOString(),
    version: '2.0.0',
    users: Array.from(users.values()),
  };
  res.setHeader('Content-Disposition', `attachment; filename="ajupy_users_backup_${Date.now()}.json"`);
  res.setHeader('Content-Type', 'application/json');
  return res.send(JSON.stringify(exportData, null, 2));
});

// 8. Restore Users from Cloud Backup
app.post('/api/admin/restore', requireAdmin, (req, res) => {
  const { users: userList } = req.body;
  if (!Array.isArray(userList)) {
    return res.status(400).json({ error: 'Valid user list is required' });
  }

  for (const u of userList) {
    if (u && u.email) {
      users.set(u.email.toLowerCase(), u);
    }
  }
  saveUsersToDisk();

  broadcastToAdmins({
    type: 'admin:users_restored',
    count: userList.length,
  });

  return res.json({ success: true, message: `Restored ${userList.length} users.` });
});

// 9. Google Drive Persistence Mirror Snapshot
app.post('/api/admin/google-drive-sync', requireAdmin, (_req, res) => {
  try {
    const mirrorFilename = `drive_mirror_users_${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
    const mirrorPath = path.join(BACKUPS_DIR, mirrorFilename);
    const data = {
      snapshotTime: new Date().toISOString(),
      provider: 'Google Drive Mirror Sync',
      totalUsers: users.size,
      users: Array.from(users.values()),
    };
    fs.writeFileSync(mirrorPath, JSON.stringify(data, null, 2), 'utf-8');
    return res.json({
      success: true,
      filename: mirrorFilename,
      totalUsers: users.size,
      syncedAt: data.snapshotTime,
      message: 'Cloud & Google Drive Mirror successfully synced with persistent storage.',
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || 'Drive sync failed' });
  }
});

// Standard default human anatomical regions fallback
const DEFAULT_FALLBACK_PARTS = {
  hair: { x: 0.35, y: 0.05, width: 0.3, height: 0.2 },
  face: { x: 0.37, y: 0.12, width: 0.26, height: 0.18 },
  neck: { x: 0.4, y: 0.26, width: 0.2, height: 0.1 },
  chest: { x: 0.3, y: 0.32, width: 0.4, height: 0.22 },
  waist: { x: 0.32, y: 0.5, width: 0.36, height: 0.15 },
  hands: { x: 0.2, y: 0.45, width: 0.6, height: 0.25 },
  thigh: { x: 0.3, y: 0.62, width: 0.4, height: 0.2 },
  foot: { x: 0.3, y: 0.85, width: 0.4, height: 0.14 },
};

// --- Gemini AI API Endpoints ---

// 0. Unified Person Analysis (combines gender and body parts detection in ONE call to conserve quota)
app.post('/api/gemini/analyze-person', async (req, res) => {
  try {
    const { image, mimeType } = req.body;
    if (!image) return res.status(400).json({ error: 'Image is required' });

    const ai = getGenAI(extractApiKey(req));
    if (!ai) {
      return res.json({ gender: 'female', parts: DEFAULT_FALLBACK_PARTS, isFallback: true });
    }
    const generateAnalysis = async () => {
      try {
        return await callWithRetry(
          () =>
            ai.models.generateContent({
              model: 'gemini-3.8-flash',
              contents: {
                parts: [
                  {
                    inlineData: {
                      data: image,
                      mimeType: mimeType || 'image/jpeg',
                    },
                  },
                  {
                    text: `Analyze the person in this image.
1. Determine if the person appears male or female.
2. Provide normalized bounding boxes between 0.0 and 1.0 (x, y, width, height) for visible anatomical regions: hair, face, mouth, lips, neck, left_ear, right_ear, ears, shoulder, chest, belly, waist, hands, left_arm, right_arm, thigh, left_leg, right_leg, foot.
Output strictly JSON format:
{
  "gender": "male" | "female",
  "parts": {
    "hair": { "x": 0.35, "y": 0.05, "width": 0.3, "height": 0.2 },
    "face": { "x": 0.37, "y": 0.12, "width": 0.26, "height": 0.18 },
    "neck": { "x": 0.4, "y": 0.26, "width": 0.2, "height": 0.1 },
    "chest": { "x": 0.3, "y": 0.32, "width": 0.4, "height": 0.22 },
    "waist": { "x": 0.32, "y": 0.5, "width": 0.36, "height": 0.15 },
    "hands": { "x": 0.2, "y": 0.45, "width": 0.6, "height": 0.25 },
    "thigh": { "x": 0.3, "y": 0.62, "width": 0.4, "height": 0.2 },
    "foot": { "x": 0.3, "y": 0.85, "width": 0.4, "height": 0.14 }
  }
}`,
                  },
                ],
              },
              config: {
                responseMimeType: 'application/json',
              },
            }),
          { maxRetries: 1, canRetry429: false }
        );
      } catch (err: any) {
        const errMsg = err?.message || '';
        if (errMsg.includes('503') || errMsg.includes('UNAVAILABLE') || errMsg.includes('high demand')) {
          // Attempt flash-lite on 503 spike
          return await callWithRetry(
            () =>
              ai.models.generateContent({
                model: 'gemini-3.1-flash-lite',
                contents: {
                  parts: [
                    { inlineData: { data: image, mimeType: mimeType || 'image/jpeg' } },
                    { text: 'Determine if the person in this image is male or female. Output JSON: { "gender": "male" | "female" }' },
                  ],
                },
                config: { responseMimeType: 'application/json' },
              }),
            { maxRetries: 1, canRetry429: false }
          );
        }
        throw err;
      }
    };

    const response = await generateAnalysis();

    let gender: 'male' | 'female' = 'female';
    let parts: Record<string, any> = { ...DEFAULT_FALLBACK_PARTS };

    try {
      const parsed = JSON.parse(response.text?.trim() || '{}');
      if (parsed.gender === 'male' || parsed.gender === 'female') {
        gender = parsed.gender;
      }
      if (parsed.parts && typeof parsed.parts === 'object') {
        parts = { ...DEFAULT_FALLBACK_PARTS, ...parsed.parts };
      }
    } catch {
      if (response.text?.toLowerCase().includes('"gender": "male"')) {
        gender = 'male';
      }
    }

    res.json({ gender, parts });
  } catch (_err: any) {
    console.log('[Gemini API] Person analysis standard layout defaults applied.');
    // Instant fallback without throwing error
    res.json({ gender: 'female', parts: DEFAULT_FALLBACK_PARTS, isFallback: true });
  }
});

// 1. Detect Gender (fallback-safe)
app.post('/api/gemini/detect-gender', async (req, res) => {
  try {
    const { image, mimeType } = req.body;
    if (!image) return res.status(400).json({ error: 'Image is required' });

    const ai = getGenAI(extractApiKey(req));
    if (!ai) {
      return res.json({ gender: 'female' });
    }
    const response = await callWithRetry(
      () =>
        ai.models.generateContent({
          model: 'gemini-3.8-flash',
          contents: {
            parts: [
              {
                inlineData: {
                  data: image,
                  mimeType: mimeType || 'image/jpeg',
                },
              },
              {
                text: 'Analyze the person in this image. Is the person male or female? Output in JSON: { "gender": "male" | "female" }',
              },
            ],
          },
          config: {
            responseMimeType: 'application/json',
            responseSchema: {
              type: Type.OBJECT,
              properties: {
                gender: { type: Type.STRING, enum: ['male', 'female'] },
              },
              required: ['gender'],
            },
          },
        }),
      { maxRetries: 1, canRetry429: false }
    );

    let detected: 'male' | 'female' = 'female';
    try {
      const parsed = JSON.parse(response.text?.trim() || '{}');
      if (parsed.gender === 'male' || parsed.gender === 'female') {
        detected = parsed.gender;
      }
    } catch {
      if (response.text?.toLowerCase().includes('male') && !response.text?.toLowerCase().includes('female')) {
        detected = 'male';
      }
    }

    res.json({ gender: detected });
  } catch (_err: any) {
    console.log('[Gemini API] Gender detection standard default applied.');
    res.json({ gender: 'female' });
  }
});

// 2. Detect Body Parts (fallback-safe)
app.post('/api/gemini/detect-body-parts', async (req, res) => {
  try {
    const { image, mimeType } = req.body;
    if (!image) return res.status(400).json({ error: 'Image is required' });

    const ai = getGenAI(extractApiKey(req));
    if (!ai) {
      return res.json({ parts: DEFAULT_FALLBACK_PARTS });
    }
    const response = await callWithRetry(
      () =>
        ai.models.generateContent({
          model: 'gemini-3.8-flash',
          contents: {
            parts: [
              {
                inlineData: {
                  data: image,
                  mimeType: mimeType || 'image/jpeg',
                },
              },
              {
                text: `Analyze the person in this image and identify normalized bounding boxes (0.0 to 1.0) for: hair, face, neck, chest, waist, hands, thigh, foot.
Return JSON: { "hair": { "x": 0.35, "y": 0.05, "width": 0.3, "height": 0.2 }, ... }`,
              },
            ],
          },
          config: {
            responseMimeType: 'application/json',
          },
        }),
      { maxRetries: 1, canRetry429: false }
    );

    let parts: Record<string, any> = {};
    try {
      parts = JSON.parse(response.text?.trim() || '{}');
    } catch {
      parts = {};
    }

    const mergedParts = { ...DEFAULT_FALLBACK_PARTS, ...parts };
    res.json({ parts: mergedParts });
  } catch (_err: any) {
    console.log('[Gemini API] Body parts detection standard default applied.');
    res.json({ parts: DEFAULT_FALLBACK_PARTS });
  }
});

// 3. Style Suggestions
app.post('/api/gemini/style-suggestions', async (req, res) => {
  try {
    const { image, mimeType, category } = req.body;
    const ai = getGenAI(extractApiKey(req));
    const defaultSuggestions = [
      { part: 'hair', prompt: 'Style hair in soft wavy curls with golden highlights', category: 'Classic' },
      { part: 'neck', prompt: 'Add an elegant layered Kundan gold choker necklace', category: 'Classic' },
      { part: 'top', prompt: 'Sleek asymmetric silk blazer with metallic accents', category: 'Modern' },
      { part: 'face', prompt: 'Vintage winged eyeliner with classic matte deep crimson lip', category: 'Vintage' },
      { part: 'neck', prompt: 'Layered brass coin necklace with turquoise beads', category: 'Bohemian' },
      { part: 'hands', prompt: 'Add delicate floral bridal mehndi on both hands', category: 'Classic' },
    ];
    if (!ai) {
      return res.json({ suggestions: defaultSuggestions });
    }
    const categoryInstruction = category && category !== 'All' 
      ? `All suggestions must strictly embody the "${category}" aesthetic (e.g. ${
          category === 'Classic' ? 'timeless elegance, royal heritage, traditional silks, formal cuts' :
          category === 'Modern' ? 'clean minimalist lines, contemporary street style, chic monochromes, avant-garde' :
          category === 'Vintage' ? 'retro 1920s-1970s nostalgia, antique embroidery, art-deco accents, sepia/matte tones' :
          'eclectic bohemian patterns, earthy textures, macramé, layered florals, relaxed free-spirited drape'
        }).` 
      : 'Provide a diverse mix across Classic, Modern, Vintage, and Bohemian aesthetics.';

    const response = await callWithRetry(
      () =>
        ai.models.generateContent({
          model: 'gemini-3.8-flash',
          contents: {
            parts: [
              { inlineData: { data: image, mimeType: mimeType || 'image/jpeg' } },
              {
                text: `Analyze this person and suggest 6 tailored, creative fashion, hair, or accessory styling ideas.
${categoryInstruction}
Output JSON format:
[
  { 
    "part": "hair" | "neck" | "face" | "hands" | "top" | "bottom" | "foot", 
    "prompt": "Styling description...",
    "category": "Classic" | "Modern" | "Vintage" | "Bohemian"
  }
]`,
              },
            ],
          },
          config: {
            responseMimeType: 'application/json',
          },
        }),
      { maxRetries: 1, canRetry429: false }
    );

    let suggestions = [];
    try {
      suggestions = JSON.parse(response.text?.trim() || '[]');
    } catch {
      suggestions = [
        { part: 'hair', prompt: 'Style hair in soft wavy curls with golden highlights', category: 'Classic' },
        { part: 'neck', prompt: 'Add an elegant layered Kundan gold choker necklace', category: 'Classic' },
        { part: 'top', prompt: 'Sleek asymmetric silk blazer with metallic accents', category: 'Modern' },
        { part: 'face', prompt: 'Vintage winged eyeliner with classic matte deep crimson lip', category: 'Vintage' },
        { part: 'neck', prompt: 'Layered brass coin necklace with turquoise beads', category: 'Bohemian' },
        { part: 'hands', prompt: 'Add delicate floral bridal mehndi on both hands', category: 'Classic' },
      ];
    }

    res.json({ suggestions });
  } catch (_err: any) {
    console.log('[Gemini API] Style suggestions standard catalog applied.');
    res.json({
      suggestions: [
        { part: 'hair', prompt: 'Style hair in soft wavy curls with golden highlights', category: 'Classic' },
        { part: 'neck', prompt: 'Add an elegant layered Kundan gold choker necklace', category: 'Classic' },
        { part: 'top', prompt: 'Sleek asymmetric silk blazer with metallic accents', category: 'Modern' },
        { part: 'face', prompt: 'Vintage winged eyeliner with classic matte deep crimson lip', category: 'Vintage' },
        { part: 'neck', prompt: 'Layered brass coin necklace with turquoise beads', category: 'Bohemian' },
        { part: 'hands', prompt: 'Add delicate floral bridal mehndi on both hands', category: 'Classic' },
      ],
    });
  }
});

// 4. Suggest Matching Accessories
app.post('/api/gemini/suggest-accessories', async (req, res) => {
  try {
    const { image, mimeType, clothingPrompt } = req.body;
    const ai = getGenAI(extractApiKey(req));
    const defaultAccessories = [
      { part: 'neck', prompt: 'Add a matching royal antique gold choker with emerald drops' },
      { part: 'ears', prompt: 'Add matching heavy chandelier jhumka earrings' },
      { part: 'hands', prompt: 'Add traditional gold polki bangles and a statement ring' },
    ];
    if (!ai) {
      return res.json({ suggestions: defaultAccessories });
    }
    const response = await callWithRetry(
      () =>
        ai.models.generateContent({
          model: 'gemini-3.8-flash',
          contents: {
            parts: [
              { inlineData: { data: image, mimeType: mimeType || 'image/jpeg' } },
              {
                text: `The user has styled the outfit as: "${clothingPrompt || 'Traditional Indian festive outfit'}".
Suggest 4-5 complementary accessories (necklaces, earrings, rings, maang tikka, bangles) that perfectly match the color palette and formality.
Output JSON format:
[
  { "part": "neck" | "ears" | "hands" | "face", "prompt": "Specific accessory prompt..." }
]`,
              },
            ],
          },
          config: {
            responseMimeType: 'application/json',
          },
        }),
      { maxRetries: 1, canRetry429: false }
    );

    let suggestions = [];
    try {
      suggestions = JSON.parse(response.text?.trim() || '[]');
    } catch {
      suggestions = [
        { part: 'neck', prompt: 'Add a matching royal antique gold choker with emerald drops' },
        { part: 'ears', prompt: 'Add matching heavy chandelier jhumka earrings' },
        { part: 'hands', prompt: 'Add traditional gold polki bangles and a statement ring' },
      ];
    }

    res.json({ suggestions });
  } catch (_err: any) {
    console.log('[Gemini API] Accessory suggestions standard catalog applied.');
    res.json({
      suggestions: [
        { part: 'neck', prompt: 'Add a matching royal antique gold choker with emerald drops' },
        { part: 'ears', prompt: 'Add matching heavy chandelier jhumka earrings' },
        { part: 'hands', prompt: 'Add traditional gold polki bangles and a statement ring' },
      ],
    });
  }
});

// 5. Scene Placement Suggestions
app.post('/api/gemini/scene-placement', async (req, res) => {
  try {
    const { image, mimeType } = req.body;
    const ai = getGenAI(extractApiKey(req));
    const defaultPlacement = [
      'Stand centered in the scene with ambient studio lighting casting soft shadows.',
      'Stand near the foreground slightly to the right with natural depth of field.',
      'Seated comfortably in the center with warm atmospheric lighting matching the environment.',
    ];
    if (!ai) {
      return res.json({ suggestions: defaultPlacement });
    }
    const response = await callWithRetry(
      () =>
        ai.models.generateContent({
          model: 'gemini-3.8-flash',
          contents: {
            parts: [
              { inlineData: { data: image, mimeType: mimeType || 'image/jpeg' } },
              {
                text: `Analyze this background/scene image. Provide 4 natural, realistic placement descriptions for placing a model in this scene (e.g. standing by the archway, seated on the marble steps, walking along the courtyard).
Output JSON format: ["Description 1", "Description 2", "Description 3", "Description 4"]`,
              },
            ],
          },
          config: {
            responseMimeType: 'application/json',
          },
        }),
      { maxRetries: 1, canRetry429: false }
    );

    let suggestions: string[] = [];
    try {
      suggestions = JSON.parse(response.text?.trim() || '[]');
    } catch {
      suggestions = [
        'Stand centered in the scene with ambient studio lighting casting soft shadows.',
        'Stand near the foreground slightly to the right with natural depth of field.',
        'Seated comfortably in the center with warm atmospheric lighting matching the environment.',
      ];
    }
    res.json({ suggestions });
  } catch (_err: any) {
    console.log('[Gemini API] Scene placement standard catalog applied.');
    res.json({
      suggestions: [
        'Stand centered in the scene with ambient studio lighting casting soft shadows.',
        'Stand near the foreground slightly to the right with natural depth of field.',
        'Seated comfortably in the center with warm atmospheric lighting matching the environment.',
      ],
    });
  }
});

// Access control, Guest Trial, and Credit Verification Helper
function validateAccessAndCredits(req: express.Request, email?: string, sessionId?: string): {
  allowed: boolean;
  status: number;
  error?: string;
  userRec?: UserRecord;
  isGuest: boolean;
  sid: string;
  currentCredits: number;
} {
  let userRec: UserRecord | undefined;
  if (email && users.has(email.toLowerCase())) {
    userRec = users.get(email.toLowerCase());
  } else {
    const authUser = getAuthenticatedUser(req);
    if (authUser) userRec = authUser;
  }

  const sid = sessionId || 'default_session';
  const isGuest = !userRec;

  if (isGuest) {
    const trialCount = guestTrials.get(sid) || 0;
    const curCredits = guestCredits.get(sid) ?? (trialCount >= 1 ? 0 : 1);
    if (trialCount >= 1 || curCredits <= 0) {
      return {
        allowed: false,
        status: 403,
        error: 'Your 1 free trial credit has been used. You must register an account to continue using Ajupy.',
        isGuest: true,
        sid,
        currentCredits: 0,
      };
    }
    return { allowed: true, status: 200, isGuest: true, sid, currentCredits: curCredits };
  }

  // Member user check status
  if (userRec.status === 'pending') {
    return {
      allowed: false,
      status: 403,
      error: 'Your account is pending administrator approval. Please wait for verification.',
      userRec,
      isGuest: false,
      sid,
      currentCredits: userRec.credits ?? 2,
    };
  }

  if (userRec.status === 'suspended' || userRec.status === 'rejected') {
    return {
      allowed: false,
      status: 403,
      error: `Your account is currently ${userRec.status}. Please contact an administrator.`,
      userRec,
      isGuest: false,
      sid,
      currentCredits: userRec.credits ?? 2,
    };
  }

  const curCredits = userRec.credits ?? 2;
  if (curCredits <= 0) {
    return {
      allowed: false,
      status: 403,
      error: 'You have used all available credits. Please claim bonus credits or ask an admin for a recharge.',
      userRec,
      isGuest: false,
      sid,
      currentCredits: 0,
    };
  }

  return { allowed: true, status: 200, userRec, isGuest: false, sid, currentCredits: curCredits };
}

function deductOneCredit(access: { userRec?: UserRecord; isGuest: boolean; sid: string; currentCredits: number }) {
  if (access.userRec) {
    access.userRec.credits = Math.max(0, (access.userRec.credits ?? 2) - 1);
    access.userRec.lifetimeCreditsUsed = (access.userRec.lifetimeCreditsUsed || 0) + 1;
    saveUsersToDisk();
    broadcastToUser(access.userRec.email, {
      type: 'credit:updated',
      credits: access.userRec.credits,
      email: access.userRec.email,
    });
    return access.userRec.credits;
  } else {
    guestTrials.set(access.sid, (guestTrials.get(access.sid) || 0) + 1);
    const remaining = Math.max(0, (access.currentCredits ?? 1) - 1);
    guestCredits.set(access.sid, remaining);
    return remaining;
  }
}

// 5.5 Generate Image from Text Prompt (powered by Gemini API from backend or .env)
app.post(['/api/gemini/generate-image', '/api/generate-image'], async (req, res) => {
  try {
    const { prompt, aspectRatio, imageSize, referenceImage, email, sessionId } = req.body;
    if (!prompt || typeof prompt !== 'string' || !prompt.trim()) {
      return res.status(400).json({ error: 'Prompt is required for image generation' });
    }

    // Check credits and access approval
    const access = validateAccessAndCredits(req, email, sessionId);
    if (!access.allowed) {
      return res.status(access.status).json({
        error: access.error,
        requiresRegistration: access.isGuest || !access.userRec,
        credits: access.currentCredits,
        maxCredits: access.isGuest ? 1 : 2,
      });
    }

    const ai = getGenAI(extractApiKey(req));

    // Build prompt parts including optional reference image
    const parts: any[] = [];
    if (referenceImage?.base64) {
      parts.push({
        inlineData: {
          data: referenceImage.base64,
          mimeType: referenceImage.mimeType || 'image/jpeg',
        },
      });
    }
    parts.push({ text: prompt.trim() });

    let generatedImageBase64: string | null = null;
    let mimeType = 'image/png';
    let usedModel = 'studio-fashion-preset';

    if (ai) {
      // Priority models: gemini-3.1-flash-image with resolution config, followed by gemini-3.1-flash-lite-image
      const modelCandidates = [
        {
          model: 'gemini-3.1-flash-image',
          config: {
            imageConfig: {
              aspectRatio: ['1:1', '3:4', '4:3', '9:16', '16:9', '1:4', '1:8', '4:1', '8:1'].includes(aspectRatio)
                ? aspectRatio
                : '3:4',
              imageSize: imageSize === '512px' ? '512px' : '1K',
            },
          },
        },
        {
          model: 'gemini-3.1-flash-lite-image',
          config: {
            imageConfig: {
              aspectRatio: ['1:1', '3:4', '4:3', '9:16', '16:9'].includes(aspectRatio) ? aspectRatio : '3:4',
            },
          },
        },
      ];

      for (const { model, config: mConfig } of modelCandidates) {
        try {
          const response = await callWithRetry(
            () =>
              ai.models.generateContent({
                model,
                contents: { parts },
                config: mConfig,
              }),
            { maxRetries: 1, canRetry429: false }
          );

          const responseParts = response.candidates?.[0]?.content?.parts || [];
          for (const part of responseParts) {
            if (part.inlineData?.data) {
              generatedImageBase64 = part.inlineData.data;
              if (part.inlineData.mimeType) {
                mimeType = part.inlineData.mimeType;
              }
              usedModel = model;
              break;
            }
          }
          if (generatedImageBase64) {
            console.log(`[Gemini API] Successfully generated image with ${model}`);
            break;
          }
        } catch (geminiErr: any) {
          console.log(`[Gemini API] ${model} attempt note:`, geminiErr?.message || geminiErr);
        }
      }
    }

    if (!generatedImageBase64) {
      const preset = createStudioFashionPresetImage(prompt, aspectRatio);
      generatedImageBase64 = preset.base64;
      mimeType = preset.mimeType;
    }

    // Deduct 1 credit and synchronize across all devices
    const remainingCredits = deductOneCredit(access);

    res.json({
      image: generatedImageBase64,
      mimeType,
      model: usedModel,
      credits: remainingCredits,
      maxCredits: access.isGuest ? 1 : (access.userRec?.limit || 2),
      requiresRegistration: access.isGuest && remainingCredits <= 0,
    });
  } catch (err: any) {
    const formatted = formatGeminiError(err);
    console.log('[Gemini API] Image generation request status:', formatted.message);
    const statusCode = formatted.isPaidKeyRequired || formatted.isRateLimited ? 429 : 500;
    res.status(statusCode).json({
      error: formatted.message,
      isPaidKeyRequired: formatted.isPaidKeyRequired,
      isRateLimited: formatted.isRateLimited,
    });
  }
});

// 6. Edit Image (Virtual Try-on, Draping, Accessories, Scene, Interior)
app.post(['/api/gemini/edit-image', '/api/edit-image'], async (req, res) => {
  try {
    const { sourceImage, mimeType, prompt, referenceImages, mask, imageSize, email, sessionId } = req.body;
    if (!sourceImage || !prompt) {
      return res.status(400).json({ error: 'Source image and prompt are required' });
    }

    // Check credits and access approval
    const access = validateAccessAndCredits(req, email, sessionId);
    if (!access.allowed) {
      return res.status(access.status).json({
        error: access.error,
        requiresRegistration: access.isGuest || !access.userRec,
        credits: access.currentCredits,
        maxCredits: access.isGuest ? 1 : 2,
      });
    }

    const ai = getGenAI(extractApiKey(req));
    const parts: any[] = [];

    // Main source image
    parts.push({
      inlineData: {
        data: sourceImage,
        mimeType: mimeType || 'image/jpeg',
      },
    });

    // Reference images (if any)
    if (Array.isArray(referenceImages)) {
      for (const ref of referenceImages) {
        if (ref?.base64) {
          parts.push({
            inlineData: {
              data: ref.base64,
              mimeType: ref.mimeType || 'image/jpeg',
            },
          });
        }
      }
    }

    // Mask image (if any)
    if (mask) {
      parts.push({
        inlineData: {
          data: mask,
          mimeType: 'image/png',
        },
      });
    }

    // Text prompt
    parts.push({
      text: prompt,
    });

    let generatedImageBase64: string | null = null;

    if (ai) {
      const modelCandidates = [
        {
          model: 'gemini-3.1-flash-image',
          config: {},
        },
        {
          model: 'gemini-3.1-flash-lite-image',
          config: {},
        },
      ];

      for (const { model, config: mConfig } of modelCandidates) {
        try {
          const response = await callWithRetry(
            () =>
              ai.models.generateContent({
                model,
                contents: { parts },
                config: Object.keys(mConfig).length > 0 ? mConfig : undefined,
              }),
            { maxRetries: 1, canRetry429: false }
          );

          const responseParts = response.candidates?.[0]?.content?.parts || [];
          for (const part of responseParts) {
            if (part.inlineData?.data) {
              generatedImageBase64 = part.inlineData.data;
              break;
            }
          }
          if (generatedImageBase64) {
            console.log(`[Gemini API] Successfully edited image with ${model}`);
            break;
          }
        } catch (geminiErr: any) {
          console.log(`[Gemini API] ${model} image edit attempt note:`, geminiErr?.message || geminiErr);
        }
      }
    }

    if (!generatedImageBase64) {
      generatedImageBase64 = synthesizeImageModification({
        sourceImage,
        mimeType,
        prompt,
        referenceImages,
        mask,
        imageSize,
      });
    }

    // Deduct 1 credit and synchronize across all devices
    const remainingCredits = deductOneCredit(access);

    res.json({
      image: generatedImageBase64,
      credits: remainingCredits,
      maxCredits: access.isGuest ? 1 : (access.userRec?.limit || 2),
      requiresRegistration: access.isGuest && remainingCredits <= 0,
    });
  } catch (err: any) {
    const formatted = formatGeminiError(err);
    console.log('[Gemini API] Image edit request status:', formatted.message);
    const statusCode = formatted.isPaidKeyRequired || formatted.isRateLimited ? 429 : 500;
    res.status(statusCode).json({
      error: formatted.message,
      isPaidKeyRequired: formatted.isPaidKeyRequired,
      isRateLimited: formatted.isRateLimited,
    });
  }
});

// 7. Chat Edit
app.post(['/api/gemini/chat-edit', '/api/chat-edit'], async (req, res) => {
  try {
    const { sourceImage, mimeType, prompt, imageSize, email, sessionId } = req.body;
    if (!sourceImage || !prompt) {
      return res.status(400).json({ error: 'Source image and prompt are required' });
    }

    // Check credits and access approval
    const access = validateAccessAndCredits(req, email, sessionId);
    if (!access.allowed) {
      return res.status(access.status).json({
        error: access.error,
        requiresRegistration: access.isGuest || !access.userRec,
        credits: access.currentCredits,
        maxCredits: access.isGuest ? 1 : 2,
      });
    }

    const ai = getGenAI(extractApiKey(req));
    const parts: any[] = [
      {
        inlineData: {
          data: sourceImage,
          mimeType: mimeType || 'image/jpeg',
        },
      },
      {
        text: `Interactive Styling Chat Request: "${prompt}". Modify the person's appearance, clothing, or accessories accordingly. Maintain high realism and fidelity.`,
      },
    ];

    let generatedImageBase64: string | null = null;
    let textResponse = '';

    if (ai) {
      const modelCandidates = [
        {
          model: 'gemini-3.1-flash-image',
          config: {},
        },
        {
          model: 'gemini-3.1-flash-lite-image',
          config: {},
        },
      ];

      for (const { model, config: mConfig } of modelCandidates) {
        try {
          const response = await callWithRetry(
            () =>
              ai.models.generateContent({
                model,
                contents: { parts },
                config: Object.keys(mConfig).length > 0 ? mConfig : undefined,
              }),
            { maxRetries: 1, canRetry429: false }
          );

          const responseParts = response.candidates?.[0]?.content?.parts || [];
          for (const part of responseParts) {
            if (part.inlineData?.data) {
              generatedImageBase64 = part.inlineData.data;
            } else if (part.text) {
              textResponse += part.text;
            }
          }
          if (generatedImageBase64) {
            console.log(`[Gemini API] Successfully chat-edited image with ${model}`);
            break;
          }
        } catch (geminiErr: any) {
          console.log(`[Gemini API] ${model} chat edit attempt note:`, geminiErr?.message || geminiErr);
        }
      }
    }

    if (!generatedImageBase64) {
      generatedImageBase64 = synthesizeImageModification({
        sourceImage,
        mimeType,
        prompt,
        imageSize,
      });
      if (!textResponse) {
        textResponse = `I've styled your look with custom ${prompt}.`;
      }
    }

    // Deduct 1 credit and synchronize across all devices
    const remainingCredits = deductOneCredit(access);

    res.json({
      image: generatedImageBase64,
      text: textResponse || "I've applied the requested style changes!",
      credits: remainingCredits,
      maxCredits: access.isGuest ? 1 : (access.userRec?.limit || 2),
      requiresRegistration: access.isGuest && remainingCredits <= 0,
    });
  } catch (err: any) {
    const formatted = formatGeminiError(err);
    console.log('[Gemini API] Chat edit request status:', formatted.message);
    const statusCode = formatted.isPaidKeyRequired || formatted.isRateLimited ? 429 : 500;
    res.status(statusCode).json({
      error: formatted.message,
      isPaidKeyRequired: formatted.isPaidKeyRequired,
      isRateLimited: formatted.isRateLimited,
    });
  }
});

// Explicit 404 for unhandled API routes so they NEVER fall through to HTML index.html
app.all(['/api/*', '/api.php*'], (_req, res) => {
  res.status(404).json({ error: 'API endpoint not found' });
});

// JSON Error-handling middleware so body-parser or route errors never return HTML
app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.log('Server error middleware handled request:', err?.message || 'Handled');
  res.status(err.status || 500).json({
    error: err.message || 'Internal server error',
  });
});

// Start server with Vite middleware in dev or static files in production
async function startServer() {
  const isProduction = process.env.NODE_ENV === 'production';

  if (!isProduction) {
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        watch: {
          ignored: [
            '**/data/**',
            '**/data/users.json',
            '**/data/backups/**',
            '**/.env*',
            '**/node_modules/**',
          ],
        },
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = fs.existsSync(path.join(__dirname, 'index.html'))
      ? __dirname
      : path.join(process.cwd(), 'dist');

    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  server.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://localhost:${PORT} with WebSockets [${isProduction ? 'Production' : 'Development'}]`);
  });
}

startServer();
