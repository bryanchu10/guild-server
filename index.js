require('dotenv').config();
const express              = require('express');
const { WebSocketServer }  = require('ws');
const { createServer }     = require('http');
const path                 = require('path');
const fs                   = require('fs');
const crypto               = require('crypto');
const cookieParser         = require('cookie-parser');
const { verifyWebhook, mapWebhookEvent } = require('./github');

const PORT         = process.env.PORT         || 3000;
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'changeme';
const APP_SLUG     = process.env.GITHUB_APP_SLUG || '';
const MEMBERS_FILE = process.env.MEMBERS_FILE || path.join(__dirname, 'members.json');
const MEMBER_LIMIT = 300;

// ── 成員名單（記憶體 + JSON 持久化） ─────────────────────────
let members = { approved: new Set() };

function loadMembers() {
  try {
    const data = JSON.parse(fs.readFileSync(MEMBERS_FILE, 'utf8'));
    members.approved = new Set(data.approved || []);
  } catch {
    members = { approved: new Set() };
  }
}

function saveMembers() {
  fs.writeFileSync(MEMBERS_FILE, JSON.stringify({
    approved: [...members.approved],
  }, null, 2));
}

loadMembers();

// ── Express ───────────────────────────────────────────────────
const app = express();
const cors = require('cors');
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || '*';
app.use(cors({ origin: FRONTEND_ORIGIN }));

// Webhook route 需要 raw body 才能驗簽
app.use('/webhook/github', express.raw({ type: 'application/json' }));
app.use(express.json());
app.use(cookieParser());

// ── Session 管理 ──────────────────────────────────────────────
const sessions = new Map();  // token → expiresAt
const SESSION_TTL = 8 * 60 * 60 * 1000;  // 8 小時

// ── Admin 驗證 ────────────────────────────────────────────────
function adminOnly(req, res, next) {
  // 優先檢查 session cookie
  const token = req.cookies?.session;
  if (token && sessions.has(token)) {
    const exp = sessions.get(token);
    if (Date.now() < exp) return next();
    sessions.delete(token);
  }
  // fallback：x-admin-secret header（供 curl / 工具使用）
  const secret = req.headers['x-admin-secret'];
  if (secret === ADMIN_SECRET) return next();
  return res.status(403).json({ error: 'Forbidden' });
}

// POST /api/admin/login
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (password !== ADMIN_SECRET) return res.status(403).json({ error: 'Forbidden' });
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, Date.now() + SESSION_TTL);
  res.cookie('session', token, {
    httpOnly: true,
    sameSite: 'strict',
    maxAge: SESSION_TTL,
  });
  res.json({ ok: true });
});

// POST /api/admin/logout
app.post('/api/admin/logout', (req, res) => {
  const token = req.cookies?.session;
  if (token) sessions.delete(token);
  res.clearCookie('session');
  res.json({ ok: true });
});

function isValidUsername(u) {
  return typeof u === 'string' && /^[a-zA-Z0-9-]{1,39}$/.test(u);
}

// ── Admin API ─────────────────────────────────────────────────
app.get('/api/members', adminOnly, (req, res) => {
  res.json({ approved: [...members.approved] });
});

// Admin 直接新增成員（邊緣情況用，例如 webhook 失敗時）
app.post('/api/members', adminOnly, (req, res) => {
  const { username } = req.body;
  if (!isValidUsername(username))
    return res.status(400).json({ error: 'Invalid username' });
  if (members.approved.size >= MEMBER_LIMIT)
    return res.status(400).json({ error: '已達人數上限' });
  members.approved.add(username);
  saveMembers();
  broadcast({ type: 'member_join', username });
  res.json({ ok: true });
});

// 移除成員
app.delete('/api/members/:username', adminOnly, (req, res) => {
  members.approved.delete(req.params.username);
  saveMembers();
  broadcast({ type: 'member_leave', username: req.params.username });
  res.json({ ok: true });
});

// ── 開發測試端點 ───────────────────────────────────────────────
app.post('/api/test', adminOnly, (req, res) => {
  const { actor, anonymous, action } = req.body;
  if (!actor || !action) return res.status(400).json({ error: 'Missing actor or action' });
  broadcast({ type: 'event', actor, anonymous: !!anonymous, action });
  res.json({ ok: true });
});

// ── Public API ────────────────────────────────────────────────
app.get('/api/config', (req, res) => {
  res.json({ appSlug: APP_SLUG });
});

app.get('/api/capacity', (req, res) => {
  const count = members.approved.size;
  res.json({ count, limit: MEMBER_LIMIT, isFull: count >= MEMBER_LIMIT });
});

// ── GitHub App Webhook ────────────────────────────────────────
app.post('/webhook/github', (req, res) => {
  const sig       = req.headers['x-hub-signature-256'];
  const eventType = req.headers['x-github-event'];

  if (!verifyWebhook(req.body, sig)) {
    console.warn('[webhook] Invalid signature — 忽略');
    return res.status(401).send('Invalid signature');
  }

  res.sendStatus(200); // 立刻回應，不讓 GitHub 等待

  let payload;
  try { payload = JSON.parse(req.body); } catch { return; }

  // App 安裝 / 移除 → 自動加入 / 退出公會
  if (eventType === 'installation') {
    const username = payload.sender?.login;
    if (!username) return;
    if (payload.action === 'created') {
      if (members.approved.has(username)) return; // 已是成員，忽略
      if (members.approved.size >= MEMBER_LIMIT) {
        console.log(`[webhook] App installed by ${username}, but guild is full`);
        return;
      }
      members.approved.add(username);
      saveMembers();
      console.log(`[webhook] ${username} joined via GitHub App install`);
      broadcast({ type: 'member_join', username });
    } else if (payload.action === 'deleted') {
      members.approved.delete(username);
      saveMembers();
      console.log(`[webhook] ${username} left via GitHub App uninstall`);
      broadcast({ type: 'member_leave', username });
    }
    return;
  }

  const actor = payload.sender?.login;
  if (!actor) return;

  const action = mapWebhookEvent(eventType, payload);
  if (!action) return;

  // 事件雙方至少有一人是公會成員才處理
  const actorApproved  = members.approved.has(actor);
  const targetApproved = action.targetActor && members.approved.has(action.targetActor);
  if (!actorApproved && !targetApproved) return;

  console.log(`[event] ${actor}: ${action.msg}`);
  broadcast({ type: 'event', actor, anonymous: !actorApproved, action });
});

// ── WebSocket ─────────────────────────────────────────────────
const server  = createServer(app);
const wss     = new WebSocketServer({ server, path: '/ws' });
const clients = new Set();

wss.on('connection', ws => {
  clients.add(ws);

  // 新 viewer 連線時送出完整成員名單與當前在線人數
  ws.send(JSON.stringify({
    type:    'init',
    members: [...members.approved],
    viewers: clients.size,
  }));
  broadcast({ type: 'viewers', count: clients.size });

  ws.on('close', () => {
    clients.delete(ws);
    broadcast({ type: 'viewers', count: clients.size });
  });
  ws.on('error', () => clients.delete(ws));
});

function broadcast(msg) {
  const data = JSON.stringify(msg);
  for (const ws of clients) {
    if (ws.readyState === 1) ws.send(data);
  }
}

// ── Start ─────────────────────────────────────────────────────
server.listen(PORT, () => {
  console.log(`\n🏰  Guild Hall  →  http://localhost:5173`);
  console.log(`🔑  Admin       →  http://localhost:5173/admin`);
  console.log(`🔗  Webhook URL →  http://your-domain:${PORT}/webhook/github\n`);
  if (!APP_SLUG) console.warn('⚠️  GITHUB_APP_SLUG 未設定，成員無法看到安裝 App 的連結');
});
