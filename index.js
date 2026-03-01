require('dotenv').config();
const express              = require('express');
const { WebSocketServer }  = require('ws');
const { createServer }     = require('http');
const path                 = require('path');
const fs                   = require('fs');
const { verifyWebhook, mapWebhookEvent } = require('./github');

const PORT         = process.env.PORT         || 3000;
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'changeme';
const APP_SLUG     = process.env.GITHUB_APP_SLUG || '';
const MEMBERS_FILE = path.join(__dirname, 'members.json');

// ── 成員名單（記憶體 + JSON 持久化） ─────────────────────────
// 結構：{ approved: Set<string>, pending: Set<string> }
let members = { approved: new Set(), pending: new Set() };

function loadMembers() {
  try {
    const data = JSON.parse(fs.readFileSync(MEMBERS_FILE, 'utf8'));
    members.approved = new Set(data.approved || []);
    members.pending  = new Set(data.pending  || []);
  } catch {
    members = { approved: new Set(), pending: new Set() };
  }
}

function saveMembers() {
  fs.writeFileSync(MEMBERS_FILE, JSON.stringify({
    approved: [...members.approved],
    pending:  [...members.pending],
  }, null, 2));
}

loadMembers();

// ── Express ───────────────────────────────────────────────────
const app = express();

// Webhook route 需要 raw body 才能驗簽
app.use('/webhook/github', express.raw({ type: 'application/json' }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Admin 驗證 ────────────────────────────────────────────────
function adminOnly(req, res, next) {
  const secret = req.headers['x-admin-secret'] || req.query.secret;
  if (secret !== ADMIN_SECRET) return res.status(403).json({ error: 'Forbidden' });
  next();
}

function isValidUsername(u) {
  return typeof u === 'string' && /^[a-zA-Z0-9-]{1,39}$/.test(u);
}

// ── Admin API ─────────────────────────────────────────────────
app.get('/api/members', adminOnly, (req, res) => {
  res.json({
    approved: [...members.approved],
    pending:  [...members.pending],
  });
});

// Admin 直接新增核准成員
app.post('/api/members', adminOnly, (req, res) => {
  const { username } = req.body;
  if (!isValidUsername(username))
    return res.status(400).json({ error: 'Invalid username' });
  members.pending.delete(username);
  members.approved.add(username);
  saveMembers();
  broadcast({ type: 'member_join', username });
  res.json({ ok: true });
});

// 核准待審成員
app.post('/api/members/:username/approve', adminOnly, (req, res) => {
  const { username } = req.params;
  members.pending.delete(username);
  members.approved.add(username);
  saveMembers();
  broadcast({ type: 'member_join', username });
  res.json({ ok: true });
});

// 移除成員
app.delete('/api/members/:username', adminOnly, (req, res) => {
  members.approved.delete(req.params.username);
  members.pending.delete(req.params.username);
  saveMembers();
  broadcast({ type: 'member_leave', username: req.params.username });
  res.json({ ok: true });
});

// ── Public API ────────────────────────────────────────────────
// 提供 App Slug 給前端產生安裝連結
app.get('/api/config', (req, res) => {
  res.json({ appSlug: APP_SLUG });
});

// 任何人都可以送出申請
app.post('/api/join', (req, res) => {
  const { username } = req.body;
  if (!isValidUsername(username))
    return res.status(400).json({ error: 'Invalid username' });
  if (members.approved.has(username))
    return res.json({ ok: true, status: 'already_approved' });
  if (members.pending.has(username))
    return res.json({ ok: true, status: 'pending' });
  members.pending.add(username);
  saveMembers();
  console.log(`[join] New request: ${username}`);
  res.json({ ok: true, status: 'pending', message: '申請已送出，等待管理員審核' });
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

  // App 安裝 / 移除
  if (eventType === 'installation') {
    const username = payload.sender?.login;
    if (payload.action === 'created') {
      console.log(`[webhook] App installed by ${username}`);
      broadcast({ type: 'member_app_installed', username });
    } else if (payload.action === 'deleted') {
      console.log(`[webhook] App uninstalled by ${username}`);
    }
    return;
  }

  // 只處理已核准成員的事件
  const actor = payload.sender?.login;
  if (!actor || !members.approved.has(actor)) return;

  const action = mapWebhookEvent(eventType, payload);
  if (!action) return;

  console.log(`[event] ${actor}: ${action.msg}`);
  broadcast({ type: 'event', actor, action });
});

// ── WebSocket ─────────────────────────────────────────────────
const server  = createServer(app);
const wss     = new WebSocketServer({ server, path: '/ws' });
const clients = new Set();

wss.on('connection', ws => {
  clients.add(ws);

  // 新 viewer 連線時送出完整成員名單
  ws.send(JSON.stringify({
    type:    'init',
    members: [...members.approved],
  }));

  ws.on('close', () => clients.delete(ws));
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
  console.log(`\n🏰  Guild Hall  →  http://localhost:${PORT}`);
  console.log(`🔑  Admin       →  http://localhost:${PORT}/admin.html?secret=${ADMIN_SECRET}`);
  console.log(`🔗  Webhook URL →  http://your-domain:${PORT}/webhook/github\n`);
  if (!APP_SLUG) console.warn('⚠️  GITHUB_APP_SLUG 未設定，成員無法看到安裝 App 的連結');
});
