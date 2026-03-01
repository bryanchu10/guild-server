const crypto = require('crypto');

// ── Webhook 簽章驗證 ──────────────────────────────────────────
function verifyWebhook(rawBody, signature) {
  const secret = process.env.GITHUB_APP_WEBHOOK_SECRET;
  if (!secret) return true; // 開發時若未設定則跳過
  if (!signature) return false;
  const expected = 'sha256=' + crypto
    .createHmac('sha256', secret)
    .update(rawBody)
    .digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
  } catch {
    return false;
  }
}

// ── Webhook payload → game action ────────────────────────────
function rand(a, b) { return Math.floor(Math.random() * (b - a + 1)) + a; }

function mapWebhookEvent(eventType, payload) {
  const actor     = payload.sender?.login;
  const repo      = payload.repository?.name || '';
  const repoOwner = payload.repository?.owner?.login || null;
  if (!actor) return null;

  // targetActor：事件的對象（repo 擁有者），自己對自己的 repo 操作則為 null
  const ownerTarget = repoOwner !== actor ? repoOwner : null;

  switch (eventType) {
    case 'push': {
      const n      = payload.commits?.length ?? 1;
      const branch = (payload.ref || '').replace('refs/heads/', '') || 'main';
      return { actor, targetActor: ownerTarget, css: 'push', icon: '📦', col: 0xf0883e,
               msg: `pushed ${n} commit${n > 1 ? 's' : ''} to ${repo}/${branch}`,
               tx: rand(75, 170), ty: rand(295, 355) };
    }
    case 'pull_request': {
      const n  = payload.number;
      const pr = payload.pull_request;
      const title = (pr?.title || '').substring(0, 22);
      if (payload.action === 'opened')
        return { actor, targetActor: ownerTarget, css: 'pr', icon: '🔀', col: 0xa371f7,
                 msg: `opened PR #${n} on ${repo}: ${title}`,
                 tx: rand(75, 170), ty: rand(295, 355) };
      if (payload.action === 'closed' && pr?.merged)
        return { actor, targetActor: ownerTarget, css: 'merge', icon: '✅', col: 0x3fb950,
                 msg: `merged PR #${n} on ${repo}`,
                 tx: rand(310, 490), ty: rand(330, 400) };
      if (payload.action === 'closed')
        return { actor, targetActor: ownerTarget, css: 'pr', icon: '🚫', col: 0xf85149,
                 msg: `closed PR #${n} on ${repo}`,
                 tx: rand(75, 170), ty: rand(295, 355) };
      return null;
    }
    case 'pull_request_review': {
      if (payload.action !== 'submitted') return null;
      const n       = payload.pull_request?.number;
      const state   = payload.review?.state;
      const prAuthor = payload.pull_request?.user?.login || null;
      const verdict = state === 'approved'          ? 'LGTM! 👍'
                    : state === 'changes_requested' ? 'needs changes 🔧'
                    :                                 'left a comment 💬';
      // reviewer 走向 PR 作者
      const reviewTarget = prAuthor !== actor ? prAuthor : ownerTarget;
      return { actor, targetActor: reviewTarget, css: 'review', icon: '👀', col: 0x58a6ff,
               msg: `PR #${n} on ${repo}: ${verdict}`,
               tx: rand(310, 490), ty: rand(330, 400) };
    }
    case 'issues': {
      const n     = payload.issue?.number;
      const title = (payload.issue?.title || '').substring(0, 22);
      if (payload.action === 'opened')
        return { actor, targetActor: ownerTarget, css: 'bug', icon: '🐛', col: 0xf85149,
                 msg: `opened issue #${n} on ${repo}: ${title}`,
                 tx: rand(75, 170), ty: rand(295, 355) };
      if (payload.action === 'closed')
        return { actor, targetActor: ownerTarget, css: 'merge', icon: '🔒', col: 0x3fb950,
                 msg: `closed issue #${n} on ${repo}`,
                 tx: rand(310, 490), ty: rand(330, 400) };
      return null;
    }
    case 'issue_comment':
      if (payload.action !== 'created') return null;
      return { actor, targetActor: ownerTarget, css: 'review', icon: '💬', col: 0x58a6ff,
               msg: `commented on ${repo} #${payload.issue?.number}`,
               tx: rand(310, 490), ty: rand(330, 400) };
    case 'create':
      return { actor, css: 'push', icon: '🌿', col: 0xf0883e,
               msg: `created ${payload.ref_type} ${payload.ref || ''} on ${repo}`,
               tx: rand(75, 170), ty: rand(295, 355) };
    case 'delete':
      return { actor, css: 'bug', icon: '🗑️', col: 0xf85149,
               msg: `deleted ${payload.ref_type} ${payload.ref || ''} on ${repo}`,
               tx: rand(75, 170), ty: rand(295, 355) };
    case 'fork':
      return { actor, targetActor: ownerTarget, css: 'pr', icon: '🍴', col: 0xa371f7,
               msg: `forked ${payload.forkee?.full_name || repo}`,
               tx: rand(310, 490), ty: rand(330, 400) };
    case 'watch':
      if (payload.action !== 'started') return null;
      return { actor, targetActor: ownerTarget, css: 'review', icon: '⭐', col: 0xf5d076,
               msg: `starred ${repo}`,
               tx: rand(310, 490), ty: rand(330, 400) };
    case 'release':
      if (payload.action !== 'published') return null;
      return { actor, css: 'merge', icon: '🚀', col: 0x3fb950,
               msg: `released ${payload.release?.tag_name || ''} on ${repo}`,
               tx: rand(310, 490), ty: rand(330, 400) };
    default:
      return null;
  }
}

module.exports = { verifyWebhook, mapWebhookEvent };
