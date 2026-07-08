const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { Pool } = require('pg');
const path = require('path');

const app = express();
app.use(cors());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';
const SHARED_EMAIL = process.env.SHARED_EMAIL || 'household@home.com';
const SHARED_PASSWORD = process.env.SHARED_PASSWORD || 'changeme';
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
const stripe = STRIPE_SECRET_KEY ? require('stripe')(STRIPE_SECRET_KEY) : null;

const STATE_KEYS = ['inventory', 'grocery', 'cookbook', 'planner', 'settings'];
const CREDIT_PACKS = {
  small:  { credits: 50,  amountCents: 500,  label: '50 credits — $5' },
  medium: { credits: 150, amountCents: 1200, label: '150 credits — $12' },
  large:  { credits: 500, amountCents: 3500, label: '500 credits — $35' },
};

// ─── Stripe webhook — MUST be registered before express.json() so the body
// arrives raw (signature verification needs the exact bytes Stripe signed). ───
app.post('/api/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe || !STRIPE_WEBHOOK_SECRET) return res.status(500).send('Stripe is not configured');
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], STRIPE_WEBHOOK_SECRET);
  } catch (e) {
    console.error('Stripe webhook signature verification failed:', e.message);
    return res.status(400).send(`Webhook Error: ${e.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const familyId = Number(session.metadata && session.metadata.familyId);
    // Pack size travels in session metadata; fall back to the original 50-credit pack
    // for any session created before multi-pack support shipped.
    const credits = Number(session.metadata && session.metadata.credits) || 50;
    const inserted = await pool.query('INSERT INTO stripe_events (id) VALUES ($1) ON CONFLICT DO NOTHING RETURNING id', [event.id]);
    if (inserted.rows.length && familyId) {
      await pool.query('UPDATE families SET credits = credits + $1 WHERE id = $2', [credits, familyId]);
      await pool.query(
        'INSERT INTO credit_purchases (family_id, credits, amount_cents, stripe_event_id) VALUES ($1, $2, $3, $4)',
        [familyId, credits, session.amount_total || 0, event.id]
      );
    }
  }
  res.json({ received: true });
});

app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

async function backfillOwnerFamily() {
  const { rows: existing } = await pool.query('SELECT id FROM families WHERE is_owner_family = true LIMIT 1');
  let ownerFamilyId;
  if (existing.length) {
    ownerFamilyId = existing[0].id;
  } else {
    const { rows } = await pool.query(
      `INSERT INTO families (name, is_owner_family, credits) VALUES ($1, true, NULL) RETURNING id`,
      ['Tiana & Baltej']
    );
    ownerFamilyId = rows[0].id;
  }
  const { rows: existingUser } = await pool.query('SELECT id FROM users WHERE email = $1', [SHARED_EMAIL]);
  if (!existingUser.length) {
    const hash = await bcrypt.hash(SHARED_PASSWORD, 10);
    await pool.query(
      `INSERT INTO users (family_id, email, password_hash, role) VALUES ($1, $2, $3, 'owner')`,
      [ownerFamilyId, SHARED_EMAIL, hash]
    );
  }
  await pool.query('UPDATE app_state SET family_id = $1 WHERE family_id IS NULL', [ownerFamilyId]);
}

async function swapAppStatePrimaryKey() {
  const { rows } = await pool.query(`
    SELECT string_agg(kcu.column_name, ',' ORDER BY kcu.ordinal_position) AS cols
    FROM information_schema.table_constraints tc
    JOIN information_schema.key_column_usage kcu ON tc.constraint_name = kcu.constraint_name
    WHERE tc.table_name = 'app_state' AND tc.constraint_type = 'PRIMARY KEY'
  `);
  if (rows[0] && rows[0].cols === 'family_id,key') return; // already migrated
  const { rows: nullCheck } = await pool.query('SELECT COUNT(*) FROM app_state WHERE family_id IS NULL');
  if (Number(nullCheck[0].count) > 0) return; // not safe yet — backfill hasn't caught everything
  await pool.query('ALTER TABLE app_state DROP CONSTRAINT IF EXISTS app_state_pkey');
  await pool.query('ALTER TABLE app_state ALTER COLUMN family_id SET NOT NULL');
  await pool.query('ALTER TABLE app_state ADD PRIMARY KEY (family_id, key)');
}

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS families (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      is_owner_family BOOLEAN NOT NULL DEFAULT false,
      credits INTEGER,
      created_at TIMESTAMPTZ DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      family_id INTEGER NOT NULL REFERENCES families(id),
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'member',
      created_at TIMESTAMPTZ DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS invites (
      code TEXT PRIMARY KEY,
      family_id INTEGER REFERENCES families(id),
      created_by_user_id INTEGER REFERENCES users(id),
      redeemed_by_user_id INTEGER REFERENCES users(id),
      redeemed_at TIMESTAMPTZ,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS stripe_events (
      id TEXT PRIMARY KEY,
      processed_at TIMESTAMPTZ DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS credit_purchases (
      id SERIAL PRIMARY KEY,
      family_id INTEGER REFERENCES families(id),
      credits INTEGER NOT NULL,
      amount_cents INTEGER NOT NULL,
      stripe_event_id TEXT,
      created_at TIMESTAMPTZ DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_state (
      key TEXT PRIMARY KEY,
      value JSONB NOT NULL,
      updated_at TIMESTAMPTZ DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS admin_audit_log (
      id SERIAL PRIMARY KEY,
      family_id INTEGER REFERENCES families(id),
      actor_email TEXT NOT NULL,
      action TEXT NOT NULL,
      target_email TEXT,
      created_at TIMESTAMPTZ DEFAULT now()
    );
  `);
  await pool.query('ALTER TABLE app_state ADD COLUMN IF NOT EXISTS family_id INTEGER REFERENCES families(id)');
  await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS first_name TEXT');
  await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS last_name TEXT');
  await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS accent_color TEXT');
  await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS theme TEXT DEFAULT 'light'");
  await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ');
  await backfillOwnerFamily();
  await swapAppStatePrimaryKey();
  // Self-healing: families created before roles were assigned correctly get their
  // earliest member promoted to household owner (no-op once every family has one).
  await pool.query(`
    UPDATE users u SET role = 'owner'
    WHERE u.role <> 'owner'
      AND NOT EXISTS (SELECT 1 FROM users o WHERE o.family_id = u.family_id AND o.role = 'owner')
      AND u.id = (SELECT MIN(x.id) FROM users x WHERE x.family_id = u.family_id)
  `);
}

async function logAudit(familyId, actorUserId, action, targetEmail) {
  const { rows } = await pool.query('SELECT email FROM users WHERE id = $1', [actorUserId]);
  const actorEmail = rows[0] ? rows[0].email : 'unknown';
  await pool.query(
    'INSERT INTO admin_audit_log (family_id, actor_email, action, target_email) VALUES ($1, $2, $3, $4)',
    [familyId, actorEmail, action, targetEmail || null]
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(header.replace('Bearer ', ''), JWT_SECRET);
    // Fire-and-forget activity ping for admin usage stats — never blocks the request.
    pool.query('UPDATE users SET last_seen_at = now() WHERE id = $1', [req.user.userId]).catch(() => {});
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

async function signToken(user) {
  const { rows } = await pool.query('SELECT is_owner_family FROM families WHERE id = $1', [user.family_id]);
  const isOwnerFamily = !!(rows[0] && rows[0].is_owner_family);
  return jwt.sign({ userId: user.id, familyId: user.family_id, isOwnerFamily }, JWT_SECRET, { expiresIn: '30d' });
}

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
  const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  const user = rows[0];
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  res.json({ token: await signToken(user) });
});

app.get('/api/me', auth, async (req, res) => {
  const { rows } = await pool.query('SELECT email, role, first_name, last_name, accent_color, theme FROM users WHERE id = $1', [req.user.userId]);
  res.json({
    userId: req.user.userId,
    email: rows[0] ? rows[0].email : null,
    role: rows[0] ? rows[0].role : 'member',
    firstName: rows[0] ? rows[0].first_name : null,
    lastName: rows[0] ? rows[0].last_name : null,
    accentColor: rows[0] ? rows[0].accent_color : null,
    theme: rows[0] ? (rows[0].theme || 'light') : 'light',
    familyId: req.user.familyId,
    isOwnerFamily: !!req.user.isOwnerFamily,
  });
});

app.post('/api/account/theme', auth, async (req, res) => {
  const { theme } = req.body || {};
  if (theme !== 'light' && theme !== 'dark') {
    return res.status(400).json({ error: "Theme must be 'light' or 'dark'" });
  }
  await pool.query('UPDATE users SET theme = $1 WHERE id = $2', [theme, req.user.userId]);
  res.json({ ok: true });
});

app.post('/api/account/profile', auth, async (req, res) => {
  const { firstName, lastName } = req.body || {};
  await pool.query(
    'UPDATE users SET first_name = $1, last_name = $2 WHERE id = $3',
    [(firstName || '').trim() || null, (lastName || '').trim() || null, req.user.userId]
  );
  res.json({ ok: true });
});

const ACCENT_COLOR_RE = /^#[0-9a-fA-F]{6}$/;
app.post('/api/account/accent-color', auth, async (req, res) => {
  const { color } = req.body || {};
  if (color !== null && !ACCENT_COLOR_RE.test(color || '')) {
    return res.status(400).json({ error: 'Color must be a hex value like #3A6E32, or null to reset' });
  }
  await pool.query('UPDATE users SET accent_color = $1 WHERE id = $2', [color, req.user.userId]);
  res.json({ ok: true });
});

app.post('/api/account/change-password', auth, async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Current and new password are required' });
  if (newPassword.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters' });
  const { rows } = await pool.query('SELECT password_hash FROM users WHERE id = $1', [req.user.userId]);
  if (!rows[0] || !(await bcrypt.compare(currentPassword, rows[0].password_hash))) {
    return res.status(401).json({ error: 'Current password is incorrect' });
  }
  const hash = await bcrypt.hash(newPassword, 10);
  await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, req.user.userId]);
  res.json({ ok: true });
});

app.post('/api/account/change-email', auth, async (req, res) => {
  const { password, newEmail } = req.body || {};
  if (!password || !newEmail) return res.status(400).json({ error: 'Password and new email are required' });
  const { rows } = await pool.query('SELECT password_hash FROM users WHERE id = $1', [req.user.userId]);
  if (!rows[0] || !(await bcrypt.compare(password, rows[0].password_hash))) {
    return res.status(401).json({ error: 'Password is incorrect' });
  }
  try {
    await pool.query('UPDATE users SET email = $1 WHERE id = $2', [newEmail, req.user.userId]);
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'That email is already in use' });
    throw e;
  }
  res.json({ ok: true });
});

// Public lookup so the signup screen can tell someone whether their code joins an
// existing household or starts a brand-new one, before they commit to an account.
// Deliberately doesn't return the household's name — just the shape of what happens.
app.get('/api/invites/:code', async (req, res) => {
  const { rows } = await pool.query(
    'SELECT family_id, expires_at, redeemed_at FROM invites WHERE code = $1',
    [req.params.code]
  );
  if (!rows.length) return res.json({ valid: false });
  const inv = rows[0];
  const valid = !inv.redeemed_at && new Date(inv.expires_at) > new Date();
  if (!valid) return res.json({ valid: false });
  res.json({ valid: true, newFamily: inv.family_id === null });
});

app.post('/api/signup', async (req, res) => {
  const { inviteCode, email, password, familyName } = req.body || {};
  if (!inviteCode || !email || !password) {
    return res.status(400).json({ error: 'inviteCode, email and password are required' });
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows: redeemed } = await client.query(
      `UPDATE invites SET redeemed_at = now()
       WHERE code = $1 AND redeemed_at IS NULL AND expires_at > now()
       RETURNING family_id`,
      [inviteCode]
    );
    if (!redeemed.length) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Invalid, used, or expired invite code' });
    }

    let familyId = redeemed[0].family_id;
    let role = 'member';
    if (!familyId) {
      const { rows: fam } = await client.query(
        'INSERT INTO families (name, is_owner_family, credits) VALUES ($1, false, 0) RETURNING id',
        [familyName || 'My Family']
      );
      familyId = fam[0].id;
      role = 'owner'; // creator of a brand-new family manages that household
    }

    const hash = await bcrypt.hash(password, 10);
    let user;
    try {
      const { rows: userRows } = await client.query(
        `INSERT INTO users (family_id, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING *`,
        [familyId, email, hash, role]
      );
      user = userRows[0];
    } catch (e) {
      await client.query('ROLLBACK');
      if (e.code === '23505') return res.status(409).json({ error: 'An account with that email already exists' });
      throw e;
    }
    await client.query('UPDATE invites SET redeemed_by_user_id = $1 WHERE code = $2', [user.id, inviteCode]);
    await client.query('COMMIT');
    res.json({ token: await signToken(user) });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
});

app.post('/api/invites', auth, async (req, res) => {
  const { newFamily } = req.body || {};
  if (newFamily && !req.user.isOwnerFamily) {
    return res.status(403).json({ error: 'Only the owner household can create new-family invites' });
  }
  const scopeFamilyId = newFamily ? null : req.user.familyId;
  const code = crypto.randomBytes(16).toString('hex');
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  await pool.query(
    'INSERT INTO invites (code, family_id, created_by_user_id, expires_at) VALUES ($1, $2, $3, $4)',
    [code, scopeFamilyId, req.user.userId, expiresAt]
  );
  await logAudit(req.user.familyId, req.user.userId, newFamily ? 'create_new_family_invite' : 'create_invite', null);
  res.json({ code, expiresAt, newFamily: scopeFamilyId === null });
});

app.get('/api/family/members', auth, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id, email, role, first_name, last_name, created_at FROM users WHERE family_id = $1 ORDER BY created_at',
    [req.user.familyId]
  );
  res.json({ members: rows });
});

// Owner-only: generates a random temporary password for a member who's locked out.
// Returned once in the response — there's no email/reset-link flow yet, so the owner
// has to relay it to the member directly.
app.post('/api/family/members/:id/reset-password', auth, async (req, res) => {
  const targetId = Number(req.params.id);
  if (!targetId) return res.status(400).json({ error: 'Invalid member id' });
  const { rows: caller } = await pool.query('SELECT role FROM users WHERE id = $1', [req.user.userId]);
  if (!caller[0] || caller[0].role !== 'owner') {
    return res.status(403).json({ error: 'Only the household owner can do this' });
  }
  const { rows: target } = await pool.query('SELECT id, email FROM users WHERE id = $1 AND family_id = $2', [targetId, req.user.familyId]);
  if (!target.length) return res.status(404).json({ error: 'Member not found in your household' });

  const tempPassword = crypto.randomBytes(6).toString('base64url');
  const hash = await bcrypt.hash(tempPassword, 10);
  await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, targetId]);
  await logAudit(req.user.familyId, req.user.userId, 'reset_member_password', target[0].email);
  res.json({ ok: true, tempPassword });
});

app.delete('/api/family/members/:id', auth, async (req, res) => {
  const targetId = Number(req.params.id);
  if (!targetId) return res.status(400).json({ error: 'Invalid member id' });
  const { rows: target } = await pool.query('SELECT id, email FROM users WHERE id = $1 AND family_id = $2', [targetId, req.user.familyId]);
  if (!target.length) return res.status(404).json({ error: 'Member not found in your household' });

  if (targetId !== req.user.userId) {
    // Removing someone else requires household-owner role
    const { rows: caller } = await pool.query('SELECT role FROM users WHERE id = $1', [req.user.userId]);
    if (!caller[0] || caller[0].role !== 'owner') {
      return res.status(403).json({ error: 'Only the household owner can remove members' });
    }
  }

  // Detach invite references so the FK constraints allow the delete
  await pool.query('UPDATE invites SET created_by_user_id = NULL WHERE created_by_user_id = $1', [targetId]);
  await pool.query('UPDATE invites SET redeemed_by_user_id = NULL WHERE redeemed_by_user_id = $1', [targetId]);
  await pool.query('DELETE FROM users WHERE id = $1', [targetId]);
  if (targetId !== req.user.userId) {
    await logAudit(req.user.familyId, req.user.userId, 'remove_member', target[0].email);
  }
  res.json({ ok: true, left: targetId === req.user.userId });
});

// Splits a member who joined the wrong household into their own brand-new one —
// e.g. someone accidentally used a shared-family invite code instead of a new-family
// code. Keeps their login intact; they just start fresh with no shared data. Anyone
// can always split themselves off; splitting someone else off requires being owner.
app.post('/api/family/members/:id/split-off', auth, async (req, res) => {
  const targetId = Number(req.params.id);
  if (!targetId) return res.status(400).json({ error: 'Invalid member id' });
  const isSelf = targetId === req.user.userId;
  if (!isSelf) {
    const { rows: caller } = await pool.query('SELECT role FROM users WHERE id = $1', [req.user.userId]);
    if (!caller[0] || caller[0].role !== 'owner') {
      return res.status(403).json({ error: 'Only the household owner can do this' });
    }
  }
  const { rows: target } = await pool.query('SELECT id, email FROM users WHERE id = $1 AND family_id = $2', [targetId, req.user.familyId]);
  if (!target.length) return res.status(404).json({ error: 'Member not found in your household' });

  const { familyName } = req.body || {};
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows: fam } = await client.query(
      'INSERT INTO families (name, is_owner_family, credits) VALUES ($1, false, 0) RETURNING id',
      [familyName || (target[0].email.split('@')[0] + "'s Household")]
    );
    await client.query('UPDATE users SET family_id = $1, role = $2 WHERE id = $3', [fam[0].id, 'owner', targetId]);
    await client.query('COMMIT');
    await logAudit(req.user.familyId, req.user.userId, isSelf ? 'self_split_off' : 'split_off_member', target[0].email);
    res.json({ ok: true, newFamilyId: fam[0].id });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
});

app.get('/api/admin/families', auth, async (req, res) => {
  if (!req.user.isOwnerFamily) return res.status(403).json({ error: 'Owner access only' });
  const { rows } = await pool.query(`
    SELECT f.id, f.name, f.credits, f.is_owner_family, f.created_at,
      COUNT(u.id)::int AS member_count,
      MAX(u.last_seen_at) AS last_seen_at,
      COALESCE((SELECT jsonb_array_length(value) FROM app_state WHERE family_id=f.id AND key='inventory' AND jsonb_typeof(value)='array'), 0) AS inventory_count,
      COALESCE((SELECT jsonb_array_length(value) FROM app_state WHERE family_id=f.id AND key='cookbook' AND jsonb_typeof(value)='array'), 0) AS cookbook_count,
      COALESCE((SELECT jsonb_array_length(value) FROM app_state WHERE family_id=f.id AND key='grocery' AND jsonb_typeof(value)='array'), 0) AS grocery_count,
      COALESCE((SELECT count(*) FROM jsonb_object_keys(
        COALESCE((SELECT value FROM app_state WHERE family_id=f.id AND key='planner' AND jsonb_typeof(value)='object'), '{}'::jsonb)
      )), 0)::int AS planner_days
    FROM families f LEFT JOIN users u ON u.family_id = f.id
    GROUP BY f.id ORDER BY f.created_at ASC
  `);
  res.json({ families: rows });
});

// Owner-only: full read-only snapshot of another household's data, for effectiveness
// tracking. Every call is audit-logged under the owner's own family.
app.get('/api/admin/families/:id/data', auth, async (req, res) => {
  if (!req.user.isOwnerFamily) return res.status(403).json({ error: 'Owner access only' });
  const { rows: caller } = await pool.query('SELECT role FROM users WHERE id = $1', [req.user.userId]);
  if (!caller[0] || caller[0].role !== 'owner') return res.status(403).json({ error: 'Owner access only' });
  const targetId = Number(req.params.id);
  if (!targetId) return res.status(400).json({ error: 'Invalid household id' });
  const { rows: fam } = await pool.query('SELECT id, name FROM families WHERE id = $1', [targetId]);
  if (!fam.length) return res.status(404).json({ error: 'Household not found' });

  const { rows: stateRows } = await pool.query('SELECT key, value FROM app_state WHERE family_id = $1', [targetId]);
  const state = {};
  stateRows.forEach(r => { state[r.key] = r.value; });
  const { rows: members } = await pool.query(
    'SELECT email, first_name, last_name, role, last_seen_at, created_at FROM users WHERE family_id = $1 ORDER BY created_at', [targetId]
  );

  await logAudit(req.user.familyId, req.user.userId, 'view_family_data', fam[0].name);
  res.json({ family: fam[0], members, state });
});

app.get('/api/family/audit-log', auth, async (req, res) => {
  const { rows: caller } = await pool.query('SELECT role FROM users WHERE id = $1', [req.user.userId]);
  if (!caller[0] || caller[0].role !== 'owner') return res.status(403).json({ error: 'Owner access only' });
  const { rows } = await pool.query(
    'SELECT actor_email, action, target_email, created_at FROM admin_audit_log WHERE family_id = $1 ORDER BY created_at DESC LIMIT 50',
    [req.user.familyId]
  );
  res.json({ entries: rows });
});

app.get('/api/state', auth, async (req, res) => {
  const { rows } = await pool.query('SELECT key, value FROM app_state WHERE family_id = $1', [req.user.familyId]);
  const state = {};
  rows.forEach(r => { state[r.key] = r.value; });
  res.json(state);
});

app.put('/api/state/:key', auth, async (req, res) => {
  const { key } = req.params;
  if (!STATE_KEYS.includes(key)) {
    return res.status(400).json({ error: 'Unknown state key' });
  }
  await pool.query(
    `INSERT INTO app_state (family_id, key, value, updated_at) VALUES ($1, $2, $3, now())
     ON CONFLICT (family_id, key) DO UPDATE SET value = $3, updated_at = now()`,
    [req.user.familyId, key, JSON.stringify(req.body)]
  );
  res.json({ ok: true });
});

app.get('/api/credits', auth, async (req, res) => {
  const { rows } = await pool.query('SELECT credits FROM families WHERE id = $1', [req.user.familyId]);
  res.json({ credits: rows[0] ? rows[0].credits : 0 });
});

app.post('/api/checkout', auth, async (req, res) => {
  if (!stripe) return res.status(500).json({ error: 'Stripe is not configured' });
  const pack = CREDIT_PACKS[(req.body || {}).pack] || CREDIT_PACKS.small;
  const origin = `${req.protocol}://${req.get('host')}`;
  const session = await stripe.checkout.sessions.create({
    mode: 'payment',
    line_items: [{
      price_data: {
        currency: 'usd',
        product_data: { name: `PantryPal Recipe Credits (${pack.credits})` },
        unit_amount: pack.amountCents,
      },
      quantity: 1,
    }],
    client_reference_id: String(req.user.familyId),
    metadata: { familyId: String(req.user.familyId), credits: String(pack.credits) },
    success_url: `${origin}/?checkout=success`,
    cancel_url: `${origin}/?checkout=cancel`,
  });
  res.json({ url: session.url });
});

app.get('/api/billing/history', auth, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT credits, amount_cents, created_at FROM credit_purchases WHERE family_id = $1 ORDER BY created_at DESC LIMIT 50',
    [req.user.familyId]
  );
  res.json({ purchases: rows });
});

app.post('/api/generate-recipe', auth, async (req, res) => {
  if (!ANTHROPIC_API_KEY) {
    return res.status(500).json({ error: 'ANTHROPIC_API_KEY is not configured' });
  }
  const { system, messages, max_tokens } = req.body || {};
  if (!Array.isArray(messages)) {
    return res.status(400).json({ error: 'messages array is required' });
  }

  const { rows: spend } = await pool.query(
    'UPDATE families SET credits = credits - 1 WHERE id = $1 AND (credits IS NULL OR credits >= 1) RETURNING credits',
    [req.user.familyId]
  );
  if (!spend.length) return res.status(402).json({ error: 'Out of credits' });

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-5',
        max_tokens: max_tokens || 1000,
        system,
        messages,
      }),
    });
    const data = await response.json();
    if (!response.ok) console.error('Anthropic API error:', response.status, data);
    else if (data.stop_reason && data.stop_reason !== 'end_turn') console.error('Anthropic response cut short:', data.stop_reason);
    res.status(response.status).json(data);
  } catch (e) {
    res.status(502).json({ error: 'Failed to reach Anthropic API' });
  }
});

const PORT = process.env.PORT || 3000;
initDB().then(() => {
  app.listen(PORT, () => console.log(`PantryPal server running on port ${PORT}`));
});
