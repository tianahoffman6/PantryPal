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
const CREDIT_PACK = { credits: 50, amountCents: 500 };

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
    const inserted = await pool.query('INSERT INTO stripe_events (id) VALUES ($1) ON CONFLICT DO NOTHING RETURNING id', [event.id]);
    if (inserted.rows.length && familyId) {
      await pool.query('UPDATE families SET credits = credits + $1 WHERE id = $2', [CREDIT_PACK.credits, familyId]);
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
    CREATE TABLE IF NOT EXISTS app_state (
      key TEXT PRIMARY KEY,
      value JSONB NOT NULL,
      updated_at TIMESTAMPTZ DEFAULT now()
    );
  `);
  await pool.query('ALTER TABLE app_state ADD COLUMN IF NOT EXISTS family_id INTEGER REFERENCES families(id)');
  await backfillOwnerFamily();
  await swapAppStatePrimaryKey();
}

function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(header.replace('Bearer ', ''), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function signToken(user) {
  return jwt.sign({ userId: user.id, familyId: user.family_id }, JWT_SECRET, { expiresIn: '30d' });
}

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
  const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  const user = rows[0];
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  res.json({ token: signToken(user) });
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
    if (!familyId) {
      const { rows: fam } = await client.query(
        'INSERT INTO families (name, is_owner_family, credits) VALUES ($1, false, 0) RETURNING id',
        [familyName || 'My Family']
      );
      familyId = fam[0].id;
    }

    const hash = await bcrypt.hash(password, 10);
    let user;
    try {
      const { rows: userRows } = await client.query(
        `INSERT INTO users (family_id, email, password_hash, role) VALUES ($1, $2, $3, 'member') RETURNING *`,
        [familyId, email, hash]
      );
      user = userRows[0];
    } catch (e) {
      await client.query('ROLLBACK');
      if (e.code === '23505') return res.status(409).json({ error: 'An account with that email already exists' });
      throw e;
    }
    await client.query('UPDATE invites SET redeemed_by_user_id = $1 WHERE code = $2', [user.id, inviteCode]);
    await client.query('COMMIT');
    res.json({ token: signToken(user) });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
});

app.post('/api/invites', auth, async (req, res) => {
  const code = crypto.randomBytes(16).toString('hex');
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  await pool.query(
    'INSERT INTO invites (code, family_id, created_by_user_id, expires_at) VALUES ($1, $2, $3, $4)',
    [code, req.user.familyId, req.user.userId, expiresAt]
  );
  res.json({ code, expiresAt });
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
  const origin = `${req.protocol}://${req.get('host')}`;
  const session = await stripe.checkout.sessions.create({
    mode: 'payment',
    line_items: [{
      price_data: {
        currency: 'usd',
        product_data: { name: `PantryPal Recipe Credits (${CREDIT_PACK.credits})` },
        unit_amount: CREDIT_PACK.amountCents,
      },
      quantity: 1,
    }],
    client_reference_id: String(req.user.familyId),
    metadata: { familyId: String(req.user.familyId) },
    success_url: `${origin}/?checkout=success`,
    cancel_url: `${origin}/?checkout=cancel`,
  });
  res.json({ url: session.url });
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
