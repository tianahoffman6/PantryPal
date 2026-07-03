const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');

const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';
const SHARED_EMAIL = process.env.SHARED_EMAIL || 'household@home.com';
const SHARED_PASSWORD = process.env.SHARED_PASSWORD || 'changeme';
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;

const STATE_KEYS = ['inventory', 'grocery', 'cookbook', 'planner', 'settings'];

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_state (
      key TEXT PRIMARY KEY,
      value JSONB NOT NULL,
      updated_at TIMESTAMPTZ DEFAULT now()
    );
  `);
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

app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  if (email !== SHARED_EMAIL || password !== SHARED_PASSWORD) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token });
});

app.get('/api/state', auth, async (req, res) => {
  const { rows } = await pool.query('SELECT key, value FROM app_state');
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
    `INSERT INTO app_state (key, value, updated_at) VALUES ($1, $2, now())
     ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = now()`,
    [key, JSON.stringify(req.body)]
  );
  res.json({ ok: true });
});

app.post('/api/generate-recipe', auth, async (req, res) => {
  if (!ANTHROPIC_API_KEY) {
    return res.status(500).json({ error: 'ANTHROPIC_API_KEY is not configured' });
  }
  const { system, messages, max_tokens } = req.body || {};
  if (!Array.isArray(messages)) {
    return res.status(400).json({ error: 'messages array is required' });
  }
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
    res.status(response.status).json(data);
  } catch (e) {
    res.status(502).json({ error: 'Failed to reach Anthropic API' });
  }
});

const PORT = process.env.PORT || 3000;
initDB().then(() => {
  app.listen(PORT, () => console.log(`PantryPal server running on port ${PORT}`));
});
