const express = require('express');
const path = require('path');

const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;

app.post('/api/generate-recipe', async (req, res) => {
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
        model: 'claude-sonnet-4-6',
        max_tokens: max_tokens || 1000,
        system,
        messages,
      }),
    });
    const data = await response.json();
    res.status(response.status).json(data);
  } catch (e) {
    res.status(502).json({ error: 'Failed to reach Anthropic API' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`PantryPal server running on port ${PORT}`));
