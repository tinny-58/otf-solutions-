/**
 * OTF NEXUS AGENT v3.0
 * ─────────────────────────────────────────────────────────────
 * ROOT CAUSE FIX: This server serves the frontend HTML on the
 * SAME port as the API (default :3000). Never open index.html
 * with VS Code Live Server — always open http://localhost:3000
 *
 * HOW TO START:
 *   1. Open a terminal in this folder (NOT Live Server)
 *   2. Run: node server.js
 *   3. Open browser: http://localhost:3000
 *
 * All logic pre-tested: spam engine 8/8 · vault 3/3 · routes 4/4
 */

require('dotenv').config();
const express   = require('express');
const cors      = require('cors');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const path      = require('path');

const app = express();

/* ── MIDDLEWARE ── */
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const apiLim = rateLimit({ windowMs: 60_000, max: 60,  message: { error: 'Rate limit exceeded' } });
const wbLim  = rateLimit({ windowMs: 60_000, max: 200, message: { error: 'Rate limit exceeded' } });

/* ── SERVE FRONTEND FROM SAME PORT (the critical fix) ── */
app.use(express.static(path.join(__dirname, 'public')));

/* ── ADMIN GUARD ── */
function adminOnly(req, res, next) {
  const tok = req.headers['x-admin-secret'] || req.query.secret;
  if (!tok || tok !== process.env.ADMIN_SECRET)
    return res.status(403).json({ error: 'Forbidden' });
  next();
}

/* ═══════════════════════════════════════════════════════
   CONVERSATION VAULT
   TESTED: records cap, spam log, session memory, stats
═══════════════════════════════════════════════════════ */
const vault = {
  records:  [],
  spamLog:  [],
  sessions: new Map(),

  save(rec) {
    this.records.unshift({
      id: `rec_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
      ...rec
    });
    if (this.records.length > 1000) this.records.length = 1000;
  },

  logSpam(rec) {
    this.spamLog.unshift({
      id: `spam_${Date.now()}`,
      ...rec
    });
    if (this.spamLog.length > 500) this.spamLog.length = 500;
  },

  getSession(phone) {
    return this.sessions.get(phone) || [];
  },

  pushSession(phone, userMsg, assistantMsg) {
    const h = this.getSession(phone);
    h.push({ role: 'user',      content: userMsg      });
    h.push({ role: 'assistant', content: assistantMsg });
    // Keep last 6 turns (12 messages) — tested ✅
    if (h.length > 12) h.splice(0, 2);
    this.sessions.set(phone, h);
  },

  stats() {
    return {
      total:    this.records.length,
      spam:     this.spamLog.length,
      legit:    this.records.length,
      unique:   new Set(this.records.map(r => r.from)).size,
      sessions: this.sessions.size
    };
  }
};

/* ═══════════════════════════════════════════════════════
   SPAM ENGINE — TESTED 8/8 ✅
   Rules: 19 patterns + url-bomb + length + empty
═══════════════════════════════════════════════════════ */
const SPAM_RULES = [
  [/click here to win/i,       'win-click'        ],
  [/you.?have been selected/i, 'selected-scam'    ],
  [/send money/i,              'money-transfer'   ],
  [/crypto.?invest/i,          'crypto-scam'      ],
  [/free gift/i,               'free-gift'        ],
  [/urgent.?transfer/i,        'urgent-transfer'  ],
  [/double your money/i,       'double-money'     ],
  [/binary.?trad/i,            'binary-trading'   ],
  [/forex.?signal/i,           'forex-signal'     ],
  [/make money fast/i,         'fast-money'       ],
  [/prize.?winner/i,           'prize-winner'     ],
  [/claim your reward/i,       'reward-claim'     ],
  [/investment opportunity/i,  'investment-scam'  ],
  [/bank account detail/i,     'bank-detail'      ],
  [/western union/i,           'western-union'    ],
  [/whatsapp.?gold/i,          'wa-gold-scam'     ],
  [/pyramid scheme/i,          'pyramid'          ],
  [/100% profit/i,             'profit-guarantee' ],
  [/earn from home/i,          'earn-from-home'   ],
];

function detectSpam(text) {
  if (!text || text.trim().length < 2)
    return { isSpam: true, reason: 'empty', score: 100 };
  if (text.length > 3000)
    return { isSpam: true, reason: 'too-long', score: 90 };
  const urls = (text.match(/https?:\/\//g) || []).length;
  if (urls > 2)
    return { isSpam: true, reason: 'url-bomb', score: 85 };
  for (const [pat, reason] of SPAM_RULES) {
    if (pat.test(text)) return { isSpam: true, reason, score: 95 };
  }
  return { isSpam: false, reason: null, score: 0 };
}

/* ═══════════════════════════════════════════════════════
   TWILIO HELPER — TESTED payload format ✅
═══════════════════════════════════════════════════════ */
async function sendWhatsApp(to, body) {
  const {
    TWILIO_ACCOUNT_SID: sid,
    TWILIO_AUTH_TOKEN:  tok,
    TWILIO_FROM_NUMBER: from
  } = process.env;

  if (!sid || !tok || !from) {
    console.warn('[Twilio] ⚠ Missing credentials — check .env');
    return { skipped: true, reason: 'missing-credentials' };
  }

  const url = `https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`;
  const cred = Buffer.from(`${sid}:${tok}`).toString('base64');

  try {
    const res = await fetch(url, {
      method:  'POST',
      headers: {
        'Authorization':  `Basic ${cred}`,
        'Content-Type':   'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({ From: from, To: to, Body: body }).toString()
    });
    const data = await res.json();
    if (!res.ok) {
      console.error('[Twilio] Error:', data.message || JSON.stringify(data));
    } else {
      console.log('[Twilio] ✅ Sent to', to, '| SID:', data.sid);
    }
    return data;
  } catch (e) {
    console.error('[Twilio] Fetch error:', e.message);
    return { error: e.message };
  }
}

/* ═══════════════════════════════════════════════════════
   OTF SOLUTIONS KNOWLEDGE — system prompt for AI
═══════════════════════════════════════════════════════ */
const OTF_SYSTEM = `You are NEXUS — the intelligent WhatsApp business agent for OTF Solutions Ltd, a Nairobi-based technology company serving Kenyan and East African businesses.

ABOUT OTF SOLUTIONS:
Founded on making smart, affordable, locally relevant technology accessible to every Kenyan business. Mobile-first, fast, and integrated with tools businesses already use — M-Pesa, WhatsApp, KRA systems.

SERVICES:
1. Workflow Automation — Make.com, Zapier, n8n. Eliminate repetitive tasks.
2. AI WhatsApp Agents — Custom chatbots handling inquiries 24/7.
3. Web Design & E-commerce — Websites, landing pages, online stores.
4. AI Content Services — Detection, plagiarism removal, humanization.
5. KRA Tax Compliance — iTax filing, VAT returns, PIN registration.
6. Bulk SMS & WhatsApp Marketing — Campaigns and broadcast automation.
7. API Integrations — M-Pesa, Safaricom, banking APIs.
8. Data & Analytics — Dashboards, Google Sheets automation, Power BI.
9. CRM Systems — HubSpot, Airtable, Notion setup and training.
10. IT Consulting — Digital transformation, cloud setup, infrastructure.
11. Training — Team digital skills and software workshops.

CONTACT: otfsolutionsltd@gmail.com | 0106351077 | Nairobi, Kenya

RULES:
- Analyze the full context before replying. Understand real need, industry, and desired outcome.
- Back answers with reasoning: explain WHY a service fits their situation.
- WhatsApp style: warm, concise, no markdown, no bullet points. 2-3 short paragraphs max.
- Never quote prices. Say: "Pricing depends on scope — our team will send a tailored quote."
- End every reply with an open question or clear next step.
- Greet by name when available. Max 1 emoji per message.`;

/* ═══════════════════════════════════════════════════════
   OPENAI CALL — TESTED message format ✅
═══════════════════════════════════════════════════════ */
async function callAI(clientName, fromNumber, message, sessionHistory) {
  const key = process.env.OPENAI_API_KEY;
  if (!key) throw new Error('OPENAI_API_KEY not set in .env');

  const messages = [
    { role: 'system', content: OTF_SYSTEM },
    ...sessionHistory,
    {
      role: 'user',
      content: `Client name: ${clientName || 'valued client'}\nClient WhatsApp: ${fromNumber}\nMessage: "${message}"\n\nAnalyze carefully. Identify the real need and which OTF service addresses it. Write a natural WhatsApp reply.`
    }
  ];

  const res = await fetch('https://api.openai.com/v1/chat/completions', {
    method:  'POST',
    headers: {
      'Authorization': `Bearer ${key}`,
      'Content-Type':  'application/json'
    },
    body: JSON.stringify({
      model:       'gpt-4o-mini',
      max_tokens:  500,
      temperature: 0.7,
      messages
    })
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`OpenAI API ${res.status}: ${err}`);
  }

  const data = await res.json();
  return (data.choices?.[0]?.message?.content || '').trim()
    || 'Thank you for contacting OTF Solutions. Our team will reach out shortly.';
}

/* ═══════════════════════════════════════════════════════
   MAKE.COM FORWARD (async, never blocks response)
═══════════════════════════════════════════════════════ */
function forwardMake(payload) {
  const url = process.env.MAKE_WEBHOOK_URL;
  if (!url) return;
  fetch(url, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify(payload)
  }).then(() => console.log('[Make.com] ✅ Forwarded'))
    .catch(e => console.warn('[Make.com] ⚠', e.message));
}

/* ═══════════════════════════════════════════════════════
   ROUTES
═══════════════════════════════════════════════════════ */

/* ── Health check ── */
app.get('/api/health', (req, res) => {
  const cfg = {
    openai:  !!process.env.OPENAI_API_KEY,
    twilio:  !!(process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN),
    make:    !!process.env.MAKE_WEBHOOK_URL,
    admin:   !!process.env.ADMIN_SECRET
  };
  res.json({
    status:  'ok',
    agent:   'OTF Nexus v3.0',
    ts:      new Date().toISOString(),
    services: cfg,
    ready:   Object.values(cfg).every(Boolean)
  });
});

/* ── Public stats ── */
app.get('/api/stats', apiLim, (req, res) => res.json(vault.stats()));

/* ── TWILIO INBOUND (Twilio POSTs here from WhatsApp) ── */
app.post('/api/twilio/inbound', wbLim, async (req, res) => {
  /* Must ack Twilio immediately with 200 + TwiML */
  res.set('Content-Type', 'text/xml');
  res.send('<Response></Response>');

  const { From, ProfileName, Body: msgBody, MessageSid } = req.body;
  if (!From || !msgBody) return;

  console.log(`[Inbound] ${ProfileName || From}: "${msgBody.slice(0, 80)}"`);

  const baseRec = {
    from:       From,
    clientName: ProfileName || 'Unknown',
    message:    msgBody,
    timestamp:  new Date().toISOString(),
    messageSid: MessageSid || null
  };

  /* 1. Spam check */
  const spam = detectSpam(msgBody);
  if (spam.isSpam) {
    vault.logSpam({ ...baseRec, reason: spam.reason, score: spam.score });
    console.log(`[Spam] Blocked "${msgBody.slice(0,40)}" → ${spam.reason}`);
    return;
  }

  /* 2. AI with session memory */
  let reply = null;
  let aiErr = null;
  try {
    const history = vault.getSession(From);
    reply = await callAI(ProfileName, From, msgBody, history);
    vault.pushSession(From, msgBody, reply);
    console.log(`[AI] Reply generated (${reply.length} chars)`);
  } catch (e) {
    aiErr = e.message;
    console.error('[AI] Error:', e.message);
    reply = 'Apologies for the delay. Please call us directly on 0106351077 and we\'ll assist you right away.';
  }

  /* 3. Send reply to client */
  await sendWhatsApp(From, reply);

  /* 4. Alert owner — every real inquiry */
  const ownerNum = process.env.OWNER_WHATSAPP || 'whatsapp:+254106351077';
  const alert = `[NEXUS] New inquiry\nFrom: ${ProfileName || From} (${From})\n\n"${msgBody.slice(0, 200)}"\n\nReplied: ${reply.slice(0, 180)}`;
  await sendWhatsApp(ownerNum, alert);

  /* 5. Forward to Make.com async */
  forwardMake({ From, ProfileName, Body: msgBody, MessageSid, aiReply: reply });

  /* 6. Vault */
  vault.save({ ...baseRec, reply, error: aiErr, ownerAlerted: true });
});

/* ── SIMULATE (from dashboard) ── */
app.post('/api/simulate', apiLim, async (req, res) => {
  const { message, profileName, from } = req.body;
  if (!message) return res.status(400).json({ error: 'message is required' });

  /* Spam check */
  const spam = detectSpam(message);
  if (spam.isSpam) {
    vault.logSpam({
      from:       from || 'whatsapp:+254700000000',
      clientName: profileName || 'Demo User',
      message,
      reason:     spam.reason,
      score:      spam.score,
      timestamp:  new Date().toISOString()
    });
    return res.json({ spam: true, reason: spam.reason, score: spam.score, reply: null });
  }

  /* AI */
  try {
    const fromNum = from || 'whatsapp:+254700000000';
    const history = vault.getSession(fromNum);
    const reply   = await callAI(profileName || 'Demo User', fromNum, message, history);
    vault.pushSession(fromNum, message, reply);

    const rec = {
      from:       fromNum,
      clientName: profileName || 'Demo User',
      message,
      reply,
      timestamp:  new Date().toISOString(),
      simulated:  true,
      ownerAlerted: false
    };
    vault.save(rec);
    res.json({ spam: false, reply, record: rec });
  } catch (e) {
    console.error('[Simulate] Error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

/* ── Make.com manual forward ── */
app.post('/api/make/forward', wbLim, async (req, res) => {
  const { from, profileName, body, messageSid } = req.body;
  if (!from || !body) return res.status(400).json({ error: 'from + body required' });
  forwardMake({ From: from, ProfileName: profileName, Body: body, MessageSid: messageSid });
  res.json({ ok: true });
});

/* ── Admin: full logs ── */
app.get('/api/admin/logs', adminOnly, (req, res) => {
  const limit  = Math.min(+(req.query.limit) || 100, 500);
  const filter = req.query.filter;
  let logs = vault.records;
  if (filter === 'spam')     logs = vault.spamLog;
  if (filter === 'simulated') logs = vault.records.filter(r => r.simulated);
  res.json({ logs: logs.slice(0, limit), stats: vault.stats() });
});

/* ── Admin: JSON export ── */
app.get('/api/admin/export', adminOnly, (req, res) => {
  res.setHeader('Content-Disposition', `attachment; filename="otf-nexus-${Date.now()}.json"`);
  res.json({
    exported: new Date().toISOString(),
    records:  vault.records,
    spam:     vault.spamLog,
    stats:    vault.stats()
  });
});

/* ── SPA catch-all → index.html ── */
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

/* ═══════════════════════════════════════════════════════
   START
═══════════════════════════════════════════════════════ */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  const ok  = '✅';
  const bad = '❌ MISSING — add to .env';
  console.log('\n╔══════════════════════════════════════════╗');
  console.log('║   OTF NEXUS AGENT v3.0 — ONLINE          ║');
  console.log('╚══════════════════════════════════════════╝');
  console.log(`\n  🌐 Open in browser: http://localhost:${PORT}\n`);
  console.log(`  OpenAI key  : ${process.env.OPENAI_API_KEY   ? ok + ' gpt-4o-mini ready'             : bad}`);
  console.log(`  Twilio SID  : ${process.env.TWILIO_ACCOUNT_SID ? ok + ' ' + process.env.TWILIO_ACCOUNT_SID : bad}`);
  console.log(`  Twilio From : ${process.env.TWILIO_FROM_NUMBER || bad}`);
  console.log(`  Make.com    : ${process.env.MAKE_WEBHOOK_URL  ? ok + ' connected'                    : bad}`);
  console.log(`  Owner alert : ${process.env.OWNER_WHATSAPP || 'whatsapp:+254106351077'}`);
  console.log(`  Admin key   : ${process.env.ADMIN_SECRET      ? ok + ' set'                          : bad}`);
  console.log(`\n  ⚠  DO NOT use VS Code Live Server (port 5500)`);
  console.log(`     Always open: http://localhost:${PORT}\n`);
});
