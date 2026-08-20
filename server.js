// ============================================
// server.js — Angkor AI Backend
// ============================================
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const Anthropic = require('@anthropic-ai/sdk');
const PDFDocument = require('pdfkit');
const { Document, Packer, Paragraph, TextRun } = require('docx');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const {
  createUser, createGoogleUser,
  findUserByEmail, findUserByGoogleId, findUserById, linkGoogleId,
  setResetToken, findUserByResetToken, resetPassword,
  saveMessage, getMessages, clearHistory,
  saveFact, getFacts, deleteFact,
  getAllUsers, getTodayMessageCount,
} = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

const DOWNLOADS_DIR = path.join(__dirname, 'public', 'downloads');
if (!fs.existsSync(DOWNLOADS_DIR)) fs.mkdirSync(DOWNLOADS_DIR, { recursive: true });

app.use(cors());
app.use(express.json({ limit: '25mb' }));
app.use(express.static('public'));
app.use('/admin_panel', express.static('admin'));

// ============================================
// STARTUP CHECKS — fail fast with a clear message instead of a confusing crash later
// ============================================
const REQUIRED_ENV = ['ANTHROPIC_API_KEY', 'JWT_SECRET'];
for (const key of REQUIRED_ENV) {
  if (!process.env[key]) {
    console.error(`❌ Missing ${key} in .env — copy .env.example to .env and fill it in.`);
    process.exit(1);
  }
}
if (!process.env.GOOGLE_CLIENT_ID) {
  console.warn('⚠️  GOOGLE_CLIENT_ID not set — Google Sign In will not work until you add it.');
}

const JWT_SECRET = process.env.JWT_SECRET;
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
const googleClient = process.env.GOOGLE_CLIENT_ID ? new OAuth2Client(process.env.GOOGLE_CLIENT_ID) : null;

// ============================================
// AUTH MIDDLEWARE
// ============================================
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'សូម Sign in ជាមុនសិន' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.userId;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Session ផុតកំណត់ សូម Sign in ម្តងទៀត' });
  }
}

function requireAdmin(req, res, next) {
  const user = findUserById(req.userId);
  if (!user || !user.is_admin) return res.status(403).json({ error: 'តម្រូវសិទ្ធិ Admin' });
  next();
}

function signToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '30d' });
}

// ============================================
// AUTH ENDPOINTS
// ============================================
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, name, grade } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email និង password ត្រូវការ' });
    if (password.length < 8) return res.status(400).json({ error: 'Password ត្រូវការយ៉ាងតិច ៨ តួអក្សរ' });
    if (findUserByEmail(email)) return res.status(409).json({ error: 'Email នេះមានគណនីរួចហើយ' });

    const password_hash = await bcrypt.hash(password, 10);
    const info = createUser({ email: email.toLowerCase().trim(), password_hash, name, grade });
    const token = signToken(info.lastInsertRowid);
    res.json({ token, user: { id: info.lastInsertRowid, email, name, grade } });
  } catch (error) {
    console.error('Signup error:', error.message);
    res.status(500).json({ error: 'មិនអាចបង្កើតគណនីបានទេ' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email និង password ត្រូវការ' });

    const user = findUserByEmail(email);
    if (!user || !user.password_hash) return res.status(401).json({ error: 'Email ឬ password មិនត្រឹមត្រូវ' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Email ឬ password មិនត្រឹមត្រូវ' });

    const token = signToken(user.id);
    res.json({ token, user: { id: user.id, email: user.email, name: user.name, grade: user.grade } });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ error: 'មិនអាច Sign in បានទេ' });
  }
});

app.post('/api/auth/google', async (req, res) => {
  try {
    if (!googleClient) return res.status(500).json({ error: 'Google Sign In មិនទាន់ config នៅ server' });
    const { credential } = req.body;
    if (!credential) return res.status(400).json({ error: 'គ្មាន Google credential' });

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const { sub: googleId, email, name } = payload;

    let user = findUserByGoogleId(googleId);
    if (!user) {
      user = findUserByEmail(email);
      if (user) {
        linkGoogleId(user.id, googleId); // existing email account → link Google
      } else {
        const info = createGoogleUser({ email, google_id: googleId, name, grade: null });
        user = findUserById(info.lastInsertRowid);
      }
    }

    const token = signToken(user.id);
    res.json({ token, user: { id: user.id, email: user.email, name: user.name, grade: user.grade } });
  } catch (error) {
    console.error('Google auth error:', error.message);
    res.status(401).json({ error: 'Google Sign In បរាជ័យ — សូមសាកល្បងម្តងទៀត' });
  }
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  const user = findUserById(req.userId);
  if (!user) return res.status(404).json({ error: 'រកគណនីមិនឃើញ' });
  res.json({ user });
});

// ============================================
// FORGOT PASSWORD
// ============================================
// NOTE: This works fully for local testing right now — the reset link
// prints to the server console. To actually EMAIL the link to students,
// add an email service later (e.g. nodemailer + Gmail app password, or
// a service like Resend/SendGrid) and swap the console.log below for it.
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'សូមដាក់ email' });

    const user = findUserByEmail(email);
    // Always respond the same way whether or not the email exists —
    // this stops attackers from using this endpoint to discover which emails are registered.
    const genericMessage = 'បើ email នេះមានគណនី យើងបានផ្ញើ reset link ទៅហើយ';

    if (!user || !user.password_hash) {
      // no account, or Google-only account with no password to reset
      return res.json({ ok: true, message: genericMessage });
    }

    const token = crypto.randomBytes(32).toString('hex');
    const expiry = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour
    setResetToken(user.id, token, expiry);

    const resetLink = `${req.protocol}://${req.get('host')}/?reset_token=${token}`;
    console.log('\n📧 PASSWORD RESET LINK (copy this to the browser to test):');
    console.log(resetLink, '\n');

    // TODO once email service is configured: actually send resetLink to user.email

    res.json({ ok: true, message: genericMessage });
  } catch (error) {
    console.error('Forgot password error:', error.message);
    res.status(500).json({ error: 'មានបញ្ហា! សូមសាកល្បងម្តងទៀត' });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) return res.status(400).json({ error: 'ត្រូវការ token និង password ថ្មី' });
    if (newPassword.length < 8) return res.status(400).json({ error: 'Password ត្រូវការយ៉ាងតិច ៨ តួអក្សរ' });

    const user = findUserByResetToken(token);
    if (!user) return res.status(400).json({ error: 'Reset link មិនត្រឹមត្រូវ ឬផុតកំណត់ហើយ' });
    if (new Date(user.reset_token_expiry) < new Date()) {
      return res.status(400).json({ error: 'Reset link ផុតកំណត់ហើយ សូមស្នើសុំម្តងទៀត' });
    }

    const password_hash = await bcrypt.hash(newPassword, 10);
    resetPassword(user.id, password_hash);

    res.json({ ok: true });
  } catch (error) {
    console.error('Reset password error:', error.message);
    res.status(500).json({ error: 'មិនអាចប្តូរ password បានទេ' });
  }
});

// ============================================
// FILE GENERATION HELPERS
// ============================================
function slugify(text) {
  return text.toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 40) || 'document';
}

function createPDF(content, title) {
  const filename = `${slugify(title)}-${crypto.randomBytes(4).toString('hex')}.pdf`;
  const filepath = path.join(DOWNLOADS_DIR, filename);
  const doc = new PDFDocument({ margin: 50 });
  doc.pipe(fs.createWriteStream(filepath));
  doc.fontSize(18).text(title, { underline: true });
  doc.moveDown();
  doc.fontSize(12).text(content, { align: 'left' });
  doc.end();
  return filename;
}

async function createDocx(content, title) {
  const filename = `${slugify(title)}-${crypto.randomBytes(4).toString('hex')}.docx`;
  const filepath = path.join(DOWNLOADS_DIR, filename);
  const paragraphs = content.split('\n').map((line) => new Paragraph({ children: [new TextRun(line)] }));
  const doc = new Document({
    sections: [{
      children: [
        new Paragraph({ children: [new TextRun({ text: title, bold: true, size: 32 })] }),
        new Paragraph({ children: [new TextRun('')] }),
        ...paragraphs,
      ],
    }],
  });
  const buffer = await Packer.toBuffer(doc);
  fs.writeFileSync(filepath, buffer);
  return filename;
}

// Plain-text-based formats — no library needed, just write the raw content as-is
const PLAIN_TEXT_EXTENSIONS = ['txt', 'py', 'js', 'md', 'csv', 'json', 'html', 'css', 'java', 'cpp', 'c', 'sql', 'yaml', 'xml'];

function createPlainTextFile(content, title, ext) {
  const filename = `${slugify(title)}-${crypto.randomBytes(4).toString('hex')}.${ext}`;
  const filepath = path.join(DOWNLOADS_DIR, filename);
  fs.writeFileSync(filepath, content, 'utf8');
  return filename;
}

function safeCalculate(expression) {
  if (!/^[0-9+\-*/().\s]+$/.test(expression)) {
    throw new Error('កន្សោមមិនត្រឹមត្រូវ — អនុញ្ញាតតែលេខ និងសញ្ញា + - * / ( )');
  }
  const result = Function(`"use strict"; return (${expression});`)();
  if (typeof result !== 'number' || !isFinite(result)) throw new Error('លទ្ធផលមិនត្រឹមត្រូវ');
  return result;
}

// ============================================
// fetch_webpage — reads full page content (complements web_search snippets)
// Requires Node 18+ for global fetch()
// ============================================
async function fetchWebpageText(url) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
    const res = await fetch(url, { signal: controller.signal, headers: { 'User-Agent': 'AngkorAI/1.0' } });
    const html = await res.text();
    const text = html
      .replace(/<script[\s\S]*?<\/script>/gi, ' ')
      .replace(/<style[\s\S]*?<\/style>/gi, ' ')
      .replace(/<[^>]+>/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();
    return text.slice(0, 12000);
  } finally {
    clearTimeout(timeout);
  }
}

// ============================================
// TOOL DEFINITIONS
// ============================================
const tools = [
  {
    name: 'create_document',
    description:
      'បង្កើត file ពិត ដែល user អាចទាញយកបាន។ គាំទ្រច្រើនប្រភេទ: pdf, docx (Word), txt, py (Python), js (JavaScript), md (Markdown), csv, json, html, css, java, cpp, c, sql, yaml, xml។ ប្រើនៅពេល user ស្នើសុំ document, report, essay, code file, script, ឬអ្វីៗគួរផ្តល់ជា file ដើម្បីរក្សាទុក/run/ចែករំលែក — មិនមែនគ្រាន់តែបង្ហាញ code inline ក្នុងចម្លើយប៉ុណ្ណោះ។',
    input_schema: {
      type: 'object',
      properties: {
        title: { type: 'string', description: 'ចំណងជើង/ឈ្មោះ file' },
        content: { type: 'string', description: 'ខ្លឹមសារពេញលេញ (code ឬ text)' },
        format: {
          type: 'string',
          enum: ['pdf', 'docx', 'txt', 'py', 'js', 'md', 'csv', 'json', 'html', 'css', 'java', 'cpp', 'c', 'sql', 'yaml', 'xml'],
          description: 'ប្រភេទ file — ជ្រើសតាមខ្លឹមសារ (ឧទាហរណ៍ Python code → py, report → pdf ឬ docx)',
        },
      },
      required: ['title', 'content', 'format'],
    },
  },
  { type: 'web_search_20250305', name: 'web_search' },
  {
    name: 'fetch_webpage',
    description:
      'អាន ខ្លឹមសារ TEXT ពេញលេញ នៃ URL ជាក់លាក់មួយ (មិនមែនត្រឹមតែ snippet ខ្លីៗពី web_search ទេ)។ **សំខាន់: ត្រូវប្រើ tool នេះជានិច្ច** បន្ទាប់ពី web_search ពេល user ចង់ដឹងព័ត៌មានលម្អិត/ត្រឹមត្រូវនៃគេហទំព័រណាមួយ (ដូចជា admission requirements ពេញលេញ, official announcement, ខ្លឹមសារអត្ថបទ) — កុំពឹងផ្អែកតែ snippet ខ្លីៗ ដែលអាចមិនគ្រប់គ្រាន់ ឬហួសសម័យ។',
    input_schema: {
      type: 'object',
      properties: { url: { type: 'string', description: 'URL ពេញលេញ (ចាប់ផ្តើមដោយ http/https)' } },
      required: ['url'],
    },
  },
  {
    name: 'remember_fact',
    description: 'រក្សាទុកព័ត៌មានសំខាន់អំពី user ជាអចិន្ត្រៃយ៍ (ឈ្មោះ, grade, គោលដៅសិក្សា, ចំណូលចិត្ត)។',
    input_schema: {
      type: 'object',
      properties: { fact: { type: 'string', description: 'ព័ត៌មានខ្លីមួយប្រយោគ' } },
      required: ['fact'],
    },
  },
  {
    name: 'calculate',
    description: 'គណនាកន្សោមគណិតវិទ្យាឲ្យបានត្រឹមត្រូវ 100%។',
    input_schema: {
      type: 'object',
      properties: { expression: { type: 'string', description: 'ឧទាហរណ៍ "1500 * 1.08"' } },
      required: ['expression'],
    },
  },
  {
    name: 'get_datetime',
    description: 'ទាញយកកាលបរិច្ឆេទ/ម៉ោងបច្ចុប្បន្នពិត។',
    input_schema: { type: 'object', properties: {} },
  },
];

// ============================================
// MAIN CHAT ENDPOINT
// ============================================
app.post('/api/chat', requireAuth, async (req, res) => {
  try {
    const { message, attachment } = req.body;
    if (!message && !attachment) return res.status(400).json({ error: 'សូមផ្ញើសារ' });

    const user = findUserById(req.userId);
    const pastMessages = getMessages(req.userId).map((m) => ({ role: m.role, content: m.content }));
    const facts = getFacts(req.userId);

    const memoryBlock = facts.length
      ? `\n\nរឿងដែលអ្នកចាំពី student នេះ (ប្រើដោយធម្មជាតិ):\n${facts.map((f) => `- ${f.fact}`).join('\n')}`
      : '';
    const gradeBlock = user?.grade ? `\nStudent នេះនៅ Grade ${user.grade}.` : '';

    const systemPrompt = `អ្នកឈ្មោះ Angkor AI — ជំនួយការសិក្សាសម្រាប់និស្សិតកម្ពុជា។ ចម្លើយជាភាសាខ្មែរជាលំនាំដើម លុះត្រាតែ user សរសេរជាភាសាអង់គ្លេស។ អត្តចរិក: កក់ក្តៅ, ជួយបានពិតប្រាកដ, ស្មោះត្រង់។

ការប្រើ tool ត្រឹមត្រូវ:
- ពេលស្វែងរកព័ត៌មាន ត្រូវប្រើ web_search មុន រួច **ត្រូវហៅ fetch_webpage** លើ URL ដែលពាក់ព័ន្ធបំផុត ដើម្បីអានខ្លឹមសារពេញលេញ កុំពឹងផ្អែកតែ snippet ខ្លីៗ
- ពេល user ចង់បាន code, script, report ឬអ្វីមួយសមគួរជា file ដាច់ដោយឡែក ត្រូវហៅ create_document ជានិច្ច (កុំគ្រាន់តែសរសេរ code inline ក្នុងចម្លើយ)${gradeBlock}${memoryBlock}`;

    const userContent = [];
    let attachmentLabel = null;
    if (attachment) {
      if (attachment.kind === 'image') {
        userContent.push({ type: 'image', source: { type: 'base64', media_type: attachment.mediaType, data: attachment.base64 } });
        attachmentLabel = `[image: ${attachment.name}]`;
      } else if (attachment.kind === 'pdf') {
        userContent.push({ type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: attachment.base64 } });
        attachmentLabel = `[pdf: ${attachment.name}]`;
      } else if (attachment.kind === 'text') {
        userContent.push({ type: 'text', text: `[Uploaded file: ${attachment.name}]\n---\n${attachment.textContent.slice(0, 30000)}\n---` });
        attachmentLabel = `[file: ${attachment.name}]`;
      }
    }
    userContent.push({ type: 'text', text: message || 'សូមមើល file នេះ' });

    let messages = [...pastMessages, { role: 'user', content: userContent }];
    saveMessage({ user_id: req.userId, role: 'user', content: message || attachmentLabel || '[attachment]' });

    let downloadUrl = null;
    let finalText = '';
    let usedWebSearch = false;
    let newFacts = [];

    for (let turn = 0; turn < 6; turn++) {
      const response = await anthropic.messages.create({
        model: 'claude-opus-5',
        max_tokens: 5000,
        system: systemPrompt,
        tools,
        messages,
      });

      const textBlocks = response.content.filter((b) => b.type === 'text');
      if (textBlocks.length) finalText += textBlocks.map((b) => b.text).join('\n');

      if (response.content.some((b) => b.type === 'server_tool_use' && b.name === 'web_search')) {
        usedWebSearch = true;
      }

      if (response.stop_reason !== 'tool_use') break;

      messages.push({ role: 'assistant', content: response.content });
      const toolResults = [];

      for (const block of response.content) {
        if (block.type !== 'tool_use') continue;

        if (block.name === 'create_document') {
          const { title, content, format = 'txt' } = block.input;
          let filename;
          if (format === 'docx') {
            filename = await createDocx(content, title);
          } else if (format === 'pdf') {
            filename = createPDF(content, title);
          } else if (PLAIN_TEXT_EXTENSIONS.includes(format)) {
            filename = createPlainTextFile(content, title, format);
          } else {
            filename = createPlainTextFile(content, title, 'txt'); // safe fallback, never crashes
          }
          downloadUrl = `/downloads/${filename}`;
          toolResults.push({ type: 'tool_result', tool_use_id: block.id, content: `File "${filename}" created successfully.` });
        }

        if (block.name === 'fetch_webpage') {
          try {
            const text = await fetchWebpageText(block.input.url);
            toolResults.push({ type: 'tool_result', tool_use_id: block.id, content: text || '(empty page)' });
          } catch (e) {
            toolResults.push({ type: 'tool_result', tool_use_id: block.id, content: `Error fetching page: ${e.message}`, is_error: true });
          }
        }

        if (block.name === 'remember_fact') {
          saveFact({ user_id: req.userId, fact: block.input.fact });
          newFacts.push(block.input.fact);
          toolResults.push({ type: 'tool_result', tool_use_id: block.id, content: `Remembered: "${block.input.fact}"` });
        }

        if (block.name === 'calculate') {
          try {
            const result = safeCalculate(block.input.expression);
            toolResults.push({ type: 'tool_result', tool_use_id: block.id, content: String(result) });
          } catch (e) {
            toolResults.push({ type: 'tool_result', tool_use_id: block.id, content: `Error: ${e.message}`, is_error: true });
          }
        }

        if (block.name === 'get_datetime') {
          toolResults.push({ type: 'tool_result', tool_use_id: block.id, content: new Date().toISOString() + ' (UTC)' });
        }
      }

      if (toolResults.length === 0) break;
      messages.push({ role: 'user', content: toolResults });
    }

    saveMessage({ user_id: req.userId, role: 'assistant', content: finalText, download_url: downloadUrl });
    res.json({ reply: finalText, downloadUrl, usedWebSearch, newFacts });
  } catch (error) {
    console.error('Chat error:', error.message);
    res.status(500).json({ error: 'មានបញ្ហា! សូមពិនិត្យ API key ឬ credit។', detail: error.message });
  }
});

// ============================================
// HISTORY / MEMORY / FILES
// ============================================
app.get('/api/history/me', requireAuth, (req, res) => {
  res.json({ history: getMessages(req.userId) });
});

app.delete('/api/history/me', requireAuth, (req, res) => {
  clearHistory(req.userId);
  res.json({ ok: true });
});

app.get('/api/memory/me', requireAuth, (req, res) => {
  res.json({ facts: getFacts(req.userId) });
});

app.delete('/api/memory/:factId', requireAuth, (req, res) => {
  deleteFact(req.params.factId);
  res.json({ ok: true });
});

app.get('/api/files', requireAuth, (req, res) => {
  const files = fs.readdirSync(DOWNLOADS_DIR)
    .filter((f) => f !== '.gitkeep')
    .map((f) => {
      const stat = fs.statSync(path.join(DOWNLOADS_DIR, f));
      return { name: f, url: `/downloads/${f}`, createdAt: stat.birthtime };
    })
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ files });
});

// ============================================
// ADMIN ENDPOINTS
// ============================================
app.get('/api/admin/users', requireAuth, requireAdmin, (req, res) => {
  res.json({ users: getAllUsers() });
});

app.get('/api/admin/stats', requireAuth, requireAdmin, (req, res) => {
  const users = getAllUsers();
  const todayCount = getTodayMessageCount();
  res.json({ totalStudents: users.length, messagesToday: todayCount.count });
});

app.get('/api/health', (req, res) => res.json({ status: 'ok', app: 'Angkor AI' }));

app.listen(PORT, () => {
  console.log(`✅ Angkor AI server running at http://localhost:${PORT}`);
  console.log(`   Admin panel at http://localhost:${PORT}/admin_panel`);
});
