const express = require('express');
const Database = require('better-sqlite3');
const crypto = require('node:crypto');
const path = require('node:path');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'data', 'heukwol.sqlite');
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin0000';
const SESSION_DAYS = 7;

require('node:fs').mkdirSync(path.dirname(DB_FILE), { recursive: true });
const db = new Database(DB_FILE);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT NOT NULL UNIQUE,
 password_salt TEXT NOT NULL,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('admin','staff')),
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS applications (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 callname TEXT NOT NULL,
 age TEXT NOT NULL,
 contact TEXT NOT NULL,
 activity_time TEXT NOT NULL,
 reason TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT '접수',
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ledger (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 type TEXT NOT NULL CHECK(type IN ('수입','지출')),
 description TEXT NOT NULL,
 amount INTEGER NOT NULL CHECK(amount > 0),
 created_by INTEGER NOT NULL REFERENCES users(id),
 created_at TEXT NOT NULL
);
`);

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
 const hash = crypto.scryptSync(password, salt, 64).toString('hex');
 return { salt, hash };
}
function createUser(username, password, role) {
 const { salt, hash } = hashPassword(password);
 db.prepare('INSERT INTO users (username,password_salt,password_hash,role,created_at) VALUES (?,?,?,?,?)')
   .run(username, salt, hash, role, new Date().toISOString());
}
const existingAdmin = db.prepare('SELECT id FROM users WHERE username = ?').get(ADMIN_USERNAME);
if (!existingAdmin) createUser(ADMIN_USERNAME, ADMIN_PASSWORD, 'admin');

app.disable('x-powered-by');
app.use(express.json({ limit: '32kb' }));
app.use(express.urlencoded({ extended: false, limit: '32kb' }));
app.use((req, res, next) => {
 res.setHeader('X-Content-Type-Options', 'nosniff');
 res.setHeader('Referrer-Policy', 'same-origin');
 res.setHeader('X-Frame-Options', 'DENY');
 next();
});
app.use(express.static(path.join(__dirname, 'public')));

const COOKIE_NAME = 'heukwol_session';
function cookieValue(req, name) {
 const entry = (req.headers.cookie || '').split(';').map(x => x.trim()).find(x => x.startsWith(name + '='));
 return entry ? decodeURIComponent(entry.slice(name.length + 1)) : null;
}
function setSessionCookie(res, token) {
 const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
 res.setHeader('Set-Cookie', `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_DAYS * 86400}${secure}`);
}
function clearSessionCookie(res) {
 const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
 res.setHeader('Set-Cookie', `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure}`);
}
function currentUser(req) {
 const token = cookieValue(req, COOKIE_NAME);
 if (!token) return null;
 const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
 const session = db.prepare(`SELECT users.id, users.username, users.role, sessions.expires_at
   FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=?`).get(tokenHash);
 if (!session || session.expires_at < Date.now()) {
   db.prepare('DELETE FROM sessions WHERE token_hash=?').run(tokenHash);
   return null;
 }
 return { id: session.id, username: session.username, role: session.role };
}
function requireLogin(req, res, next) {
 const user = currentUser(req);
 if (!user) return res.status(401).json({ error: '로그인이 필요합니다.' });
 req.user = user; next();
}
function requireAdmin(req, res, next) {
 const user = currentUser(req);
 if (!user || user.role !== 'admin') return res.status(403).json({ error: '관리자 계정만 접근할 수 있습니다.' });
 req.user = user; next();
}
function cleanString(value, max) {
 if (typeof value !== 'string') return '';
 return value.trim().slice(0, max);
}
function validPassword(user, password) {
 const actual = crypto.scryptSync(password, user.password_salt, 64);
 const expected = Buffer.from(user.password_hash, 'hex');
 return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}
const loginAttempts = new Map();
function loginRateLimit(req, res, next) {
 const key = req.ip || req.socket.remoteAddress || 'unknown';
 const now = Date.now();
 const record = loginAttempts.get(key) || { count: 0, start: now };
 if (now - record.start > 15 * 60 * 1000) { record.count = 0; record.start = now; }
 if (record.count >= 20) return res.status(429).json({ error: '로그인 시도가 너무 많습니다. 15분 후 다시 시도하세요.' });
 req.loginAttemptKey = key; req.loginAttemptRecord = record; next();
}
app.post('/api/login', loginRateLimit, (req, res) => {
 const username = cleanString(req.body.username, 32);
 const password = typeof req.body.password === 'string' ? req.body.password : '';
 const user = db.prepare('SELECT * FROM users WHERE username=?').get(username);
 if (!user || !validPassword(user, password)) {
   const r = req.loginAttemptRecord; r.count++; loginAttempts.set(req.loginAttemptKey, r);
   return res.status(401).json({ error: '아이디 또는 비밀번호가 올바르지 않습니다.' });
 }
 loginAttempts.delete(req.loginAttemptKey);
 const token = crypto.randomBytes(32).toString('hex');
 const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
 db.prepare('INSERT INTO sessions (token_hash,user_id,expires_at) VALUES (?,?,?)')
   .run(tokenHash, user.id, Date.now() + SESSION_DAYS * 86400000);
 setSessionCookie(res, token);
 res.json({ user: { username: user.username, role: user.role } });
});
app.post('/api/logout', (req, res) => {
 const token = cookieValue(req, COOKIE_NAME);
 if (token) db.prepare('DELETE FROM sessions WHERE token_hash=?').run(crypto.createHash('sha256').update(token).digest('hex'));
 clearSessionCookie(res); res.json({ ok: true });
});
app.get('/api/me', (req, res) => {
 const user = currentUser(req);
 res.json({ user: user ? { username: user.username, role: user.role } : null });
});
app.post('/api/staff', requireAdmin, (req, res) => {
 const username = cleanString(req.body.username, 32);
 const password = typeof req.body.password === 'string' ? req.body.password : '';
 if (!/^[A-Za-z0-9_-]{3,32}$/.test(username)) return res.status(400).json({ error: '아이디는 영문, 숫자, 밑줄, 하이픈으로 3~32자여야 합니다.' });
 if (password.length < 8 || password.length > 128) return res.status(400).json({ error: '비밀번호는 8~128자여야 합니다.' });
 try { createUser(username, password, 'staff'); res.status(201).json({ ok: true }); }
 catch { res.status(409).json({ error: '이미 사용 중인 아이디입니다.' }); }
});
app.post('/api/apply', (req, res) => {
 const callname = cleanString(req.body.callname, 30);
 const age = cleanString(req.body.age, 30);
 const contact = cleanString(req.body.contact, 80);
 const activityTime = cleanString(req.body.time, 80);
 const reason = cleanString(req.body.reason, 1000);
 if (!callname || !age || !contact || !activityTime || !reason || req.body.agree !== true) {
   return res.status(400).json({ error: '모든 필수 항목을 입력하고 동의 항목을 체크해 주세요.' });
 }
 const result = db.prepare('INSERT INTO applications (callname,age,contact,activity_time,reason,status,created_at) VALUES (?,?,?,?,?,?,?)')
   .run(callname, age, contact, activityTime, reason, '접수', new Date().toISOString());
 res.status(201).json({ ok: true, id: result.lastInsertRowid });
});
app.get('/api/applications', requireAdmin, (req, res) => {
 const applications = db.prepare('SELECT id,callname,age,contact,activity_time AS time,reason,status,created_at FROM applications ORDER BY id DESC').all();
 res.json({ applications });
});
app.patch('/api/applications/:id/status', requireAdmin, (req, res) => {
 const status = cleanString(req.body.status, 20);
 if (!['검토 중','승인','거절'].includes(status)) return res.status(400).json({ error: '올바르지 않은 상태입니다.' });
 const result = db.prepare('UPDATE applications SET status=? WHERE id=?').run(status, Number(req.params.id));
 if (!result.changes) return res.status(404).json({ error: '지원서를 찾을 수 없습니다.' });
 res.json({ ok: true });
});
app.get('/api/ledger', requireLogin, (req, res) => {
 const rows = db.prepare(`SELECT ledger.id, ledger.type, ledger.description, ledger.amount, ledger.created_at,
   users.username AS created_by FROM ledger JOIN users ON users.id=ledger.created_by ORDER BY ledger.id DESC LIMIT 100`).all();
 res.json({ ledger: rows });
});
app.post('/api/ledger', requireLogin, (req, res) => {
 const type = req.body.type;
 const description = cleanString(req.body.description, 120);
 const amount = Number(req.body.amount);
 if (!['수입','지출'].includes(type) || !description || !Number.isSafeInteger(amount) || amount < 1 || amount > 1000000000000) {
   return res.status(400).json({ error: '구분, 항목명, 금액을 올바르게 입력해 주세요.' });
 }
 const result = db.prepare('INSERT INTO ledger (type,description,amount,created_by,created_at) VALUES (?,?,?,?,?)')
   .run(type, description, amount, req.user.id, new Date().toISOString());
 res.status(201).json({ ok: true, id: result.lastInsertRowid });
});
app.get('/api/health', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
 console.log(`Heukwol portal listening on port ${PORT}`);
 console.log(`Database: ${DB_FILE}`);
 if (ADMIN_PASSWORD === 'admin0000') console.warn('WARNING: Using default admin password. Set ADMIN_PASSWORD before public deployment.');
});
