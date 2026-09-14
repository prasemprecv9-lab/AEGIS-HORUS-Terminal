const express = require('express');
const session = require('express-session');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const db = new Database(process.env.DB_PATH || path.join(__dirname, 'aegis.db'));

db.exec(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  display_name TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'OPERADOR',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)`);

app.use(express.json({limit: '1mb'}));
app.use(express.urlencoded({extended: true, limit: '1mb'}));
app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 1000 * 60 * 60 * 24 * 7 }
}));

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  const [salt, expected] = stored.split(':');
  const actual = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(expected, 'hex'));
}
function publicUser(user) {
  return { id: user.id, username: user.username, displayName: user.display_name, role: user.role, createdAt: user.created_at };
}
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({error: 'AUTH_REQUIRED'});
  next();
}

app.get('/api/health', (_req, res) => res.json({ok: true, system: 'AEGIS // HORUS'}));
app.post('/api/register', (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const displayName = String(req.body.displayName || username).trim().slice(0, 80);
  if (!/^[a-z0-9_.-]{3,32}$/.test(username)) return res.status(400).json({error: 'INVALID_USERNAME'});
  if (password.length < 8) return res.status(400).json({error: 'WEAK_PASSWORD'});
  try {
    const info = db.prepare('INSERT INTO users (username,password_hash,display_name) VALUES (?,?,?)').run(username, hashPassword(password), displayName || username);
    req.session.userId = info.lastInsertRowid;
    const user = db.prepare('SELECT * FROM users WHERE id=?').get(info.lastInsertRowid);
    res.json({user: publicUser(user)});
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) return res.status(409).json({error: 'USERNAME_TAKEN'});
    res.status(500).json({error: 'REGISTER_FAILED'});
  }
});
app.post('/api/login', (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const user = db.prepare('SELECT * FROM users WHERE username=?').get(username);
  if (!user || !verifyPassword(password, user.password_hash)) return res.status(401).json({error: 'INVALID_CREDENTIALS'});
  req.session.userId = user.id;
  res.json({user: publicUser(user)});
});
app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ok: true})));
app.get('/api/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.session.userId);
  if (!user) return res.status(401).json({error: 'AUTH_REQUIRED'});
  res.json({user: publicUser(user)});
});
app.patch('/api/profile', requireAuth, (req, res) => {
  const displayName = String(req.body.displayName || '').trim().slice(0, 80);
  if (!displayName) return res.status(400).json({error: 'INVALID_DISPLAY_NAME'});
  db.prepare('UPDATE users SET display_name=? WHERE id=?').run(displayName, req.session.userId);
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.session.userId);
  res.json({user: publicUser(user)});
});
app.post('/api/change-password', requireAuth, (req, res) => {
  const current = String(req.body.currentPassword || '');
  const next = String(req.body.newPassword || '');
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.session.userId);
  if (!user || !verifyPassword(current, user.password_hash)) return res.status(401).json({error: 'INVALID_PASSWORD'});
  if (next.length < 8) return res.status(400).json({error: 'WEAK_PASSWORD'});
  db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(hashPassword(next), user.id);
  res.json({ok: true});
});

app.use(express.static(__dirname, {extensions: ['html']}));
app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.listen(PORT, '0.0.0.0', () => console.log(`AEGIS // HORUS online on ${PORT}`));
