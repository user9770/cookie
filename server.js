const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const SQLiteStore = require('connect-sqlite3')(session);

const app = express();
const PORT = 3000;

// ─── DATABASE SETUP ──────────────────────────────────────────────────────────
const db = new sqlite3.Database('./database.db', (err) => {
  if (err) return console.error('DB error:', err.message);
  console.log('✅ SQLite ulandi');
});

db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  dark_mode INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

// ─── MIDDLEWARE ───────────────────────────────────────────────────────────────
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  store: new SQLiteStore({ db: 'sessions.db', dir: './' }),
  secret: 'my-super-secret-key-2026',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 kun
    httpOnly: true,
    sameSite: 'lax'
  },
  name: 'myapp.sid'
}));

// Dark mode cookie ni sessiondan o'rnatish (login bo'lganda)
app.use((req, res, next) => {
  // Agar session bo'lsa lekin dark_mode cookie yo'q bo'lsa - o'rnatamiz
  if (req.session.user && req.cookies === undefined) {
    // faqat session dan foydalanish yetarli
  }
  next();
});

// ─── AUTH MIDDLEWARE ──────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session.user) return next();
  res.redirect('/login');
}

// ─── ROUTES ───────────────────────────────────────────────────────────────────

// Bosh sahifa
app.get('/', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Register sahifasi
app.get('/register', (req, res) => {
  if (req.session.user) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

// Login sahifasi
app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// ─── API ROUTES ───────────────────────────────────────────────────────────────

// Register qilish
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.json({ success: false, message: 'Barcha maydonlarni to\'ldiring!' });
  }
  if (password.length < 6) {
    return res.json({ success: false, message: 'Parol kamida 6 ta belgi bo\'lishi kerak!' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  db.run(
    'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
    [username, email, hashedPassword],
    function (err) {
      if (err) {
        if (err.message.includes('UNIQUE')) {
          return res.json({ success: false, message: 'Bu username yoki email allaqachon mavjud!' });
        }
        return res.json({ success: false, message: 'Server xatosi!' });
      }

      // Avtomatik login
      req.session.user = { id: this.lastID, username, email, dark_mode: 0 };
      res.json({ success: true, message: 'Muvaffaqiyatli ro\'yxatdan o\'tdingiz!', redirect: '/' });
    }
  );
});

// Login qilish
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.json({ success: false, message: 'Email va parolni kiriting!' });
  }

  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err || !user) {
      return res.json({ success: false, message: 'Email yoki parol noto\'g\'ri!' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.json({ success: false, message: 'Email yoki parol noto\'g\'ri!' });
    }

    // Session o'rnatish - dark_mode DB dan olinadi (logout dan oldin saqlangan)
    req.session.user = {
      id: user.id,
      username: user.username,
      email: user.email,
      dark_mode: user.dark_mode
    };

    res.json({
      success: true,
      message: 'Xush kelibsiz!',
      redirect: '/',
      dark_mode: user.dark_mode // frontendga yuboramiz
    });
  });
});

// Logout
app.post('/api/logout', requireAuth, (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.json({ success: false });
    res.clearCookie('myapp.sid');
    res.json({ success: true, redirect: '/login' });
  });
});

// Foydalanuvchi ma'lumotlarini olish
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ success: true, user: req.session.user });
});

// Dark mode ni saqlash (session + DB ga)
app.post('/api/dark-mode', requireAuth, (req, res) => {
  const { dark_mode } = req.body;
  const val = dark_mode ? 1 : 0;

  // Session yangilash
  req.session.user.dark_mode = val;

  // DB ga saqlash (logout bo'lganda ham esda qolsin)
  db.run(
    'UPDATE users SET dark_mode = ? WHERE id = ?',
    [val, req.session.user.id],
    (err) => {
      if (err) return res.json({ success: false, message: 'Saqlashda xato!' });
      res.json({ success: true, dark_mode: val });
    }
  );
});

// ─── START SERVER ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 Server ishga tushdi: http://localhost:${PORT}`);
});

