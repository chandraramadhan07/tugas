const express = require('express');
const crypto  = require('crypto');
const path    = require('path');

const app  = express();
const PORT = 3000;

app.use(express.json());
app.use(express.static(__dirname)); // serve jwt-login.html

/* ==============================
   KONFIGURASI
============================== */
const JWT_SECRET = 'AuthSystem_S3cr3t_K3y_2024';
const JWT_EXPIRY = 3600; // 1 jam (detik)

const USERS = {
  admin:     { password: 'password123', role: 'admin',     name: 'Administrator' },
  mahasiswa: { password: 'kampus2024',  role: 'mahasiswa', name: 'Budi Santoso'  }
};

/* ==============================
   UTILITY JWT (tanpa library)
============================== */
function b64url(str) {
  return Buffer.from(str).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function generateJWT(username, role, name) {
  const header  = { alg: 'HS256', typ: 'JWT' };
  const now     = Math.floor(Date.now() / 1000);
  const payload = {
    sub:  username,
    name: name,
    role: role,
    iat:  now,
    exp:  now + JWT_EXPIRY,
    iss:  'authsystem.local'
  };

  const h   = b64url(JSON.stringify(header));
  const p   = b64url(JSON.stringify(payload));
  const sig = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(`${h}.${p}`)
    .digest('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

  return { token: `${h}.${p}.${sig}`, header, payload };
}

function verifyJWT(token) {
  try {
    const [h, p, sig] = token.split('.');
    const expectedSig = crypto
      .createHmac('sha256', JWT_SECRET)
      .update(`${h}.${p}`)
      .digest('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

    if (sig !== expectedSig) return null;

    const payload = JSON.parse(Buffer.from(p, 'base64').toString());
    if (payload.exp < Math.floor(Date.now() / 1000)) return null; // expired

    return payload;
  } catch {
    return null;
  }
}

/* ==============================
   MIDDLEWARE: Auth JWT
============================== */
function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token tidak ditemukan. Sertakan header Authorization: Bearer <token>' });
  }
  const token   = authHeader.split(' ')[1];
  const payload = verifyJWT(token);
  if (!payload) {
    return res.status(401).json({ error: 'Token tidak valid atau sudah kedaluwarsa' });
  }
  req.user = payload;
  next();
}

/* ==============================
   DATABASE SEMENTARA (in-memory)
============================== */
let mahasiswaList = [];

/* ==============================
   ROUTES
============================== */

// ── POST /api/auth/login ──────────────────────────────
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username dan password wajib diisi' });
  }

  const user = USERS[username];
  if (!user || user.password !== password) {
    return res.status(401).json({ error: 'Username atau password salah' });
  }

  const { token, header, payload } = generateJWT(username, user.role, user.name);

  res.json({
    message: 'Login berhasil',
    token,
    decoded: { header, payload }
  });
});

// ── GET /api/auth/token ───────────────────────────────
app.get('/api/auth/token', authMiddleware, (req, res) => {
  res.json({
    message: 'Token valid',
    user: req.user
  });
});

// ── POST /api/mahasiswa/add ───────────────────────────
app.post('/api/mahasiswa/add', authMiddleware, (req, res) => {
  const { nama, npm } = req.body;

  if (!nama || !npm) {
    return res.status(400).json({ error: 'Nama dan NPM wajib diisi' });
  }

  const newData = {
    id:        Date.now(),
    nama:      nama.trim(),
    npm:       npm.trim(),
    addedBy:   req.user.sub,
    createdAt: new Date().toISOString()
  };

  mahasiswaList.push(newData);

  res.status(201).json({
    message: 'Data mahasiswa berhasil ditambahkan',
    data:    newData
  });
});

// ── GET /api/mahasiswa/list ───────────────────────────
app.get('/api/mahasiswa/list', authMiddleware, (req, res) => {
  res.json({
    count: mahasiswaList.length,
    data:  mahasiswaList
  });
});

// ── DELETE /api/mahasiswa/:id ─────────────────────────
app.delete('/api/mahasiswa/:id', authMiddleware, (req, res) => {
  const id  = parseInt(req.params.id);
  const idx = mahasiswaList.findIndex(m => m.id === id);

  if (idx === -1) {
    return res.status(404).json({ error: 'Data tidak ditemukan' });
  }

  const deleted = mahasiswaList.splice(idx, 1)[0];
  res.json({ message: 'Data berhasil dihapus', data: deleted });
});

/* ==============================
   START SERVER
============================== */
app.listen(PORT, () => {
  console.log('');
  console.log('  ✅  Server berjalan di http://localhost:' + PORT);
  console.log('');
  console.log('  📋  Daftar endpoint:');
  console.log('  POST   http://localhost:' + PORT + '/api/auth/login');
  console.log('  GET    http://localhost:' + PORT + '/api/auth/token');
  console.log('  POST   http://localhost:' + PORT + '/api/mahasiswa/add');
  console.log('  GET    http://localhost:' + PORT + '/api/mahasiswa/list');
  console.log('  DELETE http://localhost:' + PORT + '/api/mahasiswa/:id');
  console.log('');
  console.log('  🌐  Halaman web: http://localhost:' + PORT + '/index.html');
  console.log('');
});
