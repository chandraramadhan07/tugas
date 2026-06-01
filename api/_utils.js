const crypto = require('crypto');

const JWT_SECRET = 'AuthSystem_S3cr3t_K3y_2024';
const JWT_EXPIRY = 3600;

const USERS = {
  admin: { password: 'password123', role: 'admin', name: 'Administrator' },
  mahasiswa: { password: 'kampus2024', role: 'mahasiswa', name: 'Budi Santoso' }
};

if (!global.mahasiswaList) global.mahasiswaList = [];

function b64url(str) {
  return Buffer.from(str)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64').toString();
}

function generateJWT(username, role, name) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);

  const payload = {
    sub: username,
    name,
    role,
    iat: now,
    exp: now + JWT_EXPIRY,
    iss: 'authsystem.local'
  };

  const h = b64url(JSON.stringify(header));
  const p = b64url(JSON.stringify(payload));

  const sig = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(`${h}.${p}`)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');

  return { token: `${h}.${p}.${sig}`, header, payload };
}

function verifyJWT(token) {
  try {
    const [h, p, sig] = token.split('.');

    const expectedSig = crypto
      .createHmac('sha256', JWT_SECRET)
      .update(`${h}.${p}`)
      .digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

    if (sig !== expectedSig) return null;

    const payload = JSON.parse(base64UrlDecode(p));

    if (payload.exp < Math.floor(Date.now() / 1000)) return null;

    return payload;
  } catch {
    return null;
  }
}

function getTokenFromHeader(req) {
  const auth = req.headers['authorization'] || '';
  if (!auth.startsWith('Bearer ')) return null;
  return auth.split(' ')[1];
}

function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
}

module.exports = {
  USERS,
  generateJWT,
  verifyJWT,
  getTokenFromHeader,
  setCors
};
