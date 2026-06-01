const { verifyJWT, getTokenFromHeader, setCors } = require('../_utils');

export default function handler(req, res) {
  setCors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET')     return res.status(405).json({ error: 'Method tidak diizinkan' });

  const token   = getTokenFromHeader(req);
  if (!token)   return res.status(401).json({ error: 'Token tidak ditemukan' });

  const payload = verifyJWT(token);
  if (!payload) return res.status(401).json({ error: 'Token tidak valid atau sudah kedaluwarsa' });

  return res.status(200).json({ message: 'Token valid', user: payload });
}
