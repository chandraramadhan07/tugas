const { verifyJWT, getTokenFromHeader, setCors } = require('../_utils');

export default function handler(req, res) {
  setCors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')    return res.status(405).json({ error: 'Method tidak diizinkan' });

  const token   = getTokenFromHeader(req);
  if (!token)   return res.status(401).json({ error: 'Token tidak ditemukan' });

  const payload = verifyJWT(token);
  if (!payload) return res.status(401).json({ error: 'Token tidak valid atau sudah kedaluwarsa' });

  const { nama, npm } = req.body || {};
  if (!nama || !npm)
    return res.status(400).json({ error: 'Nama dan NPM wajib diisi' });

  const newData = {
    id:        Date.now(),
    nama:      nama.trim(),
    npm:       npm.trim(),
    addedBy:   payload.sub,
    createdAt: new Date().toISOString()
  };

  global.mahasiswaList = global.mahasiswaList || [];
  global.mahasiswaList.push(newData);

  return res.status(201).json({
    message: 'Data mahasiswa berhasil ditambahkan',
    data:    newData
  });
}
