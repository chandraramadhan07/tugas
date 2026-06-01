const { verifyJWT, getTokenFromHeader, setCors } = require('../_utils');

export default function handler(req, res) {
  setCors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'DELETE')  return res.status(405).json({ error: 'Method tidak diizinkan' });

  const token   = getTokenFromHeader(req);
  if (!token)   return res.status(401).json({ error: 'Token tidak ditemukan' });

  const payload = verifyJWT(token);
  if (!payload) return res.status(401).json({ error: 'Token tidak valid atau sudah kedaluwarsa' });

  const { id } = req.query;
  if (!id) return res.status(400).json({ error: 'Parameter id wajib diisi' });

  global.mahasiswaList = global.mahasiswaList || [];
  const idx = global.mahasiswaList.findIndex(m => m.id === parseInt(id));

  if (idx === -1) return res.status(404).json({ error: 'Data tidak ditemukan' });

  const deleted = global.mahasiswaList.splice(idx, 1)[0];
  return res.status(200).json({ message: 'Data berhasil dihapus', data: deleted });
}
