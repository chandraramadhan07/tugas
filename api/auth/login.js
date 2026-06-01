const { USERS, generateJWT, setCors } = require('../_utils');

module.exports = function handler(req, res) {
  setCors(res);

  if (req.method === 'OPTIONS')
    return res.status(200).end();

  if (req.method !== 'POST')
    return res.status(405).json({
      error: 'Method tidak diizinkan'
    });

  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({
      error: 'Username dan password wajib diisi'
    });
  }

  const user = USERS[username];

  if (!user || user.password !== password) {
    return res.status(401).json({
      error: 'Username atau password salah'
    });
  }

  const { token, header, payload } =
    generateJWT(username, user.role, user.name);

  return res.status(200).json({
    message: 'Login berhasil',
    token,
    decoded: {
      header,
      payload
    }
  });
};
