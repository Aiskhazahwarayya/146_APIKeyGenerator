const express = require('express');
const path = require('path');
const crypto = require('crypto');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;
const JWT_SECRET = crypto.randomBytes(32).toString('hex');

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Database Connection
const db = mysql.createConnection({
  host: 'localhost',
  port: 3309,
  user: 'root',
  password: 'Aiszr131004',
  database: 'apikey_db'
});

db.connect(err => {
  if (err) throw err;
  console.log('✅ Terhubung ke database MySQL');
});

// Middleware untuk verifikasi JWT
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'Token tidak ditemukan!' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.admin = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ success: false, message: 'Token tidak valid!' });
  }
};

// ==================== ROUTES ====================

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ==================== AUTH ADMIN ====================

app.post('/api/admin/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ success: false, message: 'Email dan password wajib diisi!' });
  if (password.length < 6) return res.status(400).json({ success: false, message: 'Password minimal 6 karakter!' });
  
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.query('INSERT INTO admins (email, password) VALUES (?, ?)', [email, hashedPassword], (err) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ success: false, message: 'Email sudah terdaftar!' });
        return res.status(500).json({ success: false, message: 'Gagal mendaftarkan admin!' });
      }
      res.json({ success: true, message: 'Admin berhasil didaftarkan!' });
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Terjadi kesalahan server!' });
  }
});

app.post('/api/admin/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ success: false, message: 'Email dan password wajib diisi!' });
  
  db.query('SELECT * FROM admins WHERE email = ?', [email], async (err, results) => {
    if (err) return res.status(500).json({ success: false, message: 'Gagal login!' });
    if (results.length === 0) return res.status(401).json({ success: false, message: 'Email atau password salah!' });
    
    const admin = results[0];
    const validPassword = await bcrypt.compare(password, admin.password);
    if (!validPassword) return res.status(401).json({ success: false, message: 'Email atau password salah!' });
    
    const token = jwt.sign({ id: admin.id, email: admin.email }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ success: true, message: 'Login berhasil!', token, admin: { id: admin.id, email: admin.email } });
  });
});

// ==================== API KEYS ====================

// Generate API Key (hanya generate, belum disimpan ke user)
app.post('/api/apikeys/generate', (req, res) => {
  const timestamp = Date.now();
  const random = crypto.randomBytes(6).toString('hex');
  const apiKey = `sk-umy-${timestamp}-${random}`;
  res.json({ success: true, apiKey });
});

app.post("/api/apikeys/create", authMiddleware, (req, res) => {
  const generateApiKey = (length) => crypto.randomBytes(length).toString("hex");

  const apikey = generateApiKey(16);
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + 30); // Expired 30 hari

  const query = "INSERT INTO api_keys (api_key, created_at, is_active, last_used, expires_at) VALUES (?, NOW(), 1, NOW(), ?)";
  db.query(query, [apikey, expiresAt], err => {
    if (err) return res.status(500).json({ success: false, message: "Gagal menyimpan API key.", error: err.message });

    res.json({
      success: true,
      apiKey: apikey,
      message: "API key berhasil dibuat & disimpan!",
      created_at: new Date().toISOString(),
      expires_at: expiresAt.toISOString()
    });
  });
});

// Toggle API Key Status (untuk admin)
app.put('/api/apikeys/toggle', authMiddleware, (req, res) => {
  const { api_key, is_active } = req.body;
  db.query('UPDATE api_keys SET is_active = ? WHERE api_key = ?', [is_active, api_key], (err, result) => {
    if (err) return res.status(500).json({ success: false, message: 'Gagal update status!' });
    res.json({ success: true, message: 'Status berhasil diupdate!' });
  });
});

// ==================== USERS ====================

// Register User dengan API Key yang sudah di-generate
app.post('/api/users/register', (req, res) => {
  const { nama_depan, nama_belakang, email, api_key } = req.body;
  
  if (!nama_depan || !nama_belakang || !email || !api_key) {
    return res.status(400).json({ success: false, message: 'Semua field wajib diisi!' });
  }

  // Cek apakah email sudah terdaftar
  db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (err) return res.status(500).json({ success: false, message: 'Terjadi kesalahan!' });
    if (results.length > 0) return res.status(400).json({ success: false, message: 'Email sudah terdaftar!' });

    // Insert API Key dulu
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 30);

    db.query('INSERT INTO api_keys (api_key, created_at, is_active, last_used, expires_at) VALUES (?, NOW(), 1, NOW(), ?)', [api_key, expiresAt], (err2) => {
      if (err2) {
        if (err2.code === 'ER_DUP_ENTRY') return res.status(400).json({ success: false, message: 'API Key sudah digunakan!' });
        return res.status(500).json({ success: false, message: 'Gagal menyimpan API Key!' });
      }

      // Insert User
      db.query(
        'INSERT INTO users (nama_depan, nama_belakang, email, api_key) VALUES (?, ?, ?, ?)',
        [nama_depan, nama_belakang, email, api_key],
        (err3) => {
          if (err3) return res.status(500).json({ success: false, message: 'Gagal menyimpan user!' });
          res.json({ success: true, message: 'User dan API Key berhasil disimpan!' });
        }
      );
    });
  });
});

// Get All Users (Admin)
app.get('/api/users', authMiddleware, (req, res) => {
  const query = `
    SELECT u.*, ak.is_active, ak.last_used, ak.created_at as key_created 
    FROM users u 
    LEFT JOIN api_keys ak ON u.api_key = ak.api_key 
    ORDER BY u.created_at DESC
  `;
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ success: false, message: 'Gagal mengambil data!' });
    res.json({ success: true, data: results });
  });
});

// Update User
app.put('/api/users/:id', authMiddleware, (req, res) => {
  const { id } = req.params;
  const { nama_depan, nama_belakang, email } = req.body;
  db.query(
    'UPDATE users SET nama_depan = ?, nama_belakang = ?, email = ? WHERE id = ?',
    [nama_depan, nama_belakang, email, id],
    (err) => {
      if (err) return res.status(500).json({ success: false, message: 'Gagal update user!' });
      res.json({ success: true, message: 'User berhasil diupdate!' });
    }
  );
});

// Delete User (cascade ke API Key)
app.delete('/api/users/:id', authMiddleware, (req, res) => {
  const { id } = req.params;
  
  // Get api_key first
  db.query('SELECT api_key FROM users WHERE id = ?', [id], (err, results) => {
    if (err || results.length === 0) return res.status(500).json({ success: false, message: 'User tidak ditemukan!' });
    
    const apiKey = results[0].api_key;
    
    // Delete user first (karena foreign key)
    db.query('DELETE FROM users WHERE id = ?', [id], (err2) => {
      if (err2) return res.status(500).json({ success: false, message: 'Gagal menghapus user!' });
      
      // Delete api key
      db.query('DELETE FROM api_keys WHERE api_key = ?', [apiKey], (err3) => {
        res.json({ success: true, message: 'User dan API Key berhasil dihapus!' });
      });
    });
  });
});

// ==================== CHECK API (untuk Postman) ====================

app.post('/api/checkapi', (req, res) => {
  const { apiKey } = req.body;
  if (!apiKey) return res.status(400).json({ valid: false, active: false, message: 'API Key wajib dikirim!' });

  db.query('SELECT * FROM api_keys WHERE api_key = ?', [apiKey], (err, results) => {
    if (err) return res.status(500).json({ valid: false, active: false, message: 'Gagal memeriksa API Key!' });
    if (results.length === 0) return res.json({ valid: false, active: false, message: 'API Key tidak ditemukan!' });

    const key = results[0];
    
    // Update last_used
    db.query('UPDATE api_keys SET last_used = NOW() WHERE api_key = ?', [apiKey]);

    db.query('UPDATE users SET last_login = NOW() WHERE api_key = ?', [apiKey]); 
    db.query('UPDATE api_keys SET last_login = NOW() WHERE api_key = ?', [apiKey]); 
    
    // Get user info
    db.query('SELECT * FROM users WHERE api_key = ?', [apiKey], (err2, userResults) => {
      const user = userResults && userResults.length > 0 ? userResults[0] : null;
      
      res.json({
        valid: true,
        active: key.is_active === 1,
        message: key.is_active === 1 ? 'API Key valid dan aktif!' : 'API Key valid tapi tidak aktif!',
        data: {
          id: key.id,
          created_at: key.created_at,
          last_used: key.last_used,
          expires_at: key.expires_at,  // ← FIX ERROR
          user: user ? {
            nama: `${user.nama_depan} ${user.nama_belakang}`,
            email: user.email
          } : null
        }
      });
    });
  });
});

// ==================== AUTO DEACTIVATE ====================
// Jalankan setiap 24 jam - nonaktifkan API Key yang tidak digunakan 30 hari
setInterval(() => {
  const query = `
    UPDATE api_keys SET is_active = 0 
    WHERE is_active = 1 AND (
      (last_used IS NULL AND created_at < DATE_SUB(NOW(), INTERVAL 30 DAY))
      OR (last_used IS NOT NULL AND last_used < DATE_SUB(NOW(), INTERVAL 30 DAY))
    )
  `;
  db.query(query, (err, result) => {
    if (result && result.affectedRows > 0) {
      console.log(`⏰ Auto-deactivated ${result.affectedRows} unused API keys`);
    }
  });
}, 24 * 60 * 60 * 1000);

app.listen(port, () => {
  console.log(`🚀 Server berjalan di http://localhost:${port}`);
});