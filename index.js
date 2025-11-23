const express = require('express');
const mysql = require('mysql2');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const port = 3000;

const JWT_SECRET = "your-secret-key-change-this-in-production";

app.use(express.json());
app.use(express.static('public'));

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'Ayah.280270*',
    database: 'apikey_db',
    port: 3309
});

db.connect(err => {
    if (err) { 
        console.error('❌ Gagal koneksi ke MySQL:', err); 
        return; 
    }
    console.log('✅ Terkoneksi ke MySQL');
});

function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, message: 'Token tidak ditemukan' });
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ success: false, message: 'Token tidak valid' });
        req.adminId = decoded.id;
        next();
    });
}

function generateApiKey(length = 32) {
    return crypto.randomBytes(length).toString("hex").substring(0, length);
}

// ==================== HALAMAN ====================
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("/admin-login", (req, res) => res.sendFile(path.join(__dirname, "public", "admin-login.html")));
app.get("/admin-register", (req, res) => res.sendFile(path.join(__dirname, "public", "admin-register.html")));
app.get("/admin-dashboard", (req, res) => res.sendFile(path.join(__dirname, "public", "admin-dashboard.html")));

// ==================== USER ENDPOINTS ====================

// Generate API key - HANYA GENERATE, TIDAK SIMPAN KE DATABASE
app.post("/generate", (req, res) => {
    const apikey = generateApiKey(32);
    res.json({ 
        success: true, 
        apiKey: apikey, 
        message: "✅ API key berhasil dibuat."
    });
});

// Register User - SIMPAN USER DAN API KEY SEKALIGUS
app.post("/register-user", (req, res) => {
    const { namaDepan, namaBelakang, email, apiKey } = req.body;
    
    if (!namaDepan || !namaBelakang || !email || !apiKey) {
        return res.status(400).json({ 
            success: false, 
            message: "⚠️ Semua field wajib diisi!" 
        });
    }

    // Cek apakah email sudah terdaftar
    db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
        if (err) {
            console.error("Error checking email:", err);
            return res.status(500).json({ 
                success: false, 
                message: "Kesalahan server saat cek email." 
            });
        }
        
        if (results.length > 0) {
            return res.status(400).json({ 
                success: false, 
                message: "⚠️ Email sudah terdaftar!" 
            });
        }

        // Cek apakah API key sudah digunakan
        db.query("SELECT * FROM apikey WHERE api_key = ?", [apiKey], (err, keyResults) => {
            if (err) {
                console.error("Error checking API key:", err);
                return res.status(500).json({ 
                    success: false, 
                    message: "Kesalahan server saat validasi API key." 
                });
            }
            
            if (keyResults.length > 0) {
                return res.status(400).json({ 
                    success: false, 
                    message: "⚠️ API key sudah digunakan!" 
                });
            }

            // Simpan API key ke tabel apikey
            const expiresAt = new Date();
            expiresAt.setDate(expiresAt.getDate() + 30);

            const insertKeyQuery = `
                INSERT INTO apikey (api_key, created_at, is_active, last_used, last_login, expires_at) 
                VALUES (?, NOW(), 1, NOW(), NOW(), ?)
            `;
            
            db.query(insertKeyQuery, [apiKey, expiresAt], (err) => {
                if (err) {
                    console.error("Error inserting API key:", err);
                    return res.status(500).json({ 
                        success: false, 
                        message: "Gagal menyimpan API key: " + err.message 
                    });
                }

                // Simpan user ke tabel users
                const insertUserQuery = `
                    INSERT INTO users (nama_depan, nama_belakang, email, api_key, created_at, last_login) 
                    VALUES (?, ?, ?, ?, NOW(), NOW())
                `;
                
                db.query(insertUserQuery, [namaDepan, namaBelakang, email, apiKey], (err, result) => {
                    if (err) {
                        console.error("Error inserting user:", err);
                        // Rollback: hapus API key yang baru saja dibuat
                        db.query("DELETE FROM apikey WHERE api_key = ?", [apiKey]);
                        return res.status(500).json({ 
                            success: false, 
                            message: "Gagal menyimpan data user: " + err.message 
                        });
                    }

                    res.json({ 
                        success: true, 
                        message: "✅ User berhasil didaftarkan!", 
                        userId: result.insertId 
                    });
                });
            });
        });
    });
});

// ==================== USER LOGIN (untuk update last_login) ====================
app.post("/user/login", (req, res) => {
    const { apiKey } = req.body;
    if (!apiKey) return res.status(400).json({ success: false, message: "API Key wajib diisi!" });

    // Cek apakah API key valid dan aktif
    db.query("SELECT * FROM apikey WHERE api_key = ?", [apiKey], (err, results) => {
        if (err) return res.status(500).json({ success: false, message: "Kesalahan server." });
        if (results.length === 0) return res.status(401).json({ success: false, message: "❌ API Key tidak valid!" });

        const keyData = results[0];
        
        // Cek apakah sudah inactive karena 30 hari tidak login
        if (keyData.is_active === 0) {
            return res.status(401).json({ 
                success: false, 
                message: "❌ API Key sudah tidak aktif karena tidak digunakan selama 30 hari. Hubungi admin untuk mengaktifkan kembali." 
            });
        }

        // Update last_login di apikey dan users
        db.query("UPDATE apikey SET last_login = NOW(), last_used = NOW() WHERE api_key = ?", [apiKey], (err) => {
            if (err) console.error("Error updating apikey last_login:", err);
        });

        db.query("UPDATE users SET last_login = NOW() WHERE api_key = ?", [apiKey], (err) => {
            if (err) console.error("Error updating users last_login:", err);
        });

        // Ambil data user
        db.query("SELECT * FROM users WHERE api_key = ?", [apiKey], (err, userResults) => {
            if (err) return res.status(500).json({ success: false, message: "Kesalahan server." });
            if (userResults.length === 0) return res.status(404).json({ success: false, message: "User tidak ditemukan!" });

            const user = userResults[0];
            res.json({ 
                success: true, 
                message: "✅ Login berhasil!", 
                user: { 
                    id: user.id, 
                    nama: `${user.nama_depan} ${user.nama_belakang}`, 
                    email: user.email 
                }
            });
        });
    });
});

// ==================== ADMIN ENDPOINTS ====================

app.post("/admin/register", async (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ 
            success: false, 
            message: "⚠️ Email dan password wajib diisi!" 
        });
    }

    if (password.length < 6) {
        return res.status(400).json({ 
            success: false, 
            message: "⚠️ Password minimal 6 karakter!" 
        });
    }

    try {
        // Cek apakah email sudah terdaftar
        db.query("SELECT * FROM admins WHERE email = ?", [email], async (err, results) => {
            if (err) {
                console.error("Error checking admin email:", err);
                return res.status(500).json({ 
                    success: false, 
                    message: "Kesalahan server: " + err.message 
                });
            }
            
            if (results.length > 0) {
                return res.status(400).json({ 
                    success: false, 
                    message: "⚠️ Email admin sudah terdaftar!" 
                });
            }

            // Hash password
            const hashedPassword = await bcrypt.hash(password, 10);
            
            // Insert admin baru
            db.query(
                "INSERT INTO admins (email, password, created_at) VALUES (?, ?, NOW())", 
                [email, hashedPassword], 
                (err, result) => {
                    if (err) {
                        console.error("Error inserting admin:", err);
                        return res.status(500).json({ 
                            success: false, 
                            message: "Gagal menyimpan data admin: " + err.message 
                        });
                    }
                    
                    res.json({ 
                        success: true, 
                        message: "✅ Admin berhasil didaftarkan!", 
                        adminId: result.insertId 
                    });
                }
            );
        });
    } catch (error) {
        console.error("Error in admin register:", error);
        res.status(500).json({ 
            success: false, 
            message: "Error: " + error.message 
        });
    }
});

app.post("/admin/login", (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ 
            success: false, 
            message: "⚠️ Email dan password wajib diisi!" 
        });
    }

    db.query("SELECT * FROM admins WHERE email = ?", [email], async (err, results) => {
        if (err) {
            console.error("Error checking admin:", err);
            return res.status(500).json({ 
                success: false, 
                message: "Kesalahan server." 
            });
        }
        
        if (results.length === 0) {
            return res.status(401).json({ 
                success: false, 
                message: "❌ Email atau password salah!" 
            });
        }

        const admin = results[0];
        
        try {
            const isValidPassword = await bcrypt.compare(password, admin.password);
            
            if (!isValidPassword) {
                return res.status(401).json({ 
                    success: false, 
                    message: "❌ Email atau password salah!" 
                });
            }

            const token = jwt.sign(
                { id: admin.id, email: admin.email }, 
                JWT_SECRET, 
                { expiresIn: "24h" }
            );
            
            res.json({ 
                success: true, 
                message: "✅ Login berhasil!", 
                token 
            });
        } catch (error) {
            console.error("Error comparing password:", error);
            return res.status(500).json({ 
                success: false, 
                message: "Error saat login: " + error.message 
            });
        }
    });
});

// GET All Users - DENGAN LAST LOGIN & DAYS UNTIL INACTIVE
app.get("/admin/users", verifyToken, (req, res) => {
    const query = `
        SELECT 
            u.id, u.nama_depan, u.nama_belakang, u.email, u.api_key, u.created_at,
            u.last_login,
            k.is_active,
            CASE 
                WHEN u.last_login IS NULL THEN 'Never'
                ELSE DATE_FORMAT(u.last_login, '%d %b %Y %H:%i')
            END as last_login_formatted,
            CASE 
                WHEN k.is_active = 0 THEN 'inactive'
                WHEN u.last_login IS NULL AND u.created_at < DATE_SUB(NOW(), INTERVAL 25 DAY) THEN 'warning'
                WHEN u.last_login IS NULL AND u.created_at < DATE_SUB(NOW(), INTERVAL 30 DAY) THEN 'expired'
                WHEN u.last_login < DATE_SUB(NOW(), INTERVAL 30 DAY) THEN 'expired'
                WHEN u.last_login < DATE_SUB(NOW(), INTERVAL 25 DAY) THEN 'warning'
                ELSE 'ok'
            END as login_status,
            CASE 
                WHEN u.last_login IS NULL THEN DATEDIFF(DATE_ADD(u.created_at, INTERVAL 30 DAY), NOW())
                ELSE DATEDIFF(DATE_ADD(u.last_login, INTERVAL 30 DAY), NOW())
            END as days_until_inactive
        FROM users u
        JOIN apikey k ON u.api_key = k.api_key
        ORDER BY u.created_at DESC
    `;
    
    db.query(query, (err, results) => {
        if (err) {
            console.error("Error fetching users:", err);
            return res.status(500).json({ 
                success: false, 
                message: "Kesalahan mengambil data users." 
            });
        }
        res.json({ 
            success: true, 
            total: results.length, 
            users: results 
        });
    });
});

// Toggle User Status
app.put("/admin/users/:id/toggle", verifyToken, (req, res) => {
    const userId = req.params.id;
    
    db.query("SELECT api_key FROM users WHERE id = ?", [userId], (err, userResults) => {
        if (err || userResults.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: "User tidak ditemukan." 
            });
        }
        
        const apiKeyToToggle = userResults[0].api_key;
        
        db.query("SELECT is_active FROM apikey WHERE api_key = ?", [apiKeyToToggle], (err, keyResults) => {
            if (err || keyResults.length === 0) {
                return res.status(404).json({ 
                    success: false, 
                    message: "API Key tidak ditemukan." 
                });
            }
            
            const newStatus = keyResults[0].is_active === 1 ? 0 : 1;
            
            // Jika mengaktifkan kembali, reset last_login ke NOW()
            const updateQuery = newStatus === 1 
                ? "UPDATE apikey SET is_active = ?, last_login = NOW() WHERE api_key = ?"
                : "UPDATE apikey SET is_active = ? WHERE api_key = ?";
            
            db.query(updateQuery, [newStatus, apiKeyToToggle], (err) => {
                if (err) {
                    console.error("Error toggling status:", err);
                    return res.status(500).json({ 
                        success: false, 
                        message: "Gagal mengubah status." 
                    });
                }
                
                // Update juga last_login di users jika diaktifkan
                if (newStatus === 1) {
                    db.query("UPDATE users SET last_login = NOW() WHERE api_key = ?", [apiKeyToToggle]);
                }
                
                res.json({ 
                    success: true, 
                    message: `✅ Status diubah menjadi ${newStatus === 1 ? 'Aktif' : 'Nonaktif'}`, 
                    newStatus 
                });
            });
        });
    });
});

// API Validate
app.post("/api/validate", (req, res) => {
    const apiKey = req.headers['x-api-key'] || req.body.apiKey;
    
    if (!apiKey) {
        return res.status(400).json({ 
            success: false, 
            message: "API Key wajib diisi!" 
        });
    }

    // Cek API Key di database
    const query = `
        SELECT ak.*, u.nama_depan, u.nama_belakang, u.email 
        FROM apikey ak
        LEFT JOIN users u ON ak.api_key = u.api_key
        WHERE ak.api_key = ?
    `;

    db.query(query, [apiKey], (err, results) => {
        if (err) {
            return res.status(500).json({ success: false, message: "Server error" });
        }

        if (results.length === 0) {
            return res.status(401).json({ 
                success: false, 
                message: "❌ API Key tidak ditemukan!" 
            });
        }

        const data = results[0];

        // Cek apakah aktif
        if (data.is_active === 0) {
            return res.status(401).json({ 
                success: false, 
                message: "❌ API Key sudah tidak aktif! Hubungi admin.",
                status: "inactive"
            });
        }

        // UPDATE last_login di kedua table
        db.query(
            "UPDATE apikey SET last_login = NOW(), last_used = NOW() WHERE api_key = ?", 
            [apiKey]
        );
        db.query(
            "UPDATE users SET last_login = NOW() WHERE api_key = ?", 
            [apiKey]
        );

        // Response sukses
        res.json({ 
            success: true, 
            message: "✅ API Key valid!",
            status: "active",
            user: {
                nama: data.nama_depan ? `${data.nama_depan} ${data.nama_belakang}` : null,
                email: data.email || null
            },
            last_login: new Date().toISOString()
        });
    });
});

// Delete User
app.delete("/admin/users/:id", verifyToken, (req, res) => {
    const userId = req.params.id;
    
    db.query("DELETE FROM users WHERE id = ?", [userId], (err, result) => {
        if (err) {
            console.error("Error deleting user:", err);
            return res.status(500).json({ 
                success: false, 
                message: "Kesalahan server." 
            });
        }
        
        if (result.affectedRows > 0) {
            res.json({ 
                success: true, 
                message: "✅ User berhasil dihapus." 
            });
        } else {
            res.json({ 
                success: false, 
                message: "❌ User tidak ditemukan." 
            });
        }
    });
});

app.listen(port, () => {
    console.log(`🚀 Server berjalan di http://localhost:${port}`);
});