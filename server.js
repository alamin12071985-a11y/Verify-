/**
 * Verification System Backend
 * Secure device fingerprinting & multi-account prevention
 */

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const path = require('path');

// Database setup - SQLite for demo, easily swap to Postgres
let db;
try {
  const Database = require('better-sqlite3');
  db = new Database('./verification.db');
  
  // Create tables
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT UNIQUE NOT NULL,
      fingerprint TEXT NOT NULL,
      bot_hash TEXT NOT NULL,
      timezone TEXT,
      screen_res TEXT,
      user_agent TEXT,
      ip_address TEXT,
      status TEXT DEFAULT 'verified',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE INDEX IF NOT EXISTS idx_fingerprint ON users(fingerprint);
    CREATE INDEX IF NOT EXISTS idx_user_id ON users(user_id);
    
    CREATE TABLE IF NOT EXISTS banned (
      user_id TEXT PRIMARY KEY,
      reason TEXT,
      banned_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE TABLE IF NOT EXISTS whitelist (
      user_id TEXT PRIMARY KEY,
      added_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);
  console.log('[✓] SQLite database initialized');
} catch (err) {
  console.log('[!] Database not available, using in-memory storage');
  db = null;
}

// Fallback in-memory storage
const memoryStorage = {
  users: new Map(),
  banned: new Set(),
  whitelist: new Set()
};

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Rate limiting - 10 requests per minute per IP
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { status: 'fail', message: 'Too many requests. Try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/verify', limiter);

// Helper: Generate device fingerprint
function generateFingerprint(data) {
  const components = [
    data.ip || '',
    data.userAgent || '',
    data.timezone || '',
    data.screen || '',
    data.botHash || '',
    data.userId || ''
  ];
  
  const combined = components.join('|');
  return crypto.createHash('sha256').update(combined).digest('hex');
}

// Helper: Check if user is banned
function isBanned(userId) {
  if (db) {
    const stmt = db.prepare('SELECT * FROM banned WHERE user_id = ?');
    return stmt.get(userId) !== undefined;
  }
  return memoryStorage.banned.has(userId);
}

// Helper: Check if user is whitelisted
function isWhitelisted(userId) {
  if (db) {
    const stmt = db.prepare('SELECT * FROM whitelist WHERE user_id = ?');
    return stmt.get(userId) !== undefined;
  }
  return memoryStorage.whitelist.has(userId);
}

// Helper: Check for multi-account (same fingerprint, different user)
function checkMultiAccount(fingerprint, currentUserId) {
  if (db) {
    const stmt = db.prepare('SELECT user_id FROM users WHERE fingerprint = ? AND user_id != ?');
    const existing = stmt.get(fingerprint, currentUserId);
    return existing !== undefined;
  }
  
  for (const [userId, userData] of memoryStorage.users) {
    if (userData.fingerprint === fingerprint && userId !== currentUserId) {
      return true;
    }
  }
  return false;
}

// Helper: Get all users with same fingerprint
function getUsersWithSameFingerprint(fingerprint) {
  if (db) {
    const stmt = db.prepare('SELECT user_id, status FROM users WHERE fingerprint = ?');
    return stmt.all(fingerprint);
  }
  
  const users = [];
  for (const [userId, userData] of memoryStorage.users) {
    if (userData.fingerprint === fingerprint) {
      users.push({ user_id: userId, status: userData.status });
    }
  }
  return users;
}

// Helper: Save verification record
function saveVerification(data) {
  if (db) {
    const stmt = db.prepare(`
      INSERT INTO users (user_id, fingerprint, bot_hash, timezone, screen_res, user_agent, ip_address, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(user_id) DO UPDATE SET
        fingerprint = excluded.fingerprint,
        bot_hash = excluded.bot_hash,
        timezone = excluded.timezone,
        screen_res = excluded.screen_res,
        user_agent = excluded.user_agent,
        ip_address = excluded.ip_address,
        updated_at = CURRENT_TIMESTAMP
    `);
    stmt.run(
      data.userId,
      data.fingerprint,
      data.botHash,
      data.timezone,
      data.screen,
      data.userAgent,
      data.ip,
      data.status
    );
  } else {
    memoryStorage.users.set(data.userId, {
      fingerprint: data.fingerprint,
      botHash: data.botHash,
      timezone: data.timezone,
      screen: data.screen,
      userAgent: data.userAgent,
      ip: data.ip,
      status: data.status
    });
  }
}

// Helper: Validate input
function validateInput(body) {
  const { user_id, botHash, bot, timezone, screen } = body;
  
  if (!user_id || typeof user_id !== 'string') {
    return { valid: false, message: 'Invalid user ID' };
  }
  
  if (!botHash || typeof botHash !== 'string' || botHash.length !== 34) {
    return { valid: false, message: 'Invalid bot hash (must be 34 characters)' };
  }
  
  if (!bot || typeof bot !== 'string') {
    return { valid: false, message: 'Invalid bot username' };
  }
  
  return { valid: true };
}

// API Endpoint: Verify
app.post('/verify', async (req, res) => {
  const startTime = Date.now();
  console.log(`[→] Verification request from ${req.ip}`);
  
  try {
    // Validate input
    const validation = validateInput(req.body);
    if (!validation.valid) {
      return res.json({
        status: 'fail',
        user_id: req.body.user_id || null,
        message: validation.message
      });
    }
    
    const { user_id, botHash, bot, timezone, screen } = req.body;
    
    // Check if banned
    if (isBanned(user_id)) {
      console.log(`[✗] User ${user_id} is banned`);
      return res.json({
        status: 'fail',
        user_id,
        message: 'Your account has been banned. Contact support.'
      });
    }
    
    // Generate fingerprint
    const fingerprint = generateFingerprint({
      ip: req.ip || req.headers['x-forwarded-for'] || 'unknown',
      userAgent: req.headers['user-agent'] || 'unknown',
      timezone: timezone || 'unknown',
      screen: screen || 'unknown',
      botHash,
      userId: user_id
    });
    
    console.log(`[i] Fingerprint: ${fingerprint.substring(0, 16)}...`);
    
    // Check for multi-account (unless whitelisted)
    let isSuspicious = false;
    if (!isWhitelisted(user_id) && checkMultiAccount(fingerprint, user_id)) {
      isSuspicious = true;
      console.log(`[!] Multi-account detected for user ${user_id}`);
    }
    
    // Determine status
    const status = isSuspicious ? 'suspicious' : 'verified';
    
    // Save verification
    saveVerification({
      userId: user_id,
      fingerprint,
      botHash,
      timezone,
      screen,
      userAgent: req.headers['user-agent'],
      ip: req.ip || req.headers['x-forwarded-for'],
      status
    });
    
    const processingTime = Date.now() - startTime;
    console.log(`[✓] Verification complete in ${processingTime}ms`);
    
    // Response
    if (isSuspicious) {
      return res.json({
        status: 'fail',
        user_id,
        message: 'Multiple accounts detected from this device. Contact support if this is an error.'
      });
    }
    
    return res.json({
      status: 'success',
      user_id,
      message: 'Verification successful. You may now proceed.'
    });
    
  } catch (error) {
    console.error('[✗] Verification error:', error);
    return res.status(500).json({
      status: 'fail',
      user_id: req.body.user_id || null,
      message: 'Server error. Please try again later.'
    });
  }
});

// API Endpoint: Get stats (admin)
app.get('/stats', (req, res) => {
  if (db) {
    const totalUsers = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
    const verifiedUsers = db.prepare('SELECT COUNT(*) as count FROM users WHERE status = ?').get('verified').count;
    const suspiciousUsers = db.prepare('SELECT COUNT(*) as count FROM users WHERE status = ?').get('suspicious').count;
    const bannedUsers = db.prepare('SELECT COUNT(*) as count FROM banned').get().count;
    
    return res.json({ totalUsers, verifiedUsers, suspiciousUsers, bannedUsers });
  }
  
  return res.json({
    totalUsers: memoryStorage.users.size,
    verifiedUsers: Array.from(memoryStorage.users.values()).filter(u => u.status === 'verified').length,
    suspiciousUsers: Array.from(memoryStorage.users.values()).filter(u => u.status === 'suspicious').length,
    bannedUsers: memoryStorage.banned.size
  });
});

// API Endpoint: Ban user (admin - protect in production)
app.post('/ban', (req, res) => {
  const { user_id, reason } = req.body;
  
  if (!user_id) {
    return res.status(400).json({ error: 'user_id required' });
  }
  
  if (db) {
    const stmt = db.prepare('INSERT OR REPLACE INTO banned (user_id, reason) VALUES (?, ?)');
    stmt.run(user_id, reason || 'No reason provided');
  } else {
    memoryStorage.banned.add(user_id);
  }
  
  console.log(`[⚡] Banned user ${user_id}`);
  res.json({ status: 'success', message: `User ${user_id} banned` });
});

// API Endpoint: Whitelist user
app.post('/whitelist', (req, res) => {
  const { user_id } = req.body;
  
  if (!user_id) {
    return res.status(400).json({ error: 'user_id required' });
  }
  
  if (db) {
    const stmt = db.prepare('INSERT OR REPLACE INTO whitelist (user_id) VALUES (?)');
    stmt.run(user_id);
  } else {
    memoryStorage.whitelist.add(user_id);
  }
  
  console.log(`[✓] Whitelisted user ${user_id}`);
  res.json({ status: 'success', message: `User ${user_id} whitelisted` });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   🔐 VERIFICATION SYSTEM ONLINE                          ║
║   ────────────────────────────────────                   ║
║   Port: ${PORT}                                              ║
║   Database: ${db ? 'SQLite' : 'In-Memory'}                                 ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
  `);
});
