const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const Database = require('better-sqlite3');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// ─── Database ──────────────────────────────────────────────────────────────────
const db = new Database(process.env.DB_PATH || 'chat.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    password TEXT NOT NULL,
    avatar_color TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    receiver_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    color TEXT NOT NULL,
    creator_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS group_members (
    group_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    PRIMARY KEY (group_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS group_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER NOT NULL,
    sender_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// ─── Middleware ────────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'baithak-dev-secret-change-in-prod',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  next();
}

const COLORS = ['#e74c3c','#e67e22','#f1c40f','#2ecc71','#1abc9c','#3498db','#9b59b6','#e91e63','#00bcd4','#ff5722'];
const GRP_COLORS = ['#6c63ff','#e91e63','#00bcd4','#ff5722','#2ecc71','#f1c40f','#9b59b6','#3498db'];

// ─── Auth ──────────────────────────────────────────────────────────────────────
app.post('/api/register', (req, res) => {
  const { username, display_name, password } = req.body;
  if (!username || !display_name || !password) return res.json({ error: 'All fields are required' });
  if (username.length < 3 || username.length > 20) return res.json({ error: 'Username must be 3–20 characters' });
  if (!/^[a-zA-Z0-9_]+$/.test(username)) return res.json({ error: 'Username: letters, numbers, underscores only' });
  if (password.length < 6) return res.json({ error: 'Password must be at least 6 characters' });

  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username.toLowerCase());
  if (existing) return res.json({ error: 'Username already taken' });

  const hash = bcrypt.hashSync(password, 10);
  const color = COLORS[Math.floor(Math.random() * COLORS.length)];
  const result = db.prepare('INSERT INTO users (username, display_name, password, avatar_color) VALUES (?, ?, ?, ?)')
    .run(username.toLowerCase(), display_name, hash, color);

  req.session.userId = result.lastInsertRowid;
  res.json({ success: true, user: { id: result.lastInsertRowid, username: username.toLowerCase(), display_name, avatar_color: color } });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.json({ error: 'Username and password are required' });

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.toLowerCase());
  if (!user || !bcrypt.compareSync(password, user.password)) return res.json({ error: 'Invalid username or password' });

  req.session.userId = user.id;
  res.json({ success: true, user: { id: user.id, username: user.username, display_name: user.display_name, avatar_color: user.avatar_color } });
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });

app.get('/api/me', (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  const user = db.prepare('SELECT id, username, display_name, avatar_color FROM users WHERE id = ?').get(req.session.userId);
  res.json({ user });
});

app.delete('/api/account', requireAuth, (req, res) => {
  const myId = req.session.userId;
  db.prepare('DELETE FROM messages WHERE sender_id = ? OR receiver_id = ?').run(myId, myId);
  db.prepare('DELETE FROM group_messages WHERE sender_id = ?').run(myId);
  // Delete groups created by user
  const myGroups = db.prepare('SELECT id FROM groups WHERE creator_id = ?').all(myId);
  myGroups.forEach(g => {
    db.prepare('DELETE FROM group_members WHERE group_id = ?').run(g.id);
    db.prepare('DELETE FROM group_messages WHERE group_id = ?').run(g.id);
    db.prepare('DELETE FROM groups WHERE id = ?').run(g.id);
  });
  db.prepare('DELETE FROM group_members WHERE user_id = ?').run(myId);
  db.prepare('DELETE FROM users WHERE id = ?').run(myId);
  req.session.destroy();
  res.json({ success: true });
});

// ─── Search ────────────────────────────────────────────────────────────────────
app.get('/api/search', requireAuth, (req, res) => {
  const q = (req.query.q || '').trim().toLowerCase();
  if (!q) return res.json({ users: [] });
  const users = db.prepare(
    'SELECT id, username, display_name, avatar_color FROM users WHERE (username LIKE ? OR display_name LIKE ?) AND id != ? LIMIT 10'
  ).all(`%${q}%`, `%${q}%`, req.session.userId);
  res.json({ users });
});

// ─── DM Messages ──────────────────────────────────────────────────────────────
app.get('/api/messages/:userId', requireAuth, (req, res) => {
  const myId = req.session.userId;
  const otherId = parseInt(req.params.userId);
  const messages = db.prepare(`
    SELECT m.*, u.display_name as sender_display_name, u.avatar_color as sender_color
    FROM messages m JOIN users u ON m.sender_id = u.id
    WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)
    ORDER BY m.created_at ASC
  `).all(myId, otherId, otherId, myId);
  res.json({ messages });
});

app.get('/api/conversations', requireAuth, (req, res) => {
  const myId = req.session.userId;
  const rows = db.prepare(`
    SELECT u.id, u.username, u.display_name, u.avatar_color,
      m.content as last_message, m.created_at as last_time, m.sender_id as last_sender_id
    FROM users u
    JOIN messages m ON ((m.sender_id = u.id AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = u.id))
    WHERE u.id != ?
    GROUP BY u.id HAVING m.id = MAX(m.id)
    ORDER BY m.created_at DESC
  `).all(myId, myId, myId);
  res.json({ conversations: rows });
});

// ─── Groups ────────────────────────────────────────────────────────────────────
app.get('/api/groups', requireAuth, (req, res) => {
  const myId = req.session.userId;
  const groups = db.prepare(`
    SELECT g.*, GROUP_CONCAT(gm.user_id) as member_ids
    FROM groups g JOIN group_members gm ON g.id = gm.group_id
    WHERE g.id IN (SELECT group_id FROM group_members WHERE user_id = ?)
    GROUP BY g.id
  `).all(myId).map(g => ({ ...g, members: g.member_ids ? g.member_ids.split(',').map(Number) : [] }));
  res.json({ groups });
});

app.post('/api/groups', requireAuth, (req, res) => {
  const { name, color, memberIds } = req.body;
  if (!name || !memberIds || !memberIds.length) return res.json({ error: 'Name and members required' });
  const result = db.prepare('INSERT INTO groups (name, color, creator_id) VALUES (?, ?, ?)').run(name, color || GRP_COLORS[0], req.session.userId);
  const gid = result.lastInsertRowid;
  const allMembers = [...new Set([req.session.userId, ...memberIds])];
  allMembers.forEach(uid => db.prepare('INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)').run(gid, uid));
  const group = db.prepare('SELECT * FROM groups WHERE id = ?').get(gid);
  res.json({ success: true, group: { ...group, members: allMembers } });
});

app.delete('/api/groups/:id', requireAuth, (req, res) => {
  const gid = parseInt(req.params.id);
  const group = db.prepare('SELECT * FROM groups WHERE id = ?').get(gid);
  if (!group) return res.json({ error: 'Not found' });
  if (group.creator_id === req.session.userId) {
    db.prepare('DELETE FROM group_members WHERE group_id = ?').run(gid);
    db.prepare('DELETE FROM group_messages WHERE group_id = ?').run(gid);
    db.prepare('DELETE FROM groups WHERE id = ?').run(gid);
  } else {
    db.prepare('DELETE FROM group_members WHERE group_id = ? AND user_id = ?').run(gid, req.session.userId);
  }
  res.json({ success: true });
});

app.get('/api/groups/:id/messages', requireAuth, (req, res) => {
  const gid = parseInt(req.params.id);
  const msgs = db.prepare(`
    SELECT gm.*, u.display_name as sender_display_name, u.avatar_color as sender_color
    FROM group_messages gm JOIN users u ON gm.sender_id = u.id
    WHERE gm.group_id = ? ORDER BY gm.created_at ASC
  `).all(gid);
  res.json({ messages: msgs });
});

// ─── Socket.io ────────────────────────────────────────────────────────────────
const onlineUsers = new Map();

io.on('connection', (socket) => {
  socket.on('user:online', (userId) => {
    onlineUsers.set(Number(userId), socket.id);
    io.emit('users:online', Array.from(onlineUsers.keys()));
  });

  // DM
  socket.on('message:send', ({ senderId, receiverId, content }) => {
    if (!content?.trim()) return;
    const result = db.prepare('INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)').run(senderId, receiverId, content.trim());
    const msg = db.prepare(`SELECT m.*, u.display_name as sender_display_name, u.avatar_color as sender_color FROM messages m JOIN users u ON m.sender_id = u.id WHERE m.id = ?`).get(result.lastInsertRowid);
    const receiverSocket = onlineUsers.get(Number(receiverId));
    if (receiverSocket) io.to(receiverSocket).emit('message:receive', msg);
    socket.emit('message:sent', msg);
  });

  // Group message
  socket.on('gmessage:send', ({ senderId, groupId, content }) => {
    if (!content?.trim()) return;
    const result = db.prepare('INSERT INTO group_messages (group_id, sender_id, content) VALUES (?, ?, ?)').run(groupId, senderId, content.trim());
    const msg = db.prepare(`SELECT gm.*, u.display_name as sender_display_name, u.avatar_color as sender_color FROM group_messages gm JOIN users u ON gm.sender_id = u.id WHERE gm.id = ?`).get(result.lastInsertRowid);
    // Send to all online group members
    const members = db.prepare('SELECT user_id FROM group_members WHERE group_id = ?').all(groupId);
    members.forEach(({ user_id }) => {
      if (user_id !== senderId) {
        const s = onlineUsers.get(Number(user_id));
        if (s) io.to(s).emit('gmessage:receive', msg);
      }
    });
    socket.emit('gmessage:sent', msg);
  });

  socket.on('disconnect', () => {
    for (const [uid, sid] of onlineUsers.entries()) {
      if (sid === socket.id) { onlineUsers.delete(uid); break; }
    }
    io.emit('users:online', Array.from(onlineUsers.keys()));
  });
});

// ─── Serve app ────────────────────────────────────────────────────────────────
// Serve baithak.html and assets from root folder too (not just /public)
app.use(express.static(path.join(__dirname)));

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`🚀 Baithak running on port ${PORT}`));
