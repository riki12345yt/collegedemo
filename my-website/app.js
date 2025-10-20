const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const db = new sqlite3.Database('database.db');

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
  secret: 'my-super-secret-key-12345',
  resave: false,
  saveUninitialized: true
}));
app.use(express.static(path.join(__dirname, 'public')));

// Create tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    task TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);
});

// ROUTE: Login/Signup page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ROUTE: Signup
app.post('/signup', async (req, res) => {
  const { username, password, full_name, email } = req.body;
  if (!username || !password || !full_name || !email) {
    return res.status(400).json({ error: 'All fields required' });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run(`INSERT INTO users (username, password, full_name, email) VALUES (?, ?, ?, ?)`,
      [username, hashedPassword, full_name, email],
      (err) => {
        if (err) {
          return res.status(400).json({ error: 'Username exists' });
        }
        res.json({ success: 'Signup successful! Login now.' });
      });
  } catch (err) {
    res.status(500).json({ error: 'Signup failed' });
  }
});

// ROUTE: Login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (err || !user) {
      return res.status(400).json({ error: 'Invalid username' });
    }
    const match = await bcrypt.compare(password, user.password);
    if (match) {
      req.session.user = { id: user.id, username: user.username, full_name: user.full_name, email: user.email };
      res.json({ success: '/dashboard' });
    } else {
      res.status(400).json({ error: 'Wrong password' });
    }
  });
});

// Authentication middleware
function isAuthenticated(req, res, next) {
  if (req.session.user) {
    next();
  } else {
    res.redirect('/');
  }
}

// ROUTE: Dashboard
app.get('/dashboard', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// ROUTE: Get user details
app.get('/user-details', isAuthenticated, (req, res) => {
  res.json(req.session.user);
});

// ROUTE: Update profile
app.post('/update-profile', isAuthenticated, (req, res) => {
  const { full_name, email } = req.body;
  db.run(`UPDATE users SET full_name = ?, email = ? WHERE id = ?`,
    [full_name, email, req.session.user.id],
    (err) => {
      if (err) {
        return res.status(500).json({ error: 'Update failed' });
      }
      req.session.user.full_name = full_name;
      req.session.user.email = email;
      res.json({ success: 'Profile updated' });
    });
});

// ROUTE: Get tasks
app.get('/tasks', isAuthenticated, (req, res) => {
  db.all(`SELECT * FROM tasks WHERE user_id = ?`, [req.session.user.id], (err, tasks) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch tasks' });
    }
    res.json(tasks);
  });
});

// ROUTE: Add task
app.post('/tasks', isAuthenticated, (req, res) => {
  const { task } = req.body;
  if (!task) return res.status(400).json({ error: 'Task required' });
  db.run(`INSERT INTO tasks (user_id, task) VALUES (?, ?)`,
    [req.session.user.id, task],
    (err) => {
      if (err) {
        return res.status(500).json({ error: 'Add failed' });
      }
      res.json({ success: 'Task added' });
    });
});

// ROUTE: Delete task
app.delete('/tasks/:id', isAuthenticated, (req, res) => {
  db.run(`DELETE FROM tasks WHERE id = ? AND user_id = ?`,
    [req.params.id, req.session.user.id],
    (err) => {
      if (err) {
        return res.status(500).json({ error: 'Delete failed' });
      }
      res.json({ success: 'Task deleted' });
    });
});

// ROUTE: Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.listen(3000, () => {
  console.log('🌐 Server running on http://localhost:3000');
  console.log('📱 Open your browser now!');
});