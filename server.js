require('dotenv').config({ quiet: true });
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID || '';
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET || '';
const CALLBACK_URL = 'http://localhost:' + PORT + '/api/auth/github/callback';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

/* ============ RATE LIMITING ============ */
// General limit for every API route
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { errors: ['Too many requests. Please slow down.'] }
});

// Strict limit for the weather API (protects the external service)
const weatherLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { errors: ['Weather limit reached (10 per minute). Please wait.'] }
});

// Very strict limit for login/register: only FAILED attempts count
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 5,
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
  message: { errors: ['Too many failed attempts. Try again in a minute.'] }
});

app.use('/api', apiLimiter);

/* ============ DATABASE ============ */
const db = new Database(path.join(__dirname, 'task7.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    github_id TEXT UNIQUE,
    role TEXT NOT NULL DEFAULT 'user'
  );

  CREATE TABLE IF NOT EXISTS students (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    course TEXT NOT NULL,
    owner_id INTEGER NOT NULL,
    FOREIGN KEY (owner_id) REFERENCES users(id)
  );
`);

/* ============ HELPERS ============ */
function createToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '2h' }
  );
}

function validateStudent(body) {
  const errors = [];
  const name = (body.name || '').trim();
  const email = (body.email || '').trim();
  const course = (body.course || '').trim();

  if (name.length < 3) errors.push('Name must be at least 3 characters.');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) errors.push('Enter a valid email address.');
  if (!course) errors.push('Course is required.');
  return errors;
}

// Calls an external API safely: timeout + clean error messages
async function fetchJson(url, options = {}) {
  let response;
  try {
    response = await fetch(url, Object.assign({}, options, { signal: AbortSignal.timeout(5000) }));
  } catch (err) {
    const timedOut = err.name === 'TimeoutError';
    const e = new Error(timedOut
      ? 'The external service took too long to respond.'
      : 'Could not reach the external service. Check your internet connection.');
    e.status = timedOut ? 504 : 502;
    e.expose = true;
    throw e;
  }

  if (!response.ok) {
    const e = new Error('The external service returned an error (' + response.status + ').');
    e.status = 502;
    e.expose = true;
    throw e;
  }
  return response.json();
}

/* ============ AUTH MIDDLEWARE ============ */
function authenticate(req, res, next) {
  const header = req.headers.authorization || '';
  const [type, token] = header.split(' ');

  if (type !== 'Bearer' || !token) {
    return res.status(401).json({ errors: ['Login required.'] });
  }
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    res.status(401).json({ errors: ['Session expired or invalid. Please log in again.'] });
  }
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ errors: ['Admin access only.'] });
  }
  next();
}

function findAllowedStudent(req, res) {
  const student = db.prepare('SELECT * FROM students WHERE id = ?').get(Number(req.params.id));
  if (!student) {
    res.status(404).json({ errors: ['Student not found.'] });
    return null;
  }
  if (req.user.role !== 'admin' && student.owner_id !== req.user.id) {
    res.status(403).json({ errors: ['You are not allowed to access this record.'] });
    return null;
  }
  return student;
}

/* ============ AUTH ROUTES (username + password) ============ */
app.post('/api/auth/register', authLimiter, (req, res) => {
  const username = (req.body.username || '').trim();
  const email = (req.body.email || '').trim().toLowerCase();
  const password = req.body.password || '';
  const errors = [];

  if (!/^[A-Za-z][A-Za-z0-9_]{3,14}$/.test(username)) {
    errors.push('Username: 4-15 characters, start with a letter, use only letters, numbers or _');
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
    errors.push('Enter a valid email address.');
  }
  if (password.length < 8 || !/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) {
    errors.push('Password must be at least 8 characters with a letter and a number.');
  }
  if (errors.length > 0) return res.status(400).json({ errors });

  const existing = db.prepare('SELECT id FROM users WHERE username = ? OR email = ?').get(username, email);
  if (existing) {
    return res.status(409).json({ errors: ['Username or email is already registered.'] });
  }

  const count = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
  const role = count === 0 ? 'admin' : 'user';

  const hash = bcrypt.hashSync(password, 10);
  const info = db
    .prepare('INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)')
    .run(username, email, hash, role);

  const user = { id: Number(info.lastInsertRowid), username, role };
  res.status(201).json({ token: createToken(user), user });
});

app.post('/api/auth/login', authLimiter, (req, res) => {
  const username = (req.body.username || '').trim();
  const password = req.body.password || '';

  const row = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

  // GitHub users have no password, so they can't use this form
  if (!row || !row.password_hash || !bcrypt.compareSync(password, row.password_hash)) {
    return res.status(401).json({ errors: ['Invalid username or password.'] });
  }

  const user = { id: row.id, username: row.username, role: row.role };
  res.json({ token: createToken(user), user });
});

// Who am I? (used by the front end after GitHub login)
app.get('/api/auth/me', authenticate, (req, res) => {
  res.json({ id: req.user.id, username: req.user.username, role: req.user.role });
});

/* ============ OAUTH: LOGIN WITH GITHUB ============ */
const oauthStates = new Map(); // state value -> expiry time

// Step 1: send the user to GitHub
app.get('/api/auth/github', (req, res) => {
  if (!GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET) {
    return res.redirect('/#error=' + encodeURIComponent('GitHub login is not configured on the server (check the .env file).'));
  }

  // Remove expired states
  const now = Date.now();
  for (const [key, expires] of oauthStates) {
    if (expires < now) oauthStates.delete(key);
  }

  // "state" is a random value that protects against forged login requests (CSRF)
  const state = crypto.randomBytes(16).toString('hex');
  oauthStates.set(state, now + 10 * 60 * 1000);

  const params = new URLSearchParams({
    client_id: GITHUB_CLIENT_ID,
    redirect_uri: CALLBACK_URL,
    scope: 'read:user',
    state
  });
  res.redirect('https://github.com/login/oauth/authorize?' + params.toString());
});

// Step 2: GitHub sends the user back here with a temporary "code"
app.get('/api/auth/github/callback', async (req, res) => {
  const { code, state } = req.query;
  const expires = oauthStates.get(state);
  oauthStates.delete(state);

  if (!code || !expires || expires < Date.now()) {
    return res.redirect('/#error=' + encodeURIComponent('Invalid or expired login attempt. Please try again.'));
  }

  try {
    // Step 3: swap the code for an access token (needs our client secret)
    const tokenData = await fetchJson('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: CALLBACK_URL
      })
    });
    if (!tokenData.access_token) {
      const e = new Error('GitHub did not approve the login.');
      e.expose = true;
      throw e;
    }

    // Step 4: use the access token once to read the user's public profile
    const profile = await fetchJson('https://api.github.com/user', {
      headers: {
        Authorization: 'Bearer ' + tokenData.access_token,
        'User-Agent': 'task7-app',
        Accept: 'application/vnd.github+json'
      }
    });
    if (!profile.id || !profile.login) {
      const e = new Error('Could not read your GitHub profile.');
      e.expose = true;
      throw e;
    }

    // Step 5: find or create the user in OUR database
    let row = db.prepare('SELECT * FROM users WHERE github_id = ?').get(String(profile.id));
    if (!row) {
      const count = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
      const role = count === 0 ? 'admin' : 'user';
      const username = 'gh_' + profile.login;
      const email = profile.id + '+' + profile.login + '@users.noreply.github.com';

      const info = db
        .prepare('INSERT INTO users (username, email, password_hash, github_id, role) VALUES (?, ?, NULL, ?, ?)')
        .run(username, email, String(profile.id), role);
      row = { id: Number(info.lastInsertRowid), username, role };
    }

    // Step 6: give the browser OUR own login token (the GitHub token is thrown away)
    const ourToken = createToken({ id: row.id, username: row.username, role: row.role });
    res.redirect('/#token=' + encodeURIComponent(ourToken));
  } catch (err) {
    const message = err.expose ? err.message : 'GitHub login failed. Please try again.';
    res.redirect('/#error=' + encodeURIComponent(message));
  }
});

/* ============ PROTECTED STUDENT ROUTES ============ */
app.get('/api/students', authenticate, (req, res) => {
  const search = '%' + (req.query.search || '').toLowerCase() + '%';
  let rows;

  if (req.user.role === 'admin') {
    rows = db.prepare(`
      SELECT s.id, s.name, s.email, s.course, u.username AS owner
      FROM students s JOIN users u ON u.id = s.owner_id
      WHERE lower(s.name || ' ' || s.email || ' ' || s.course) LIKE ?
      ORDER BY s.id
    `).all(search);
  } else {
    rows = db.prepare(`
      SELECT id, name, email, course
      FROM students
      WHERE owner_id = ? AND lower(name || ' ' || email || ' ' || course) LIKE ?
      ORDER BY id
    `).all(req.user.id, search);
  }
  res.json(rows);
});

app.get('/api/students/:id', authenticate, (req, res) => {
  const student = findAllowedStudent(req, res);
  if (!student) return;
  res.json(student);
});

app.post('/api/students', authenticate, (req, res) => {
  const errors = validateStudent(req.body);
  const email = (req.body.email || '').trim().toLowerCase();

  if (errors.length === 0) {
    const dup = db.prepare('SELECT id FROM students WHERE owner_id = ? AND email = ?').get(req.user.id, email);
    if (dup) errors.push('You already added a student with this email.');
  }
  if (errors.length > 0) return res.status(400).json({ errors });

  const info = db
    .prepare('INSERT INTO students (name, email, course, owner_id) VALUES (?, ?, ?, ?)')
    .run(req.body.name.trim(), email, req.body.course.trim(), req.user.id);

  res.status(201).json(db.prepare('SELECT * FROM students WHERE id = ?').get(info.lastInsertRowid));
});

app.put('/api/students/:id', authenticate, (req, res) => {
  const student = findAllowedStudent(req, res);
  if (!student) return;

  const errors = validateStudent(req.body);
  const email = (req.body.email || '').trim().toLowerCase();

  if (errors.length === 0) {
    const dup = db
      .prepare('SELECT id FROM students WHERE owner_id = ? AND email = ? AND id != ?')
      .get(student.owner_id, email, student.id);
    if (dup) errors.push('Another student already uses this email.');
  }
  if (errors.length > 0) return res.status(400).json({ errors });

  db.prepare('UPDATE students SET name = ?, email = ?, course = ? WHERE id = ?')
    .run(req.body.name.trim(), email, req.body.course.trim(), student.id);

  res.json(db.prepare('SELECT * FROM students WHERE id = ?').get(student.id));
});

app.delete('/api/students/:id', authenticate, (req, res) => {
  const student = findAllowedStudent(req, res);
  if (!student) return;

  db.prepare('DELETE FROM students WHERE id = ?').run(student.id);
  res.json({ message: 'Student deleted.' });
});

/* ============ ADMIN-ONLY ROUTE ============ */
app.get('/api/admin/users', authenticate, requireAdmin, (req, res) => {
  const users = db.prepare(`
    SELECT u.id, u.username, u.email, u.role,
           (SELECT COUNT(*) FROM students s WHERE s.owner_id = u.id) AS studentCount
    FROM users u
    ORDER BY u.id
  `).all();
  res.json(users);
});

/* ============ EXTERNAL API: WEATHER (Open-Meteo) ============ */
const weatherCache = new Map();
const CACHE_MS = 5 * 60 * 1000; // remember results for 5 minutes

function describeWeather(code) {
  if (code === 0) return 'Clear sky';
  if (code >= 1 && code <= 3) return 'Cloudy';
  if (code === 45 || code === 48) return 'Fog';
  if (code >= 51 && code <= 57) return 'Drizzle';
  if (code >= 61 && code <= 67) return 'Rain';
  if (code >= 71 && code <= 77) return 'Snow';
  if (code >= 80 && code <= 82) return 'Rain showers';
  if (code === 85 || code === 86) return 'Snow showers';
  if (code >= 95 && code <= 99) return 'Thunderstorm';
  return 'Unknown';
}

app.get('/api/weather', weatherLimiter, authenticate, async (req, res, next) => {
  try {
    const city = String(req.query.city || '').trim();
    if (city.length < 2 || city.length > 50) {
      return res.status(400).json({ errors: ['Enter a city name (2-50 characters).'] });
    }

    // Serve from the cache when possible (fewer calls to the external API)
    const key = city.toLowerCase();
    const cached = weatherCache.get(key);
    if (cached && Date.now() - cached.time < CACHE_MS) {
      return res.json(Object.assign({}, cached.data, { cached: true }));
    }

    // Call 1: turn the city name into coordinates
    const geo = await fetchJson(
      'https://geocoding-api.open-meteo.com/v1/search?count=1&name=' + encodeURIComponent(city)
    );
    if (!geo.results || geo.results.length === 0) {
      return res.status(404).json({ errors: ['City "' + city + '" was not found.'] });
    }
    const place = geo.results[0];

    // Call 2: get the current weather for those coordinates
    const forecast = await fetchJson(
      'https://api.open-meteo.com/v1/forecast?current=temperature_2m,relative_humidity_2m,wind_speed_10m,weather_code&timezone=auto' +
      '&latitude=' + place.latitude + '&longitude=' + place.longitude
    );
    const c = forecast.current;

    const data = {
      city: place.name,
      country: place.country || '',
      temperature: c.temperature_2m,
      humidity: c.relative_humidity_2m,
      windSpeed: c.wind_speed_10m,
      description: describeWeather(c.weather_code),
      cached: false
    };

    if (weatherCache.size >= 100) weatherCache.clear();
    weatherCache.set(key, { time: Date.now(), data });
    res.json(data);
  } catch (err) {
    next(err);
  }
});

/* ============ ERROR HANDLING ============ */
// Unknown API route -> JSON 404
app.use('/api', (req, res) => {
  res.status(404).json({ errors: ['API route not found.'] });
});

// One central place that turns every error into a clean JSON response
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ errors: ['Invalid JSON in the request body.'] });
  }

  const status = err.status || 500;
  if (status >= 500 && !err.expose) console.error(err); // log details on the server only

  res.status(status).json({
    errors: [err.expose ? err.message : 'Internal server error.']
  });
});

app.listen(PORT, () => {
  console.log('Server running at http://localhost:' + PORT);
  if (!GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET) {
    console.log('Note: GitHub login is OFF (add GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET to .env).');
  }
});