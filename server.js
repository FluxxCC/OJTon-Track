const path = require('path');
const fs = require('fs');
const os = require('os');
const express = require('express');
const session = require('express-session');
const mysql = require('mysql2/promise');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
let memCache = new Map();
function cacheGet(key){ const e = memCache.get(key); if (!e) return null; if (Date.now() > e.exp) { memCache.delete(key); return null; } return e.data; }
function cacheSet(key, data, ttlMs){ memCache.set(key, { data, exp: Date.now() + Math.max(1000, Number(ttlMs||30000)) }); }
// Datastore selection
const FORCE_JSON = false;
app.use(express.json({ limit: '5mb' }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'ojtontrack-dev-secret',
  resave: false,
  saveUninitialized: false,
}));

app.use((req, res, next) => {
  try {
    const origin = String(req.headers.origin || '').trim();
    const allow = origin || 'http://localhost:3000';
    res.setHeader('Access-Control-Allow-Origin', allow);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.setHeader('ngrok-skip-browser-warning', 'true');
    if (req.method === 'OPTIONS') { res.status(204).end(); return; }
  } catch {}
  next();
});

// Instructors bulk aggregation endpoint
app.post('/api/instructors/aggregate', requireAuth, restrictToCourse, async (req, res) => {
  try {
    if (!supabase) return res.status(500).json({ ok: false, error: 'Supabase not configured' });
    const u = req.user;
    const allowed = Array.isArray(req.scope?.courseCodes) && req.scope.courseCodes.length ? req.scope.courseCodes : (req.scope?.courseCode ? [req.scope.courseCode] : []);
    const idNumbers = Array.isArray(req.body?.ids) ? req.body.ids.map(s=>String(s||'').trim()).filter(Boolean) : [];
    if (!idNumbers.length) return res.status(400).json({ ok: false, error: 'ids[] required' });
    const cacheKey = `instructors:aggregate:${JSON.stringify(idNumbers.slice().sort())}:${JSON.stringify(allowed.slice().sort())}`;
    const cached = cacheGet(cacheKey);
    if (cached) return res.json({ ok: true, data: cached });
    const { data: userRows } = await supabase.from('users').select('id,idnumber,role,course').in('idnumber', idNumbers).range(0, 9999);
    const users = Array.isArray(userRows) ? userRows.filter(r => String(r.role||'') === 'instructor') : [];
    const byIdn = new Map(users.map(r => [String(r.idnumber||'').trim(), Number(r.id||0)]));
    const instrIds = Array.from(byIdn.values()).filter(x=>x);
    let coursesMap = new Map();
    let sectionsMap = new Map();
    if (instrIds.length) {
      const [linksCourses, linksSections, linksSi] = await Promise.all([
        supabase.from('user_courses').select('*').in('user_id', instrIds).range(0, 9999),
        supabase.from('user_sections').select('*').in('user_id', instrIds).range(0, 9999),
        supabase.from('section_instructors').select('*').in('instructor_id', instrIds).range(0, 9999)
      ]);
      const courseList = Array.isArray(linksCourses.data) ? linksCourses.data : [];
      const courseIdSet = Array.from(new Set(courseList.map(x => Number(x.course_id||x.courseid||0)).filter(x=>x)));
      let codeByCourseId = new Map();
      if (courseIdSet.length) {
        const { data: courseRows } = await supabase.from('courses').select('id,name,name_key').in('id', courseIdSet).range(0,9999);
        for (const r of (courseRows||[])) { const c = String(r.name||r.name_key||'').trim(); if (c) codeByCourseId.set(Number(r.id||0), c); }
      }
      for (const x of courseList) {
        const key = Number(x.user_id);
        const arr = coursesMap.get(key) || [];
        const text = String((x.course || x.course_code || '')).trim();
        const byId = codeByCourseId.get(Number(x.course_id||x.courseid||0)) || '';
        const code = text || byId;
        if (code) arr.push(code);
        coursesMap.set(key, arr);
      }
      const secList = Array.isArray(linksSections.data) ? linksSections.data : [];
      const byUserSecIds = new Map();
      for (const p of secList) {
        const key = Number(p.user_id);
        const sid = Number(p.section_id || 0);
        if (sid) {
          const arrIds = byUserSecIds.get(key) || [];
          arrIds.push(sid);
          byUserSecIds.set(key, arrIds);
        } else {
          const arr = sectionsMap.get(key) || [];
          const course = String((p.course || p.course_code || '')).trim();
          const section = String((p.section || p.section_code || '')).trim();
          if (course && section) arr.push(`${course}-${section}`);
          sectionsMap.set(key, arr);
        }
      }
      const siPairs = Array.isArray(linksSi.data) ? linksSi.data : [];
      const secIdsFromSi = Array.from(new Set(siPairs.map(x => Number(x.section_id)).filter(x => x)));
      const allSecIds = Array.from(new Set([ ...Array.from(byUserSecIds.values()).flat().filter(x=>x), ...secIdsFromSi ]));
      if (allSecIds.length) {
        const { data: secRows } = await supabase.from('sections').select('id,code,course').in('id', allSecIds).range(0, 9999);
        const byId = new Map();
        for (const s of (secRows || [])) { byId.set(Number(s.id||0), { code: String(s.code||'').trim(), course: String(s.course||'').trim() }); }
        for (const [userId, listIds] of byUserSecIds.entries()) {
          const arr = sectionsMap.get(Number(userId)) || [];
          for (const sid of (listIds || [])) {
            const row = byId.get(Number(sid));
            if (row && row.code) arr.push(row.code);
          }
          sectionsMap.set(Number(userId), arr);
        }
        for (const s of (secRows || [])) {
          const course = String(s.course||'').trim();
          const code = String(s.code||'').trim();
          const instrs = siPairs.filter(p => Number(p.section_id) === Number(s.id));
          for (const p of instrs) {
            const key = Number(p.instructor_id);
            const arr = sectionsMap.get(key) || [];
            if (course && code) arr.push(code);
            sectionsMap.set(key, arr);
          }
        }
      }
    }
    const out = {};
    for (const r of users) {
      const idn = String(r.idnumber||'').trim();
      const uid = Number(r.id||0);
      let courses = Array.from(new Set((coursesMap.get(uid) || []).filter(Boolean)));
      let sections = Array.from(new Set((sectionsMap.get(uid) || []).filter(Boolean)));
      if (allowed.length) {
        courses = courses.filter(c => allowed.includes(c));
        sections = sections.filter(s => allowed.includes(String(s).split('-')[0]));
      }
      const primary = String(r.course||'').trim();
      if (!courses.length && primary) courses = [primary];
      out[idn] = { courses, sections };
    }
    cacheSet(cacheKey, out, 30000);
    return res.json({ ok: true, data: out });
  } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
});

// HTML auth guard: redirect unauthenticated users to index.html for HTML routes
app.use((req, res, next) => {
  try {
    const disableGuard = String(process.env.DISABLE_ADMIN_HTML_GUARD || '').toLowerCase() === 'true';
    const p = (req.path || '/').toLowerCase();
    const isRoot = p === '/' || p === '';
    const isHtml = isRoot || p.endsWith('.html');
    const isAdminHtml = p.startsWith('/admin/') && p.endsWith('.html') && p !== '/admin/login.html';
    const bypass = String((req.query && (req.query.preview || req.query.noauth)) || '').toLowerCase() === '1';
    if (!disableGuard && !bypass && isAdminHtml) {
      if (!req.session || !req.session.user) {
        return res.redirect('/admin/login.html');
      }
    }
  } catch {}
  next();
});

// Serve static files
app.use(express.static(path.join(__dirname)));
app.get('/config.js', (req, res) => {
  try {
    const url = process.env.SUPABASE_URL || '';
    const anon = process.env.SUPABASE_ANON_KEY || '';
    res.setHeader('Content-Type', 'application/javascript');
    res.send(`window.SUPABASE_URL=${JSON.stringify(url)};window.SUPABASE_ANON_KEY=${JSON.stringify(anon)};`);
  } catch { res.status(500).send(''); }
});

app.get(/^.*\/config\.js$/, (req, res) => {
  try {
    const url = process.env.SUPABASE_URL || '';
    const anon = process.env.SUPABASE_ANON_KEY || '';
    res.setHeader('Content-Type', 'application/javascript');
    res.send(`window.SUPABASE_URL=${JSON.stringify(url)};window.SUPABASE_ANON_KEY=${JSON.stringify(anon)};`);
  } catch { res.status(500).send(''); }
});

// Explicit routes for PWA assets
app.get('/manifest.json', (req, res) => {
  try { res.type('application/json'); res.sendFile(path.join(__dirname, 'manifest.json')); } catch { res.status(404).send('Not Found'); }
});
app.get('/service-worker.js', (req, res) => {
  try { res.type('application/javascript'); res.setHeader('Service-Worker-Allowed', '/'); res.sendFile(path.join(__dirname, 'service-worker.js')); } catch { res.status(404).send('Not Found'); }
});
app.get('/offline.html', (req, res) => {
  try { res.type('text/html'); res.sendFile(path.join(__dirname, 'offline.html')); } catch { res.status(404).send('Not Found'); }
});

// Health endpoints for Render
app.get('/healthz', (req, res) => {
  res.status(200).json({ ok: true });
});
app.get('/readyz', (req, res) => {
  res.status(200).json({ ready: true });
});
// Alias nested paths to root styles.css to avoid relative resolution issues
app.get(/^.*\/styles\.css$/, (req, res) => {
  try { res.type('text/css'); res.sendFile(path.join(__dirname, 'styles.css')); } catch { res.status(404).send('Not Found'); }
});

// Route root to index.html for better SPA navigation
app.get('/', (req, res) => {
  try { res.type('text/html'); res.sendFile(path.join(__dirname, 'index.html')); } catch { res.status(500).send('Server error'); }
});

// Optional HTTPS server for mobile installability
try {
  const enableHttps = String(process.env.HTTPS_ENABLE||'').toLowerCase() === 'true';
  if (enableHttps) {
    const https = require('https');
    const keyPath = process.env.HTTPS_KEY;
    const certPath = process.env.HTTPS_CERT;
    if (keyPath && certPath && fs.existsSync(keyPath) && fs.existsSync(certPath)) {
      const creds = { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) };
      const HTTPS_PORT = Number(process.env.HTTPS_PORT||3443);
      https.createServer(creds, app).listen(HTTPS_PORT, () => {
        console.log(`[HTTPS] OJTonTrack server running at https://localhost:${HTTPS_PORT}/`);
      });
    } else {
      console.log('[HTTPS] Missing HTTPS_KEY/HTTPS_CERT paths or files');
    }
  }
} catch (e) {
  console.log('[HTTPS] Init failed:', e.message);
}

// Optional MySQL pool; fallback to JSON when not configured
let pool = null;
let cloudinaryClient = null;
let supabase = null;
// Initialize optional MySQL
(async () => {
  const { MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DATABASE } = process.env;
  if (!FORCE_JSON && MYSQL_HOST && MYSQL_USER && MYSQL_DATABASE) {
    try {
      pool = await mysql.createPool({
        host: MYSQL_HOST,
        user: MYSQL_USER,
        password: MYSQL_PASSWORD,
        database: MYSQL_DATABASE,
        waitForConnections: true,
        connectionLimit: 10,
      });
      console.log('[DB] MySQL pool initialized');
    } catch (e) {
      console.error('[DB] Failed to init pool, falling back to JSON store:', e.message);
    }
  } else {
    console.log('[DB] Using JSON store');
  }
})();

try {
  const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = process.env;
  if (SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY) {
    const { createClient } = require('@supabase/supabase-js');
    supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
    (async () => {
      try {
        const idNum = 'CITE_Admin_OJT';
        const { data } = await supabase.from('users').select('idnumber').eq('idnumber', idNum).limit(1);
        if (!Array.isArray(data) || data.length === 0) {
          await supabase.from('users').insert([{ idnumber: idNum, password: 'Admin_CITE', role: 'super_admin', name: idNum }]);
        }
        console.log('[DB] Supabase initialized');
      } catch (e) {
        console.error('[DB] Supabase init failed:', e.message);
      }
    })();
  }
} catch (e) {
  console.error('[DB] Supabase init error:', e.message);
}

function initCloudinary() {
  const { CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET, CLOUDINARY_URL } = process.env;
  const cloudinary = require('cloudinary').v2;
  if (CLOUDINARY_URL) {
    cloudinary.config({ secure: true });
    cloudinaryClient = cloudinary;
    return;
  }
  if (CLOUDINARY_CLOUD_NAME && CLOUDINARY_API_KEY && CLOUDINARY_API_SECRET) {
    cloudinary.config({ cloud_name: CLOUDINARY_CLOUD_NAME, api_key: CLOUDINARY_API_KEY, api_secret: CLOUDINARY_API_SECRET, secure: true });
    cloudinaryClient = cloudinary;
  }
}
initCloudinary();

// JSON helpers for fallback mode


function fullName(parts) {
  const f = String(parts?.firstName || '').trim();
  const m = String(parts?.middleName || '').trim();
  const l = String(parts?.lastName || '').trim();
  return [f, m, l].filter(Boolean).join(' ').trim();
}

function parseDataUrl(dataUrl) {
  const m = String(dataUrl || '').match(/^data:image\/(png|jpeg);base64,(.+)$/);
  if (!m) return null;
  const ext = m[1] === 'jpeg' ? 'jpg' : m[1];
  return { buffer: Buffer.from(m[2], 'base64'), contentType: `image/${m[1]}`, ext };
}
function readJson(name){ try { const p=path.join(__dirname,'data',name); const s=fs.readFileSync(p,'utf8'); const j=JSON.parse(s); return Array.isArray(j)? j : []; } catch { return []; } }
function writeJson(name, arr){ try { const p=path.join(__dirname,'data',name); fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, JSON.stringify(arr, null, 2)); return true; } catch { return false; } }

// Auth middleware — cookie session only
function requireAuth(req, res, next) {
  let u = null;
  try {
    const h = String(req.headers && req.headers.authorization || '').trim();
    if (h && h.toLowerCase().startsWith('bearer ')) {
      const token = h.slice(7).trim();
      const parts = token.split('.');
      if (parts.length === 2) {
        const payload = parts[0];
        const sig = parts[1];
        const crypto = require('crypto');
        const secret = process.env.SESSION_SECRET || 'ojtontrack-dev-secret';
        const expected = crypto.createHmac('sha256', secret).update(payload).digest('base64url');
        if (expected === sig) {
          const json = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
          const idNumber = String(json.idNumber || '');
          const role = String(json.role || '');
          const roleNorm = role.toLowerCase();
          if (idNumber && roleNorm) {
            u = { idNumber, role: roleNorm, courseId: json.courseId || null, courseCode: json.courseCode || null };
          }
        }
      }
    }
  } catch {}
  if (!u) u = req.session && req.session.user ? req.session.user : null;
  if (u && u.role) u.role = String(u.role).toLowerCase();
  if (!u) return res.status(401).json({ ok: false, error: 'Auth required' });
  req.user = u;
  next();
}
async function restrictToCourse(req, res, next) {
  try {
    const u = req.user;
    if (u.role === 'super_admin') return next();
    req.scope = { courseId: u.courseId, courseCode: u.courseCode };
    if (u.role === 'instructor') {
      try {
        if (supabase) {
          let uid = null;
          const { data: row } = await supabase.from('users').select('id,course').eq('idnumber', u.idNumber).limit(1);
          const me = (Array.isArray(row) && row[0]) ? row[0] : null;
          uid = me ? Number(me.id||0) : null;
          let codes = [];
          if (uid) {
            const { data: links } = await supabase.from('user_courses').select('*').eq('user_id', uid).range(0, 9999);
            const rows = Array.isArray(links) ? links : [];
            const strCodes = rows.map(x => String((x.course||x.course_code||'')).trim()).filter(Boolean);
            const ids = rows.map(x => Number(x.course_id||x.courseid||0)).filter(Boolean);
            let codesFromIds = [];
            if (ids.length) {
              const { data: courseRows } = await supabase.from('courses').select('id,name,name_key').in('id', ids).range(0, 9999);
              codesFromIds = Array.isArray(courseRows) ? courseRows.map(r=>String(r.name||r.name_key||'').trim()).filter(Boolean) : [];
            }
            codes = Array.from(new Set([...(strCodes||[]), ...(codesFromIds||[])].filter(Boolean)));
          }
          const primary = String(me?.course||'').trim();
          const union = Array.from(new Set([primary, ...codes].filter(Boolean)));
          if (union.length) req.scope.courseCodes = union;
          // Avoid forcing a single course when multiple are assigned
          if (!union.length) req.scope.courseCodes = [];
        }
      } catch {}
    }
    if (u.role === 'coordinator') {
      try {
        if (supabase) {
          let uid = null;
          const { data: row } = await supabase.from('users').select('id').eq('idnumber', u.idNumber).limit(1);
        uid = (Array.isArray(row) && row[0]) ? Number(row[0].id) : null;
        if (uid) {
          // Primary course from users row
          try {
            const { data: userRow } = await supabase.from('users').select('course').eq('id', uid).limit(1);
            const primary = (Array.isArray(userRow) && userRow[0]) ? String(userRow[0].course||'').trim() : '';
            if (primary) req.scope.courseCode = primary;
          } catch {}
          // Assigned courses from user_courses (supports string and FK)
          const { data: cc } = await supabase.from('user_courses').select('*').eq('user_id', uid).range(0, 999);
          const rows = Array.isArray(cc) ? cc : [];
          const codesStr = rows.map(x => String((x.course||x.course_code||'')).trim()).filter(Boolean);
          const ids = rows.map(x => Number(x.course_id || 0)).filter(Boolean);
          let codesFromIds = [];
          if (ids.length) {
          const { data: courseRows } = await supabase.from('courses').select('id,name,name_key').in('id', ids).range(0, 999);
          codesFromIds = Array.isArray(courseRows) ? courseRows.map(r => String(r.name || r.name_key || '').trim()).filter(Boolean) : [];
          }
          const union = Array.from(new Set([req.scope.courseCode, ...codesStr, ...codesFromIds].filter(Boolean)));
          if (union.length) req.scope.courseCodes = union;
        } else {
          // Fallback to session values
          const single = String(u.courseCode || '').trim();
          if (single) req.scope.courseCodes = [single];
        }
      }
      if (!Array.isArray(req.scope.courseCodes) || !req.scope.courseCodes.length) {
        try {
          const list = readJson('coordinator_courses.json');
          const entry = (Array.isArray(list)?list:[]).find(x=>String(x.idNumber||'').trim() === String(u.idNumber||'').trim());
          const arr = entry && Array.isArray(entry.courses) ? entry.courses.map(c=>String(c||'').trim()).filter(Boolean) : [];
          const primary = String(req.scope.courseCode || u.courseCode || '').trim();
          const union2 = Array.from(new Set([primary, ...arr].filter(Boolean)));
          if (union2.length) req.scope.courseCodes = union2;
        } catch {}
      }
    } catch {}
  }
    if (!req.scope.courseCode && !req.scope.courseCodes) return res.status(403).json({ ok: false, error: 'No course assigned' });
    return next();
  } catch (e) {
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
}

// Admin login (compatibility with admin.json)
app.post('/admin/login', (req, res) => {
  try {
    const { username, password } = req.body || {};
    const dataPath = path.join(__dirname, 'data', 'admin.json');
    fs.readFile(dataPath, 'utf8', (err, json) => {
      if (err) return res.status(500).json({ ok: false, error: 'Server error' });
      try {
        const admin = JSON.parse(json);
        const ok = admin.username === username && admin.password === password;
        if (!ok) return res.status(401).json({ ok: false, error: 'Invalid credentials' });
        req.session.user = { idNumber: admin.username, role: 'super_admin', courseId: null, courseCode: null };
        try {
          const crypto = require('crypto');
          const secret = process.env.SESSION_SECRET || 'ojtontrack-dev-secret';
          const payload = Buffer.from(JSON.stringify({ idNumber: admin.username, role: 'super_admin', courseId: null, courseCode: null }), 'utf8').toString('base64url');
          const sig = crypto.createHmac('sha256', secret).update(payload).digest('base64url');
          const token = `${payload}.${sig}`;
          return res.json({ ok: true, redirect: '/admin/dashboard.html', token, role: 'super_admin' });
        } catch {
          return res.json({ ok: true, redirect: '/admin/dashboard.html' });
        }
      } catch (e) {
        return res.status(500).json({ ok: false, error: 'Invalid admin data format' });
      }
    });
  } catch (e) {
    res.status(400).json({ ok: false, error: 'Invalid request body' });
  }
});

// General user login (uses DB if configured, otherwise JSON fallback)
app.post('/login', async (req, res) => {
  const { idNumber, password } = req.body || {};
  if (!idNumber || !password) return res.status(400).json({ ok: false, error: 'Missing credentials' });

  try {
    if (pool && !supabase) {
      const [rows] = await pool.execute(
        'SELECT u.id, u.id_number, u.password_hash, u.role, u.course_id, c.code AS course_code FROM users u LEFT JOIN courses c ON c.id = u.course_id WHERE u.id_number=?',
        [idNumber]
      );
      const user = rows[0];
      if (!user) return res.status(401).json({ ok: false, error: 'Invalid credentials' });
      const bcrypt = require('bcrypt');
      const ok = await bcrypt.compare(password, user.password_hash);
      if (!ok) return res.status(401).json({ ok: false, error: 'Invalid credentials' });
      req.session.user = { id: user.id, idNumber: user.id_number, role: user.role, courseId: user.course_id, courseCode: user.course_code };
    } else if (supabase) {
      const { data } = await supabase.from('users').select('idnumber,password,role,course').eq('idnumber', idNumber).limit(1);
      const u = Array.isArray(data) && data[0] ? data[0] : null;
      if (!u) return res.status(401).json({ ok: false, error: 'Invalid credentials' });
      if ((u.password || '') !== password) return res.status(401).json({ ok: false, error: 'Invalid credentials' });
      const role = String(u.role||'').toLowerCase();
      const primaryCourse = String(u.course||'').trim() || null;
      const courseCode = role === 'instructor' ? null : primaryCourse;
      req.session.user = { idNumber: u.idnumber, role: u.role, courseId: null, courseCode };
    } else {
      return res.status(500).json({ ok: false, error: 'Supabase not configured' });
    }

    const u = req.session && req.session.user ? req.session.user : null;
    let redirect = '/';
    if (u.role === 'coordinator') redirect = `/coordinator/dashboard.html`;
    else if (u.role === 'instructor') redirect = `/instructor/dashboard.html`;
    else if (u.role === 'supervisor') redirect = `/supervisor/dashboard.html`;
    else if (u.role === 'student') redirect = `/student/dashboard.html`;
    else redirect = '/admin/dashboard.html';
    try {
      const crypto = require('crypto');
      const secret = process.env.SESSION_SECRET || 'ojtontrack-dev-secret';
      const payload = Buffer.from(JSON.stringify({ idNumber: u.idNumber, role: u.role, courseId: u.courseId || null, courseCode: u.courseCode || null }), 'utf8').toString('base64url');
      const sig = crypto.createHmac('sha256', secret).update(payload).digest('base64url');
      const token = `${payload}.${sig}`;
      return res.json({ ok: true, redirect, token, role: u.role });
    } catch {
      return res.json({ ok: true, redirect });
    }
  } catch (e) {
    console.error('Login error:', e);
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
});

app.post('/api/auth/link', requireAuth, async (req, res) => {
  try {
    if (!supabase || !supabase.auth || !supabase.auth.admin) return res.status(500).json({ ok: false, error: 'Supabase auth not configured' });
    const u = req.user;
    const password = String(req.body?.password || '').trim();
    if (!u || !u.idNumber) return res.status(400).json({ ok: false, error: 'Missing user' });
    if (!password) return res.status(400).json({ ok: false, error: 'Missing password' });
    const email = `${u.idNumber}@ojt.local`;
    try { await supabase.auth.admin.createUser({ email, password, email_confirm: true }); } catch {}
    try {
      const { data: list } = await supabase.auth.admin.listUsers({ page: 1, perPage: 2000 });
      const found = (list?.users || []).find(x => String(x.email || '').toLowerCase() === email.toLowerCase());
      if (found && found.id) {
        try { await supabase.from('users').update({ auth_user_id: found.id }).eq('idnumber', u.idNumber); } catch {}
      }
    } catch {}
    return res.json({ ok: true, email });
  } catch (e) {
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
});

app.post('/api/auth/link-all', requireAuth, async (req, res) => {
  try {
    const u = req.user;
    if (!u || u.role !== 'super_admin') return res.status(403).json({ ok: false, error: 'Forbidden' });
    if (!supabase || !supabase.auth || !supabase.auth.admin) return res.status(500).json({ ok: false, error: 'Supabase auth not configured' });
    const { data: usersRows } = await supabase.from('users').select('idnumber,password,auth_user_id');
    const rows = Array.isArray(usersRows) ? usersRows : [];
    let created = 0;
    for (const r of rows) {
      const idn = String(r.idnumber || '').trim();
      if (!idn) continue;
      const email = `${idn}@ojt.local`;
      try { await supabase.auth.admin.createUser({ email, password: String(r.password || 'password'), email_confirm: true }); created++; } catch {}
    }
    try {
      const { data: list } = await supabase.auth.admin.listUsers({ page: 1, perPage: 2000 });
      const map = new Map();
      for (const x of (list?.users || [])) { map.set(String(x.email || '').toLowerCase(), x.id); }
      for (const r of rows) {
        const idn = String(r.idnumber || '').trim();
        if (!idn) continue;
        const email = `${idn}@ojt.local`;
        const uid = map.get(email.toLowerCase()) || null;
        if (uid) { try { await supabase.from('users').update({ auth_user_id: uid }).eq('idnumber', idn); } catch {} }
      }
    } catch {}
    return res.json({ ok: true, created });
  } catch (e) {
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// Read endpoints with course scoping
app.get('/api/instructors', requireAuth, restrictToCourse, async (req, res) => {
  try {
    if (pool && !supabase) {
      const u = req.user;
      const params = [];
      let sql = "SELECT id_number, name, role, course_id FROM users WHERE role='instructor'";
      if (u.role !== 'super_admin') { sql += ' AND course_id=?'; params.push(u.courseId); }
      const [rows] = await pool.execute(sql, params);
      return res.json({ ok: true, data: rows });
  } else if (supabase) {
      const u = req.user;
      const isSimple = (() => { const v = String(req.query.simple||'').trim().toLowerCase(); return v==='1' || v==='true'; })();
      const page = Math.max(1, Number(req.query.page || 1));
      const limit = Math.min(200, Math.max(1, Number(req.query.limit || 50)));
      const start = (page - 1) * limit;
      const end = start + limit - 1;
      let query = supabase.from('users').select('*').eq('role', 'instructor');
      let primaryMatches = [];
      if (u.role !== 'super_admin') {
        if (Array.isArray(req.scope?.courseCodes) && req.scope.courseCodes.length) {
          const { data: dataA } = await query.in('course', req.scope.courseCodes).range(start, end);
          primaryMatches = Array.isArray(dataA) ? dataA : [];
        } else if (req.scope?.courseCode) {
          const { data: dataB } = await query.eq('course', req.scope.courseCode).range(start, end);
          primaryMatches = Array.isArray(dataB) ? dataB : [];
        } else {
          const { data: dataC } = await query.range(start, end);
          primaryMatches = Array.isArray(dataC) ? dataC : [];
        }
        if (isSimple) {
          const scopeList = Array.isArray(req.scope?.courseCodes) && req.scope.courseCodes.length ? req.scope.courseCodes : (req.scope?.courseCode ? [req.scope.courseCode] : []);
          const key = `instructors:simple:${JSON.stringify(scopeList)}:${page}:${limit}`;
          const cached = cacheGet(key);
          if (cached) return res.json({ ok: true, data: cached });
          const rows = primaryMatches.slice(0, limit);
          const normalized = rows.map(r => {
            const firstName = r.firstName || r.firstname || null;
            const middleName = r.middleName || r.middlename || null;
            const lastName = r.lastName || r.lastname || null;
            const name = r.name || fullName({ firstName, middleName, lastName }) || (r.idnumber || r.idNumber);
            const primaryCourse = String(r.course || '').trim();
            return { idNumber: r.idnumber || r.idNumber, name, course: primaryCourse, courses: primaryCourse ? [primaryCourse] : [], sections: [] };
          });
          cacheSet(key, normalized, 30000);
          return res.json({ ok: true, data: normalized });
        }
        let linkedMatches = [];
        const scopeList = Array.isArray(req.scope?.courseCodes) && req.scope.courseCodes.length ? req.scope.courseCodes : (req.scope?.courseCode ? [req.scope.courseCode] : []);
        if (scopeList.length) {
          let instrIds = [];
          try {
            const { data: linksByCode } = await supabase.from('user_courses').select('user_id').in('course', scopeList).range(0, 9999);
            const ids1 = Array.isArray(linksByCode) ? linksByCode.map(x => Number(x.user_id)).filter(x => x) : [];
            instrIds = ids1;
          } catch {}
          try {
            const { data: courseRows } = await supabase.from('courses').select('id,name,name_key').in('name', scopeList).range(0,9999);
            const idsCodes = Array.isArray(courseRows) ? courseRows.map(r => Number(r.id||0)).filter(x=>x) : [];
            const { data: courseRowsAlt } = await supabase.from('courses').select('id,name,name_key').in('name_key', scopeList).range(0,9999);
            const idsCodesAlt = Array.isArray(courseRowsAlt) ? courseRowsAlt.map(r => Number(r.id||0)).filter(x=>x) : [];
          const courseIds = Array.from(new Set([...(idsCodes||[]), ...(idsCodesAlt||[])]));
            if (courseIds.length) {
              const { data: linksById } = await supabase.from('user_courses').select('user_id').in('course_id', courseIds).range(0,9999);
              const ids2 = Array.isArray(linksById) ? linksById.map(x => Number(x.user_id)).filter(x => x) : [];
              instrIds = Array.from(new Set([...(instrIds||[]), ...(ids2||[])]));
            }
          } catch {}
          try {
            const { data: byCourse } = await supabase.from('sections').select('id,course').in('course', scopeList).range(0, 9999);
            const { data: byCourseCode } = await supabase.from('sections').select('id,course_code').in('course_code', scopeList).range(0, 9999);
            const rows = [...(Array.isArray(byCourse)?byCourse:[]), ...(Array.isArray(byCourseCode)?byCourseCode:[])];
            const secIds = Array.from(new Set(rows.map(s => Number(s.id||0)).filter(x=>x)));
            if (secIds.length) {
              const { data: secLinks } = await supabase.from('user_sections').select('user_id,section_id').in('section_id', secIds).range(0, 9999);
              const ids3 = Array.isArray(secLinks) ? secLinks.map(x => Number(x.user_id)).filter(x => x) : [];
              instrIds = Array.from(new Set([...(instrIds||[]), ...(ids3||[])]));
            }
            const { data: secLegacyA } = await supabase.from('user_sections').select('user_id').in('course', scopeList).range(0, 9999);
            const { data: secLegacyB } = await supabase.from('user_sections').select('user_id').in('course_code', scopeList).range(0, 9999);
            const ids4 = [...(Array.isArray(secLegacyA)?secLegacyA:[]), ...(Array.isArray(secLegacyB)?secLegacyB:[])].map(x=>Number(x.user_id)).filter(x=>x);
            instrIds = Array.from(new Set([...(instrIds||[]), ...(ids4||[])]));
          } catch {}
          if (instrIds.length) {
            const { data: usersRows } = await supabase.from('users').select('*').eq('role', 'instructor').in('id', instrIds).range(0, 9999);
            linkedMatches = Array.isArray(usersRows) ? usersRows : [];
          }
        }
        const byIdn = new Map();
        for (const r of primaryMatches) { byIdn.set(String(r.idnumber||r.idNumber||'').trim(), r); }
        for (const r of linkedMatches) {
          const key = String(r.idnumber||r.idNumber||'').trim();
          if (!byIdn.has(key)) byIdn.set(key, r);
        }
        const rowsAll = Array.from(byIdn.values());
        const rows = rowsAll.slice(start, start + limit);
        const ids = rows.map(r => Number(r.id || 0)).filter(x => x);
        let coursesMap = new Map();
        let sectionsMap = new Map();
        try {
        if (ids.length) {
          const { data: cc } = await supabase.from('user_courses').select('*').in('user_id', ids).range(0, 9999);
          const list = Array.isArray(cc) ? cc : [];
          const idSet = Array.from(new Set(list.map(x => Number(x.course_id||x.courseid||0)).filter(x=>x)));
          let codeById = new Map();
          if (idSet.length) {
            const { data: courseRows } = await supabase.from('courses').select('id,name,name_key').in('id', idSet).range(0,9999);
            for (const r of (courseRows||[])) { const c = String(r.name||r.name_key||'').trim(); if (c) codeById.set(Number(r.id||0), c); }
          }
          for (const x of list) {
            const key = Number(x.user_id);
            const arr = coursesMap.get(key) || [];
            const text = String((x.course || x.course_code || '')).trim();
            const byId = codeById.get(Number(x.course_id||x.courseid||0)) || '';
            const code = text || byId;
            if (code) { arr.push(code); coursesMap.set(key, arr); }
          }
          const { data: extras } = await supabase.from('user_sections').select('*').in('user_id', ids).range(0, 9999);
          const byUserSecIds = new Map();
          for (const p of (extras || [])) {
            const key = Number(p.user_id);
            const sid = Number(p.section_id || 0);
            if (sid) {
              const arrIds = byUserSecIds.get(key) || [];
              arrIds.push(sid);
              byUserSecIds.set(key, arrIds);
            } else {
              const arr = sectionsMap.get(key) || [];
              const course = String((p.course || p.course_code || '')).trim();
              const section = String((p.section || p.section_code || '')).trim();
              if (course && section) arr.push(`${course}-${section}`);
              sectionsMap.set(key, arr);
            }
          }
          const allSecIds = Array.from(new Set(Array.from(byUserSecIds.values()).flat().filter(x => x)));
          if (allSecIds.length) {
            const { data: secRows } = await supabase.from('sections').select('id,code,course').in('id', allSecIds).range(0, 9999);
            const byId = new Map();
            for (const s of (secRows || [])) { byId.set(Number(s.id||0), { code: String(s.code||'').trim(), course: String(s.course||'').trim() }); }
            for (const [userId, list] of byUserSecIds.entries()) {
              const arr = sectionsMap.get(Number(userId)) || [];
              for (const sid of (list || [])) {
                const row = byId.get(Number(sid));
                if (row && row.code) arr.push(row.code);
              }
              sectionsMap.set(Number(userId), arr);
            }
          }
          const { data: si } = await supabase.from('section_instructors').select('*').in('instructor_id', ids).range(0, 9999);
          const pairs = Array.isArray(si) ? si : [];
          const secIds = Array.from(new Set(pairs.map(x => Number(x.section_id)).filter(x => x)));
          if (secIds.length) {
            const { data: secRows } = await supabase.from('sections').select('*').in('id', secIds).range(0, 9999);
            for (const s of (secRows || [])) {
              const course = String(s.course||'').trim();
              const code = String(s.code||'').trim();
              const instrs = pairs.filter(p => Number(p.section_id) === Number(s.id));
              for (const p of instrs) {
                const key = Number(p.instructor_id);
                const arr = sectionsMap.get(key) || [];
                if (course && code) arr.push(code);
                sectionsMap.set(key, arr);
              }
            }
          }
        }
        } catch {}
        const normalized = rows.map(r => {
          const firstName = r.firstName || r.firstname || null;
          const middleName = r.middleName || r.middlename || null;
          const lastName = r.lastName || r.lastname || null;
          const name = r.name || fullName({ firstName, middleName, lastName }) || (r.idnumber || r.idNumber);
          const primaryCourse = String(r.course || '').trim();
          const allCourses = Array.from(new Set([primaryCourse, ...(coursesMap.get(Number(r.id || 0)) || [])].filter(Boolean)));
          const allSections = Array.from(new Set((sectionsMap.get(Number(r.id || 0)) || []).filter(Boolean)));
          return { ...r, idNumber: r.idnumber || r.idNumber, supervisorId: r.supervisorid || r.supervisorId || null, name, courses: allCourses, sections: allSections };
        });
        return res.json({ ok: true, data: normalized });
      }
      const { data } = await query.range(start, end);
      const rows = Array.isArray(data) ? data : [];
      const ids = rows.map(r => Number(r.id || 0)).filter(x => x);
      let coursesMap = new Map();
      let sectionsMap = new Map();
      try {
          if (ids.length) {
            const { data: cc } = await supabase.from('user_courses').select('*').in('user_id', ids).range(0, 9999);
            const list = Array.isArray(cc) ? cc : [];
            const idSet = Array.from(new Set(list.map(x => Number(x.course_id||0)).filter(x=>x)));
            let codeById = new Map();
            if (idSet.length) {
              const { data: courseRows } = await supabase.from('courses').select('id,code,course_code').in('id', idSet).range(0,9999);
              for (const r of (courseRows||[])) { const c = String(r.code||r.course_code||'').trim(); if (c) codeById.set(Number(r.id||0), c); }
            }
            for (const x of list) {
              const key = Number(x.user_id);
              const arr = coursesMap.get(key) || [];
              const text = String((x.course || x.course_code || '')).trim();
              const byId = codeById.get(Number(x.course_id||0)) || '';
              const code = text || byId;
              if (code) { arr.push(code); coursesMap.set(key, arr); }
            }
            const { data: extras } = await supabase.from('user_sections').select('*').in('user_id', ids).range(0, 9999);
            for (const p of (extras || [])) {
              const key = Number(p.user_id);
              const arr = sectionsMap.get(key) || [];
              const course = String((p.course || p.course_code || '')).trim();
              const section = String((p.section || p.section_code || '')).trim();
              if (course && section) arr.push(`${course}-${section}`);
              sectionsMap.set(key, arr);
            }
            const { data: si } = await supabase.from('section_instructors').select('*').in('instructor_id', ids).range(0, 9999);
            const pairs = Array.isArray(si) ? si : [];
            const secIds = Array.from(new Set(pairs.map(x => Number(x.section_id)).filter(x => x)));
            if (secIds.length) {
              const { data: secRows } = await supabase.from('sections').select('*').in('id', secIds).range(0, 9999);
              for (const s of (secRows || [])) {
                const course = String(s.course||'').trim();
                const code = String(s.code||'').trim();
                const instrs = pairs.filter(p => Number(p.section_id) === Number(s.id));
                for (const p of instrs) {
                  const key = Number(p.instructor_id);
                  const arr = sectionsMap.get(key) || [];
                  if (course && code) arr.push(code);
                  sectionsMap.set(key, arr);
                }
              }
            }
          }
      } catch {}
      const normalized = rows.map(r => {
        const firstName = r.firstName || r.firstname || null;
        const middleName = r.middleName || r.middlename || null;
        const lastName = r.lastName || r.lastname || null;
        const name = r.name || fullName({ firstName, middleName, lastName }) || (r.idnumber || r.idNumber);
        const primaryCourse = String(r.course || '').trim();
        const allCourses = Array.from(new Set([primaryCourse, ...(coursesMap.get(Number(r.id || 0)) || [])].filter(Boolean)));
        const allSections = Array.from(new Set((sectionsMap.get(Number(r.id || 0)) || []).filter(Boolean)));
        return { ...r, idNumber: r.idnumber || r.idNumber, supervisorId: r.supervisorid || r.supervisorId || null, name, courses: allCourses, sections: allSections };
      });
      return res.json({ ok: true, data: normalized });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) { res.status(500).json({ ok: false, error: 'Server error' }); }
});

// Full instructor list with aggregated courses and sections in one call
app.get('/api/instructors/full', requireAuth, restrictToCourse, async (req, res) => {
  try {
    if (pool && !supabase) {
      const u = req.user;
      const params = [];
      let sql = "SELECT id_number, name, role, course_id FROM users WHERE role='instructor'";
      if (u.role !== 'super_admin') { sql += ' AND course_id=?'; params.push(u.courseId); }
      const [rows] = await pool.execute(sql, params);
      return res.json({ ok: true, data: rows });
    } else if (supabase) {
      const u = req.user;
      let query = supabase.from('users').select('*').eq('role', 'instructor');
      let primaryMatches = [];
      if (u.role !== 'super_admin') {
        if (Array.isArray(req.scope?.courseCodes) && req.scope.courseCodes.length) {
          const { data: dataA } = await query.in('course', req.scope.courseCodes).range(0, 9999);
          primaryMatches = Array.isArray(dataA) ? dataA : [];
        } else if (req.scope?.courseCode) {
          const { data: dataB } = await query.eq('course', req.scope.courseCode).range(0, 9999);
          primaryMatches = Array.isArray(dataB) ? dataB : [];
        } else {
          const { data: dataC } = await query.range(0, 9999);
          primaryMatches = Array.isArray(dataC) ? dataC : [];
        }
        let linkedMatches = [];
        const scopeList = Array.isArray(req.scope?.courseCodes) && req.scope.courseCodes.length ? req.scope.courseCodes : (req.scope?.courseCode ? [req.scope.courseCode] : []);
        if (scopeList.length) {
          let instrIds = [];
          try {
            const { data: linksByCode } = await supabase.from('user_courses').select('user_id').in('course', scopeList).range(0, 9999);
            const ids1 = Array.isArray(linksByCode) ? linksByCode.map(x => Number(x.user_id)).filter(x => x) : [];
            instrIds = ids1;
          } catch {}
          try {
            const { data: courseRows } = await supabase.from('courses').select('id,name,name_key').in('name', scopeList).range(0,9999);
            const idsCodes = Array.isArray(courseRows) ? courseRows.map(r => Number(r.id||0)).filter(x=>x) : [];
            const { data: courseRowsAlt } = await supabase.from('courses').select('id,name,name_key').in('name_key', scopeList).range(0,9999);
            const idsCodesAlt = Array.isArray(courseRowsAlt) ? courseRowsAlt.map(r => Number(r.id||0)).filter(x=>x) : [];
            const courseIds = Array.from(new Set([...(idsCodes||[]), ...(idsCodesAlt||[])]));
            if (courseIds.length) {
              const { data: linksById } = await supabase.from('user_courses').select('user_id').in('course_id', courseIds).range(0,9999);
              const ids2 = Array.isArray(linksById) ? linksById.map(x => Number(x.user_id)).filter(x => x) : [];
              instrIds = Array.from(new Set([...(instrIds||[]), ...(ids2||[])]));
            }
          } catch {}
          try {
            const { data: byCourse } = await supabase.from('sections').select('id,course').in('course', scopeList).range(0, 9999);
            const { data: byCourseCode } = await supabase.from('sections').select('id,course_code').in('course_code', scopeList).range(0, 9999);
            const rows = [...(Array.isArray(byCourse)?byCourse:[]), ...(Array.isArray(byCourseCode)?byCourseCode:[])];
            const secIds = Array.from(new Set(rows.map(s => Number(s.id||0)).filter(x=>x)));
            if (secIds.length) {
              const { data: secLinks } = await supabase.from('user_sections').select('user_id,section_id').in('section_id', secIds).range(0, 9999);
              const ids3 = Array.isArray(secLinks) ? secLinks.map(x => Number(x.user_id)).filter(x => x) : [];
              instrIds = Array.from(new Set([...(instrIds||[]), ...(ids3||[])]));
            }
            const { data: secLegacyA } = await supabase.from('user_sections').select('user_id').in('course', scopeList).range(0, 9999);
            const { data: secLegacyB } = await supabase.from('user_sections').select('user_id').in('course_code', scopeList).range(0, 9999);
            const ids4 = [...(Array.isArray(secLegacyA)?secLegacyA:[]), ...(Array.isArray(secLegacyB)?secLegacyB:[])].map(x=>Number(x.user_id)).filter(x=>x);
            instrIds = Array.from(new Set([...(instrIds||[]), ...(ids4||[])]));
          } catch {}
          if (instrIds.length) {
            const { data: usersRows } = await supabase.from('users').select('*').eq('role', 'instructor').in('id', instrIds).range(0, 9999);
            linkedMatches = Array.isArray(usersRows) ? usersRows : [];
          }
        }
        const byIdn = new Map();
        for (const r of primaryMatches) { byIdn.set(String(r.idnumber||r.idNumber||'').trim(), r); }
        for (const r of linkedMatches) {
          const key = String(r.idnumber||r.idNumber||'').trim();
          if (!byIdn.has(key)) byIdn.set(key, r);
        }
        const rows = Array.from(byIdn.values());
        const ids = rows.map(r => Number(r.id || 0)).filter(x => x);
        let coursesMap = new Map();
        let sectionsMap = new Map();
        try {
          if (ids.length) {
            const { data: cc } = await supabase.from('user_courses').select('*').in('user_id', ids).range(0, 9999);
            const list = Array.isArray(cc) ? cc : [];
            const idSet = Array.from(new Set(list.map(x => Number(x.course_id||x.courseid||0)).filter(x=>x)));
            let codeById = new Map();
            if (idSet.length) {
              const { data: courseRows } = await supabase.from('courses').select('id,name,name_key').in('id', idSet).range(0,9999);
              for (const r of (courseRows||[])) { const c = String(r.name||r.name_key||'').trim(); if (c) codeById.set(Number(r.id||0), c); }
            }
            for (const x of list) {
              const key = Number(x.user_id);
              const arr = coursesMap.get(key) || [];
              const text = String((x.course || x.course_code || '')).trim();
              const byId = codeById.get(Number(x.course_id||x.courseid||0)) || '';
              const code = text || byId;
              if (code) { arr.push(code); coursesMap.set(key, arr); }
            }
            const { data: extras } = await supabase.from('user_sections').select('*').in('user_id', ids).range(0, 9999);
            const byUserSecIds = new Map();
            for (const p of (extras || [])) {
              const key = Number(p.user_id);
              const sid = Number(p.section_id || 0);
              if (sid) {
                const arrIds = byUserSecIds.get(key) || [];
                arrIds.push(sid);
                byUserSecIds.set(key, arrIds);
              } else {
                const arr = sectionsMap.get(key) || [];
                const course = String((p.course || p.course_code || '')).trim();
                const section = String((p.section || p.section_code || '')).trim();
                if (course && section) arr.push(`${course}-${section}`);
                sectionsMap.set(key, arr);
              }
            }
            const allSecIds = Array.from(new Set(Array.from(byUserSecIds.values()).flat().filter(x => x)));
            if (allSecIds.length) {
              const { data: secRows } = await supabase.from('sections').select('id,code,course').in('id', allSecIds).range(0, 9999);
              const byId = new Map();
              for (const s of (secRows || [])) { byId.set(Number(s.id||0), { code: String(s.code||'').trim(), course: String(s.course||'').trim() }); }
              for (const [userId, list] of byUserSecIds.entries()) {
                const arr = sectionsMap.get(Number(userId)) || [];
                for (const sid of (list || [])) {
                  const row = byId.get(Number(sid));
                  if (row && row.code) arr.push(row.code);
                }
                sectionsMap.set(Number(userId), arr);
              }
            }
            const { data: si } = await supabase.from('section_instructors').select('*').in('instructor_id', ids).range(0, 9999);
            const pairs = Array.isArray(si) ? si : [];
            const secIds = Array.from(new Set(pairs.map(x => Number(x.section_id)).filter(x => x)));
            if (secIds.length) {
              const { data: secRows } = await supabase.from('sections').select('*').in('id', secIds).range(0, 9999);
              for (const s of (secRows || [])) {
                const course = String(s.course||'').trim();
                const code = String(s.code||'').trim();
                const instrs = pairs.filter(p => Number(p.section_id) === Number(s.id));
                for (const p of instrs) {
                  const key = Number(p.instructor_id);
                  const arr = sectionsMap.get(key) || [];
                  if (course && code) arr.push(code);
                  sectionsMap.set(key, arr);
                }
              }
            }
          }
        } catch {}
        const normalized = rows.map(r => {
          const firstName = r.firstName || r.firstname || null;
          const middleName = r.middleName || r.middlename || null;
          const lastName = r.lastName || r.lastname || null;
          const name = r.name || fullName({ firstName, middleName, lastName }) || (r.idnumber || r.idNumber);
          const primaryCourse = String(r.course || '').trim();
          const allCourses = Array.from(new Set([primaryCourse, ...(coursesMap.get(Number(r.id || 0)) || [])].filter(Boolean)));
          const allSections = Array.from(new Set((sectionsMap.get(Number(r.id || 0)) || []).filter(Boolean)));
          return { ...r, idNumber: r.idnumber || r.idNumber, supervisorId: r.supervisorid || r.supervisorId || null, name, courses: allCourses, sections: allSections };
        });
        return res.json({ ok: true, data: normalized });
      }
      return res.status(500).json({ ok: false, error: 'Supabase not configured' });
    }
  } catch (e) { res.status(500).json({ ok: false, error: 'Server error' }); }
});

app.get('/api/coordinators', requireAuth, async (req, res) => {
  if (pool) {
    try {
      const [rows] = await pool.execute("SELECT id_number, name, role, course_id FROM users WHERE role='coordinator'");
      return res.json({ ok: true, data: rows });
    } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
  } else if (supabase) {
    try {
      const { data } = await supabase.from('users').select('*').eq('role', 'coordinator');
      const rows = Array.isArray(data) ? data : [];
      let map = new Map();
      try {
        const { data: cc } = await supabase.from('coordinator_courses').select('coordinator_id,course').range(0, 5000);
        for (const x of (cc || [])) {
          const key = Number(x.coordinator_id);
          const arr = map.get(key) || [];
          arr.push(String(x.course || '').trim());
          map.set(key, arr);
        }
      } catch {}
      let jsonMap = new Map();
      try {
        const list = readJson('coordinator_courses.json');
        for (const x of (list || [])) {
          const key = String(x.idNumber || x.id || '').trim();
          const arr = Array.isArray(x.courses) ? x.courses : [];
          if (key && arr.length) jsonMap.set(key, arr);
        }
      } catch {}
      const normalized = rows.map(r => {
        const idn = r.idnumber || r.idNumber;
        const byId = map.get(Number(r.id || 0)) || null;
        const byIdn = jsonMap.get(String(idn||'').trim()) || null;
        return { ...r, idNumber: idn, courses: byId || byIdn || null };
      });
      return res.json({ ok: true, data: normalized });
    } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
  }
  return res.status(500).json({ ok: false, error: 'Supabase not configured' });
});

app.get('/api/students', requireAuth, restrictToCourse, async (req, res) => {
  try {
    if (pool && !supabase) {
      const u = req.user;
      const params = [];
      let sql = "SELECT u.id_number, u.name, u.role, u.section, c.code AS course FROM users u LEFT JOIN courses c ON c.id=u.course_id WHERE u.role='student'";
      if (u.role !== 'super_admin') { sql += ' AND course_id=?'; params.push(u.courseId); }
      const [rows] = await pool.execute(sql, params);
      return res.json({ ok: true, data: rows });
    } else if (supabase) {
      const u = req.user;
      let query = supabase.from('users').select('*').eq('role', 'student');
      if (u.role !== 'super_admin') {
        if (Array.isArray(req.scope?.courseCodes) && req.scope.courseCodes.length) {
          query = query.in('course', req.scope.courseCodes);
        } else if (req.scope?.courseCode) {
          query = query.eq('course', req.scope.courseCode);
        }
      }
      const { data } = await query;
      const rows = Array.isArray(data) ? data : [];
      let supMap = {};
      let supByCS = new Map();
      try {
        let supQ = supabase.from('users').select('idnumber,name,course,section').eq('role', 'supervisor');
        if (u.role !== 'super_admin') {
          if (Array.isArray(req.scope?.courseCodes) && req.scope.courseCodes.length) {
            supQ = supQ.in('course', req.scope.courseCodes);
          } else if (req.scope?.courseCode) {
            supQ = supQ.eq('course', req.scope.courseCode);
          }
        }
        const { data: supData } = await supQ;
        for (const s of (Array.isArray(supData) ? supData : [])) {
          const id = String(s.idnumber || '').trim();
          const name = s.name || id;
          if (id) supMap[id] = name;
          const c = String(s.course || '').trim();
          const sec = String(s.section || '').trim();
          if (c || sec) {
            const key = c + '|' + sec;
            if (!supByCS.has(key)) supByCS.set(key, { id, name });
          }
        }
      } catch {}
      const normalized = rows.map(r => {
        const sid = String(r.supervisorid || r.supervisorId || '').trim();
        let supervisorName = sid ? (supMap[sid] || null) : null;
        if (!supervisorName) {
          const c = String(r.course || '').trim();
          const sec = String(r.section || '').trim();
          const found = supByCS.get(c + '|' + sec);
          supervisorName = found ? found.name : null;
        }
        return { ...r, idNumber: r.idnumber || r.idNumber, supervisorName };
      });
      return res.json({ ok: true, data: normalized });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) { res.status(500).json({ ok: false, error: 'Server error' }); }
});

app.get('/api/me', requireAuth, async (req, res) => {
  try {
    const u = req.user;
    if (pool) {
      const [rows] = await pool.execute(
        'SELECT u.id_number, u.name, u.role, u.section, u.company, u.location, c.code AS course FROM users u LEFT JOIN courses c ON c.id=u.course_id WHERE u.id_number=?',
        [u.idNumber]
      );
      const row = rows[0];
      if (!row) return res.status(404).json({ ok: false, error: 'Not found' });
      return res.json({ ok: true, data: row });
    } else if (supabase) {
      const { data } = await supabase.from('users').select('*').eq('idnumber', u.idNumber).limit(1);
      let d = Array.isArray(data) && data[0] ? data[0] : null;
      if (!d && u.role === 'super_admin') {
        d = { idnumber: u.idNumber, role: 'super_admin', name: u.idNumber };
      }
      if (!d) return res.status(404).json({ ok: false, error: 'Not found' });
      const firstName = d.firstName || d.firstname || null;
      const middleName = d.middleName || d.middlename || null;
      const lastName = d.lastName || d.lastname || null;
      const name = d.name || fullName({ firstName, middleName, lastName }) || d.idnumber || u.idNumber;
      let sections = null;
      let courses = null;
      try {
        if (String(d.role||'') === 'instructor') {
          const uid = d.id || null;
          if (uid) {
            const { data: links } = await supabase.from('section_instructors').select('section_id').eq('instructor_id', uid).range(0, 999);
            const ids = (Array.isArray(links)?links:[]).map(r=>r.section_id).filter(x=>x!=null);
            if (ids.length) {
              const { data: sec } = await supabase.from('sections').select('code').in('id', ids).range(0,999);
              const arr = Array.isArray(sec)? sec.map(s=>s.code) : [];
              if (arr.length) sections = arr;
            }
          }
        } else if (String(d.role||'') === 'coordinator') {
          const uid = d.id || null;
          const primary = String(d.course || '').trim();
          let codes = [];
          if (uid) {
            try {
              const { data: cc } = await supabase.from('user_courses').select('*').eq('user_id', uid).range(0, 9999);
              const rows = Array.isArray(cc) ? cc : [];
              const codesStr = rows.map(x => String((x.course||x.course_code||'')).trim()).filter(Boolean);
              const ids = rows.map(x => Number(x.course_id || x.courseid || 0)).filter(Boolean);
              let codesFromIds = [];
              if (ids.length) {
                const { data: courseRows } = await supabase.from('courses').select('id,name,name_key,code').in('id', ids).range(0, 9999);
                codesFromIds = Array.isArray(courseRows) ? courseRows.map(r => String(r.name || r.name_key || r.code || '').trim()).filter(Boolean) : [];
              }
              codes = Array.from(new Set([primary, ...codesStr, ...codesFromIds].filter(Boolean)));
            } catch {}
          }
          if (!codes.length) {
            try {
              const list = readJson('coordinator_courses.json');
              const entry = (Array.isArray(list)?list:[]).find(x=>String(x.idNumber||'').trim() === String(u.idNumber||'').trim());
              const arr = entry && Array.isArray(entry.courses) ? entry.courses.filter(Boolean).map(String) : [];
              if (arr.length) codes = Array.from(new Set([primary, ...arr].filter(Boolean)));
            } catch {}
          }
          if (codes.length) courses = codes;
        }
      } catch {}
      return res.json({ ok: true, data: { id_number: d.idnumber || u.idNumber, name, firstName, middleName, lastName, role: d.role, section: d.section || null, company: d.company || null, location: d.location || null, course: d.course || null, sections, courses } });
    } else {
      return res.status(500).json({ ok: false, error: 'Supabase not configured' });
    }
  } catch (e) {
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

app.post('/api/logout', async (req, res) => {
  try {
    req.session.destroy(() => {
      res.json({ ok: true });
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

app.get('/api/debug/supabase-admin', async (req, res) => {
  try {
    if (!supabase) return res.status(500).json({ ok: false, error: 'Supabase not configured' });
    const { data, error } = await supabase.from('users').select('*').eq('idnumber', 'CITE_Admin_OJT').limit(1);
    const row = Array.isArray(data) && data[0] ? data[0] : null;
    return res.json({ ok: true, present: !!row, data: row, error: error ? String(error.message) : null });
  } catch (e) {
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// Attendance: photo-based time-in/out
app.post('/api/attendance', requireAuth, async (req, res) => {
  const u = req.user;
  const body = req.body || {};
  const type = String(body.type || '').toLowerCase();
  const photo = String(body.photo || '');
  if (!['in', 'out'].includes(type)) return res.status(400).json({ ok: false, error: 'type must be in|out' });
  if (!photo || !/^data:image\/(png|jpeg);base64,/.test(photo)) return res.status(400).json({ ok: false, error: 'photo dataURL required' });
  const ts = Date.now();
  try {
    if (supabase) {
      const { data: prevRows } = await supabase.from('attendance').select('*').eq('idnumber', u.idNumber).order('ts', { ascending: false }).limit(1);
      const prev = Array.isArray(prevRows) && prevRows[0] ? prevRows[0] : null;
      if (prev && String(prev.type) === type) return res.status(409).json({ ok: false, error: 'Already logged this action' });
      let photoUrl = null;
      if (cloudinaryClient) {
        const uploadResult = await cloudinaryClient.uploader.upload(photo, { folder: `attendance/${u.idNumber}`, public_id: `${ts}-${type}`, overwrite: true, resource_type: 'image' });
        photoUrl = uploadResult.secure_url || uploadResult.url || null;
      }
      await supabase.from('attendance').insert([{ idnumber: u.idNumber, role: u.role, course: u.courseCode || null, type, ts, photourl: photoUrl, storage: photoUrl ? 'cloudinary' : 'none', status: 'awaiting_supervisor', createdat: new Date().toISOString() }]);
      return res.status(201).json({ ok: true, photoUrl });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) {
    console.error('attendance post error:', e);
    const msg = String(e && e.message || '').toLowerCase();
    if (msg.includes('cloud name') || msg.includes('invalid signature') || msg.includes('cloudinary')) {
      return res.status(500).json({ ok: false, error: 'Cloudinary upload failed. Check CLOUDINARY_* env variables.' });
    }
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
});

app.get('/api/attendance/recent', requireAuth, async (req, res) => {
    const u = req.user;
  try {
    const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;
    if (supabase) {
      const { data } = await supabase.from('attendance').select('id,idnumber,ts,type,status,photourl,course').eq('idnumber', u.idNumber).order('ts', { ascending: false }).range(0, 199);
      let docs = Array.isArray(data) ? data : [];
      docs = docs.map(d => ({ ...d, idNumber: d.idnumber, photoUrl: d.photourl, createdAt: d.createdat }));
      const rows = docs.filter(d => Number(d.ts || 0) >= cutoff).sort((a, b) => Number(b.ts || 0) - Number(a.ts || 0)).slice(0, 50);
      return res.json({ ok: true, data: rows });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) {
    console.error('attendance recent error:', e);
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
});

app.get('/api/attendance/accumulated-hours', requireAuth, async (req, res) => {
  const u = req.user;
  try {
    if (supabase) {
      const { data } = await supabase
        .from('attendance')
        .select('ts,type,status,approvedat')
        .eq('idnumber', u.idNumber)
        .eq('status', 'confirmed')
        .order('approvedat', { ascending: true })
        .range(0, 999);
      const rows = Array.isArray(data) ? data : [];
      let closed = 0;
      let open = null;
      for (const r of rows) {
        const t = String(r.type || '');
        const a = Number(Date.parse(String(r.approvedat||'')) || 0);
        const ts = a || Number(r.ts || 0);
        if (t === 'in') {
          open = ts;
        } else if (t === 'out' && open !== null) {
          if (ts > open) closed += ts - open;
          open = null;
        }
      }
      const now = Date.now();
      let total = closed;
      let ongoing = false;
      let openStartTs = null;
      if (open !== null) {
        ongoing = true;
        openStartTs = open;
        total += Math.max(0, now - open);
      }
      const h = Math.floor(total / 3600000);
      const m = Math.floor((total % 3600000) / 60000);
      const s = Math.floor((total % 60000) / 1000);
      const formatted = `${h}h ${m}m ${s}s`;
      return res.json({ ok: true, data: { milliseconds: total, closedMilliseconds: closed, openStartTs, hours: h, minutes: m, seconds: s, formatted, ongoing } });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) {
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
});

app.get('/api/instructor/students/activity', requireAuth, async (req, res) => {
  const u = req.user;
  if (u.role !== 'instructor' && u.role !== 'super_admin') return res.status(403).json({ ok: false, error: 'Forbidden' });
  try {
    const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;
    if (supabase) {
      const { data: meRow } = await supabase.from('users').select('*').eq('idnumber', u.idNumber).limit(1);
      const meData = Array.isArray(meRow) && meRow[0] ? meRow[0] : {};
      const section = meData.section || null;
      const course = u.courseCode || meData.course || null;
      let stuQuery = supabase.from('users').select('idnumber,name,course,section').eq('role', 'student');
      if (course) stuQuery = stuQuery.eq('course', course);
      if (section) stuQuery = stuQuery.eq('section', section);
      const { data: students } = await stuQuery.limit(500);
      const ids = (Array.isArray(students) ? students : []).map(s => s.idnumber || s.idNumber);
      const nameMap = new Map((Array.isArray(students) ? students : []).map(s => [(s.idnumber || s.idNumber), s.name]));
      const courseMap = new Map((Array.isArray(students) ? students : []).map(s => [(s.idnumber || s.idNumber), s.course || null]));
      const sectionMap = new Map((Array.isArray(students) ? students : []).map(s => [(s.idnumber || s.idNumber), s.section || null]));
      let attDocs = [];
      if (ids.length) {
        const { data: att } = await supabase.from('attendance').select('id,idnumber,ts,type,status,photourl,course').in('idnumber', ids).range(0, 499);
        attDocs = Array.isArray(att) ? att : [];
      }
      attDocs = attDocs.map(d => ({ ...d, idNumber: d.idnumber, photoUrl: d.photourl, createdAt: d.createdat }));
      attDocs.forEach(d => { d.name = nameMap.get(d.idNumber) || d.idNumber; d.course = d.course || courseMap.get(d.idNumber) || null; d.section = d.section || sectionMap.get(d.idNumber) || null; });
      attDocs = attDocs.filter(d => Number(d.ts || 0) >= cutoff);
      attDocs.sort((a, b) => Number(b.ts || 0) - Number(a.ts || 0));
      return res.json({ ok: true, data: attDocs });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
});

app.get('/api/instructor/reports/activity', requireAuth, async (req, res) => {
  const u = req.user;
  if (u.role !== 'instructor' && u.role !== 'super_admin') return res.status(403).json({ ok: false, error: 'Forbidden' });
  try {
    const isAll = (() => { const v = String(req.query.all||'').trim().toLowerCase(); return v==='1' || v==='true'; })();
    const cutoff = isAll ? 0 : (Date.now() - 7 * 24 * 60 * 60 * 1000);
    if (supabase) {
      const { data: meRow } = await supabase.from('users').select('*').eq('idnumber', u.idNumber).limit(1);
      const meData = Array.isArray(meRow) && meRow[0] ? meRow[0] : {};
      const section = meData.section || null;
      const course = u.courseCode || meData.course || null;
      let stuQuery = supabase.from('users').select('idnumber,name,course,section').eq('role', 'student');
      if (!isAll) {
        if (course) stuQuery = stuQuery.eq('course', course);
        if (section) stuQuery = stuQuery.eq('section', section);
      }
      const { data: students } = await stuQuery.limit(500);
      const ids = (Array.isArray(students) ? students : []).map(s => s.idnumber || s.idNumber);
      const nameMap = new Map((Array.isArray(students) ? students : []).map(s => [(s.idnumber || s.idNumber), s.name]));
      const courseMap = new Map((Array.isArray(students) ? students : []).map(s => [(s.idnumber || s.idNumber), s.course || null]));
      const sectionMap = new Map((Array.isArray(students) ? students : []).map(s => [(s.idnumber || s.idNumber), s.section || null]));
      let repDocs = [];
      if (ids.length) {
        const { data: reps } = await supabase.from('reports').select('*').in('idnumber', ids).limit(500);
        repDocs = Array.isArray(reps) ? reps : [];
      }
      repDocs = repDocs.map(d => ({ ...d, idNumber: d.idnumber }));
      repDocs.forEach(d => { d.name = nameMap.get(d.idNumber) || d.idNumber; d.course = d.course || courseMap.get(d.idNumber) || null; d.section = d.section || sectionMap.get(d.idNumber) || null; });
      repDocs = repDocs.filter(d => Number(d.ts || 0) >= cutoff);
      repDocs.sort((a, b) => Number(b.ts || 0) - Number(a.ts || 0));
      return res.json({ ok: true, data: repDocs });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
});

// Instructor: update weekly report status (accepted/rejected)
app.post('/api/instructor/reports/status', requireAuth, async (req, res) => {
  const u = req.user;
  try {
    if (u.role !== 'instructor' && u.role !== 'super_admin') return res.status(403).json({ ok: false, error: 'Forbidden' });
    if (supabase) {
      const id = String((req.body && req.body.id) || '');
      const status = String((req.body && req.body.status) || '').toLowerCase();
      if (!id) return res.status(400).json({ ok: false, error: 'Missing id' });
      if (!['accepted','rejected'].includes(status)) return res.status(400).json({ ok: false, error: 'Invalid status' });
      const key = /^\d+$/.test(id) ? ['id', Number(id)] : ['docId', id];
      const { data: snap } = await supabase.from('reports').select('*').eq(key[0], key[1]).limit(1);
      const doc = Array.isArray(snap) && snap[0] ? snap[0] : null;
      if (!doc) return res.status(404).json({ ok: false, error: 'Not found' });
      const course = u.courseCode || null;
      if (course && doc.course && String(doc.course) !== String(course) && u.role !== 'super_admin') {
        return res.status(403).json({ ok: false, error: 'Forbidden' });
      }
      if (!doc.course && course && u.role !== 'super_admin') {
        const { data: stuRow } = await supabase.from('users').select('*').eq('idnumber', String(doc.idnumber || doc.idNumber || '')).limit(1);
        const stu = Array.isArray(stuRow) && stuRow[0] ? stuRow[0] : null;
        if (stu && String(stu.course || '') !== String(course)) return res.status(403).json({ ok: false, error: 'Forbidden' });
      }
      await supabase.from('reports').update({ status, reviewedby: u.idNumber, reviewedat: new Date().toISOString() }).eq(key[0], key[1]);
      if (status === 'accepted') {
        const { data: q } = await supabase.from('report_comments').select('id').eq('reportid', id).limit(500);
        const ids = (Array.isArray(q) ? q : []).map(r => r.id);
        if (ids.length) await supabase.from('report_comments').update({ unreadforstudent: true }).in('id', ids);
      }
      return res.json({ ok: true });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
});

// Instructor: add comment to a weekly report
app.post('/api/instructor/reports/comment', requireAuth, async (req, res) => {
  const u = req.user;
  try {
    if (u.role !== 'instructor' && u.role !== 'super_admin') return res.status(403).json({ ok: false, error: 'Forbidden' });
    if (supabase) {
      const id = String(req.body?.id || '');
      let text = String(req.body?.text || '').trim();
      if (!id) return res.status(400).json({ ok: false, error: 'Missing id' });
      if (!text) return res.status(400).json({ ok: false, error: 'Missing text' });
      text = text.slice(0, 2000);
      const key = /^\d+$/.test(id) ? ['id', Number(id)] : ['docId', id];
      const { data: repRow } = await supabase.from('reports').select('*').eq(key[0], key[1]).limit(1);
      const doc = Array.isArray(repRow) && repRow[0] ? repRow[0] : null;
      if (!doc) return res.status(404).json({ ok: false, error: 'Not found' });
      const course = u.courseCode || null;
      if (course && doc.course && String(doc.course) !== String(course) && u.role !== 'super_admin') {
        return res.status(403).json({ ok: false, error: 'Forbidden' });
      }
      if (!doc.course && course && u.role !== 'super_admin') {
        const { data: stuRow } = await supabase.from('users').select('*').eq('idnumber', String(doc.idNumber || '')).limit(1);
        const stu = Array.isArray(stuRow) && stuRow[0] ? stuRow[0] : null;
        if (stu && String(stu.course || '') !== String(course)) return res.status(403).json({ ok: false, error: 'Forbidden' });
      }
      const payload = { reportid: id, idnumber: String(doc.idnumber || doc.idNumber || ''), text, byid: u.idNumber, byrole: u.role, ts: Date.now(), unreadforstudent: true, createdat: new Date().toISOString() };
      await supabase.from('report_comments').insert([payload]);
      return res.status(201).json({ ok: true });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
});

// Get comments for a weekly report
app.get('/api/reports/:id/comments', requireAuth, async (req, res) => {
  const u = req.user;
  const id = String(req.params.id || '');
  try {
    if (supabase) {
      if (!id) return res.status(400).json({ ok: false, error: 'Missing id' });
      const { data: repRow } = await supabase.from('reports').select('*').eq('id', id).limit(1);
      const rep = Array.isArray(repRow) && repRow[0] ? repRow[0] : null;
      if (!rep) return res.status(404).json({ ok: false, error: 'Not found' });
      if (u.role === 'student') {
        if (String(rep.idnumber || rep.idNumber || '') !== String(u.idNumber || '')) return res.status(403).json({ ok: false, error: 'Forbidden' });
      } else if (u.role === 'instructor') {
        const course = u.courseCode || null;
        if (course && rep.course && String(rep.course) !== String(course)) return res.status(403).json({ ok: false, error: 'Forbidden' });
        if (!rep.course && course) {
          const { data: stuRef } = await supabase.from('users').select('*').eq('idnumber', String(rep.idnumber || rep.idNumber || '')).limit(1);
          const stu = Array.isArray(stuRef) && stuRef[0] ? stuRef[0] : null;
          if (stu && String(stu.course || '') !== String(course)) return res.status(403).json({ ok: false, error: 'Forbidden' });
        }
      } else if (u.role !== 'super_admin') {
        return res.status(403).json({ ok: false, error: 'Forbidden' });
      }
      const { data: s } = await supabase.from('report_comments').select('*').eq('reportid', id).order('ts', { ascending: true }).limit(500);
      return res.json({ ok: true, data: Array.isArray(s) ? s : [] });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
});

// Unread comment count for student
app.get('/api/reports/:id/comments/unread', requireAuth, async (req, res) => {
  const u = req.user;
  const id = String(req.params.id || '');
  try {
    if (supabase) {
      if (!id) return res.status(400).json({ ok: false, error: 'Missing id' });
      const { data: repRow } = await supabase.from('reports').select('*').eq('id', id).limit(1);
      const rep = Array.isArray(repRow) && repRow[0] ? repRow[0] : null;
      if (!rep) return res.status(404).json({ ok: false, error: 'Not found' });
      if (u.role !== 'student' || String(rep.idnumber || rep.idNumber || '') !== String(u.idNumber || '')) return res.status(403).json({ ok: false, error: 'Forbidden' });
      const { count } = await supabase.from('report_comments').select('*', { count: 'exact', head: true }).eq('reportid', id).eq('unreadforstudent', true);
      return res.json({ ok: true, count: count || 0 });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
});

// Mark comments as read for student
app.post('/api/reports/:id/comments/read', requireAuth, async (req, res) => {
  const u = req.user;
  const id = String(req.params.id || '');
  try {
    if (supabase) {
      if (!id) return res.status(400).json({ ok: false, error: 'Missing id' });
      const { data: repRow } = await supabase.from('reports').select('*').eq('id', id).limit(1);
      const rep = Array.isArray(repRow) && repRow[0] ? repRow[0] : null;
      if (!rep) return res.status(404).json({ ok: false, error: 'Not found' });
      if (u.role !== 'student' || String(rep.idnumber || rep.idNumber || '') !== String(u.idNumber || '')) return res.status(403).json({ ok: false, error: 'Forbidden' });
      const { data: s } = await supabase.from('report_comments').select('id').eq('reportid', id).eq('unreadforstudent', true).limit(500);
      const ids = (Array.isArray(s) ? s : []).map(r => r.id);
      if (ids.length) await supabase.from('report_comments').update({ unreadforstudent: false, readat: new Date().toISOString() }).in('id', ids);
      return res.json({ ok: true });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
});

// Student: unread comments count across reports
app.get('/api/comments/unread', requireAuth, async (req, res) => {
  const u = req.user;
  try {
    if (supabase) {
      if (u.role !== 'student') return res.status(403).json({ ok: false, error: 'Forbidden' });
      const { count } = await supabase.from('report_comments').select('*', { count: 'exact', head: true }).eq('idnumber', u.idNumber).eq('unreadForStudent', true);
      return res.json({ ok: true, count: count || 0 });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
});

// Student: list comments from instructors
app.get('/api/comments/mine', requireAuth, async (req, res) => {
  const u = req.user;
  try {
    if (supabase) {
      if (u.role !== 'student') return res.status(403).json({ ok: false, error: 'Forbidden' });
      const { data } = await supabase.from('report_comments').select('*').eq('idnumber', u.idNumber).order('ts', { ascending: false }).limit(200);
      return res.json({ ok: true, data: Array.isArray(data) ? data : [] });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
});

// Student: mark all comments as read
app.post('/api/comments/read_all', requireAuth, async (req, res) => {
  const u = req.user;
  try {
    if (supabase) {
      if (u.role !== 'student') return res.status(403).json({ ok: false, error: 'Forbidden' });
      const { data: s } = await supabase.from('report_comments').select('id').eq('idnumber', u.idNumber).eq('unreadForStudent', true).limit(500);
      const ids = (Array.isArray(s) ? s : []).map(r => r.id);
      if (ids.length) await supabase.from('report_comments').update({ unreadForStudent: false, readAt: new Date().toISOString() }).in('id', ids);
      return res.json({ ok: true });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
});

// Supervisor: students under supervision
app.get('/api/supervisor/students', requireAuth, async (req, res) => {
    const u = req.user;
  try {
    if (u.role !== 'supervisor' && u.role !== 'super_admin') return res.status(403).json({ ok: false, error: 'Forbidden' });
    if (supabase) {
      let students = [];
      try {
        const { data: a } = await supabase.from('users').select('idnumber,name,supervisorid').eq('role', 'student').eq('supervisorid', u.idNumber).limit(500);
        if (Array.isArray(a)) students = a;
      } catch {}
      if (!students.length) {
        try {
          const { data: b } = await supabase.from('users').select('idnumber,name').eq('role', 'student').eq('supervisorId', u.idNumber).limit(500);
          if (Array.isArray(b)) students = b;
        } catch {}
      }
      if (!students.length) {
        try {
          const { data: all } = await supabase.from('users').select('idnumber,name,supervisorid').eq('role', 'student').limit(2000);
          const filtered = (Array.isArray(all) ? all : []).filter(s => String(s.supervisorid||'').toLowerCase() === String(u.idNumber||'').toLowerCase());
          students = filtered;
        } catch {}
      }
      const rows = (Array.isArray(students) ? students : []).map(x => ({ idNumber: x.idnumber || x.idNumber, name: x.name || x.idnumber || x.idNumber }));
      return res.json({ ok: true, data: rows });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) {
    console.error('supervisor students error:', e);
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// Supervisor: recent activity of supervised students
app.get('/api/supervisor/activity', requireAuth, async (req, res) => {
    const u = req.user;
  try {
    if (u.role !== 'supervisor' && u.role !== 'super_admin') return res.status(403).json({ ok: false, error: 'Forbidden' });
    const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;
    if (supabase) {
      let students = [];
      try {
        const { data: a } = await supabase.from('users').select('idnumber,name,supervisorid').eq('role', 'student').eq('supervisorid', u.idNumber).range(0, 499);
        if (Array.isArray(a)) students = a;
      } catch {}
      if (!students.length) {
        try {
          const { data: b } = await supabase.from('users').select('idnumber,name').eq('role', 'student').eq('supervisorId', u.idNumber).range(0, 499);
          if (Array.isArray(b)) students = b;
        } catch {}
      }
      if (!students.length) {
        try {
          const { data: all } = await supabase.from('users').select('idnumber,name,supervisorid').eq('role', 'student').range(0, 1999);
          const filtered = (Array.isArray(all) ? all : []).filter(s => String(s.supervisorid||'').toLowerCase() === String(u.idNumber||'').toLowerCase());
          students = filtered;
        } catch {}
      }
      const ids = (Array.isArray(students) ? students : []).map(s => s.idnumber || s.idNumber);
      let rows = [];
      if (ids.length) {
        const { data: att } = await supabase.from('attendance').select('id,idnumber,ts,type,status,photourl,course').in('idnumber', ids).range(0, 999);
        rows = Array.isArray(att) ? att : [];
      }
      rows = rows.map(d => ({ ...d, idNumber: d.idnumber, photoUrl: d.photourl, createdAt: d.createdat }));
      rows = rows.filter(r => Number(r.ts || 0) >= cutoff).sort((a, b) => Number(b.ts || 0) - Number(a.ts || 0)).slice(0, 100);
      return res.json({ ok: true, data: rows });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) {
    console.error('supervisor activity error:', e);
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// Supervisor: pending attendance needing confirmation
app.get('/api/supervisor/attendance/pending', requireAuth, async (req, res) => {
    const u = req.user;
  try {
    if (u.role !== 'supervisor' && u.role !== 'super_admin') return res.status(403).json({ ok: false, error: 'Forbidden' });
    if (supabase) {
      let students = [];
      try {
        const { data: a } = await supabase.from('users').select('idnumber,supervisorid').eq('role', 'student').eq('supervisorid', u.idNumber).range(0, 499);
        if (Array.isArray(a)) students = a;
      } catch {}
      if (!students.length) {
        try {
          const { data: b } = await supabase.from('users').select('idnumber').eq('role', 'student').eq('supervisorId', u.idNumber).range(0, 499);
          if (Array.isArray(b)) students = b;
        } catch {}
      }
      if (!students.length) {
        try {
          const { data: all } = await supabase.from('users').select('idnumber,supervisorid').eq('role', 'student').range(0, 1999);
          const filtered = (Array.isArray(all) ? all : []).filter(s => String(s.supervisorid||'').toLowerCase() === String(u.idNumber||'').toLowerCase());
          students = filtered;
        } catch {}
      }
      const ids = (Array.isArray(students) ? students : []).map(d => d.idnumber || d.idNumber);
      let rows = [];
      if (ids.length) {
        const { data: att } = await supabase.from('attendance').select('id,idnumber,ts,type,status,photourl,course').in('idnumber', ids).eq('status', 'awaiting_supervisor').order('ts', { ascending: false }).range(0, 999);
        rows = Array.isArray(att) ? att : [];
      }
      rows = rows.map(d => ({ ...d, idNumber: d.idnumber, photoUrl: d.photourl, createdAt: d.createdat }));
      return res.json({ ok: true, data: rows.slice(0, 100) });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) {
    console.error('supervisor attendance pending error:', e);
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// Supervisor: confirmed attendance
app.get('/api/supervisor/attendance/confirmed', requireAuth, async (req, res) => {
  const u = req.user;
  try {
    if (u.role !== 'supervisor' && u.role !== 'super_admin') return res.status(403).json({ ok: false, error: 'Forbidden' });
    if (supabase) {
      let students = [];
      try {
        const { data: a } = await supabase.from('users').select('idnumber,supervisorid').eq('role', 'student').eq('supervisorid', u.idNumber).range(0, 499);
        if (Array.isArray(a)) students = a;
      } catch {}
      if (!students.length) {
        try {
          const { data: b } = await supabase.from('users').select('idnumber').eq('role', 'student').eq('supervisorId', u.idNumber).range(0, 499);
          if (Array.isArray(b)) students = b;
        } catch {}
      }
      if (!students.length) {
        try {
          const { data: all } = await supabase.from('users').select('idnumber,supervisorid').eq('role', 'student').range(0, 1999);
          const filtered = (Array.isArray(all) ? all : []).filter(s => String(s.supervisorid||'').toLowerCase() === String(u.idNumber||'').toLowerCase());
          students = filtered;
        } catch {}
      }
      const ids = (Array.isArray(students) ? students : []).map(d => d.idnumber || d.idNumber);
      let rows = [];
      if (ids.length) {
        const { data: att } = await supabase.from('attendance').select('id,idnumber,ts,type,status,photourl,course,approvedat').in('idnumber', ids).eq('status', 'confirmed').order('ts', { ascending: false }).range(0, 999);
        rows = Array.isArray(att) ? att : [];
      }
      rows = rows.map(d => ({ ...d, idNumber: d.idnumber, photoUrl: d.photourl, createdAt: d.createdat }));
      return res.json({ ok: true, data: rows.slice(0, 100) });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) {
    console.error('supervisor attendance confirmed error:', e);
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// Supervisor: confirm an attendance record
app.post('/api/supervisor/attendance/confirm', requireAuth, async (req, res) => {
  const u = req.user;
  try {
    if (u.role !== 'supervisor' && u.role !== 'super_admin') return res.status(403).json({ ok: false, error: 'Forbidden' });
    const id = String(req.body?.id || '');
    if (!id) return res.status(400).json({ ok: false, error: 'Missing id' });
    if (supabase) {
      if (!/^\d+$/.test(id)) return res.status(400).json({ ok: false, error: 'Invalid id' });
      const attId = Number(id);
      const { data: rows } = await supabase.from('attendance').select('*').eq('id', attId).limit(1);
      const doc = Array.isArray(rows) && rows[0] ? rows[0] : null;
      if (!doc) return res.status(404).json({ ok: false, error: 'Not found' });
      const { data: students } = await supabase.from('users').select('idnumber,supervisorid,course').eq('idnumber', String(doc.idnumber || doc.idNumber || '')).limit(1);
      const student = Array.isArray(students) && students[0] ? students[0] : null;
      if (!student) return res.status(404).json({ ok: false, error: 'Student not found' });
      const supMatches = String(student.supervisorid || '') === String(u.idNumber || '');
      const allowed = (u.role === 'super_admin') || supMatches;
      if (!allowed) return res.status(403).json({ ok: false, error: 'Forbidden' });
      const { data: updatedRows, error: updateError } = await supabase
        .from('attendance')
        .update({ status: 'confirmed', approvedby: u.idNumber, approvedat: new Date().toISOString() })
        .eq('id', attId)
        .select('id,status');
      if (updateError) return res.status(500).json({ ok: false, error: String(updateError.message || updateError) });
      const changed = Array.isArray(updatedRows) && updatedRows.length > 0 && String(updatedRows[0].status || '') === 'confirmed';
      if (!changed) return res.status(409).json({ ok: false, error: 'Confirm failed' });
      return res.json({ ok: true });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) {
    console.error('supervisor attendance confirm error:', e);
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
});

app.post('/api/reports', requireAuth, async (req, res) => {
  const u = req.user;
  const body = req.body || {};
  const action = String(body.action || 'save').toLowerCase();
  const title = String(body.title || '');
  const text = String(body.text || '');
  const files = Array.isArray(body.files) ? body.files : [];
  const ts = Date.now();
  try {
    if (supabase) {
      const uploads = [];
      for (const f of files.slice(0, 5)) {
        const name = String(f.name || 'file');
        const dataUrl = String(f.dataUrl || '');
        if (!/^data:/.test(dataUrl)) continue;
        let url = null;
        if (cloudinaryClient) {
          const up = await cloudinaryClient.uploader.upload(dataUrl, { folder: `reports/${u.idNumber}`, public_id: `${ts}-${name}`, overwrite: true, resource_type: 'auto' });
          url = up.secure_url || up.url || null;
        }
        uploads.push({ url, name, type: String(f.type || ''), size: Number(f.size || 0) });
      }
      const doc = { idnumber: u.idNumber, title, text, status: action === 'submit' ? 'under_review' : 'draft', ts, createdat: new Date().toISOString(), files: uploads, course: u.courseCode || null };
      const { error } = await supabase.from('reports').insert([doc]);
      if (error) return res.status(500).json({ ok: false, error: 'Database error: ' + String(error.message || error) });
      return res.status(201).json({ ok: true });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) {
    console.error('reports post error:', e);
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
});

app.get('/api/reports/recent', requireAuth, async (req, res) => {
  const u = req.user;
  try {
    if (supabase) {
      const { data } = await supabase.from('reports').select('*').eq('idnumber', u.idNumber).order('ts', { ascending: false }).limit(500);
      const repDocs = Array.isArray(data) ? data : [];
      const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;
      let rows = repDocs;
      if (!req.query.all) rows = rows.filter(r => Number(r.ts || 0) >= cutoff);
      rows = rows.sort((a, b) => Number(b.ts || 0) - Number(a.ts || 0)).slice(0, (req.query.all ? 200 : 20));
      return res.json({ ok: true, data: rows });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) {
    console.error('reports recent error:', e);
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
});

app.get('/api/reports/drafts', requireAuth, async (req, res) => {
  const u = req.user;
  try {
    if (supabase) {
      const { data } = await supabase.from('reports').select('*').eq('idnumber', u.idNumber).eq('status', 'draft').order('ts', { ascending: false }).limit(500);
      const rows = Array.isArray(data) ? data : [];
      return res.json({ ok: true, data: rows });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) {
    console.error('reports drafts error:', e);
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// Evaluation enable state (instructor -> supervisor)
const __evalEnabled = global.__evalEnabled || new Set();
global.__evalEnabled = __evalEnabled;

// Instructor enables evaluation for a student
app.post('/api/instructor/evaluation/enable', requireAuth, async (req, res) => {
  try {
    const u = req.user;
    if (u.role !== 'instructor' && u.role !== 'coordinator' && u.role !== 'super_admin') return res.status(403).json({ ok: false, error: 'Forbidden' });
    const id = String(req.body?.idNumber || req.body?.id || '').trim();
    if (!id) return res.status(400).json({ ok: false, error: 'idNumber required' });
    try {
      if (supabase) {
        await supabase.from('users').update({ evaluation_status: 'enabled' }).eq('idnumber', id);
      } else {
        const rows = readJson('evaluation_status.json');
        const idx = rows.findIndex(x => String(x.idNumber||x.id||'') === id);
        if (idx >= 0) rows[idx].status = 'enabled'; else rows.push({ idNumber: id, status: 'enabled' });
        writeJson('evaluation_status.json', rows);
      }
    } catch {}
    __evalEnabled.add(id);
    return res.json({ ok: true });
  } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
});

app.post('/api/instructor/evaluation/disable', requireAuth, async (req, res) => {
  try {
    const u = req.user;
    if (u.role !== 'instructor' && u.role !== 'coordinator' && u.role !== 'super_admin') return res.status(403).json({ ok: false, error: 'Forbidden' });
    const id = String(req.body?.idNumber || req.body?.id || '').trim();
    if (!id) return res.status(400).json({ ok: false, error: 'idNumber required' });
    try {
      if (supabase) {
        await supabase.from('users').update({ evaluation_status: 'disabled' }).eq('idnumber', id);
      } else {
        const rows = readJson('evaluation_status.json');
        const idx = rows.findIndex(x => String(x.idNumber||x.id||'') === id);
        if (idx >= 0) rows[idx].status = 'disabled'; else rows.push({ idNumber: id, status: 'disabled' });
        writeJson('evaluation_status.json', rows);
      }
    } catch {}
    __evalEnabled.delete(id);
    return res.json({ ok: true });
  } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
});

// Check if evaluation is enabled for a student
app.get('/api/evaluation/enabled/:id', requireAuth, async (req, res) => {
  try {
    const id = String(req.params.id || '').trim();
    if (!id) return res.status(400).json({ ok: false, error: 'Missing id' });
    let enabled = __evalEnabled.has(id);
    try {
      if (supabase) {
        const { data } = await supabase.from('users').select('evaluation_status').eq('idnumber', id).limit(1);
        const row = Array.isArray(data) && data[0] ? data[0] : null;
        if (row) enabled = String(row.evaluation_status||'').toLowerCase() === 'enabled';
      } else {
        const rows = readJson('evaluation_status.json');
        const found = rows.find(x => String(x.idNumber||x.id||'') === id);
        if (found) enabled = String(found.status||'').toLowerCase() === 'enabled';
      }
    } catch {}
    return res.json({ ok: true, enabled });
  } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
});

app.post('/api/reports/submit', requireAuth, async (req, res) => {
  const u = req.user;
  const id = String((req.body && req.body.id) || '');
  try {
    if (supabase) {
      if (!id) return res.status(400).json({ ok: false, error: 'Missing id' });
      const key = /^\d+$/.test(id) ? ['id', Number(id)] : ['docId', id];
      const { data } = await supabase.from('reports').select('*').eq(key[0], key[1]).limit(1);
      const snap = Array.isArray(data) && data[0] ? data[0] : null;
      if (!snap) return res.status(404).json({ ok: false, error: 'Not found' });
      const dataDoc = snap;
      if (String(dataDoc.idnumber || dataDoc.idNumber || '') !== String(u.idNumber || '')) return res.status(403).json({ ok: false, error: 'Forbidden' });
      await supabase.from('reports').update({ status: 'under_review', submittedAt: new Date().toISOString() }).eq(key[0], key[1]);
      return res.json({ ok: true });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) {
    console.error('reports submit error:', e);
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
});

app.delete('/api/reports/:id', requireAuth, async (req, res) => {
  const u = req.user;
  const id = String(req.params.id || '');
  try {
    if (supabase) {
      if (!id) return res.status(400).json({ ok: false, error: 'Missing id' });
      const key = /^\d+$/.test(id) ? ['id', Number(id)] : ['docId', id];
      const { data } = await supabase.from('reports').select('*').eq(key[0], key[1]).limit(1);
      const doc = Array.isArray(data) && data[0] ? data[0] : null;
      if (!doc) return res.status(404).json({ ok: false, error: 'Not found' });
      if (String(doc.idnumber || doc.idNumber || '') !== String(u.idNumber || '')) return res.status(403).json({ ok: false, error: 'Forbidden' });
      if (String(doc.status || '') !== 'draft') return res.status(400).json({ ok: false, error: 'Only drafts can be deleted' });
      await supabase.from('reports').delete().eq(key[0], key[1]);
      return res.json({ ok: true });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) {
    console.error('reports delete error:', e);
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
});

app.put('/api/reports/:id', requireAuth, async (req, res) => {
  const u = req.user;
  const id = String(req.params.id || '');
  const body = req.body || {};
  const title = String(body.title || '');
  const text = String(body.text || '');
  const files = Array.isArray(body.files) ? body.files : [];
  const ts = Date.now();
  try {
    if (supabase) {
      if (!id) return res.status(400).json({ ok: false, error: 'Missing id' });
      const key = /^\d+$/.test(id) ? ['id', Number(id)] : ['docId', id];
      const { data } = await supabase.from('reports').select('*').eq(key[0], key[1]).limit(1);
      const snap = Array.isArray(data) && data[0] ? data[0] : null;
      if (!snap) return res.status(404).json({ ok: false, error: 'Not found' });
      const dataDoc = snap;
      if (String(dataDoc.idnumber || dataDoc.idNumber || '') !== String(u.idNumber || '')) return res.status(403).json({ ok: false, error: 'Forbidden' });
      if (String(dataDoc.status || '') !== 'draft') return res.status(400).json({ ok: false, error: 'Only drafts can be edited' });
      const uploads = [];
      for (const f of files.slice(0, 5)) {
        const name = String(f.name || 'file');
        const dataUrl = String(f.dataUrl || '');
        if (!/^data:/.test(dataUrl)) continue;
        let url = null;
        if (cloudinaryClient) {
          const up = await cloudinaryClient.uploader.upload(dataUrl, { folder: `reports/${u.idNumber}`, public_id: `${ts}-${name}`, overwrite: true, resource_type: 'auto' });
          url = up.secure_url || up.url || null;
        }
        uploads.push({ url, name, type: String(f.type || ''), size: Number(f.size || 0) });
      }
      const mergedFiles = Array.isArray(dataDoc.files) ? [...dataDoc.files, ...uploads] : uploads;
      await supabase.from('reports').update({ title, text, files: mergedFiles, ts, updatedat: new Date().toISOString() }).eq(key[0], key[1]);
      return res.json({ ok: true });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) {
    console.error('reports put error:', e);
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
});

app.get('/api/supervisors', requireAuth, restrictToCourse, async (req, res) => {
  const qSection = (req.query.section || '').trim();
  if (pool) {
    try {
      const u = req.user;
      const params = [];
      let sql = "SELECT id_number, name, role, company, location, section FROM users WHERE role='supervisor'";
      if (u.role !== 'super_admin') { sql += ' AND course_id=?'; params.push(u.courseId); }
      if (qSection) { sql += ' AND section=?'; params.push(qSection); }
      const [rows] = await pool.execute(sql, params);
      return res.json({ ok: true, data: rows });
    } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
    } else if (supabase) {
    try {
      let query = supabase.from('users').select('*').eq('role', 'supervisor');
      if (req.scope?.courseCode) {
        query = query.eq('course', req.scope.courseCode);
      }
      if (qSection) {
        query = query.eq('section', qSection);
      }
      const { data } = await query;
      const rows = Array.isArray(data) ? data : [];
      const normalized = rows.map(r => ({ ...r, idNumber: r.idnumber || r.idNumber }));
      return res.json({ ok: true, data: normalized });
    } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
  }
  return res.status(500).json({ ok: false, error: 'Supabase not configured' });
});

// Unified users listing for Super Admin
app.get('/api/users/all', requireAuth, async (req, res) => {
  const u = req.user;
  if (u.role !== 'super_admin') return res.status(403).json({ ok: false, error: 'Forbidden' });
  try {
    if (supabase) {
      const { data } = await supabase.from('users').select('*');
      const rows = Array.isArray(data) ? data : [];
      const ids = rows.map(r => Number(r.id||0)).filter(x=>x);
      let coursesByUser = new Map();
      try {
        if (ids.length) {
          const { data: uc } = await supabase.from('user_courses').select('*').in('user_id', ids).range(0, 9999);
          const pairs = Array.isArray(uc)?uc:[];
          const courseIds = Array.from(new Set(pairs.map(p=>Number(p.course_id||0)).filter(x=>x)));
          let byCourseId = new Map();
          if (courseIds.length) {
            const { data: crs } = await supabase.from('courses').select('id,code,course_code').in('id', courseIds).range(0, 9999);
            for (const c of (Array.isArray(crs)?crs:[])) byCourseId.set(Number(c.id||0), String(c.code||c.course_code||'').trim());
          }
          for (const p of pairs) {
            const key = Number(p.user_id||0);
            const arr = coursesByUser.get(key) || [];
            const code = p.course ? String(p.course).trim() : byCourseId.get(Number(p.course_id||0)) || '';
            if (code) { arr.push(code); coursesByUser.set(key, arr); }
          }
        }
      } catch {}
      const grouped = { coordinators: [], instructors: [], supervisors: [], students: [] };
      for (const r of rows) {
        const enriched = { ...r, courses: Array.from(new Set((coursesByUser.get(Number(r.id||0))||[]).filter(Boolean))) };
        if (r.role === 'coordinator') grouped.coordinators.push(enriched);
        else if (r.role === 'instructor') grouped.instructors.push(enriched);
        else if (r.role === 'supervisor') grouped.supervisors.push(enriched);
        else if (r.role === 'student') grouped.students.push(enriched);
      }
      return res.json({ ok: true, data: grouped });
    } else if (pool) {
      const [rows] = await pool.execute("SELECT u.id_number, u.name, u.role, u.section, u.company, u.location, c.code AS course FROM users u LEFT JOIN courses c ON c.id=u.course_id");
      const grouped = { coordinators: [], instructors: [], supervisors: [], students: [] };
      for (const r of rows) {
        if (r.role === 'coordinator') grouped.coordinators.push(r);
        else if (r.role === 'instructor') grouped.instructors.push(r);
        else if (r.role === 'supervisor') grouped.supervisors.push(r);
        else if (r.role === 'student') grouped.students.push(r);
      }
      return res.json({ ok: true, data: grouped });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) {
    console.error('users/all error:', e);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// Unified create/update/delete for Super Admin
app.post('/api/users', requireAuth, async (req, res) => {
  const u = req.user;
  if (u.role !== 'super_admin') return res.status(403).json({ ok: false, error: 'Forbidden' });
  const p = req.body || {};
  if (!p.idNumber || !p.password || !p.role) return res.status(400).json({ ok: false, error: 'idNumber, password, role required' });
  try {
    if (pool && !supabase) {
      const bcrypt = require('bcrypt');
      const hash = await bcrypt.hash(p.password, 10);
      let courseId = null;
      if (p.course && p.role === 'student') {
        const [c] = await pool.execute('SELECT id FROM courses WHERE code=?', [p.course]);
        courseId = c[0]?.id || null;
      }
      const nameCombined = (p.name || fullName(p) || p.idNumber);
      await pool.execute(
        'INSERT INTO users (id_number, password_hash, role, name, course_id, section, company, location) VALUES (?,?,?,?,?,?,?,?)',
        [p.idNumber, hash, p.role, nameCombined, courseId, p.section || null, p.company || null, p.location || null]
      );
      return res.status(201).json({ ok: true });
    } else if (supabase) {
      const nameCombined = (p.name || fullName(p) || p.idNumber);
      const isStudent = String(p.role||'').toLowerCase() === 'student';
      const isSupervisor = String(p.role||'').toLowerCase() === 'supervisor';
      const payload = { idnumber: p.idNumber, role: p.role, name: (p.name || fullName(p) || p.idNumber), password: p.password, firstname: p.firstName || null, middlename: p.middleName || null, lastname: p.lastName || null, company: p.company || null, location: p.location || null };
      if (isStudent) { payload.course = p.course || null; payload.section = p.section || null; payload.supervisorid = p.supervisorId || null; }
      if (isSupervisor) { payload.course = p.course || null; payload.section = p.section || null; }
      let { data: inserted, error } = await supabase.from('users').insert([payload]).select('id');
      if (error && /duplicate/i.test(String(error.message))) return res.status(409).json({ ok: false, error: 'User exists' });
      if (error) {
        console.error('POST /api/users insert error:', error);
        const minimal = { idnumber: p.idNumber, password: p.password, role: p.role, name: nameCombined };
        const alt = await supabase.from('users').insert([minimal]).select('id');
        inserted = alt.data;
        if (alt.error && /duplicate/i.test(String(alt.error.message))) return res.status(409).json({ ok: false, error: 'User exists' });
        if (alt.error) { console.error('POST /api/users insert minimal error:', alt.error); return res.status(500).json({ ok: false, error: String(alt.error.message || alt.error) }); }
      }
      if (!isStudent && !isSupervisor) {
        try { await supabase.from('users').update({ course: null, section: null }).eq('idnumber', p.idNumber); } catch {}
      }
      try {
        if (isStudent) {
          const wantsCourses = Array.isArray(p.courses) ? p.courses.map(c=>String(c||'').trim()).filter(Boolean) : [];
          console.log('[POST /api/users] wantsCourses (student):', wantsCourses, 'for', p.idNumber);
          if (wantsCourses.length) {
            let uid = Array.isArray(inserted) && inserted[0] ? Number(inserted[0].id) : null;
            if (!uid) {
              const { data: row } = await supabase.from('users').select('id').eq('idnumber', p.idNumber).limit(1);
              uid = (Array.isArray(row) && row[0]) ? Number(row[0].id) : null;
            }
            if (uid) {
              await supabase.from('user_courses').delete().eq('user_id', uid);
              let courseRows = [];
              try {
                const { data: byCode } = await supabase.from('courses').select('id,name').in('name', wantsCourses);
                courseRows = Array.isArray(byCode) ? byCode : [];
                const missing = wantsCourses.filter(c => !courseRows.find(r => String(r.name||'') === c));
                if (missing.length) {
                  const { data: byAlt } = await supabase.from('courses').select('id,name_key').in('name_key', missing);
                  for (const r of (byAlt || [])) { courseRows.push({ id: r.id, name: r.name_key }); }
                }
              } catch {}
              if (!courseRows.length) {
                console.error('POST /api/users: selected course codes not found:', wantsCourses);
                return res.status(400).json({ ok: false, error: 'Selected courses not found. Please add courses first.' });
              }
              const payloadFk = courseRows.map(c => ({ user_id: uid, course_id: Number(c.id), assigned_at: new Date().toISOString() }));
              console.log('[POST /api/users] insert user_courses payload (student):', payloadFk);
              const { error: insErr } = await supabase.from('user_courses').insert(payloadFk);
              if (insErr) { console.error('POST /api/users user_courses error:', insErr); }
            }
          }
        } else {
          const wantsCourses = Array.isArray(p.courses) ? p.courses.map(c=>String(c||'').trim()).filter(Boolean) : [];
          if (wantsCourses.length) console.log('[POST /api/users] skipping user_courses insert for non-student; will assign via dedicated endpoint. wantsCourses:', wantsCourses, 'for', p.idNumber);
        }
      } catch {}
      try {
        if (supabase.auth && supabase.auth.admin) {
          const email = `${p.idNumber}@ojt.local`;
          try { await supabase.auth.admin.createUser({ email, password: p.password, email_confirm: true }); } catch {}
          try {
            const { data: list } = await supabase.auth.admin.listUsers({ page: 1, perPage: 2000 });
            const found = (list?.users || []).find(x => String(x.email || '').toLowerCase() === email.toLowerCase());
            if (found && found.id) {
              try { await supabase.from('users').update({ auth_user_id: found.id }).eq('idnumber', p.idNumber); } catch {}
            }
          } catch {}
        }
      } catch {}
      return res.status(201).json({ ok: true });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) {
    if (String(e.message).includes('exists')) return res.status(409).json({ ok: false, error: 'User exists' });
    console.error('Create user error:', e && (e.message || e));
    res.status(500).json({ ok: false, error: String(e && (e.message || e) || 'Server error') });
  }
});

app.put('/api/users/:id', requireAuth, async (req, res) => {
  const u = req.user;
  if (u.role !== 'super_admin') return res.status(403).json({ ok: false, error: 'Forbidden' });
  const id = req.params.id;
  const p = req.body || {};
  try {
    if (pool && !supabase) {
      let courseId = null;
      if (p.course) {
        const [c] = await pool.execute('SELECT id FROM courses WHERE code=?', [p.course]);
        courseId = c[0]?.id || null;
      }
      await pool.execute(
        'UPDATE users SET name=COALESCE(?, name), course_id=COALESCE(?, course_id), section=COALESCE(?, section), company=COALESCE(?, company), location=COALESCE(?, location) WHERE id_number=?',
        [p.name || null, courseId, p.section || null, p.company || null, p.location || null, id]
      );
      return res.json({ ok: true });
    } else if (supabase) {
      const merged = { ...p };
      const nameCombined = (merged.name || fullName(merged) || id);
      const isStudent = String(merged.role||'').toLowerCase() === 'student';
      const update = { name: nameCombined, firstname: merged.firstName || null, middlename: merged.middleName || null, lastname: merged.lastName || null, company: merged.company || null, location: merged.location || null, supervisorid: merged.supervisorId || null };
      if (isStudent) { update.course = merged.course || null; update.section = merged.section || null; } else { update.course = null; update.section = null; }
      await supabase.from('users').update(update).eq('idnumber', id);
      try {
        if (Array.isArray(merged.courses)) {
          const wants = merged.courses.map(c=>String(c||'').trim()).filter(Boolean);
          console.log('[PUT /api/users/:id] wantsCourses:', wants, 'for', id);
          let uid = null;
          const { data: row } = await supabase.from('users').select('id').eq('idnumber', id).limit(1);
          uid = (Array.isArray(row) && row[0]) ? Number(row[0].id) : null;
          if (uid) {
            await supabase.from('user_courses').delete().eq('user_id', uid);
            let courseRows = [];
            try {
              const { data: byCode } = await supabase.from('courses').select('id,name').in('name', wants);
              courseRows = Array.isArray(byCode) ? byCode : [];
              const missing = wants.filter(c => !courseRows.find(r => String(r.name||'') === c));
              if (missing.length) {
                const { data: byAlt } = await supabase.from('courses').select('id,name_key').in('name_key', missing);
                for (const r of (byAlt || [])) { courseRows.push({ id: r.id, name: r.name_key }); }
              }
            } catch {}
            if (!courseRows.length) {
              console.error('PUT /api/users/:id: selected course codes not found:', wants);
              return res.json({ ok: true });
            }
            const payloadFk = courseRows.map(c => ({ user_id: uid, course_id: Number(c.id), assigned_at: new Date().toISOString() }));
            console.log('[PUT /api/users/:id] insert user_courses payload:', payloadFk);
            const { error: insErr } = await supabase.from('user_courses').insert(payloadFk);
            if (insErr) return res.json({ ok: true });
          }
        }
      } catch {}
      return res.json({ ok: true });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) {
    console.error('Update user error:', e);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

app.delete('/api/users/:id', requireAuth, async (req, res) => {
  const u = req.user;
  if (u.role !== 'super_admin') return res.status(403).json({ ok: false, error: 'Forbidden' });
  const id = req.params.id;
  try {
    if (pool && !supabase) {
      await pool.execute('DELETE FROM users WHERE id_number=?', [id]);
      return res.json({ ok: true });
    } else if (supabase) {
      await supabase.from('users').delete().eq('idnumber', id);
      return res.json({ ok: true });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) {
    console.error('Delete user error:', e);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// Sections unchanged; still JSON-backed for now
app.get('/api/sections/catalog', requireAuth, restrictToCourse, async (req, res) => {
  try {
    if (supabase) {
      let query = supabase.from('sections').select('*');
      if (Array.isArray(req.scope?.courseCodes) && req.scope.courseCodes.length) {
        query = query.in('course', req.scope.courseCodes);
      } else if (req.scope?.courseCode) {
        query = query.eq('course', req.scope.courseCode);
      }
      const { data } = await query;
      return res.json({ ok: true, data: Array.isArray(data) ? data : [] });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
});

app.get('/api/courses/catalog', requireAuth, async (req, res) => {
  try {
    if (supabase) {
      const { data } = await supabase.from('courses').select('*');
      return res.json({ ok: true, data: Array.isArray(data) ? data : [] });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
});

app.post('/api/sections', requireAuth, restrictToCourse, async (req, res) => {
  const b = req.body || {};
  const id = String(b.id || '').trim();
  const name = String(b.name || '').trim();
  const instructorId = String(b.instructorId || '').trim() || null;
  const term = String(b.term || '').trim() || null;
  const students = Array.isArray(b.students) ? b.students.map(String) : [];
  if (!id || !name) return res.status(400).json({ ok: false, error: 'id and name required' });
  try {
    if (supabase) {
      const payload = { id, name, instructorId, term, students, course: req.scope?.courseCode || null };
      const { error } = await supabase.from('sections').insert([payload]);
      if (error && /duplicate/i.test(String(error.message))) return res.status(409).json({ ok: false, error: 'Section exists' });
      if (error) return res.status(500).json({ ok: false, error: 'Server error' });
      return res.status(201).json({ ok: true });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
});

app.put('/api/sections/:id', requireAuth, restrictToCourse, async (req, res) => {
  const id = String(req.params.id || '').trim();
  if (!id) return res.status(400).json({ ok: false, error: 'Missing id' });
  const b = req.body || {};
  const updates = {
    name: b.name || null,
    instructorId: b.instructorId || null,
    term: b.term || null,
    students: Array.isArray(b.students) ? b.students.map(String) : null,
    course: req.scope?.courseCode || b.course || null,
  };
  try {
    if (supabase) {
      let q = supabase.from('sections').update(updates).eq('id', id);
      if (req.scope?.courseCode) q = q.eq('course', req.scope.courseCode);
      await q;
      return res.json({ ok: true });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
});

app.delete('/api/sections/:id', requireAuth, restrictToCourse, async (req, res) => {
  const id = String(req.params.id || '').trim();
  if (!id) return res.status(400).json({ ok: false, error: 'Missing id' });
  try {
    if (supabase) {
      let q = supabase.from('sections').delete().eq('id', id);
      if (req.scope?.courseCode) q = q.eq('course', req.scope.courseCode);
      await q;
      return res.json({ ok: true });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
});

// Sections catalog (global) — independent of coordinator course scoping
app.get('/api/sections/catalog', requireAuth, async (req, res) => {
  try {
    if (supabase) {
      const { data } = await supabase.from('sections').select('*').order('code', { ascending: true }).range(0, 9999);
      return res.json({ ok: true, data: Array.isArray(data) ? data : [] });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
});

// Create section in catalog (super admin only)
app.post('/api/sections/catalog', requireAuth, async (req, res) => {
  const u = req.user;
  if (u.role !== 'super_admin') return res.status(403).json({ ok: false, error: 'Forbidden' });
  const b = req.body || {};
  const code = String(b.code || '').trim();
  const name = String(b.name || '').trim();
  const course = String(b.course || '').trim();
  const term = (b.term || null);
  if (!code || !name || !course) return res.status(400).json({ ok: false, error: 'code, name, course required' });
  try {
    if (supabase) {
      const { error } = await supabase.from('sections').insert([{ code, name, course, term }]);
      if (error && /duplicate|unique/i.test(String(error.message))) return res.status(409).json({ ok: false, error: 'Section exists' });
      if (error) return res.status(500).json({ ok: false, error: 'Database error: ' + String(error.message || error) });
      return res.status(201).json({ ok: true });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
});

app.delete('/api/sections/catalog/:id', requireAuth, async (req, res) => {
  const u = req.user;
  if (u.role !== 'super_admin') return res.status(403).json({ ok: false, error: 'Forbidden' });
  const id = Number(req.params.id || 0);
  if (!id) return res.status(400).json({ ok: false, error: 'Missing id' });
  try {
    if (supabase) {
      const { error } = await supabase.from('sections').delete().eq('id', id);
      if (error) return res.status(500).json({ ok: false, error: 'Database error: ' + String(error.message || error) });
      return res.json({ ok: true });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
});

// Instructor-section assignments (many-to-many): list assigned sections for instructor idNumber
app.get('/api/instructor/:id/sections', requireAuth, restrictToCourse, async (req, res) => {
  const u = req.user;
  if (u.role !== 'super_admin' && u.role !== 'coordinator') return res.status(403).json({ ok: false, error: 'Forbidden' });
  const idNumber = String(req.params.id || '').trim();
  if (!idNumber) return res.status(400).json({ ok: false, error: 'Missing id' });
  try {
    if (supabase) {
      const { data: usersRows } = await supabase.from('users').select('id,idnumber,role').eq('idnumber', idNumber).limit(1);
      const user = Array.isArray(usersRows) && usersRows[0] ? usersRows[0] : null;
      if (!user || String(user.role||'') !== 'instructor') return res.status(404).json({ ok: false, error: 'Instructor not found' });
      const instrId = Number(user.id || 0);
      let sections = [];
      const { data: pairs } = await supabase.from('user_sections').select('*').eq('user_id', instrId).range(0, 9999);
      const rows = Array.isArray(pairs) ? pairs : [];
      const allowed = Array.isArray(req.scope?.courseCodes) && req.scope.courseCodes.length ? req.scope.courseCodes : (req.scope?.courseCode ? [req.scope.courseCode] : []);
      const secIds = rows.map(r => Number(r.section_id || 0)).filter(x => x);
      if (secIds.length) {
        const { data: secs } = await supabase.from('sections').select('*').in('id', secIds).range(0, 9999);
        for (const s of (secs || [])) {
          const course = String(s.course || s.course_code || '').trim();
          const code = String(s.code || s.section_code || '').trim();
          if (!code) continue;
          if (allowed.length && course && !allowed.includes(course)) continue;
          sections.push({ id: Number(s.id||0), code, course, name: String(s.name||'').trim() || code });
        }
      }
      // Legacy rows storing course/section strings
      for (const p of rows) {
        const course = String((p.course||p.course_code||'')).trim();
        const section = String((p.section||p.section_code||'')).trim();
        if (!course || !section) continue;
        if (allowed.length && !allowed.includes(course)) continue;
        const code = `${course}-${section}`;
        sections.push({ id: null, code, course, name: section });
      }
      const { data: links } = await supabase.from('section_instructors').select('*').eq('instructor_id', instrId).range(0, 9999);
      const ids = Array.isArray(links) ? links.map(x => Number(x.section_id)).filter(x => x) : [];
      if (ids.length) {
        const { data: secs } = await supabase.from('sections').select('*').in('id', ids).range(0, 9999);
        for (const s of (secs || [])) {
          const course = String(s.course||'').trim();
          const code = String(s.code||'').trim();
          if (!code || !course) continue;
          if (allowed.length && !allowed.includes(course)) continue;
          sections.push({ id: Number(s.id||0), code, course, name: String(s.name||'').trim() || code });
        }
      }
      const seen = new Set();
      const merged = [];
      for (const s of sections) { const key = String(s.code||'').trim(); if (!key || seen.has(key)) continue; seen.add(key); merged.push(s); }
      return res.json({ ok: true, data: merged });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
});

// Instructor-course assignments (many-to-many)
app.get('/api/instructor/:id/courses', requireAuth, restrictToCourse, async (req, res) => {
  const u = req.user;
  if (u.role !== 'super_admin' && u.role !== 'coordinator') return res.status(403).json({ ok: false, error: 'Forbidden' });
  const idNumber = String(req.params.id || '').trim();
  if (!idNumber) return res.status(400).json({ ok: false, error: 'Missing id' });
  try {
    if (supabase) {
      const { data: usersRows } = await supabase.from('users').select('id,idnumber,role,course').eq('idnumber', idNumber).limit(1);
      const user = Array.isArray(usersRows) && usersRows[0] ? usersRows[0] : null;
      if (!user || String(user.role||'') !== 'instructor') return res.status(404).json({ ok: false, error: 'Instructor not found' });
      const instrId = Number(user.id || 0);
      let codes = [];
      if (instrId) {
        const { data: linksA } = await supabase.from('user_courses').select('*').eq('user_id', instrId).range(0, 9999);
        const { data: linksB } = await supabase.from('user_courses').select('*').eq('userid', instrId).range(0, 9999);
        const rows = Array.isArray(linksA) || Array.isArray(linksB) ? [ ...(Array.isArray(linksA)?linksA:[]), ...(Array.isArray(linksB)?linksB:[]) ] : [];
        const ids = rows.map(r => Number(r.course_id || r.courseid || 0)).filter(x => x);
        if (ids.length) {
          const { data: coursesRows } = await supabase.from('courses').select('id,name,name_key').in('id', ids).range(0,9999);
          const courseNames = Array.isArray(coursesRows) ? coursesRows.map(cr => String(cr.name || cr.name_key || '').trim()).filter(Boolean) : [];
          codes.push(...courseNames);
        }
        // Fallback for legacy rows that store course string
        const legacy = rows.map(x => String((x.course||x.course_code||'')).trim()).filter(Boolean);
        codes.push(...legacy);
      }
      const primary = String(user.course || '').trim();
      const merged = Array.from(new Set([primary, ...codes].filter(Boolean)));
      return res.json({ ok: true, data: merged });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
});

// Logged-in instructor assignments (fast path)
app.get('/api/instructor/me/assignments', requireAuth, async (req, res) => {
  try {
    const u = req.user;
    if (!u || u.role !== 'instructor') return res.status(403).json({ ok: false, error: 'Forbidden' });
    if (!supabase) return res.status(500).json({ ok: false, error: 'Supabase not configured' });
    const idNumber = String(u.idNumber || '').trim();
    const { data: usersRows } = await supabase.from('users').select('id,idnumber,role,course').eq('idnumber', idNumber).limit(1);
    const user = Array.isArray(usersRows) && usersRows[0] ? usersRows[0] : null;
    if (!user || String(user.role||'') !== 'instructor') return res.status(404).json({ ok: false, error: 'Instructor not found' });
    const instrId = Number(user.id || 0);
    let courses = [];
    let sections = [];
    if (instrId) {
      const [{ data: linksA }, { data: linksB }] = await Promise.all([
        supabase.from('user_courses').select('*').eq('user_id', instrId).range(0, 9999),
        supabase.from('user_courses').select('*').eq('userid', instrId).range(0, 9999)
      ]);
      const rows = Array.isArray(linksA) || Array.isArray(linksB) ? [ ...(Array.isArray(linksA)?linksA:[]), ...(Array.isArray(linksB)?linksB:[]) ] : [];
      const ids = rows.map(r => Number(r.course_id || r.courseid || 0)).filter(x => x);
      if (ids.length) {
        const { data: coursesRows } = await supabase.from('courses').select('id,name,name_key').in('id', ids).range(0,9999);
        const courseNames = Array.isArray(coursesRows) ? coursesRows.map(cr => String(cr.name || cr.name_key || '').trim()).filter(Boolean) : [];
        courses.push(...courseNames);
      }
      const legacyCourses = rows.map(x => String((x.course||x.course_code||'')) ).map(s=>s.trim()).filter(Boolean);
      courses.push(...legacyCourses);
      const { data: pairs } = await supabase.from('user_sections').select('*').eq('user_id', instrId).range(0, 9999);
      const secRows = Array.isArray(pairs) ? pairs : [];
      const secIds = secRows.map(r => Number(r.section_id || 0)).filter(x => x);
      if (secIds.length) {
        const { data: secs } = await supabase.from('sections').select('id,code,course').in('id', secIds).range(0, 9999);
        for (const s of (secs || [])) { const code = String(s.code||'').trim(); if (code) sections.push(code); }
      }
      for (const p of secRows) {
        const course = String((p.course||p.course_code||'')).trim();
        const section = String((p.section||p.section_code||'')).trim();
        if (course && section) sections.push(`${course}-${section}`);
      }
      const { data: si } = await supabase.from('section_instructors').select('*').eq('instructor_id', instrId).range(0, 9999);
      const ids2 = Array.isArray(si) ? si.map(x => Number(x.section_id)).filter(x => x) : [];
      if (ids2.length) {
        const { data: secRows2 } = await supabase.from('sections').select('id,code,course').in('id', ids2).range(0, 9999);
        for (const s of (secRows2 || [])) { const code = String(s.code||'').trim(); if (code) sections.push(code); }
      }
    }
    const primaryCourse = String(user.course || '').trim();
    const mergedCourses = Array.from(new Set([primaryCourse, ...courses].filter(Boolean)));
    const mergedSections = Array.from(new Set(sections.filter(Boolean)));
    return res.json({ ok: true, data: { courses: mergedCourses, sections: mergedSections } });
  } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
});

// Coordinator-course assignments (many-to-many): list courses for coordinator idNumber
app.get('/api/coordinator/:id/courses', requireAuth, async (req, res) => {
  const u = req.user;
  if (u.role !== 'super_admin') return res.status(403).json({ ok: false, error: 'Forbidden' });
  const idNumber = String(req.params.id || '').trim();
  if (!idNumber) return res.status(400).json({ ok: false, error: 'Missing id' });
  try {
    if (supabase) {
      const { data: usersRows } = await supabase.from('users').select('id,idnumber,role,course').eq('idnumber', idNumber).limit(1);
      const user = Array.isArray(usersRows) && usersRows[0] ? usersRows[0] : null;
      if (!user || String(user.role||'') !== 'coordinator') return res.status(404).json({ ok: false, error: 'Coordinator not found' });
      const coordId = Number(user.id || 0);
      let rows = [];
      if (coordId) {
        const { data: linksA } = await supabase.from('user_courses').select('*').eq('user_id', coordId).range(0, 9999);
        const { data: linksB } = await supabase.from('user_courses').select('*').eq('userid', coordId).range(0, 9999);
        const arr = Array.isArray(linksA) || Array.isArray(linksB) ? [ ...(Array.isArray(linksA)?linksA:[]), ...(Array.isArray(linksB)?linksB:[]) ] : [];
        const byText = arr.map(x => String((x.course||x.course_code||'')).trim()).filter(Boolean);
        const byIds = arr.map(x => Number(x.course_id||x.courseid||0)).filter(x => x);
        let codesFromIds = [];
        if (byIds.length) {
          const { data: courseRows } = await supabase.from('courses').select('id,name,name_key').in('id', Array.from(new Set(byIds))).range(0,9999);
          for (const r of (courseRows||[])) { const code = String(r.name||r.name_key||'').trim(); if (code) codesFromIds.push(code); }
        }
        rows = Array.from(new Set([...(byText||[]), ...(codesFromIds||[])]));
      }
      const primary = String(user.course || '').trim();
      const merged = Array.from(new Set([primary, ...rows].filter(Boolean)));
      return res.json({ ok: true, data: merged });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
});

// Assign multiple courses to coordinator (replaces current set)
app.post('/api/coordinator/:id/courses/assign', requireAuth, async (req, res) => {
  const u = req.user;
  if (u.role !== 'super_admin') return res.status(403).json({ ok: false, error: 'Forbidden' });
  const idNumber = String(req.params.id || '').trim();
  const courses = Array.isArray(req.body?.courses) ? req.body.courses.map(c => String(c||'').trim()).filter(Boolean) : [];
  const courseIds = Array.isArray(req.body?.courseIds) ? req.body.courseIds.map(x=>Number(x)).filter(x=>x) : [];
  if (!idNumber || (!courses.length && !courseIds.length)) return res.status(400).json({ ok: false, error: 'id and courses[] or courseIds[] required' });
  try {
    if (supabase) {
      const { data: usersRows } = await supabase.from('users').select('id,idnumber,role').eq('idnumber', idNumber).limit(1);
      const user = Array.isArray(usersRows) && usersRows[0] ? usersRows[0] : null;
      if (!user || String(user.role||'') !== 'coordinator') return res.status(404).json({ ok: false, error: 'Coordinator not found' });
      const coordId = Number(user.id || 0);
      await supabase.from('user_courses').delete().eq('user_id', coordId);
      if (courseIds.length) {
        const payloadFk = courseIds.map(id => ({ user_id: coordId, course_id: Number(id), assigned_at: new Date().toISOString() }));
        const { error: insErr } = await supabase.from('user_courses').insert(payloadFk);
        if (insErr) {
          console.error('POST /api/coordinator/:id/courses/assign FK error:', insErr);
          return res.status(500).json({ ok: false, error: 'Database error: ' + String(insErr.message || insErr) });
        }
        return res.json({ ok: true, count: payloadFk.length });
      } else {
        let courseRows = [];
        try {
          const { data: byCode } = await supabase.from('courses').select('id,name').in('name', courses);
          courseRows = Array.isArray(byCode) ? byCode : [];
          const missing = courses.filter(c => !courseRows.find(r => String(r.name||'') === c));
          if (missing.length) {
            const { data: byAlt } = await supabase.from('courses').select('id,name_key').in('name_key', missing);
            for (const r of (byAlt || [])) { courseRows.push({ id: r.id, name: r.name_key }); }
          }
        } catch {}
        if (!courseRows.length) {
          return res.status(400).json({ ok: false, error: 'Selected courses not found' });
        }
        const payloadFk = courseRows.map(c => ({ user_id: coordId, course_id: Number(c.id), assigned_at: new Date().toISOString() }));
        const { error: insErr } = await supabase.from('user_courses').insert(payloadFk);
        if (insErr) {
          console.error('POST /api/coordinator/:id/courses/assign code error:', insErr);
          return res.status(500).json({ ok: false, error: 'Database error: ' + String(insErr.message || insErr) });
        }
        return res.json({ ok: true, count: payloadFk.length });
      }
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
});

app.post('/api/instructor/:id/courses/assign', requireAuth, restrictToCourse, async (req, res) => {
  const u = req.user;
  if (u.role !== 'super_admin' && u.role !== 'coordinator') return res.status(403).json({ ok: false, error: 'Forbidden' });
  const idNumber = String(req.params.id || '').trim();
  const courses = Array.isArray(req.body?.courses) ? req.body.courses.map(c => String(c||'').trim()).filter(Boolean) : [];
  const courseIds = Array.isArray(req.body?.courseIds) ? req.body.courseIds.map(x=>Number(x)).filter(x=>x) : [];
  if (!idNumber || (!courses.length && !courseIds.length)) return res.status(400).json({ ok: false, error: 'id and courses[] or courseIds[] required' });
  try {
    if (supabase) {
      const { data: usersRows } = await supabase.from('users').select('id,idnumber,role').eq('idnumber', idNumber).limit(1);
      const user = Array.isArray(usersRows) && usersRows[0] ? usersRows[0] : null;
      if (!user || String(user.role||'') !== 'instructor') return res.status(404).json({ ok: false, error: 'Instructor not found' });
      const instrId = Number(user.id || 0);
      const allowed = Array.isArray(req.scope?.courseCodes) && req.scope.courseCodes.length ? req.scope.courseCodes : (req.scope?.courseCode ? [req.scope.courseCode] : []);
      await supabase.from('user_courses').delete().eq('user_id', instrId);
      if (courseIds.length) {
        let rows = [];
        try { const { data } = await supabase.from('courses').select('id,name').in('id', courseIds); rows = Array.isArray(data)?data:[]; } catch {}
        if (u.role === 'coordinator' && allowed.length) {
          const codes = rows.map(r=>String(r.name||'').trim()).filter(Boolean);
          const allAllowed = codes.every(c => allowed.includes(c));
          if (!allAllowed) return res.status(403).json({ ok: false, error: 'Forbidden: outside course scope' });
        }
        const payloadFk = courseIds.map(id => ({ user_id: instrId, course_id: Number(id), assigned_at: new Date().toISOString() }));
        const { error: insErr } = await supabase.from('user_courses').insert(payloadFk);
        if (insErr) {
          console.error('POST /api/instructor/:id/courses/assign FK error:', insErr);
          return res.status(500).json({ ok: false, error: 'Database error: ' + String(insErr.message || insErr) });
        }
        return res.json({ ok: true, count: payloadFk.length });
      } else {
        if (u.role === 'coordinator' && allowed.length) {
          const allAllowed = courses.every(c => allowed.includes(c));
          if (!allAllowed) return res.status(403).json({ ok: false, error: 'Forbidden: outside course scope' });
        }
        let courseRows = [];
        try {
          const { data: byCode } = await supabase.from('courses').select('id,name').in('name', courses);
          courseRows = Array.isArray(byCode) ? byCode : [];
          const missing = courses.filter(c => !courseRows.find(r => String(r.name||'') === c));
          if (missing.length) {
            const { data: byAlt } = await supabase.from('courses').select('id,name_key').in('name_key', missing);
            for (const r of (byAlt || [])) { courseRows.push({ id: r.id, name: r.name_key }); }
          }
        } catch {}
        if (!courseRows.length) { return res.status(400).json({ ok: false, error: 'Selected courses not found' }); }
        const payloadFk = courseRows.map(c => ({ user_id: instrId, course_id: Number(c.id), assigned_at: new Date().toISOString() }));
        const { error: insErr } = await supabase.from('user_courses').insert(payloadFk);
        if (insErr) {
          console.error('POST /api/instructor/:id/courses/assign code error:', insErr);
          return res.status(500).json({ ok: false, error: 'Database error: ' + String(insErr.message || insErr) });
        }
        return res.json({ ok: true, count: payloadFk.length });
      }
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
});
// Assign multiple sections to instructor (replaces current set)
app.post('/api/instructor/:id/sections/assign', requireAuth, restrictToCourse, async (req, res) => {
  const u = req.user;
  if (u.role !== 'super_admin' && u.role !== 'coordinator') return res.status(403).json({ ok: false, error: 'Forbidden' });
  const idNumber = String(req.params.id || '').trim();
  const codes = Array.isArray(req.body?.codes) ? req.body.codes.map(String) : [];
  const sectionIds = Array.isArray(req.body?.sectionIds) ? req.body.sectionIds.map(x=>Number(x)).filter(x=>x) : [];
  if (!idNumber || (!codes.length && !sectionIds.length)) return res.status(400).json({ ok: false, error: 'id and codes[] or sectionIds[] required' });
  try {
    if (supabase) {
      const { data: usersRows } = await supabase.from('users').select('id,idnumber,role').eq('idnumber', idNumber).limit(1);
      const user = Array.isArray(usersRows) && usersRows[0] ? usersRows[0] : null;
      if (!user || String(user.role||'') !== 'instructor') return res.status(404).json({ ok: false, error: 'Instructor not found' });
      const instrId = Number(user.id || 0);
      const allowed = Array.isArray(req.scope?.courseCodes) && req.scope.courseCodes.length ? req.scope.courseCodes : (req.scope?.courseCode ? [req.scope.courseCode] : []);
      await supabase.from('user_sections').delete().eq('user_id', instrId);
      if (sectionIds.length) {
        let rows = [];
        try { const { data } = await supabase.from('sections').select('id,course').in('id', sectionIds); rows = Array.isArray(data)?data:[]; } catch {}
        if (u.role === 'coordinator' && allowed.length) {
          const codes = rows.map(r=>String(r.course||'').trim()).filter(Boolean);
          const allAllowed = codes.every(c => allowed.includes(c));
          if (!allAllowed) return res.status(403).json({ ok: false, error: 'Forbidden: outside course scope' });
        }
        const payloadFk = sectionIds.map(id => ({ user_id: instrId, section_id: Number(id) }));
        const { error: insErr } = await supabase.from('user_sections').insert(payloadFk);
        if (insErr) return res.status(500).json({ ok: false, error: 'Database error: ' + String(insErr.message || insErr) });
        return res.json({ ok: true, count: payloadFk.length });
      } else {
      const parsed = codes.map(c => {
        const s = String(c||'').trim();
        let course = null, section = null;
        if (s.includes('-')) {
          const idx = s.indexOf('-');
          course = s.slice(0, idx).trim();
          section = s.slice(idx+1).trim();
        } else {
          const parts = s.split(' ').map(x=>x.trim()).filter(Boolean);
          if (parts.length >= 2) { course = parts[0]; section = parts[1]; }
        }
        if (!course || !section) return null;
        return { course, section };
      }).filter(Boolean);
        const selectedCourses = Array.from(new Set(parsed.map(r => r.course).filter(Boolean)));
        if (u.role === 'coordinator' && allowed.length) {
          const allAllowed = selectedCourses.every(c => allowed.includes(c));
          if (!allAllowed) return res.status(403).json({ ok: false, error: 'Forbidden: outside course scope' });
        }
        let sectionRows = [];
        try {
          const { data: byCode } = await supabase.from('sections').select('id,code').in('code', codes);
          sectionRows = Array.isArray(byCode) ? byCode : [];
          const missing = codes.filter(c => !sectionRows.find(r => String(r.code||'') === c));
          if (missing.length) {
            const sectionCodes = parsed.map(p => p.section).filter(Boolean);
            const { data: byAlt } = await supabase.from('sections').select('id,section_code,course_id').in('section_code', sectionCodes);
            for (const r of (byAlt || [])) {
              const full = parsed.find(p => p.section === r.section_code);
              const code = full ? `${full.course}-${full.section}` : r.section_code;
              sectionRows.push({ id: r.id, code });
            }
          }
        } catch {}
        if (!sectionRows.length) {
          const payloadLegacy = parsed.map(p => ({ user_id: instrId, course: p.course, section: p.section }));
          if (payloadLegacy.length) {
            const { error: insErr } = await supabase.from('user_sections').insert(payloadLegacy);
            if (insErr) return res.status(500).json({ ok: false, error: 'Database error: ' + String(insErr.message || insErr) });
          }
          return res.json({ ok: true, count: payloadLegacy.length });
        } else {
          const payloadFk = sectionRows.map(s => ({ user_id: instrId, section_id: Number(s.id) }));
          const { error: insErr } = await supabase.from('user_sections').insert(payloadFk);
          if (insErr) {
            const payloadLegacy = parsed.map(p => ({ user_id: instrId, course: p.course, section: p.section }));
            const { error: insErr2 } = await supabase.from('user_sections').insert(payloadLegacy);
            if (insErr2) return res.status(500).json({ ok: false, error: 'Database error: ' + String(insErr2.message || insErr2) });
            return res.json({ ok: true, count: payloadLegacy.length });
          }
          return res.json({ ok: true, count: payloadFk.length });
        }
      }
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
});

// Unassign section from instructor by section code
app.delete('/api/instructor/:id/sections/:code', requireAuth, async (req, res) => {
  const u = req.user;
  if (u.role !== 'super_admin') return res.status(403).json({ ok: false, error: 'Forbidden' });
  const idNumber = String(req.params.id || '').trim();
  const code = String(req.params.code || '').trim();
  if (!idNumber || !code) return res.status(400).json({ ok: false, error: 'Missing id or code' });
  try {
    if (supabase) {
      const { data: usersRows } = await supabase.from('users').select('id,idnumber,role').eq('idnumber', idNumber).limit(1);
      const user = Array.isArray(usersRows) && usersRows[0] ? usersRows[0] : null;
      if (!user || String(user.role||'') !== 'instructor') return res.status(404).json({ ok: false, error: 'Instructor not found' });
      const instrId = Number(user.id || 0);
      const { data: s } = await supabase.from('sections').select('id,code').eq('code', code).limit(1);
      const sec = Array.isArray(s) && s[0] ? s[0] : null;
      if (!sec) return res.status(404).json({ ok: false, error: 'Section not found' });
      await supabase.from('section_instructors').delete().eq('instructor_id', instrId).eq('section_id', sec.id);
      return res.json({ ok: true });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
});

// Create/update/delete endpoints with course enforcement for coordinators
app.post('/api/students', requireAuth, restrictToCourse, async (req, res) => {
  const payload = req.body || {};
  if (!payload.idNumber) return res.status(400).json({ ok: false, error: 'idNumber required' });
  try {
    if (pool) {
      const u = req.user;
      const bcrypt = require('bcrypt');
      const hash = await bcrypt.hash(payload.password || 'password', 10);
      const allowed = Array.isArray(req.scope?.courseCodes) && req.scope.courseCodes.length ? req.scope.courseCodes : (req.scope?.courseCode ? [req.scope.courseCode] : []);
      const requested = String(payload.course||'').trim();
      const chosenCode = (requested && allowed.includes(requested)) ? requested : (u.courseCode || allowed[0] || null);
      let courseId = u.courseId || null;
      if (chosenCode) {
        const [course] = await pool.execute('SELECT id FROM courses WHERE code=?',[chosenCode]);
        courseId = course[0]?.id || courseId;
      }
      await pool.execute(
        "INSERT INTO users (id_number, password_hash, role, name, course_id, section) VALUES (?,?,?,?,?,?)",
        [payload.idNumber, hash, 'student', payload.name || payload.idNumber, courseId, payload.section || null]
      );
      return res.status(201).json({ ok: true });
    } else if (supabase) {
      const allowed = Array.isArray(req.scope?.courseCodes) && req.scope.courseCodes.length ? req.scope.courseCodes : (req.scope?.courseCode ? [req.scope.courseCode] : []);
      const requested = String(payload.course||'').trim();
      const chosenCode = (requested && allowed.includes(requested)) ? requested : (req.scope?.courseCode || allowed[0] || null);
      const doc = {
        idnumber: payload.idNumber,
        password: payload.password || 'password',
        role: 'student',
        name: fullName(payload) || payload.name || payload.idNumber,
        firstname: payload.firstName || null,
        middlename: payload.middleName || null,
        lastname: payload.lastName || null,
        section: payload.section || null,
        supervisorid: payload.supervisorId || null,
        course: chosenCode || null,
      };
      const { error } = await supabase.from('users').insert([doc]);
      if (error && /duplicate/i.test(String(error.message))) return res.status(409).json({ ok: false, error: 'Student exists' });
      if (error) return res.status(500).json({ ok: false, error: 'Server error' });
      return res.status(201).json({ ok: true });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) { res.status(500).json({ ok: false, error: 'Server error' }); }
});

app.post('/api/instructors', requireAuth, restrictToCourse, async (req, res) => {
  const payload = req.body || {};
  if (!payload.idNumber) return res.status(400).json({ ok: false, error: 'idNumber required' });
  try {
    if (pool) {
      const u = req.user;
      const bcrypt = require('bcrypt');
      const hash = await bcrypt.hash(payload.password || 'password', 10);
      const [course] = await pool.execute('SELECT id FROM courses WHERE code=?',[u.courseCode]);
      const courseId = course[0]?.id || u.courseId;
      await pool.execute(
        "INSERT INTO users (id_number, password_hash, role, name, course_id) VALUES (?,?,?,?,?)",
        [payload.idNumber, hash, 'instructor', payload.name || payload.idNumber, courseId]
      );
      return res.status(201).json({ ok: true });
    } else if (supabase) {
      const doc = {
        idnumber: payload.idNumber,
        password: payload.password || 'password',
        role: 'instructor',
        name: fullName(payload) || payload.name || payload.idNumber,
        firstname: payload.firstName || null,
        middlename: payload.middleName || null,
        lastname: payload.lastName || null,
        course: req.scope?.courseCode || (payload.course || null),
        section: payload.section || null,
      };
      const { error } = await supabase.from('users').insert([doc]);
      if (error && /duplicate/i.test(String(error.message))) return res.status(409).json({ ok: false, error: 'Instructor exists' });
      if (error) return res.status(500).json({ ok: false, error: 'Server error' });
      return res.status(201).json({ ok: true });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) { res.status(500).json({ ok: false, error: 'Server error' }); }
});

// Update/delete instructors (JSON fallback only for now)
app.put('/api/instructors/:id', requireAuth, restrictToCourse, async (req, res) => {
  const id = req.params.id;
  if (pool) {
    // MySQL update not implemented in current stack
  } else if (supabase) {
    const scopeCode = req.scope?.courseCode;
    const updates = { name: req.body?.name || null, course: scopeCode || req.body?.course || null };
    await supabase.from('users').update(updates).eq('idnumber', id);
    return res.json({ ok: true });
  } else {
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  }
});

app.delete('/api/instructors/:id', requireAuth, restrictToCourse, async (req, res) => {
  const id = req.params.id;
  if (pool) {
    // MySQL delete not implemented in current stack
  } else if (supabase) {
    await supabase.from('users').delete().eq('idnumber', id);
    return res.json({ ok: true });
  } else {
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  }
});

// Update/delete (JSON fallback only for now)
app.put('/api/students/:id', requireAuth, restrictToCourse, async (req, res) => {
  const id = req.params.id;
  if (pool) {
    // MySQL update not implemented in current stack
  } else if (supabase) {
    const scopeCode = req.scope?.courseCode;
    const body = req.body || {};
    const firstName = body.firstName || null;
    const middleName = body.middleName || null;
    const lastName = body.lastName || null;
    const nameCombined = body.name || fullName({ firstName, middleName, lastName }) || id;
    const updates = { name: nameCombined, firstname: firstName, middlename: middleName, lastname: lastName, section: body.section || null, supervisorid: body.supervisorId || null, course: scopeCode || body.course || null };
    await supabase.from('users').update(updates).eq('idnumber', id);
    return res.json({ ok: true });
  } else {
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  }
});

app.delete('/api/students/:id', requireAuth, restrictToCourse, async (req, res) => {
  const id = req.params.id;
  if (pool) {
    // MySQL delete not implemented in current stack
  } else if (supabase) {
    await supabase.from('users').delete().eq('idnumber', id);
    return res.json({ ok: true });
  } else {
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  }
});

// Supervisors create stays course-agnostic (business context)
app.post('/api/supervisors', requireAuth, restrictToCourse, async (req, res) => {
  const payload = req.body || {};
  if (!payload.idNumber) return res.status(400).json({ ok: false, error: 'idNumber required' });
  if (pool) {
    try {
      const bcrypt = require('bcrypt');
      const hash = await bcrypt.hash(payload.password || 'password', 10);
      const u = req.user;
      let courseId = u.courseId;
      if (!courseId && u.courseCode) {
        const [course] = await pool.execute('SELECT id FROM courses WHERE code=?', [u.courseCode]);
        courseId = course[0]?.id || null;
      }
      await pool.execute(
        "INSERT INTO users (id_number, password_hash, role, name, company, location, course_id) VALUES (?,?,?,?,?,?,?)",
        [payload.idNumber, hash, 'supervisor', payload.name || payload.idNumber, payload.company || null, payload.location || null, courseId]
      );
      return res.status(201).json({ ok: true });
    } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
  } else if (supabase) {
    const doc = { idnumber: payload.idNumber, password: payload.password || 'password', role: 'supervisor', name: fullName(payload) || payload.name || payload.idNumber, firstname: payload.firstName || null, middlename: payload.middleName || null, lastname: payload.lastName || null, company: payload.company || null, location: payload.location || null, course: req.scope?.courseCode || payload.course || null, section: payload.section || null };
    const { error } = await supabase.from('users').insert([doc]);
    if (error && /duplicate/i.test(String(error.message))) return res.status(409).json({ ok: false, error: 'Supervisor exists' });
    if (error) return res.status(500).json({ ok: false, error: 'Server error' });
    return res.status(201).json({ ok: true });
  }
  return res.status(500).json({ ok: false, error: 'Supabase not configured' });
});

// Update/delete supervisors
app.put('/api/supervisors/:id', requireAuth, restrictToCourse, async (req, res) => {
  const id = req.params.id;
  if (pool) {
    // MySQL update not implemented in current stack
    return res.status(501).json({ ok: false, error: 'Not implemented' });
  } else if (supabase) {
    const scopeCode = req.scope?.courseCode;
    const updates = {
      name: req.body?.name || null,
      company: req.body?.company || null,
      location: req.body?.location || null,
      section: req.body?.section || null,
      course: scopeCode || req.body?.course || null,
    };
    await supabase.from('users').update(updates).eq('idnumber', id);
    return res.json({ ok: true });
  }
  return res.status(500).json({ ok: false, error: 'Supabase not configured' });
});

app.delete('/api/supervisors/:id', requireAuth, restrictToCourse, async (req, res) => {
  const id = req.params.id;
  if (pool) {
    // MySQL delete not implemented in current stack
    return res.status(501).json({ ok: false, error: 'Not implemented' });
  } else if (supabase) {
    await supabase.from('users').delete().eq('idnumber', id);
    return res.json({ ok: true });
  }
  return res.status(500).json({ ok: false, error: 'Supabase not configured' });
});

// Evaluation status: read
app.get('/api/evaluation/status/:id', requireAuth, restrictToCourse, async (req, res) => {
  const id = String(req.params.id || '').trim();
  if (!id) return res.status(400).json({ ok: false, error: 'Missing id' });
  try {
    if (supabase) {
      try { console.log('[EVAL] GET status', id, 'by', req.user?.idNumber, 'role', req.user?.role); } catch {}
      let { data, error } = await supabase
        .from('evaluation_status')
        .select('idnumber,enabled')
        .eq('idnumber', id)
        .single();
      if (error || !data) {
        const alt = await supabase
          .from('evaluation_status')
          .select('idnumber,enabled')
          .ilike('idnumber', id)
          .single();
        data = alt.data;
      }
      if (!data) return res.status(404).json({ ok: false, error: 'Not found' });
      const enabled = !!data.enabled;
      return res.json({ ok: true, enabled });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
});

// Evaluation status: update
app.post('/api/evaluation/status/:id', requireAuth, restrictToCourse, async (req, res) => {
  const u = req.user;
  if (u.role !== 'instructor' && u.role !== 'super_admin') return res.status(403).json({ ok: false, error: 'Forbidden' });
  const id = String(req.params.id || '').trim();
  const enabled = !!(req.body && req.body.enabled);
  if (!id) return res.status(400).json({ ok: false, error: 'Missing id' });
  try {
    if (supabase) {
      try { console.log('[EVAL] POST status', id, 'enabled', enabled, 'by', req.user?.idNumber, 'role', req.user?.role); } catch {}
      let { data: stuRows } = await supabase.from('users').select('idnumber,course').eq('idnumber', id).limit(1);
      let stu = Array.isArray(stuRows) && stuRows[0] ? stuRows[0] : null;
      if (!stu) {
        const res2 = await supabase.from('users').select('idnumber,course').ilike('idnumber', id).limit(1);
        stuRows = res2.data;
        stu = Array.isArray(stuRows) && stuRows[0] ? stuRows[0] : null;
      }
      if (!stu) return res.status(404).json({ ok: false, error: 'Not found' });
      const stuCourse = String(stu.course || '');
      const scopeCourse = String(req.scope?.courseCode || '');
      const allowed = (u.role === 'super_admin') || (u.role === 'instructor') || (!stuCourse && !!scopeCourse) || (stuCourse && scopeCourse && stuCourse === scopeCourse);
      if (!allowed) return res.status(403).json({ ok: false, error: 'Forbidden' });
      const payload = !stuCourse && scopeCourse ? { idnumber: stu.idnumber || id, enabled, course: scopeCourse, updated_at: new Date().toISOString() } : { idnumber: stu.idnumber || id, enabled, updated_at: new Date().toISOString() };
      const { error } = await supabase.from('evaluation_status').upsert(payload, { onConflict: 'idnumber' });
      if (error) return res.status(500).json({ ok: false, error: String(error.message || error) });
      return res.json({ ok: true });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
});

// Student hours
app.get('/api/student/:id/hours', requireAuth, restrictToCourse, async (req, res) => {
  const u = req.user;
  if (u.role !== 'instructor' && u.role !== 'supervisor' && u.role !== 'super_admin') return res.status(403).json({ ok: false, error: 'Forbidden' });
  const id = String(req.params.id || '').trim();
  if (!id) return res.status(400).json({ ok: false, error: 'Missing id' });
  try {
    if (supabase) {
      const { data } = await supabase
        .from('attendance')
        .select('idnumber,ts,type,status,course,approvedat')
        .eq('idnumber', id)
        .eq('status', 'confirmed')
        .order('approvedat', { ascending: true })
        .range(0, 9999);
      let rows = Array.isArray(data) ? data : [];
      let closed = 0;
      let open = null;
      for (const r of rows) {
        const t = String(r.type || '');
        const a = Number(Date.parse(String(r.approvedat||'')) || 0);
        const ts = a || Number(r.ts || 0);
        if (t === 'in') {
          open = ts;
        } else if (t === 'out' && open !== null) {
          if (ts > open) closed += ts - open;
          open = null;
        }
      }
      const now = Date.now();
      let total = closed;
      let ongoing = false;
      let openStartTs = null;
      if (open !== null) {
        ongoing = true;
        openStartTs = open;
        total += Math.max(0, now - open);
      }
      const h = Math.floor(total / 3600000);
      const m = Math.floor((total % 3600000) / 60000);
      const s = Math.floor((total % 60000) / 1000);
      const formatted = `${h}h ${m}m ${s}s`;
      const hoursDec = Math.max(0, Math.round(total / 3600000 * 100) / 100);
      return res.json({ ok: true, hours: hoursDec, data: { milliseconds: total, closedMilliseconds: closed, openStartTs, hours: h, minutes: m, seconds: s, formatted, ongoing } });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
});

// Save evaluation form
app.post('/api/evaluations', requireAuth, restrictToCourse, async (req, res) => {
  const u = req.user;
  if (u.role !== 'supervisor' && u.role !== 'super_admin') return res.status(403).json({ ok: false, error: 'Forbidden' });
  const b = req.body || {};
  const idNumber = String(b.idNumber || '').trim();
  const form = b.form;
  if (!idNumber || !form) return res.status(400).json({ ok: false, error: 'Missing data' });
  try {
    if (supabase) {
      const { data: stuRows } = await supabase.from('users').select('*').eq('idnumber', idNumber).limit(1);
      const stu = Array.isArray(stuRows) && stuRows[0] ? stuRows[0] : null;
      if (!stu) return res.status(404).json({ ok: false, error: 'Student not found' });
      if (req.scope?.courseCode && String(stu.course || '') !== String(req.scope.courseCode) && u.role !== 'super_admin') return res.status(403).json({ ok: false, error: 'Forbidden' });
      const supOk = u.role === 'super_admin' || String(stu.supervisorid || '') === String(u.idNumber || '');
      if (!supOk) return res.status(403).json({ ok: false, error: 'Forbidden' });
      const rawStatus = (stu.evaluation_status !== undefined) ? stu.evaluation_status : stu.evaluationStatus;
      const enabled = (typeof rawStatus === 'boolean') ? rawStatus : (String(rawStatus || '').toLowerCase() === 'enabled');
      if (!enabled && u.role !== 'super_admin') return res.status(409).json({ ok: false, error: 'Evaluation disabled' });
      const payload = { idnumber: idNumber, byid: u.idNumber, byrole: u.role, data: JSON.stringify(form), ts: Date.now(), createdat: new Date().toISOString(), course: stu.course || null };
      const { error } = await supabase.from('evaluation_forms').insert([payload]);
      if (error) return res.status(500).json({ ok: false, error: String(error.message || error) });
      return res.status(201).json({ ok: true });
    }
    return res.status(500).json({ ok: false, error: 'Supabase not configured' });
  } catch (e) { return res.status(500).json({ ok: false, error: 'Server error' }); }
});

// HTML extension fallback: serve <path>.html when no extension is provided
app.use((req, res, next) => {
  try {
    const reqPath = req.path || '/';
    const ext = path.extname(reqPath);
    if (!ext) {
      const candidate = path.join(__dirname, reqPath.replace(/^\/+/, '') + '.html');
      if (fs.existsSync(candidate)) {
        return res.sendFile(candidate);
      }
    }
  } catch (e) {
    // ignore and continue to 404
  }
  next();
});

// Final 404 handler
app.use((req, res) => {
  res.status(404).send('Not Found');
});

if (!process.env.VERCEL) {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`OJTonTrack server running at http://localhost:${PORT}/`);
    try {
      const ifaces = os.networkInterfaces();
      const addrs = [];
      Object.values(ifaces).forEach(list => {
        (list||[]).forEach(i => { if (i && i.family === 'IPv4' && !i.internal) addrs.push(i.address); });
      });
      addrs.forEach(a => console.log(`OJTonTrack LAN: http://${a}:${PORT}/`));
    } catch {}
  });
}

module.exports = app;
