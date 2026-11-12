const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');

const PORT = process.env.PORT || 3000;
const BIN_ID = process.env.JSONBIN_BIN_ID;
const API_KEY = process.env.JSONBIN_API_KEY;
const BASE = process.env.JSONBIN_BASE || 'https://api.jsonbin.io/v3/b';
const DB_URL = `${BASE}/${BIN_ID}`;
const CONFIGURED = !!(BIN_ID && API_KEY);
const ADMIN_USER = (process.env.ADMIN_USERNAME || 'superadmin').toLowerCase();
const TEACHER_USER = (process.env.TEACHER_USERNAME || 'zeynab').toLowerCase();
const SECRET = process.env.SESSION_SECRET || crypto.createHash('sha256').update('planner:' + (API_KEY || 'dev')).digest('hex');
const TTL = 30 * 24 * 3600 * 1000;
const KEYS = ['done', 'plan', 'habits', 'hist', 'exams', 'theme', 'study', 'tasks', 'water', 'sleep', 'mood', 'jr', 'goal'];
const THEMES = ['normal', 'halloween', 'christmas', 'yalda', 'nowruz', 'teacher', 'ramadan', 'autumn'];
const ADMIN_DEFAULT_PW = 'Super@2026'; // رمز ثابت اولیه‌ی مدیر؛ اگر ADMIN_PASSWORD ست شود آن اولویت دارد
const TEACHER_DEFAULT_PW = 'admin123'; // رمز ثابت اولیه‌ی خانم زینب؛ اگر TEACHER_PASSWORD ست شود آن اولویت دارد
const MAX_USER = 25 * 1024, MAX_BIN = 90 * 1024; // سقف رایگان JSONBin حدود ۱۰۰ کیلوبایت است

class HttpErr extends Error { constructor(status, msg) { super(msg); this.status = status; } }
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res)).catch(next);
const str = (v, n) => (typeof v === 'string' ? v.trim().slice(0, n) : '');
const J = (s, f) => { try { const v = JSON.parse(s); return v == null ? f : v; } catch { return f; } };

app.use((req, res, next) => { res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Referrer-Policy', 'same-origin'); next(); });
app.use(express.json({ limit: '200kb' }));
app.get('/healthz', (req, res) => res.type('text').send('ok'));

// ===== رمز و نشست =====
async function hash(pw) { const salt = crypto.randomBytes(16); const k = await scrypt(pw, salt, 32); return salt.toString('hex') + ':' + k.toString('hex'); }
async function verify(pw, stored) {
    const [s, h] = String(stored).split(':');
    const k = await scrypt(pw, Buffer.from(s, 'hex'), 32), e = Buffer.from(h, 'hex');
    return k.length === e.length && crypto.timingSafeEqual(k, e);
}
const sign = (u) => {
    const p = Buffer.from(JSON.stringify({ u: u.username, tv: u.tv || 0, exp: Date.now() + TTL })).toString('base64url');
    return p + '.' + crypto.createHmac('sha256', SECRET).update(p).digest('base64url');
};
function readToken(t) {
    const [p, m] = String(t || '').split('.');
    if (!p || !m) return null;
    const e = crypto.createHmac('sha256', SECRET).update(p).digest('base64url');
    if (e.length !== m.length || !crypto.timingSafeEqual(Buffer.from(e), Buffer.from(m))) return null;
    try { const o = JSON.parse(Buffer.from(p, 'base64url').toString()); return o.exp > Date.now() ? o : null; } catch { return null; }
}
const fails = new Map();
const throttle = (k) => { const f = fails.get(k); if (f && f.until > Date.now()) throw new HttpErr(429, 'تلاش‌های زیاد؛ چند دقیقه بعد دوباره امتحان کن'); };
const failed = (k) => { if (fails.size > 2000) fails.clear(); const f = fails.get(k) || { n: 0, until: 0 }; if (++f.n >= 8) { f.until = Date.now() + 10 * 60000; f.n = 0; } fails.set(k, f); };

// ===== ذخیره‌سازی روی JSONBin (کش حافظه + صف نوشتن) =====
let db = null, loadP = null, chain = Promise.resolve();
async function persist(d) {
    const body = JSON.stringify(d);
    if (Buffer.byteLength(body) > MAX_BIN) throw new HttpErr(507, 'ظرفیت ذخیره‌سازی پر شده؛ با مدیر تماس بگیر');
    const r = await fetch(DB_URL, { method: 'PUT', headers: { 'Content-Type': 'application/json', 'X-Master-Key': API_KEY }, body });
    if (!r.ok) throw new HttpErr(502, 'ذخیره روی JSONBin ناموفق بود');
}
const tag = (pw) => crypto.createHash('sha256').update('def:' + pw).digest('hex').slice(0, 12);
async function ensure(d, username, displayName, role, envPw, defPw) {
    let u = d.users[username], ch = false;
    if (!u) {
        const pw = envPw || defPw || crypto.randomBytes(6).toString('hex');
        if (!envPw && !defPw) console.log(`[حساب ${role}] نام کاربری=${username} رمز=${pw}  (فقط همین یک بار؛ بهتر است رمز را با متغیر محیطی بگذاری)`);
        d.users[username] = { username, displayName, role, passHash: await hash(pw), tv: 0, data: {}, rev: 0, created: Date.now(), pwDef: !envPw && defPw ? tag(defPw) : undefined };
        ch = true;
    } else {
        if (u.role !== role) { u.role = role; ch = true; }
        if (u.displayName !== displayName) { u.displayName = displayName; ch = true; }
        if (envPw && !(await verify(envPw, u.passHash))) { u.passHash = await hash(envPw); u.tv = (u.tv || 0) + 1; ch = true; }
        else if (!envPw && defPw && u.pwDef !== tag(defPw)) { u.passHash = await hash(defPw); u.pwDef = tag(defPw); u.tv = (u.tv || 0) + 1; ch = true; } // یک‌بار برای هر رمز ثابتِ جدید؛ بعدش کاربر می‌تواند عوضش کند
    }
    return ch;
}
async function doLoad() {
    const r = await fetch(DB_URL + '/latest', { headers: { 'X-Master-Key': API_KEY } });
    if (!r.ok) throw new HttpErr(502, 'اتصال به JSONBin ناموفق بود');
    const rec = (await r.json()).record || {};
    const d = { users: rec.users && typeof rec.users === 'object' ? rec.users : {}, theme: THEMES.includes(rec.theme) ? rec.theme : 'normal' };
    // مهاجرت: حساب قدیمیِ «admin» به نام کاربری جدید منتقل می‌شود (اطلاعاتش حفظ می‌شود)
    const old = d.users.admin;
    if (ADMIN_USER !== 'admin' && old && old.role === 'admin' && !d.users[ADMIN_USER]) {
        delete d.users.admin; old.username = ADMIN_USER; old.tv = (old.tv || 0) + 1; d.users[ADMIN_USER] = old;
    }
    const a = await ensure(d, ADMIN_USER, 'superadmin', 'admin', process.env.ADMIN_PASSWORD, ADMIN_DEFAULT_PW);
    const b = await ensure(d, TEACHER_USER, 'خانم زینب', 'teacher', process.env.TEACHER_PASSWORD, TEACHER_DEFAULT_PW);
    if (a || b) await persist(d);
    return (db = d);
}
const load = () => (db ? Promise.resolve(db) : (loadP = loadP || doLoad().catch((e) => { loadP = null; throw e; })));
function mutate(fn) {
    const job = chain.then(async () => {
        const draft = structuredClone(await load());
        const out = await fn(draft);
        await persist(draft);
        db = draft;
        return out;
    });
    chain = job.catch(() => {});
    return job;
}

const me = (u) => ({ username: u.username, displayName: u.displayName, role: u.role, theme: db.theme, note: u.note || null });
async function auth(req, res, next) {
    try {
        if (!CONFIGURED) throw new HttpErr(503, 'سرور هنوز تنظیم نشده');
        const t = readToken((req.get('Authorization') || '').replace(/^Bearer /, ''));
        const d = await load();
        const u = t && d.users[t.u];
        if (!u || (u.tv || 0) !== t.tv) throw new HttpErr(401, 'نشست معتبر نیست');
        req.user = u;
        next();
    } catch (e) { next(e); }
}
const roles = (...rs) => (req, res, next) => (rs.includes(req.user.role) ? next() : next(new HttpErr(403, 'دسترسی ندارید')));
const needCfg = () => { if (!CONFIGURED) throw new HttpErr(503, 'سرور هنوز تنظیم نشده'); };

// ===== ثبت‌نام و ورود =====
app.post('/api/register', wrap(async (req, res) => {
    needCfg();
    const username = str(req.body.username, 30).toLowerCase(), displayName = str(req.body.displayName, 40);
    const password = typeof req.body.password === 'string' ? req.body.password.slice(0, 200) : '';
    if (!/^[a-z0-9_]{3,20}$/.test(username)) throw new HttpErr(400, 'نام کاربری: ۳ تا ۲۰ حرف انگلیسی کوچک، عدد یا _');
    if (!displayName) throw new HttpErr(400, 'نام نمایشی را بنویس');
    if (password.length < 6) throw new HttpErr(400, 'رمز عبور حداقل ۶ کاراکتر باشد');
    const passHash = await hash(password);
    const u = await mutate(async (d) => {
        if (d.users[username]) throw new HttpErr(409, 'این نام کاربری قبلاً ثبت شده');
        if (Object.keys(d.users).length >= 150) throw new HttpErr(403, 'ظرفیت ثبت‌نام پر است');
        return (d.users[username] = { username, displayName, role: 'user', passHash, tv: 0, data: {}, rev: 0, created: Date.now() });
    });
    res.json({ token: sign(u), me: me(u) });
}));
app.post('/api/login', wrap(async (req, res) => {
    needCfg();
    const username = str(req.body.username, 30).toLowerCase();
    const password = typeof req.body.password === 'string' ? req.body.password.slice(0, 200) : '';
    const key = req.ip + ':' + username;
    throttle(key);
    const u = (await load()).users[username];
    if (!u || !(await verify(password, u.passHash))) { failed(key); throw new HttpErr(401, 'نام کاربری یا رمز عبور اشتباه است'); }
    fails.delete(key);
    res.json({ token: sign(u), me: me(u) });
}));
app.get('/api/me', auth, (req, res) => res.json(me(req.user)));
app.post('/api/password', auth, wrap(async (req, res) => {
    const o = typeof req.body.old === 'string' ? req.body.old : '', n = typeof req.body.new === 'string' ? req.body.new.slice(0, 200) : '';
    if (n.length < 6) throw new HttpErr(400, 'رمز جدید حداقل ۶ کاراکتر باشد');
    if (!(await verify(o, req.user.passHash))) throw new HttpErr(403, 'رمز فعلی درست نیست');
    const passHash = await hash(n);
    const u = await mutate(async (d) => { const x = d.users[req.user.username]; x.passHash = passHash; x.tv = (x.tv || 0) + 1; return x; });
    res.json({ token: sign(u) });
}));

// ===== اطلاعات برنامه‌ی هر کاربر =====
app.get('/api/data', auth, (req, res) => {
    const { plan, ...rest } = req.user.data || {}; // برنامه‌ی روزانه فقط از طرف معلم تعیین می‌شود
    res.set('Cache-Control', 'no-store').json({ rev: req.user.rev || 0, data: req.user.plan ? { ...rest, plan: req.user.plan } : rest });
});
app.put('/api/data', auth, wrap(async (req, res) => {
    const body = req.body && req.body.data;
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new HttpErr(400, 'داده نامعتبر است');
    const data = {};
    let bytes = 0;
    for (const k of KEYS) {
        if (k === 'plan' || body[k] == null) continue; // دانش‌آموز نمی‌تواند برنامه را عوض کند
        if (typeof body[k] !== 'string') throw new HttpErr(400, 'داده نامعتبر است');
        bytes += Buffer.byteLength(body[k]) + k.length;
        data[k] = body[k];
    }
    if (bytes > MAX_USER) throw new HttpErr(413, 'حجم اطلاعات بیش از حد مجاز است');
    const rev = await mutate(async (d) => { const u = d.users[req.user.username]; u.data = data; u.rev = (u.rev || 0) + 1; u.updatedAt = Date.now(); return { rev: u.rev, plan: u.plan || null }; });
    res.json(rev);
}));

// ===== رتبه‌بندی دوستانه =====
const score = (u) => {
    const x = u.data || {};
    const study = Object.values(J(x.study, {})).reduce((a, b) => a + (+b || 0), 0);
    return Object.values(J(x.done, {})).filter(Boolean).length + J(x.habits, []).filter(Boolean).length * 3 +
        J(x.tasks, []).filter((t) => t && t.x).length * 5 + Math.floor(study / 15);
};
app.get('/api/leaderboard', auth, wrap(async (req, res) => {
    const list = Object.values((await load()).users).filter((u) => u.role === 'user' && !u.hideLb)
        .map((u) => ({ username: u.username, displayName: u.displayName, score: score(u) })).sort((a, b) => b.score - a.score).slice(0, 20);
    res.json({ list, hidden: !!req.user.hideLb });
}));
app.post('/api/leaderboard/hide', auth, wrap(async (req, res) => {
    await mutate(async (d) => { d.users[req.user.username].hideLb = !!req.body.hide; });
    res.json({ success: true });
}));

// ===== معلم (خانم زینب) =====
app.get('/api/teacher/students', auth, roles('teacher', 'admin'), wrap(async (req, res) => {
    const students = Object.values((await load()).users).filter((u) => u.role === 'user').map((u) => {
        const x = u.data || {}, tasks = J(x.tasks, []);
        return { username: u.username, displayName: u.displayName, score: score(u), habits: J(x.habits, []).filter(Boolean).length,
            tasks: tasks.length, done: tasks.filter((t) => t && t.x).length,
            study: Object.values(J(x.study, {})).reduce((a, b) => a + (+b || 0), 0), updatedAt: u.updatedAt || null };
    });
    res.json({ students });
}));
app.post('/api/teacher/note', auth, roles('teacher', 'admin'), wrap(async (req, res) => {
    const username = str(req.body.username, 30).toLowerCase(), text = str(req.body.text, 200);
    await mutate(async (d) => {
        const u = d.users[username];
        if (!u || u.role !== 'user') throw new HttpErr(404, 'دانش‌آموز پیدا نشد');
        if (text) u.note = { text, by: req.user.displayName, at: Date.now() }; else delete u.note;
    });
    res.json({ success: true });
}));

// برنامه‌ی روزانه‌ی هر دانش‌آموز را فقط معلم/مدیر تعیین می‌کند
const okStr = (x, n) => typeof x === 'string' && x.length <= n && !/[<>]/.test(x);
const validPlan = (p) => Array.isArray(p) && p.length === 7 && p.every((d) => Array.isArray(d) && d.length <= 30 &&
    d.every((i) => Array.isArray(i) && i.length === 3 && okStr(i[0], 8) && okStr(i[1], 30) && okStr(i[2], 60)));
app.get('/api/teacher/plan', auth, roles('teacher', 'admin'), wrap(async (req, res) => {
    const u = (await load()).users[str(req.query.username, 30).toLowerCase()];
    if (!u || u.role !== 'user') throw new HttpErr(404, 'دانش‌آموز پیدا نشد');
    res.json({ plan: u.plan ? J(u.plan, null) : null });
}));
app.post('/api/teacher/plan', auth, roles('teacher', 'admin'), wrap(async (req, res) => {
    const username = str(req.body.username, 30).toLowerCase(), plan = req.body.plan;
    if (plan !== null && !validPlan(plan)) throw new HttpErr(400, 'برنامه نامعتبر است (۷ روز، هر روز حداکثر ۳۰ مورد، بدون < و >)');
    await mutate(async (d) => {
        const u = d.users[username];
        if (!u || u.role !== 'user') throw new HttpErr(404, 'دانش‌آموز پیدا نشد');
        if (plan === null) delete u.plan; else u.plan = JSON.stringify(plan);
        u.rev = (u.rev || 0) + 1;
    });
    res.json({ success: true });
}));

// ===== مدیر =====
const locked = (u) => u.username === ADMIN_USER || u.username === TEACHER_USER;
const target = (d, name) => { const u = d.users[str(name, 30).toLowerCase()]; if (!u) throw new HttpErr(404, 'کاربر پیدا نشد'); return u; };
app.get('/api/admin/users', auth, roles('admin'), wrap(async (req, res) => {
    res.json({ users: Object.values((await load()).users).map((u) => ({ username: u.username, displayName: u.displayName, role: u.role, locked: locked(u), self: u.username === req.user.username })) });
}));
app.post('/api/admin/users/:u/reset', auth, roles('admin'), wrap(async (req, res) => {
    const tempPassword = crypto.randomBytes(5).toString('hex'), passHash = await hash(tempPassword);
    await mutate(async (d) => { const u = target(d, req.params.u); if (u.username === req.user.username) throw new HttpErr(400, 'رمز خودت را از «تغییر رمز» عوض کن'); u.passHash = passHash; u.tv = (u.tv || 0) + 1; });
    res.json({ tempPassword });
}));
app.post('/api/admin/users/:u/role', auth, roles('admin'), wrap(async (req, res) => {
    const r = req.body.role;
    if (!['user', 'teacher'].includes(r)) throw new HttpErr(400, 'نقش نامعتبر است');
    await mutate(async (d) => { const u = target(d, req.params.u); if (locked(u)) throw new HttpErr(403, 'این حساب قابل تغییر نیست'); u.role = r; u.tv = (u.tv || 0) + 1; });
    res.json({ success: true });
}));
app.delete('/api/admin/users/:u', auth, roles('admin'), wrap(async (req, res) => {
    await mutate(async (d) => { const u = target(d, req.params.u); if (locked(u)) throw new HttpErr(403, 'این حساب قابل حذف نیست'); delete d.users[u.username]; });
    res.json({ success: true });
}));
app.post('/api/admin/theme', auth, roles('admin'), wrap(async (req, res) => {
    const t = str(req.body.theme, 20);
    if (!THEMES.includes(t)) throw new HttpErr(400, 'تم نامعتبر است');
    await mutate(async (d) => { d.theme = t; });
    res.json({ theme: t });
}));

app.use(express.static(path.join(__dirname, 'public')));
app.use((err, req, res, next) => {
    if (!err.status) console.error(err.message);
    res.status(err.status || 500).json({ error: err.status ? err.message : 'خطای سرور' });
});

app.listen(PORT, () => {
    console.log(`برنامه هفتگی روی پورت ${PORT} اجرا شد`);
    if (!CONFIGURED) console.warn('هشدار: JSONBIN_BIN_ID / JSONBIN_API_KEY ست نشده؛ ورود و ذخیره‌ی ابری غیرفعال است و برنامه فقط روی همین دستگاه کار می‌کند.');
    else load().catch((e) => console.error('خطای اتصال به JSONBin:', e.message));
});
