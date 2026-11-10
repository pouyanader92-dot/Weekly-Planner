const express = require('express');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');

const PORT = process.env.PORT || 3000;
const BIN_ID = process.env.JSONBIN_BIN_ID;
const API_KEY = process.env.JSONBIN_API_KEY;
const ACCESS_KEY = process.env.ACCESS_KEY;
const BASE = process.env.JSONBIN_BASE || 'https://api.jsonbin.io/v3/b';
const DB_URL = `${BASE}/${BIN_ID}`;

// فقط همین کلیدها ذخیره می‌شوند (همان کلیدهای localStorage صفحه)
const KEYS = ['done', 'plan', 'habits', 'hist', 'exams', 'theme', 'study', 'tasks', 'water', 'sleep', 'mood', 'jr', 'goal'];
const MAX_BYTES = 80 * 1024; // سقف رایگان JSONBin حدود ۱۰۰ کیلوبایت است

app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'same-origin');
    next();
});
app.use(express.json({ limit: '200kb' }));

app.get('/healthz', (req, res) => res.type('text').send('ok'));

// ===== دسترسی: کلید ACCESS_KEY + محدودیت تلاش اشتباه =====
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
const fails = new Map();
function auth(req, res, next) {
    if (!BIN_ID || !API_KEY || !ACCESS_KEY)
        return res.status(503).json({ error: 'سرور هنوز تنظیم نشده (JSONBIN_BIN_ID, JSONBIN_API_KEY, ACCESS_KEY)' });
    const ip = req.ip;
    let f = fails.get(ip);
    if (f && f.until && f.until <= Date.now()) { fails.delete(ip); f = null; }
    if (f && f.until) return res.status(429).json({ error: 'تلاش‌های زیاد؛ چند دقیقه بعد دوباره امتحان کن' });
    if (!crypto.timingSafeEqual(sha(req.get('X-Access-Key') || ''), sha(ACCESS_KEY))) {
        if (fails.size > 1000) fails.clear();
        const n = ((f && f.n) || 0) + 1;
        fails.set(ip, { n, until: n >= 10 ? Date.now() + 10 * 60 * 1000 : 0 });
        return res.status(401).json({ error: 'کلید دسترسی نادرست است' });
    }
    fails.delete(ip);
    next();
}

// ===== ذخیره‌سازی روی JSONBin (با کش حافظه برای کم‌کردن درخواست‌ها) =====
let cache = null, chain = Promise.resolve();
async function load() {
    if (cache) return cache;
    const r = await fetch(DB_URL + '/latest', { headers: { 'X-Master-Key': API_KEY } });
    if (!r.ok) throw new Error('JSONBin GET ' + r.status);
    const rec = (await r.json()).record || {};
    cache = { rev: Number(rec.rev) || 0, updatedAt: rec.updatedAt || null, data: rec.data && typeof rec.data === 'object' ? rec.data : {} };
    return cache;
}
async function save(next) {
    const r = await fetch(DB_URL, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'X-Master-Key': API_KEY },
        body: JSON.stringify(next)
    });
    if (!r.ok) throw new Error('JSONBin PUT ' + r.status);
    cache = next;
}

app.get('/api/data', auth, async (req, res, next) => {
    try {
        const d = await load();
        res.set('Cache-Control', 'no-store').json({ rev: d.rev, data: d.data });
    } catch (e) { next(e); }
});

app.put('/api/data', auth, (req, res, next) => {
    const body = req.body && req.body.data;
    if (!body || typeof body !== 'object' || Array.isArray(body)) return res.status(400).json({ error: 'داده نامعتبر است' });
    const data = {};
    let bytes = 0;
    for (const k of KEYS) {
        if (body[k] == null) continue;
        if (typeof body[k] !== 'string') return res.status(400).json({ error: 'داده نامعتبر است' });
        bytes += Buffer.byteLength(body[k]) + k.length;
        data[k] = body[k];
    }
    if (bytes > MAX_BYTES) return res.status(413).json({ error: 'حجم اطلاعات بیش از حد مجاز است' });
    const job = chain.then(async () => {
        const cur = await load();
        const nxt = { rev: cur.rev + 1, updatedAt: new Date().toISOString(), data };
        await save(nxt);
        return nxt.rev;
    });
    chain = job.catch(() => {});
    job.then((rev) => res.json({ rev }), next);
});

app.use(express.static(path.join(__dirname, 'public')));

app.use((err, req, res, next) => {
    console.error(err.message);
    res.status(500).json({ error: 'خطای سرور یا اتصال به JSONBin' });
});

app.listen(PORT, () => {
    console.log(`برنامه هفتگی روی پورت ${PORT} اجرا شد`);
    if (!BIN_ID || !API_KEY || !ACCESS_KEY) console.warn('هشدار: JSONBIN_BIN_ID / JSONBIN_API_KEY / ACCESS_KEY ست نشده؛ ذخیره‌ی ابری غیرفعال است و برنامه فقط روی هر دستگاه جدا کار می‌کند.');
});
