const path = require('path');
const crypto = require('crypto');

require('dotenv').config();

const { S3_ACCESS_KEY, S3_SECRET_KEY } = process.env;

const S3_CONFIGURED = !!(S3_ACCESS_KEY && S3_SECRET_KEY);
if (!S3_CONFIGURED) {
  console.error(
    'WARNING: S3 credentials are missing.\n' +
    'Create a .env file (see .env.example) and set S3_ACCESS_KEY and S3_SECRET_KEY.'
  );
}

const express = require('express');
const multer = require('multer');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const rateLimit = require('express-rate-limit');

// ---------------------------------------------------------------------------
// S3 client (initialised only when credentials are available)
// ---------------------------------------------------------------------------
const s3 = S3_CONFIGURED
  ? new S3Client({
      endpoint: 'https://s3.twcstorage.ru',
      region: 'ru-1',
      credentials: {
        accessKeyId: S3_ACCESS_KEY,
        secretAccessKey: S3_SECRET_KEY,
      },
    })
  : null;

const BUCKET = 'my-data';
const BUCKET_URL = `https://${BUCKET}.s3.twcstorage.ru`;

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------
const AUTH_PASSWORD = 'neodark';

// Rate limiting for auth attempts
const authLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 10, // 10 attempts per window
  message: { error: 'Слишком много попыток. Подождите минуту.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Auth middleware
function requireAuth(req, res, next) {
  const password = req.headers['x-password'];
  
  if (!password || password !== AUTH_PASSWORD) {
    return res.status(401).json({ error: 'Неверный пароль' });
  }
  
  next();
}

// ---------------------------------------------------------------------------
// Allowed formats
// ---------------------------------------------------------------------------
const ALLOWED_EXTENSIONS = new Set(['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg']);
const ALLOWED_MIMETYPES = new Set([
  'image/jpeg',
  'image/png',
  'image/gif',
  'image/webp',
  'image/svg+xml',
]);

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB

// ---------------------------------------------------------------------------
// Cyrillic-to-Latin transliteration map
// ---------------------------------------------------------------------------
const TRANSLIT_MAP = {
  'а': 'a',   'б': 'b',   'в': 'v',   'г': 'g',   'д': 'd',
  'е': 'e',   'ё': 'yo',  'ж': 'zh',  'з': 'z',   'и': 'i',
  'й': 'y',   'к': 'k',   'л': 'l',   'м': 'm',   'н': 'n',
  'о': 'o',   'п': 'p',   'р': 'r',   'с': 's',   'т': 't',
  'у': 'u',   'ф': 'f',   'х': 'kh',  'ц': 'ts',  'ч': 'ch',
  'ш': 'sh',  'щ': 'shch','ъ': '',    'ы': 'y',   'ь': '',
  'э': 'e',   'ю': 'yu',  'я': 'ya',
  'А': 'A',   'Б': 'B',   'В': 'V',   'Г': 'G',   'Д': 'D',
  'Е': 'E',   'Ё': 'Yo',  'Ж': 'Zh',  'З': 'Z',   'И': 'I',
  'Й': 'Y',   'К': 'K',   'Л': 'L',   'М': 'M',   'Н': 'N',
  'О': 'O',   'П': 'P',   'Р': 'R',   'С': 'S',   'Т': 'T',
  'У': 'U',   'Ф': 'F',   'Х': 'Kh',  'Ц': 'Ts',  'Ч': 'Ch',
  'Ш': 'Sh',  'Щ': 'Shch','Ъ': '',    'Ы': 'Y',   'Ь': '',
  'Э': 'E',   'Ю': 'Yu',  'Я': 'Ya',
};

function transliterate(str) {
  return str
    .split('')
    .map((ch) => (ch in TRANSLIT_MAP ? TRANSLIT_MAP[ch] : ch))
    .join('');
}

// ---------------------------------------------------------------------------
// Filename sanitiser
// ---------------------------------------------------------------------------
function sanitizeFilename(original) {
  const ext = path.extname(original).toLowerCase();          // .png
  const base = path.basename(original, path.extname(original)); // my file

  let clean = transliterate(base);
  clean = clean.replace(/\s+/g, '-');                        // spaces -> hyphens
  clean = clean.replace(/[^a-zA-Z0-9.\-]/g, '');            // remove specials
  clean = clean.replace(/-{2,}/g, '-');                      // collapse hyphens
  clean = clean.replace(/^-+|-+$/g, '');                     // trim hyphens

  if (!clean) clean = 'file';

  const suffix = crypto.randomBytes(3).toString('hex');      // 6 hex chars
  return `${clean}-${suffix}${ext}`;
}

// ---------------------------------------------------------------------------
// Multer setup
// ---------------------------------------------------------------------------
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_SIZE },
});

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------
const app = express();

// CORS
app.use((_req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (_req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// ---------------------------------------------------------------------------
// POST /api/upload
// ---------------------------------------------------------------------------
app.post('/api/upload', authLimiter, requireAuth, (req, res) => {
  if (!S3_CONFIGURED) {
    return res.status(500).json({ error: 'S3 credentials not configured.' });
  }

  const multi = upload.array('files', 10);

  multi(req, res, async (multerErr) => {
    // Handle multer-level errors
    if (multerErr) {
      if (multerErr.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ error: 'File too large. Maximum size is 10 MB.' });
      }
      if (multerErr.code === 'LIMIT_UNEXPECTED_FILE') {
        return res.status(400).json({ error: 'Too many files. Maximum is 10.' });
      }
      return res.status(400).json({ error: multerErr.message });
    }

    const files = req.files;
    if (!files || files.length === 0) {
      return res.status(400).json({ error: 'No files provided.' });
    }

    // Validate each file
    for (const file of files) {
      const ext = path.extname(file.originalname).toLowerCase().replace('.', '');
      if (!ALLOWED_EXTENSIONS.has(ext)) {
        return res.status(400).json({
          error: `Invalid file format: .${ext}. Allowed: jpg, jpeg, png, gif, webp, svg.`,
        });
      }
      if (!ALLOWED_MIMETYPES.has(file.mimetype)) {
        return res.status(400).json({
          error: `Invalid MIME type: ${file.mimetype}. Allowed: ${[...ALLOWED_MIMETYPES].join(', ')}.`,
        });
      }
    }

    // Upload to S3
    try {
      const results = [];

      for (const file of files) {
        const filename = sanitizeFilename(file.originalname);

        const command = new PutObjectCommand({
          Bucket: BUCKET,
          Key: filename,
          Body: file.buffer,
          ContentType: file.mimetype,
          ACL: 'public-read',
        });

        await s3.send(command);

        results.push({
          url: `${BUCKET_URL}/${filename}`,
          filename,
        });
      }

      return res.json({ files: results });
    } catch (err) {
      console.error('S3 upload error:', err);
      return res.status(500).json({ error: `S3 upload failed: ${err.message}` });
    }
  });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
const PORT = 3000;
if (!process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

module.exports = app;
