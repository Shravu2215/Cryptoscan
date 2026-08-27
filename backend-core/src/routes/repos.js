const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { requireAuth } = require('../middleware/auth');
const prisma = require('../utils/prismaClient');

const router = express.Router();

const UPLOAD_DIR = path.join(__dirname, '../../uploads');
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const unique = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    cb(null, `${unique}-${file.originalname}`);
  },
});

const maxSizeMb = Number(process.env.MAX_UPLOAD_SIZE_MB || 50);

const upload = multer({
  storage,
  limits: { fileSize: maxSizeMb * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    // Accept zip uploads of repos. Extend this list if scanner needs more.
    const allowed = ['.zip'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (!allowed.includes(ext)) {
      return cb(new Error(`Only ${allowed.join(', ')} files are allowed`));
    }
    cb(null, true);
  },
});

// POST /repos/upload
router.post('/upload', requireAuth, upload.single('repo'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded (field name must be "repo")' });
    }

    const repo = await prisma.repo.create({
      data: {
        name: req.body.name || req.file.originalname,
        filePath: req.file.path,
        uploadedBy: req.user.id,
      },
    });

    return res.status(201).json({
      id: repo.id,
      name: repo.name,
      createdAt: repo.createdAt,
    });
  } catch (err) {
    console.error('Repo upload error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
