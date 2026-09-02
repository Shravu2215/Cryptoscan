const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const AdmZip = require('adm-zip');
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
const maxExtractedMb = Number(process.env.MAX_EXTRACTED_SIZE_MB || 250);

function parseGitHubUrl(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return null;
  }

  if (parsed.protocol !== 'https:' || parsed.hostname.toLowerCase() !== 'github.com') {
    return null;
  }

  const parts = parsed.pathname.split('/').filter(Boolean);
  if (parts.length !== 2) return null;

  const owner = parts[0];
  const repo = parts[1].replace(/\.git$/, '');
  if (!/^[A-Za-z0-9_.-]+$/.test(owner) || !/^[A-Za-z0-9_.-]+$/.test(repo)) {
    return null;
  }

  return { owner, repo };
}

function extractArchive(buffer, destination) {
  const archive = new AdmZip(buffer);
  const entries = archive.getEntries();
  if (entries.length > 10000) throw new Error('Repository archive contains too many files');

  const destinationRoot = path.resolve(destination) + path.sep;
  let extractedBytes = 0;
  for (const entry of entries) {
    const target = path.resolve(destination, entry.entryName);
    if (!target.startsWith(destinationRoot)) {
      throw new Error('Repository archive contains an unsafe path');
    }
    if (!entry.isDirectory) {
      extractedBytes += entry.header.size;
      if (extractedBytes > maxExtractedMb * 1024 * 1024) {
        throw new Error(`Repository archive exceeds the ${maxExtractedMb} MB extracted-size limit`);
      }
    }
  }

  archive.extractAllTo(destination, true);
  const children = fs.readdirSync(destination, { withFileTypes: true });
  const root = children.length === 1 && children[0].isDirectory()
    ? path.join(destination, children[0].name)
    : destination;
  return root;
}

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

// POST /repos/github
// Imports a public GitHub repository archive without executing repository code.
router.post('/github', requireAuth, async (req, res) => {
  let extractDir;
  try {
    const github = parseGitHubUrl(req.body?.url);
    if (!github) {
      return res.status(400).json({ error: 'Use a public GitHub repository URL such as https://github.com/owner/repository' });
    }

    const headers = { 'User-Agent': 'CryptoScan/1.0', Accept: 'application/vnd.github+json' };
    const metadataResponse = await fetch(`https://api.github.com/repos/${github.owner}/${github.repo}`, { headers });
    if (!metadataResponse.ok) {
      return res.status(metadataResponse.status === 404 ? 404 : 502).json({ error: 'GitHub repository could not be found or accessed' });
    }
    const metadata = await metadataResponse.json();
    if (metadata.archived) {
      return res.status(400).json({ error: 'Archived GitHub repositories cannot be scanned' });
    }

    const branch = encodeURIComponent(metadata.default_branch || 'main');
    const archiveUrl = `https://codeload.github.com/${github.owner}/${github.repo}/zip/refs/heads/${branch}`;
    const archiveResponse = await fetch(archiveUrl, { headers });
    if (!archiveResponse.ok) {
      return res.status(502).json({ error: 'GitHub repository archive could not be downloaded' });
    }
    const contentLength = Number(archiveResponse.headers.get('content-length') || 0);
    if (contentLength > maxSizeMb * 1024 * 1024) {
      return res.status(413).json({ error: `Repository archive exceeds the ${maxSizeMb} MB download limit` });
    }

    const archiveBuffer = Buffer.from(await archiveResponse.arrayBuffer());
    if (archiveBuffer.length > maxSizeMb * 1024 * 1024) {
      return res.status(413).json({ error: `Repository archive exceeds the ${maxSizeMb} MB download limit` });
    }

    extractDir = fs.mkdtempSync(path.join(UPLOAD_DIR, 'github-'));
    const repositoryPath = extractArchive(archiveBuffer, extractDir);
    const repo = await prisma.repo.create({
      data: {
        name: metadata.full_name || `${github.owner}/${github.repo}`,
        filePath: repositoryPath,
        uploadedBy: req.user.id,
      },
    });

    return res.status(201).json({ id: repo.id, name: repo.name, createdAt: repo.createdAt, source: 'github' });
  } catch (err) {
    if (extractDir) fs.rmSync(extractDir, { recursive: true, force: true });
    console.error('GitHub import error:', err);
    return res.status(502).json({ error: err.message || 'GitHub repository import failed' });
  }
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
