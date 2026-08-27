/**
 * CryptoScan Real-Time Scanner & IndexedDB Storage Engine
 */

const CryptoEngine = {
  STORAGE_KEY: 'CRYPTOSCAN_PLATFORM_DATA',
  DB_NAME: 'CryptoScanDB',
  STORE_NAME: 'uploads',

  // Open IndexedDB to store actual File / ArrayBuffer across page navigations
  openDB: function() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.DB_NAME, 1);
      request.onupgradeneeded = function(e) {
        const db = e.target.result;
        if (!db.objectStoreNames.contains('uploads')) {
          db.createObjectStore('uploads', { keyPath: 'id' });
        }
      };
      request.onsuccess = function(e) { resolve(e.target.result); };
      request.onerror = function(e) { reject(e); };
    });
  },

  storeUploadedFile: async function(file) {
    const db = await this.openDB();
    const arrayBuffer = await file.arrayBuffer();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('uploads', 'readwrite');
      const store = tx.objectStore('uploads');
      store.put({
        id: 'pending_file',
        name: file.name,
        size: file.size,
        data: arrayBuffer,
        timestamp: Date.now()
      });
      tx.oncomplete = () => resolve();
      tx.onerror = (e) => reject(e);
    });
  },

  getPendingFile: async function() {
    const db = await this.openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('uploads', 'readonly');
      const store = tx.objectStore('uploads');
      const req = store.get('pending_file');
      req.onsuccess = () => resolve(req.result);
      req.onerror = (e) => reject(e);
    });
  },

  getInitialState: function() {
    return {
      repositories: [],
      scans: [],
      activeScan: null,
      totalScans: 0,
      totalFindings: 0,
      criticalFindings: 0,
      quantumVulnerable: 0
    };
  },

  getData: function() {
    try {
      const raw = localStorage.getItem(this.STORAGE_KEY);
      if (!raw) return this.getInitialState();
      return JSON.parse(raw);
    } catch(e) {
      return this.getInitialState();
    }
  },

  saveData: function(data) {
    localStorage.setItem(this.STORAGE_KEY, JSON.stringify(data));
    window.dispatchEvent(new Event('cryptoscan_data_updated'));
  },

  clearAllData: function() {
    localStorage.removeItem(this.STORAGE_KEY);
    window.dispatchEvent(new Event('cryptoscan_data_updated'));
  },

  RULES: [
    {
      id: 'CRYPTO-RULE-RSA-SHORT',
      name: 'RSA Short Key Usage (< 2048-bit)',
      category: 'Asymmetric Key Length',
      severity: 'critical',
      quantum: 'yes',
      regex: /(?:RSA\.generate\(\s*(?:512|1024)|key_size\s*=\s*(?:512|1024)|generate_private_key\([^)]*1024)/i,
      remediation: 'Migrate to NIST ML-DSA or minimum RSA-3072 bit key.'
    },
    {
      id: 'CRYPTO-RULE-MD5-BROKEN',
      name: 'MD5 Cryptographically Broken Hash',
      category: 'Broken Hash Function',
      severity: 'critical',
      quantum: 'no',
      regex: /(?:createHash\(\s*['"]md5['"]|hashlib\.md5|MessageDigest\.getInstance\(\s*["']MD5["']|MD5_Init|crypto\.md5)/i,
      remediation: 'Replace MD5 with collision-resistant SHA-256 or SHA-3.'
    },
    {
      id: 'CRYPTO-RULE-SHA1-DEP',
      name: 'SHA-1 Deprecated Hash Function',
      category: 'Deprecated Hash',
      severity: 'high',
      quantum: 'no',
      regex: /(?:createHash\(\s*['"]sha1['"]|hashlib\.sha1|MessageDigest\.getInstance\(\s*["']SHA-?1["']|SHA1_Init)/i,
      remediation: 'Upgrade to SHA-256 or SHA-512.'
    },
    {
      id: 'CRYPTO-RULE-DES-WEAK',
      name: 'DES / 3DES Deprecated Cipher',
      category: 'Weak Block Cipher',
      severity: 'high',
      quantum: 'no',
      regex: /(?:des\.NewCipher|DES_ecb_encrypt|Cipher\.getInstance\(\s*["']DES|CryptoJS\.DES|TripleDES)/i,
      remediation: 'Migrate to AES-256-GCM.'
    },
    {
      id: 'CRYPTO-RULE-ECDSA-CLASSIC',
      name: 'Classical ECDSA / ECDH (Quantum-Vulnerable)',
      category: 'Post-Quantum Risk',
      severity: 'high',
      quantum: 'yes',
      regex: /(?:secp256k1|secp256r1|prime256v1|SECP256R1|crypto\.createECDH|EC_KEY_new_by_curve_name)/i,
      remediation: 'Implement NIST PQC hybrid key exchange (ML-KEM-768).'
    },
    {
      id: 'CRYPTO-RULE-AES-CBC-PADDING',
      name: 'AES in CBC Mode with PKCS#7 Padding',
      category: 'Padding Oracle Risk',
      severity: 'medium',
      quantum: 'no',
      regex: /(?:AES\/CBC\/PKCS5Padding|AES\/CBC\/PKCS7Padding|modes\.CBC|Cipher\.AES_CBC)/i,
      remediation: 'Switch to Authenticated Encryption (AES-GCM).'
    },
    {
      id: 'CRYPTO-ASSET-AES-GCM',
      name: 'AES-256-GCM Authenticated Encryption',
      category: 'Modern Symmetric Cipher',
      severity: 'info',
      quantum: 'safe',
      regex: /(?:AES-256-GCM|AES\/GCM\/NoPadding|modes\.GCM|aes-256-gcm)/i,
      remediation: 'Compliant with FIPS 140-3.'
    }
  ],

  processRealBackendFindings: function(repo, scanId, dbFindings) {
    const findings = dbFindings.map(f => ({
      id: f.id,
      title: f.algorithm + ' ' + (f.usage || ''),
      category: f.library || 'Unknown API',
      library: f.library || null,
      severity: f.severity.toLowerCase(),
      quantum: (f.quantumStatus || '').toLowerCase().includes('vulnerable') ? 'yes' : 'safe',
      file: f.filePath,
      line: f.lineNumber,
      snippet: f.description || '',
      remediation: f.recommendation || '',
      algorithm: f.algorithm,
      usage: f.usage,
      keySize: f.keySize,
      quantumStatus: f.quantumStatus
    }));

    const componentMap = {};
    for (const f of dbFindings) {
      const algo = f.algorithm || 'Unknown Component';
      if (!componentMap[algo]) {
        componentMap[algo] = {
          name: algo,
          operations: new Set(),
          libraries: new Set(),
          locations: [],
          keySizes: new Set(),
          quantumRisk: (f.quantumStatus || '').toLowerCase().includes('vulnerable') ? 'Vulnerable' : 'Quantum-Ready',
          severities: new Set(),
          recommendation: f.recommendation || ''
        };
      }
      
      const comp = componentMap[algo];
      if (f.usage) comp.operations.add(f.usage);
      if (f.library) comp.libraries.add(f.library);
      
      const locStr = f.filePath + ':' + (f.lineNumber || '?');
      comp.locations.push(locStr);
      
      if (f.keySize) comp.keySizes.add(f.keySize);
      comp.severities.add(f.severity ? f.severity.toUpperCase() : 'LOW');
    }

    const cbomAssets = Object.values(componentMap).map(c => ({
      name: c.name,
      operations: Array.from(c.operations),
      library: Array.from(c.libraries).join(', ') || 'Unknown',
      locations: c.locations,
      keySize: Array.from(c.keySizes).join(', ') || 'N/A',
      quantumRisk: c.quantumRisk,
      severity: Array.from(c.severities).includes('CRITICAL') ? 'Critical' : 
               Array.from(c.severities).includes('HIGH') ? 'High' : 
               Array.from(c.severities).includes('MEDIUM') ? 'Medium' : 'Low',
      recommendation: c.recommendation
    }));

    const cbomMetrics = {
      totalComponents: cbomAssets.length,
      totalUsages: dbFindings.length,
      quantumVulnerable: cbomAssets.filter(c => c.quantumRisk === 'Vulnerable').length,
      quantumReady: cbomAssets.filter(c => c.quantumRisk === 'Quantum-Ready').length,
      unknownPotential: cbomAssets.filter(c => c.name.toLowerCase().includes('unknown') || c.name.toLowerCase().includes('potential')).length,
      highRisk: cbomAssets.filter(c => c.severity === 'Critical' || c.severity === 'High').length
    };

    const criticalCount = findings.filter(f => f.severity === 'critical').length;
    const quantumCount = findings.filter(f => f.quantum === 'yes').length;

    const scanResult = {
      scanId: scanId,
      repoId: repo.id,
      repoName: repo.name,
      fileSize: 0,
      timestamp: new Date().toLocaleString(),
      durationSeconds: 1, // Optional: Calculate real duration
      filesDiscovered: findings.length, // Can't easily know total files without scanner returning it, fallback to finding count
      filesScanned: findings.length,
      assetsFound: cbomAssets.length,
      criticalCount: criticalCount,
      quantumCount: quantumCount,
      findings: findings,
      cbom: cbomAssets,
      cbomMetrics: cbomMetrics,
      status: 'complete'
    };

    const currentData = this.getData();
    const existingRepoIdx = currentData.repositories.findIndex(r => r.name === repo.name);
    const repoSummary = {
      id: scanResult.repoId,
      name: repo.name,
      size: 0,
      lastScan: 'Just now',
      status: 'completed',
      filesCount: 0,
      findingsCount: findings.length,
      criticalCount: criticalCount,
      quantumCount: quantumCount
    };

    if (existingRepoIdx >= 0) {
      currentData.repositories[existingRepoIdx] = repoSummary;
    } else {
      currentData.repositories.unshift(repoSummary);
    }

    currentData.scans.unshift(scanResult);
    currentData.activeScan = scanResult;
    
    currentData.totalScans = currentData.scans.length;
    currentData.totalFindings = currentData.scans.reduce((acc, s) => acc + s.findings.length, 0);
    currentData.criticalFindings = currentData.scans.reduce((acc, s) => acc + s.criticalCount, 0);
    currentData.quantumVulnerable = currentData.scans.reduce((acc, s) => acc + s.quantumCount, 0);

    this.saveData(currentData);
    return scanResult;
  }
};

// Attach Profile Dropdown Toggle
window.addEventListener('DOMContentLoaded', () => {
  const pBtn = document.getElementById('profile-btn');
  const pDrop = document.getElementById('profile-dropdown');
  if (pBtn && pDrop) {
    pBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      pDrop.classList.toggle('open');
    });
    document.addEventListener('click', (e) => {
      if (!pDrop.contains(e.target)) pDrop.classList.remove('open');
    });
  }

  // Also sync user data if available in localStorage
  try {
    const user = JSON.parse(localStorage.getItem('cs_user'));
    if (user) {
      const name = user.name || (user.email ? user.email.split('@')[0] : 'User');
      const email = user.email || '';
      const initial = name.charAt(0).toUpperCase();

      const pdInitials = document.getElementById('pd-initials');
      if (pdInitials) pdInitials.textContent = initial;

      const pdName = document.getElementById('pd-name');
      if (pdName) pdName.textContent = name;

      const pdEmail = document.getElementById('pd-email');
      if (pdEmail) pdEmail.textContent = email;

      document.querySelectorAll('.profile-initials').forEach(el => el.textContent = initial);
    }
  } catch(e) {}
});


