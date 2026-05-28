/* ═══════════════════════════════════════════════════════════════
   CIPHERIX — Application JavaScript Principal
   Architecture modulaire Vanilla JS — v2.1
═══════════════════════════════════════════════════════════════ */

'use strict';

/* ────────────────────────────────────────────────────────────────
   MODULE : UTILITAIRES
──────────────────────────────────────────────────────────────── */
const Utils = {
  /** Génère des octets aléatoires via Web Crypto API */
  randomBytes(n) {
    const arr = new Uint8Array(n);
    window.crypto.getRandomValues(arr);
    return arr;
  },
  /** Génère un entier aléatoire [0, max[ via Web Crypto API */
  randomInt(max) {
    const arr = new Uint32Array(1);
    window.crypto.getRandomValues(arr);
    return arr[0] % max;
  },
  /** Sanitize texte pour innerHTML */
  sanitize(str) {
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
  },
  /** Copie texte dans le presse-papier */
  async copy(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      const el = document.createElement('textarea');
      el.value = text;
      el.style.position = 'fixed';
      el.style.opacity = '0';
      document.body.appendChild(el);
      el.select();
      document.execCommand('copy');
      document.body.removeChild(el);
      return true;
    }
  },
  /** Formate timestamp lisible */
  timeAgo(ts) {
    const d = Date.now() - ts;
    if (d < 60000) return 'À l\'instant';
    if (d < 3600000) return `Il y a ${Math.floor(d/60000)} min`;
    if (d < 86400000) return `Il y a ${Math.floor(d/3600000)} h`;
    return new Date(ts).toLocaleDateString('fr-FR');
  },
  /** Formate heure courante */
  clock() {
    return new Date().toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  },
  /** Génère un ID unique */
  uid() {
    return Date.now().toString(36) + Utils.randomInt(1000000).toString(36);
  },
  /** Convertit ArrayBuffer en hex */
  bufToHex(buf) {
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  },
  /** Convertit ArrayBuffer en base64 */
  bufToB64(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
  },
  /** Convertit base64 en ArrayBuffer */
  b64ToBuf(b64) {
    const bin = atob(b64);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr.buffer;
  },
  /** Encode string en Uint8Array */
  encode(str) { return new TextEncoder().encode(str); },
  /** Décode Uint8Array en string */
  decode(buf) { return new TextDecoder().decode(buf); },
};

/* ────────────────────────────────────────────────────────────────
   MODULE : STORAGE SÉCURISÉ
──────────────────────────────────────────────────────────────── */
const Storage = {
  get(key, fallback = null) {
    try {
      const val = localStorage.getItem('cipherix_' + key);
      return val ? JSON.parse(val) : fallback;
    } catch { return fallback; }
  },
  set(key, value) {
    try {
      localStorage.setItem('cipherix_' + key, JSON.stringify(value));
      return true;
    } catch { return false; }
  },
  remove(key) {
    localStorage.removeItem('cipherix_' + key);
  },
  increment(key) {
    const v = this.get(key, 0);
    this.set(key, v + 1);
    return v + 1;
  },
};

/* ────────────────────────────────────────────────────────────────
   MODULE : CRYPTOGRAPHIE (Web Crypto API)
──────────────────────────────────────────────────────────────── */
const Crypto = {
  /** Dérive une clé AES-256-GCM depuis une passphrase */
  async deriveKey(passphrase, salt) {
    const rawKey = await window.crypto.subtle.importKey(
      'raw', Utils.encode(passphrase), 'PBKDF2', false, ['deriveKey']
    );
    return window.crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
      rawKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  },
  /** Chiffre un texte avec AES-256-GCM */
  async encryptAES(plaintext, passphrase) {
    const salt = Utils.randomBytes(16);
    const iv = Utils.randomBytes(12);
    const key = await this.deriveKey(passphrase, salt);
    const enc = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      Utils.encode(plaintext)
    );
    const payload = new Uint8Array(salt.byteLength + iv.byteLength + enc.byteLength);
    payload.set(salt, 0);
    payload.set(iv, 16);
    payload.set(new Uint8Array(enc), 28);
    return Utils.bufToB64(payload.buffer);
  },
  /** Déchiffre un texte AES-256-GCM */
  async decryptAES(cipherB64, passphrase) {
    const data = new Uint8Array(Utils.b64ToBuf(cipherB64));
    const salt = data.slice(0, 16);
    const iv = data.slice(16, 28);
    const cipher = data.slice(28);
    const key = await this.deriveKey(passphrase, salt);
    const dec = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      cipher
    );
    return Utils.decode(dec);
  },
  /** Hash SHA-256 */
  async sha256(text) {
    const hash = await window.crypto.subtle.digest('SHA-256', Utils.encode(text));
    return Utils.bufToHex(hash);
  },
  /** Chiffrement/déchiffrement César */
  caesar(text, shift, decrypt = false) {
    const s = decrypt ? (26 - shift) % 26 : shift;
    return text.replace(/[a-zA-Z]/g, c => {
      const base = c < 'a' ? 65 : 97;
      return String.fromCharCode(((c.charCodeAt(0) - base + s) % 26) + base);
    });
  },
  /** ROT13 */
  rot13(text) { return this.caesar(text, 13); },
};

/* ────────────────────────────────────────────────────────────────
   MODULE : TOAST NOTIFICATIONS
──────────────────────────────────────────────────────────────── */
const Toast = {
  container: null,
  init() { this.container = document.getElementById('toastContainer'); },
  show(message, type = 'info', duration = 3200) {
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.innerHTML = `<span class="toast-dot"></span><span>${Utils.sanitize(message)}</span>`;
    this.container.appendChild(el);
    setTimeout(() => {
      el.classList.add('out');
      setTimeout(() => el.remove(), 320);
    }, duration);
  },
  success(msg) { this.show(msg, 'success'); },
  error(msg)   { this.show(msg, 'error'); },
  info(msg)    { this.show(msg, 'info'); },
};

/* ────────────────────────────────────────────────────────────────
   MODULE : ACTIVITÉ
──────────────────────────────────────────────────────────────── */
const Activity = {
  MAX: 20,
  log(message) {
    const list = Storage.get('activity', []);
    list.unshift({ message, ts: Date.now() });
    Storage.set('activity', list.slice(0, this.MAX));
    Dashboard.refreshActivity();
  },
};

/* ────────────────────────────────────────────────────────────────
   MODULE : ANALYSE DE FORCE
──────────────────────────────────────────────────────────────── */
const StrengthAnalyzer = {
  COMMON: ['password','123456','qwerty','azerty','admin','letmein','welcome','monkey','dragon','master','sunshine','princess','abc123','iloveyou','111111','000000','login','pass','test','secret'],
  SEQUENCES: ['abcdefghijklmnopqrstuvwxyz','0123456789','qwertyuiop','asdfghjkl','zxcvbnm'],

  analyze(pw) {
    if (!pw) return { score: 0, level: 'Vide', color: '#4a5270', feedback: [], bruteforce: '—', entropy: 0, keyspace: 1, criteria: [] };

    let score = 0;
    const feedback = [];
    const criteria = [];

    // Longueur
    const len = pw.length;
    if (len >= 8)  { score += 10; criteria.push({ text: '8+ caractères', pass: true }); }
    else           { criteria.push({ text: '8+ caractères', pass: false }); feedback.push({ type: 'danger', msg: 'Le mot de passe est trop court (minimum 8 caractères).' }); }
    if (len >= 12) { score += 10; criteria.push({ text: '12+ caractères', pass: true }); }
    else           { criteria.push({ text: '12+ caractères', pass: false }); }
    if (len >= 16) { score += 10; criteria.push({ text: '16+ caractères', pass: true }); }
    else           { criteria.push({ text: '16+ caractères', pass: false }); if (len >= 8) feedback.push({ type: 'warning', msg: 'Allonger à 16+ caractères augmente significativement la sécurité.' }); }

    // Charset
    const hasUpper = /[A-Z]/.test(pw);
    const hasLower = /[a-z]/.test(pw);
    const hasNum   = /[0-9]/.test(pw);
    const hasSym   = /[^a-zA-Z0-9]/.test(pw);

    if (hasUpper) { score += 10; criteria.push({ text: 'Majuscules', pass: true }); }
    else          { criteria.push({ text: 'Majuscules', pass: false }); feedback.push({ type: 'warning', msg: 'Ajoutez des majuscules (A-Z).' }); }
    if (hasLower) { score += 10; criteria.push({ text: 'Minuscules', pass: true }); }
    else          { criteria.push({ text: 'Minuscules', pass: false }); }
    if (hasNum)   { score += 10; criteria.push({ text: 'Chiffres', pass: true }); }
    else          { criteria.push({ text: 'Chiffres', pass: false }); feedback.push({ type: 'warning', msg: 'Ajoutez des chiffres (0-9).' }); }
    if (hasSym)   { score += 15; criteria.push({ text: 'Symboles', pass: true }); }
    else          { criteria.push({ text: 'Symboles', pass: false }); feedback.push({ type: 'warning', msg: 'Ajoutez des caractères spéciaux (!@#$…).' }); }

    // Patterns
    const lc = pw.toLowerCase();
    const isCommon = this.COMMON.some(w => lc.includes(w));
    if (isCommon) { score -= 20; feedback.push({ type: 'danger', msg: 'Contient un mot de passe courant très vulnérable.' }); }
    else { score += 5; feedback.push({ type: 'success', msg: 'Pas de mot de passe commun détecté.' }); }

    // Répétitions
    const reps = pw.match(/(.)\1{2,}/g);
    if (reps) { score -= 10; feedback.push({ type: 'danger', msg: `Répétitions détectées : "${Utils.sanitize(reps[0])}"` }); }
    else { score += 5; feedback.push({ type: 'success', msg: 'Aucune répétition de caractère détectée.' }); }

    // Suites
    let seqFound = false;
    for (const seq of this.SEQUENCES) {
      for (let i = 0; i < seq.length - 2; i++) {
        if (lc.includes(seq.slice(i, i + 3))) { seqFound = true; break; }
      }
      if (seqFound) break;
    }
    if (seqFound) { score -= 10; feedback.push({ type: 'danger', msg: 'Séquence logique détectée (ex: abc, 123, qwerty).' }); }
    else { score += 5; feedback.push({ type: 'success', msg: 'Aucune séquence logique détectée.' }); }

    // Unicité
    const uniqueChars = new Set(pw).size;
    const uniqueRatio = uniqueChars / len;
    if (uniqueRatio > 0.7) { score += 5; feedback.push({ type: 'success', msg: 'Bonne diversité de caractères.' }); }
    else { feedback.push({ type: 'warning', msg: 'Trop de caractères répétés. Augmentez la diversité.' }); }

    // Calcul entropie et espace de clés
    let charset = 0;
    if (hasLower) charset += 26;
    if (hasUpper) charset += 26;
    if (hasNum)   charset += 10;
    if (hasSym)   charset += 32;
    const keyspace = Math.pow(charset || 1, len);
    const entropy = Math.log2(keyspace);

    score = Math.max(0, Math.min(100, score));

    // Bruteforce (10 milliards/sec)
    const seconds = keyspace / 1e10;
    const bruteforce = this.formatTime(seconds);

    let level, color;
    if (score < 25)      { level = 'Très faible'; color = '#ff3d5a'; }
    else if (score < 45) { level = 'Faible';       color = '#ff7043'; }
    else if (score < 65) { level = 'Moyen';        color = '#ffd600'; }
    else if (score < 85) { level = 'Fort';         color = '#00ff88'; }
    else                  { level = 'Extrême';      color = '#00ffe7'; }

    return { score, level, color, feedback, bruteforce, entropy: entropy.toFixed(1), keyspace, charset, criteria, seconds, len };
  },

  formatTime(seconds) {
    if (!isFinite(seconds) || seconds > 1e30) return '> 1 quintillion d\'années';
    if (seconds < 1e-6) return 'Instantané';
    if (seconds < 1) return `${(seconds * 1000).toFixed(1)} ms`;
    if (seconds < 60) return `${seconds.toFixed(1)} s`;
    if (seconds < 3600) return `${(seconds/60).toFixed(1)} min`;
    if (seconds < 86400) return `${(seconds/3600).toFixed(1)} h`;
    if (seconds < 31536000) return `${(seconds/86400).toFixed(1)} jours`;
    if (seconds < 3.15e9) return `${(seconds/31536000).toFixed(1)} ans`;
    if (seconds < 3.15e12) return `${(seconds/3.15e9).toFixed(1)} millénaires`;
    if (seconds < 3.15e15) return `${(seconds/3.15e12).toFixed(0)} millions d'années`;
    return `${(seconds/3.15e15).toFixed(0)} milliards d'années`;
  },
};

/* ────────────────────────────────────────────────────────────────
   MODULE : GÉNÉRATEUR DE MOTS DE PASSE
──────────────────────────────────────────────────────────────── */
const Generator = {
  UPPER:   'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  LOWER:   'abcdefghijklmnopqrstuvwxyz',
  DIGITS:  '0123456789',
  SYMBOLS: '!@#$%^&*()-_=+[]{}|;:,.<>?',
  AMBIGUOUS: '0O1lI',

  SMART_SEPARATORS: ['!', '@', '#', '_', '.', '-', '$', '*'],
  SMART_NUMBERS: ['1', '2', '3', '4', '5', '9', '0'],
  LEET: { a:'4', e:'3', i:'1', o:'0', s:'5', t:'7', l:'1', g:'9', b:'8' },

  /** Génère un caractère aléatoire depuis un charset */
  pickChar(charset) {
    return charset[Utils.randomInt(charset.length)];
  },

  /** Génère mot de passe aléatoire */
  generateRandom(opts) {
    let charset = '';
    if (opts.upper) charset += this.UPPER;
    if (opts.lower) charset += this.LOWER;
    if (opts.numbers) charset += this.DIGITS;
    if (opts.symbols) charset += this.SYMBOLS;
    if (opts.excludeAmbiguous) charset = charset.split('').filter(c => !this.AMBIGUOUS.includes(c)).join('');
    if (opts.exclude) charset = charset.split('').filter(c => !opts.exclude.includes(c)).join('');
    if (!charset.length) charset = this.LOWER + this.DIGITS;

    const len = opts.length || 16;
    const mandatory = [];
    if (opts.upper && charset.includes(this.UPPER[0])) {
      const uc = this.UPPER.split('').filter(c => charset.includes(c)).join('');
      if (uc) mandatory.push(this.pickChar(uc));
    }
    if (opts.lower && charset.includes(this.LOWER[0])) {
      const lc = this.LOWER.split('').filter(c => charset.includes(c)).join('');
      if (lc) mandatory.push(this.pickChar(lc));
    }
    if (opts.numbers) {
      const nc = this.DIGITS.split('').filter(c => charset.includes(c)).join('');
      if (nc) mandatory.push(this.pickChar(nc));
    }
    if (opts.symbols) {
      const sc = this.SYMBOLS.split('').filter(c => charset.includes(c)).join('');
      if (sc) mandatory.push(this.pickChar(sc));
    }

    const pw = [];
    for (let i = 0; i < len - mandatory.length; i++) pw.push(this.pickChar(charset));
    pw.push(...mandatory);

    // Mélange sécurisé (Fisher-Yates)
    for (let i = pw.length - 1; i > 0; i--) {
      const j = Utils.randomInt(i + 1);
      [pw[i], pw[j]] = [pw[j], pw[i]];
    }
    return pw.join('');
  },

  /** Applique leetspeak partiel aléatoire */
  applyLeet(word) {
    return word.split('').map(c => {
      const l = this.LEET[c.toLowerCase()];
      return l && Utils.randomInt(2) ? l : c;
    }).join('');
  },

  /** Capitalise aléatoirement */
  capitalizeRandom(word) {
    if (!word) return word;
    return word.charAt(0).toUpperCase() + word.slice(1);
  },

  /** Génère des mots de passe intelligents basés sur les données utilisateur */
  generateSmart(opts) {
    const { keyword, date, city, extra } = opts;
    if (!keyword && !date && !city && !extra) {
      return [this.generateRandom({ upper: true, lower: true, numbers: true, symbols: true, length: 16 })];
    }

    const parts = [];
    if (keyword) parts.push(keyword.trim().replace(/\s+/g, ''));
    if (city)    parts.push(city.trim().replace(/\s+/g, ''));
    if (extra)   parts.push(extra.trim().replace(/\s+/g, ''));

    const results = [];

    // Pattern 1 : Leet + Séparateur + Date
    if (parts.length > 0) {
      const base = this.applyLeet(this.capitalizeRandom(parts[0]));
      const sep = this.SMART_SEPARATORS[Utils.randomInt(this.SMART_SEPARATORS.length)];
      const num = date ? date.slice(-4) : this.SMART_NUMBERS[Utils.randomInt(this.SMART_NUMBERS.length)] + Utils.randomInt(99).toString().padStart(2,'0');
      results.push(base + sep + num);
    }
    // Pattern 2 : Deux parties fusionnées
    if (parts.length >= 2) {
      const p1 = this.applyLeet(this.capitalizeRandom(parts[0]));
      const p2 = this.capitalizeRandom(parts[1]);
      const sep = this.SMART_SEPARATORS[Utils.randomInt(this.SMART_SEPARATORS.length)];
      const num = date ? date.slice(-2) : Utils.randomInt(99).toString().padStart(2,'0');
      results.push(p1 + sep + p2 + num);
    }
    // Pattern 3 : 3 parties
    if (parts.length >= 3) {
      const p1 = this.applyLeet(this.capitalizeRandom(parts[0]));
      const p2 = this.capitalizeRandom(parts[1]);
      const p3 = this.capitalizeRandom(parts[2]);
      results.push(p1 + '_' + p2 + '_' + p3 + (date ? date.slice(-4) : ''));
    }
    // Pattern 4 : Abréviation majuscule + chiffres
    if (parts.length > 0) {
      const abbr = parts.map(p => p.charAt(0).toUpperCase()).join('');
      const num = date || (Utils.randomInt(9000) + 1000).toString();
      const sym = this.SMART_SEPARATORS[Utils.randomInt(this.SMART_SEPARATORS.length)];
      results.push(abbr + sym + num + this.pickChar(this.SYMBOLS));
    }
    // Pattern 5 : Full aléatoire en supplément
    results.push(this.generateRandom({ upper: true, lower: true, numbers: true, symbols: true, length: 16 }));

    return results.slice(0, 5);
  },
};

/* ────────────────────────────────────────────────────────────────
   MODULE : VAULT SÉCURISÉ
──────────────────────────────────────────────────────────────── */
const Vault = {
  PIN_HASH_KEY: 'vault_pin_hash',
  DATA_KEY: 'vault_data',
  unlocked: false,
  entries: [],
  lockTimer: null,
  LOCK_TIMEOUT: 5 * 60 * 1000, // 5 minutes

  /** Hash un PIN avec SHA-256 */
  async hashPin(pin) {
    return Crypto.sha256('cipherix_pin_v1_' + pin);
  },

  /** Vérifie si un PIN est défini */
  hasPIN() {
    return !!Storage.get(this.PIN_HASH_KEY);
  },

  /** Définit le PIN */
  async setPin(pin) {
    const hash = await this.hashPin(pin);
    Storage.set(this.PIN_HASH_KEY, hash);
  },

  /** Vérifie un PIN */
  async verifyPin(pin) {
    const stored = Storage.get(this.PIN_HASH_KEY);
    if (!stored) return false;
    const hash = await this.hashPin(pin);
    return hash === stored;
  },

  /** Chiffre et sauvegarde les données */
  async saveEntries() {
    const json = JSON.stringify(this.entries);
    const passphrase = Storage.get(this.PIN_HASH_KEY, 'fallback');
    const enc = await Crypto.encryptAES(json, passphrase);
    Storage.set(this.DATA_KEY, enc);
  },

  /** Déchiffre et charge les données */
  async loadEntries() {
    const enc = Storage.get(this.DATA_KEY);
    if (!enc) { this.entries = []; return; }
    try {
      const passphrase = Storage.get(this.PIN_HASH_KEY, 'fallback');
      const json = await Crypto.decryptAES(enc, passphrase);
      this.entries = JSON.parse(json) || [];
    } catch {
      this.entries = [];
    }
  },

  /** Déverrouille le vault */
  async unlock(pin) {
    const ok = await this.verifyPin(pin);
    if (!ok) return false;
    this.unlocked = true;
    await this.loadEntries();
    this.resetLockTimer();
    return true;
  },

  /** Verrouille le vault */
  lock() {
    this.unlocked = false;
    this.entries = [];
    clearTimeout(this.lockTimer);
    VaultUI.showLockScreen();
  },

  /** Réinitialise le timer de verrouillage automatique */
  resetLockTimer() {
    clearTimeout(this.lockTimer);
    this.lockTimer = setTimeout(() => {
      this.lock();
      Toast.info('Vault verrouillé automatiquement (inactivité).');
    }, this.LOCK_TIMEOUT);
  },

  /** Ajoute ou modifie une entrée */
  async upsert(entry) {
    const idx = this.entries.findIndex(e => e.id === entry.id);
    if (idx >= 0) this.entries[idx] = entry;
    else this.entries.unshift(entry);
    await this.saveEntries();
    this.resetLockTimer();
  },

  /** Supprime une entrée */
  async remove(id) {
    this.entries = this.entries.filter(e => e.id !== id);
    await this.saveEntries();
  },

  /** Réinitialise entièrement le vault */
  reset() {
    Storage.remove(this.PIN_HASH_KEY);
    Storage.remove(this.DATA_KEY);
    this.entries = [];
    this.unlocked = false;
  },

  /** Filtre les entrées */
  filter(search = '', category = '') {
    return this.entries.filter(e => {
      const matchSearch = !search || [e.title, e.username, e.url].some(f => f && f.toLowerCase().includes(search.toLowerCase()));
      const matchCat = !category || e.category === category;
      return matchSearch && matchCat;
    });
  },
};

/* ────────────────────────────────────────────────────────────────
   MODULE : CONFIRM DIALOG
──────────────────────────────────────────────────────────────── */
const Confirm = {
  resolve: null,
  show(message, title = 'Confirmation') {
    return new Promise(res => {
      this.resolve = res;
      document.getElementById('confirmModalTitle').textContent = title;
      document.getElementById('confirmMessage').textContent = message;
      document.getElementById('confirmModal').classList.remove('hidden');
    });
  },
  hide() {
    document.getElementById('confirmModal').classList.add('hidden');
  },
  ok() {
    this.hide();
    if (this.resolve) { this.resolve(true); this.resolve = null; }
  },
  cancel() {
    this.hide();
    if (this.resolve) { this.resolve(false); this.resolve = null; }
  },
};

/* ────────────────────────────────────────────────────────────────
   MODULE : DASHBOARD
──────────────────────────────────────────────────────────────── */
const Dashboard = {
  TIPS: [
    'Utilisez un mot de passe unique pour chaque service.',
    'Activez l\'authentification à deux facteurs partout où c\'est possible.',
    'Un mot de passe fort doit comporter au moins 16 caractères.',
    'Ne réutilisez jamais un mot de passe entre différents sites.',
    'Changez vos mots de passe tous les 6 mois minimum.',
    'Évitez les informations personnelles (date de naissance, prénom…).',
    'Préférez une phrase secrète à un mot complexe : plus longue = plus sûre.',
    'Ne partagez jamais vos mots de passe, même avec des proches.',
    'Méfiez-vous des emails demandant vos identifiants (phishing).',
    'Vérifiez toujours que l\'URL commence par https:// avant de vous connecter.',
  ],

  refresh() {
    this.refreshStats();
    this.refreshActivity();
    this.refreshVaultHealth();
    this.renderTips();
  },

  refreshStats() {
    document.getElementById('dashVaultCount').textContent = Vault.entries.length || Storage.get('vault_count', 0);
    document.getElementById('dashGenCount').textContent = Storage.get('gen_count', 0);
    document.getElementById('dashCryptoCount').textContent = Storage.get('crypto_count', 0);

    const entries = Vault.unlocked ? Vault.entries : [];
    if (entries.length) {
      const scores = entries.map(e => StrengthAnalyzer.analyze(e.password).score);
      const avg = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
      document.getElementById('dashAvgScore').textContent = avg + '/100';
    } else {
      document.getElementById('dashAvgScore').textContent = '—';
    }
  },

  refreshActivity() {
    const list = Storage.get('activity', []);
    const el = document.getElementById('activityList');
    if (!list.length) {
      el.innerHTML = '<li class="activity-empty">Aucune activité enregistrée.</li>';
      return;
    }
    el.innerHTML = list.slice(0, 8).map(a =>
      `<li class="activity-item"><span class="activity-dot"></span><span>${Utils.sanitize(a.message)}</span><span class="activity-time">${Utils.timeAgo(a.ts)}</span></li>`
    ).join('');
  },

  refreshVaultHealth() {
    const arc = document.getElementById('healthArc');
    const scoreEl = document.getElementById('healthScore');
    if (!Vault.unlocked || !Vault.entries.length) {
      if (arc) arc.style.strokeDashoffset = '314';
      if (scoreEl) scoreEl.textContent = '—';
      document.getElementById('hl-strong').textContent = '0 forts';
      document.getElementById('hl-medium').textContent = '0 moyens';
      document.getElementById('hl-weak').textContent = '0 faibles';
      return;
    }
    const entries = Vault.entries;
    let strong = 0, medium = 0, weak = 0;
    entries.forEach(e => {
      const s = StrengthAnalyzer.analyze(e.password).score;
      if (s >= 70) strong++;
      else if (s >= 45) medium++;
      else weak++;
    });
    const avg = Math.round((entries.reduce((a, e) => a + StrengthAnalyzer.analyze(e.password).score, 0)) / entries.length);
    const offset = 314 - (314 * avg / 100);
    if (arc) arc.style.strokeDashoffset = offset;
    if (scoreEl) scoreEl.textContent = avg;
    document.getElementById('hl-strong').textContent = `${strong} fort${strong > 1 ? 's' : ''}`;
    document.getElementById('hl-medium').textContent = `${medium} moyen${medium > 1 ? 's' : ''}`;
    document.getElementById('hl-weak').textContent = `${weak} faible${weak > 1 ? 's' : ''}`;
  },

  renderTips() {
    const el = document.getElementById('tipsList');
    const shuffled = [...this.TIPS].sort(() => Utils.randomInt(3) - 1).slice(0, 4);
    el.innerHTML = shuffled.map(t => `<div class="tip-item">${Utils.sanitize(t)}</div>`).join('');
  },
};

/* ────────────────────────────────────────────────────────────────
   MODULE : UI VAULT
──────────────────────────────────────────────────────────────── */
const VaultUI = {
  pinBuffer: [],
  setPinBuffer: [],
  editingId: null,
  shownPasswords: new Set(),

  showLockScreen() {
    document.getElementById('vaultLockScreen').classList.remove('hidden');
    document.getElementById('vaultContent').classList.add('hidden');
    this.pinBuffer = [];
    this.renderPinDots('pin');
  },

  showContent() {
    document.getElementById('vaultLockScreen').classList.add('hidden');
    document.getElementById('vaultContent').classList.remove('hidden');
    this.render();
    Dashboard.refresh();
  },

  renderPinDots(prefix) {
    const buf = prefix === 'pin' ? this.pinBuffer : this.setPinBuffer;
    for (let i = 0; i < 4; i++) {
      const dot = document.getElementById(`${prefix === 'pin' ? 'pd' : 'spd'}${i}`);
      if (dot) dot.classList.toggle('filled', i < buf.length);
    }
  },

  async handlePinDigit(prefix, digit) {
    const buf = prefix === 'pin' ? this.pinBuffer : this.setPinBuffer;
    if (buf.length >= 4) return;
    buf.push(digit);
    this.renderPinDots(prefix);
    if (buf.length === 4 && prefix === 'pin') await this.submitPin();
    if (buf.length === 4 && prefix === 'set') await this.submitSetPin();
  },

  handlePinClear(prefix) {
    const buf = prefix === 'pin' ? this.pinBuffer : this.setPinBuffer;
    buf.pop();
    this.renderPinDots(prefix);
  },

  async submitPin() {
    const pin = this.pinBuffer.join('');
    const ok = await Vault.unlock(pin);
    if (ok) {
      document.getElementById('pinError').textContent = '';
      Toast.success('Vault déverrouillé.');
      Activity.log('Vault déverrouillé.');
      this.showContent();
    } else {
      document.getElementById('pinError').textContent = 'PIN incorrect. Réessayez.';
      this.pinBuffer = [];
      this.renderPinDots('pin');
      const dots = document.querySelectorAll('#pinDisplay .pin-dot');
      dots.forEach(d => { d.classList.add('error-dot'); setTimeout(() => d.classList.remove('error-dot'), 500); });
    }
  },

  async submitSetPin() {
    const pin = this.setPinBuffer.join('');
    await Vault.setPin(pin);
    document.getElementById('setPinModal').classList.add('hidden');
    this.setPinBuffer = [];
    Toast.success('PIN créé. Déverrouillez maintenant votre vault.');
    Activity.log('PIN Vault créé.');
    this.pinBuffer = [];
    this.renderPinDots('pin');
  },

  render() {
    const search = document.getElementById('vaultSearch').value;
    const category = document.getElementById('vaultCategoryFilter').value;
    const entries = Vault.filter(search, category);
    const grid = document.getElementById('vaultGrid');
    const empty = document.getElementById('vaultEmpty');
    Storage.set('vault_count', Vault.entries.length);

    if (!entries.length) {
      grid.innerHTML = '';
      empty.classList.remove('hidden');
      return;
    }
    empty.classList.add('hidden');

    grid.innerHTML = entries.map(e => {
      const analysis = StrengthAnalyzer.analyze(e.password);
      const shown = this.shownPasswords.has(e.id);
      const displayPw = shown ? Utils.sanitize(e.password) : '•'.repeat(Math.min(e.password.length, 20));
      const catClass = 'cat-' + (e.category || 'other');
      const icon = { web: '🌐', app: '💻', bank: '🏦', email: '✉️', other: '🔑' }[e.category] || '🔑';
      return `
        <div class="vault-card" data-id="${Utils.sanitize(e.id)}">
          <div class="vault-card-header">
            <div class="vault-card-favicon">${icon}</div>
            <div class="vault-card-title" title="${Utils.sanitize(e.title)}">${Utils.sanitize(e.title)}</div>
            <button class="vault-card-fav ${e.favorite ? 'active' : ''}" data-action="fav" data-id="${Utils.sanitize(e.id)}" aria-label="Favori" title="Favori">★</button>
          </div>
          ${e.username ? `<div class="vault-card-username">${Utils.sanitize(e.username)}</div>` : ''}
          <div class="vault-card-pw-row">
            <span class="vault-pw-text" id="vpw-${Utils.sanitize(e.id)}">${displayPw}</span>
            <button class="pw-action-btn" data-action="toggle-pw" data-id="${Utils.sanitize(e.id)}" aria-label="${shown ? 'Masquer' : 'Afficher'}">${shown ? '◉' : '◎'}</button>
          </div>
          <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap;">
            <span class="vault-category-badge ${catClass}">${e.category || 'autre'}</span>
            <span style="font-size:0.72rem;color:${analysis.color};margin-left:auto;">${analysis.level} (${analysis.score}/100)</span>
          </div>
          <div class="vault-card-actions">
            <button class="vault-action-btn" data-action="copy" data-id="${Utils.sanitize(e.id)}" aria-label="Copier">Copier</button>
            <button class="vault-action-btn" data-action="edit" data-id="${Utils.sanitize(e.id)}" aria-label="Modifier">Modifier</button>
            <button class="vault-action-btn delete" data-action="delete" data-id="${Utils.sanitize(e.id)}" aria-label="Supprimer">Supprimer</button>
          </div>
        </div>`;
    }).join('');
  },

  openAddModal() {
    this.editingId = null;
    document.getElementById('vaultModalTitle').textContent = 'Ajouter une entrée';
    document.getElementById('entryTitle').value = '';
    document.getElementById('entryUsername').value = '';
    document.getElementById('entryPassword').value = '';
    document.getElementById('entryUrl').value = '';
    document.getElementById('entryCategory').value = 'web';
    document.getElementById('entryNotes').value = '';
    document.getElementById('vaultModal').classList.remove('hidden');
    document.getElementById('entryTitle').focus();
  },

  openEditModal(id) {
    const entry = Vault.entries.find(e => e.id === id);
    if (!entry) return;
    this.editingId = id;
    document.getElementById('vaultModalTitle').textContent = 'Modifier l\'entrée';
    document.getElementById('entryTitle').value = entry.title;
    document.getElementById('entryUsername').value = entry.username || '';
    document.getElementById('entryPassword').value = entry.password;
    document.getElementById('entryUrl').value = entry.url || '';
    document.getElementById('entryCategory').value = entry.category || 'web';
    document.getElementById('entryNotes').value = entry.notes || '';
    document.getElementById('vaultModal').classList.remove('hidden');
  },

  closeModal() {
    document.getElementById('vaultModal').classList.add('hidden');
  },

  async saveEntry() {
    const title = document.getElementById('entryTitle').value.trim();
    const password = document.getElementById('entryPassword').value.trim();
    if (!title) { Toast.error('Le titre est requis.'); return; }
    if (!password) { Toast.error('Le mot de passe est requis.'); return; }

    const entry = {
      id: this.editingId || Utils.uid(),
      title,
      username: document.getElementById('entryUsername').value.trim(),
      password,
      url: document.getElementById('entryUrl').value.trim(),
      category: document.getElementById('entryCategory').value,
      notes: document.getElementById('entryNotes').value.trim(),
      favorite: this.editingId ? (Vault.entries.find(e => e.id === this.editingId)?.favorite || false) : false,
      createdAt: this.editingId ? (Vault.entries.find(e => e.id === this.editingId)?.createdAt || Date.now()) : Date.now(),
      updatedAt: Date.now(),
    };

    await Vault.upsert(entry);
    this.closeModal();
    this.render();
    Dashboard.refresh();
    Activity.log(this.editingId ? `Entrée modifiée : ${title}` : `Entrée ajoutée : ${title}`);
    Toast.success(this.editingId ? 'Entrée modifiée.' : 'Entrée ajoutée au vault.');
  },
};

/* ────────────────────────────────────────────────────────────────
   MODULE : SECURITY LAB
──────────────────────────────────────────────────────────────── */
const SecurityLab = {
  COMPARISON_EXAMPLES: [
    { label: 'abc', pw: 'abc' },
    { label: 'password', pw: 'password' },
    { label: 'Password1', pw: 'Password1' },
    { label: 'P4ssw0rd!', pw: 'P4ssw0rd!' },
    { label: 'Tr0ub4dour&3', pw: 'Tr0ub4dour&3' },
    { label: 'X#9kL!2mP$4nQ', pw: 'X#9kL!2mP$4nQ' },
  ],

  analyzeForLab(pw) {
    const a = StrengthAnalyzer.analyze(pw);
    document.getElementById('labEntropy').textContent = `${a.entropy} bits`;
    const entPct = Math.min(100, (a.entropy / 128) * 100);
    document.getElementById('labEntropyBar').style.width = entPct + '%';

    const ks = isFinite(a.keyspace) ? a.keyspace.toExponential(2) : '∞';
    document.getElementById('labKeyspace').textContent = ks;
    document.getElementById('labLength').textContent = `${a.len} chars`;
    const lenPct = Math.min(100, (a.len / 32) * 100);
    document.getElementById('labLengthBar').style.width = lenPct + '%';

    const charDesc = [];
    if (/[a-z]/.test(pw)) charDesc.push('a-z(26)');
    if (/[A-Z]/.test(pw)) charDesc.push('A-Z(26)');
    if (/[0-9]/.test(pw)) charDesc.push('0-9(10)');
    if (/[^a-zA-Z0-9]/.test(pw)) charDesc.push('sym(32)');
    document.getElementById('labCharset').textContent = charDesc.join(' + ') || '—';

    this.renderComparison(pw);
    this.scanPatterns(pw);
  },

  renderComparison(currentPw) {
    const all = [...this.COMPARISON_EXAMPLES.map(ex => ({ label: ex.label, pw: ex.pw })), { label: '[Votre mot de passe]', pw: currentPw }];
    const maxSeconds = Math.max(...all.map(e => StrengthAnalyzer.analyze(e.pw).seconds || 1));

    document.getElementById('comparisonTable').innerHTML = all.map(e => {
      const a = StrengthAnalyzer.analyze(e.pw);
      const pct = maxSeconds > 0 ? Math.min(100, ((a.seconds || 0.001) / maxSeconds) * 100) : 1;
      const isUser = e.label === '[Votre mot de passe]';
      return `<div class="comp-row">
        <span class="comp-label" style="color:${isUser ? 'var(--accent-cyan)' : ''}">${Utils.sanitize(e.label)}</span>
        <div class="comp-bar-wrap"><div class="comp-bar" style="width:${Math.max(1, pct)}%;background:${a.color}"></div></div>
        <span class="comp-time" style="color:${a.color};font-size:0.7rem">${a.bruteforce}</span>
      </div>`;
    }).join('');
  },

  scanPatterns(pw) {
    const patterns = [
      { label: 'Mots communs', detected: StrengthAnalyzer.COMMON.some(w => pw.toLowerCase().includes(w)), desc: 'Contient un mot de passe fréquent' },
      { label: 'Répétitions', detected: /(.)\1{2,}/.test(pw), desc: 'Caractère répété 3+ fois' },
      { label: 'Suite numérique', detected: /0123|1234|2345|3456|4567|5678|6789|9876|8765/.test(pw), desc: 'Suite de chiffres consécutifs' },
      { label: 'Suite alpha', detected: /abcd|bcde|cdef|defg|efgh|wxyz/i.test(pw), desc: 'Suite de lettres consécutives' },
      { label: 'Clavier QWERTY', detected: /qwer|wert|erty|asdf|sdfg|zxcv/i.test(pw), desc: 'Pattern de clavier QWERTY' },
      { label: 'Date potentielle', detected: /\d{4}/.test(pw) && /19\d{2}|20\d{2}/.test(pw), desc: 'Contient une année (19xx ou 20xx)' },
    ];

    const el = document.getElementById('patternsResult');
    el.innerHTML = patterns.map(p => `
      <div class="pattern-item ${p.detected ? 'detected' : 'clear'}">
        <span>${p.detected ? '⚠' : '✓'}</span>
        <span><strong>${Utils.sanitize(p.label)}</strong> — ${Utils.sanitize(p.desc)}</span>
      </div>`).join('');
  },

  async runBruteforceSim(pw) {
    const terminal = document.getElementById('terminalBody');
    const analysis = StrengthAnalyzer.analyze(pw);

    const lines = [
      { cls: 'term-prompt', text: `$ analyze "${pw.replace(/./g, '*')}"` },
      { cls: 'term-result', text: `> Longueur : ${pw.length} caractères` },
      { cls: 'term-result', text: `> Charset : ${analysis.charset} symboles possibles` },
      { cls: 'term-result', text: `> Entropie : ${analysis.entropy} bits` },
      { cls: 'term-result', text: `> Espace de clés : ${isFinite(analysis.keyspace) ? analysis.keyspace.toExponential(2) : '> 10^30'} combinaisons` },
      { cls: 'term-warn', text: `> Vitesse simulée : 10,000,000,000 tentatives/s` },
      { cls: 'term-result', text: `> Calcul en cours...` },
    ];

    for (const line of lines) {
      await new Promise(r => setTimeout(r, 120));
      const el = document.createElement('div');
      el.className = `term-line ${line.cls}`;
      el.textContent = line.text;
      terminal.appendChild(el);
      terminal.scrollTop = terminal.scrollHeight;
    }

    await new Promise(r => setTimeout(r, 600));

    const resultClass = analysis.score >= 70 ? 'term-success' : analysis.score >= 45 ? 'term-warn' : 'term-error';
    const result = document.createElement('div');
    result.className = `term-line ${resultClass}`;
    result.textContent = `> Temps estimé : ${analysis.bruteforce} — Niveau : ${analysis.level}`;
    terminal.appendChild(result);
    terminal.scrollTop = terminal.scrollHeight;

    this.analyzeForLab(pw);
  },
};

/* ────────────────────────────────────────────────────────────────
   MODULE : CRYPTOGRAPHIE UI
──────────────────────────────────────────────────────────────── */
const CryptoUI = {
  METHOD_DESCS: {
    aes:    'AES-256-GCM — Chiffrement symétrique de niveau militaire. Nécessite une passphrase secrète.',
    sha256: 'SHA-256 — Fonction de hachage cryptographique. Irréversible (empreinte numérique).',
    base64: 'Base64 — Encodage/décodage (pas un chiffrement). Transforme des données en texte ASCII.',
    caesar: 'Chiffre de César — Substitution par décalage alphabétique. Usage éducatif uniquement.',
    rot13:  'ROT-13 — Rotation de 13 positions. Variante du César, symétrique (chiffrer = déchiffrer).',
  },

  currentMethod: 'aes',
  history: [],

  init() {
    this.history = Storage.get('crypto_history', []);
    this.renderHistory();
    this.updateMethodUI();
  },

  updateMethodUI() {
    document.getElementById('methodDesc').textContent = this.METHOD_DESCS[this.currentMethod];
    const isAes = this.currentMethod === 'aes';
    const isCaesar = this.currentMethod === 'caesar';
    const isSha = this.currentMethod === 'sha256';
    document.getElementById('cryptoKeyGroup').style.display = isAes ? '' : 'none';
    document.getElementById('caesarShiftGroup').style.display = isCaesar ? '' : 'none';
    document.getElementById('btnDecrypt').style.display = (isAes || isCaesar || this.currentMethod === 'base64' || this.currentMethod === 'rot13') ? '' : 'none';
    document.getElementById('btnHash').style.display = isSha ? '' : 'none';
    document.getElementById('btnEncrypt').textContent = this.currentMethod === 'base64' ? 'Encoder' : this.currentMethod === 'sha256' ? 'Hacher' : 'Chiffrer';
    document.getElementById('btnDecrypt').textContent = this.currentMethod === 'base64' ? 'Décoder' : 'Déchiffrer';
  },

  async operate(op) {
    const input = document.getElementById('cryptoInput').value;
    const key = document.getElementById('cryptoKey').value;
    const shift = parseInt(document.getElementById('caesarShift').value) || 3;
    const method = this.currentMethod;
    const outputEl = document.getElementById('cryptoOutput');
    const metaEl = document.getElementById('cryptoMeta');

    if (!input.trim()) { Toast.error('Entrez du texte à traiter.'); return; }
    if (method === 'aes' && !key && op !== 'hash') { Toast.error('Entrez une passphrase pour AES-GCM.'); return; }

    let result = '';
    let meta = '';

    try {
      if (method === 'aes' && op === 'encrypt') {
        result = await Crypto.encryptAES(input, key);
        meta = `AES-256-GCM | PBKDF2 100k iters | Salt+IV intégrés`;
      } else if (method === 'aes' && op === 'decrypt') {
        result = await Crypto.decryptAES(input, key);
        meta = `AES-256-GCM | Déchiffrement réussi`;
      } else if (method === 'sha256') {
        result = await Crypto.sha256(input);
        meta = `SHA-256 | ${result.length * 4} bits | Irréversible`;
      } else if (method === 'base64' && op === 'encrypt') {
        result = btoa(unescape(encodeURIComponent(input)));
        meta = `Base64 | Encodé (${result.length} chars)`;
      } else if (method === 'base64' && op === 'decrypt') {
        result = decodeURIComponent(escape(atob(input)));
        meta = `Base64 | Décodé (${result.length} chars)`;
      } else if (method === 'caesar' && op === 'encrypt') {
        result = Crypto.caesar(input, shift, false);
        meta = `César | Décalage +${shift}`;
      } else if (method === 'caesar' && op === 'decrypt') {
        result = Crypto.caesar(input, shift, true);
        meta = `César | Décalage -${shift}`;
      } else if (method === 'rot13') {
        result = Crypto.rot13(input);
        meta = `ROT-13 | Symétrique`;
      }

      outputEl.value = result;
      metaEl.textContent = meta;

      const histEntry = {
        id: Utils.uid(),
        method: method.toUpperCase(),
        op,
        input: input.slice(0, 40),
        ts: Date.now(),
      };
      this.history.unshift(histEntry);
      this.history = this.history.slice(0, 20);
      Storage.set('crypto_history', this.history);
      Storage.increment('crypto_count');
      this.renderHistory();
      Dashboard.refreshStats();
      Activity.log(`Crypto : ${method.toUpperCase()} ${op}`);
      Toast.success('Opération effectuée.');
    } catch (err) {
      Toast.error('Erreur : ' + (err.message || 'Opération impossible.'));
      outputEl.value = '';
    }
  },

  renderHistory() {
    const el = document.getElementById('cryptoHistory');
    if (!this.history.length) {
      el.innerHTML = '<div class="history-empty">Aucune opération effectuée.</div>';
      return;
    }
    el.innerHTML = this.history.slice(0, 10).map(h => `
      <div class="crypto-hist-item">
        <span class="hist-method">${Utils.sanitize(h.method)}</span>
        <span class="hist-text">${Utils.sanitize(h.input)}${h.input.length >= 40 ? '…' : ''}</span>
        <span class="hist-op">${Utils.sanitize(h.op)}</span>
      </div>`).join('');
  },
};

/* ────────────────────────────────────────────────────────────────
   MODULE : EXPORT / IMPORT
──────────────────────────────────────────────────────────────── */
const ExportImport = {
  async exportData() {
    const data = {};
    if (document.getElementById('expVault').checked) data.vault = Storage.get(Vault.DATA_KEY);
    if (document.getElementById('expHistory').checked) data.genHistory = Storage.get('gen_history');
    if (document.getElementById('expCryptoHist').checked) data.cryptoHistory = Storage.get('crypto_history');
    data.exportedAt = new Date().toISOString();
    data.version = '2.1';

    let finalData = JSON.stringify(data, null, 2);
    const passphrase = document.getElementById('exportPassphrase').value;
    if (passphrase) {
      finalData = JSON.stringify({ encrypted: await Crypto.encryptAES(finalData, passphrase), v: 2 });
    }

    const blob = new Blob([finalData], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cipherix-backup-${new Date().toISOString().slice(0,10)}.json`;
    a.click();
    URL.revokeObjectURL(url);

    const preview = document.getElementById('exportPreview');
    preview.style.display = '';
    preview.textContent = finalData.slice(0, 400) + (finalData.length > 400 ? '…' : '');

    Activity.log('Export des données effectué.');
    Toast.success('Données exportées avec succès.');
  },

  loadFile(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const raw = e.target.result;
        const parsed = JSON.parse(raw);
        this._importData = parsed;
        if (parsed.encrypted) {
          document.getElementById('importPassGroup').style.display = '';
          document.getElementById('btnImport').style.display = '';
          document.getElementById('importStatus').textContent = 'Fichier chiffré détecté. Entrez la passphrase.';
        } else {
          document.getElementById('importPassGroup').style.display = 'none';
          document.getElementById('btnImport').style.display = '';
          document.getElementById('importStatus').textContent = 'Fichier Cipherix valide. Prêt à importer.';
        }
      } catch {
        Toast.error('Fichier JSON invalide.');
        document.getElementById('importStatus').textContent = 'Fichier invalide.';
      }
    };
    reader.readAsText(file);
  },

  async importData() {
    if (!this._importData) { Toast.error('Aucun fichier sélectionné.'); return; }
    let data = this._importData;
    const pass = document.getElementById('importPassphrase').value;

    if (data.encrypted) {
      if (!pass) { Toast.error('Passphrase requise.'); return; }
      try {
        const raw = await Crypto.decryptAES(data.encrypted, pass);
        data = JSON.parse(raw);
      } catch {
        Toast.error('Passphrase incorrecte ou fichier corrompu.');
        return;
      }
    }

    const ok = await Confirm.show('Importer ces données remplacera vos données existantes. Continuer ?', 'Confirmer l\'import');
    if (!ok) return;

    if (data.vault) Storage.set(Vault.DATA_KEY, data.vault);
    if (data.genHistory) Storage.set('gen_history', data.genHistory);
    if (data.cryptoHistory) Storage.set('crypto_history', data.cryptoHistory);

    document.getElementById('importStatus').textContent = `Import réussi — ${new Date(data.exportedAt || Date.now()).toLocaleString('fr-FR')}`;
    Activity.log('Import de données effectué.');
    Toast.success('Données importées avec succès.');
    Dashboard.refresh();
  },
};

/* ────────────────────────────────────────────────────────────────
   MODULE : PWA
──────────────────────────────────────────────────────────────── */
const PWA = {
  deferredPrompt: null,
  init() {
    window.addEventListener('beforeinstallprompt', (e) => {
      e.preventDefault();
      this.deferredPrompt = e;
      const banner = document.getElementById('installBanner');
      if (banner) banner.classList.remove('hidden');
    });

    const installBtn = document.getElementById('installBtn');
    if (installBtn) installBtn.addEventListener('click', () => this.install());
    const closeBtn = document.getElementById('installClose');
    if (closeBtn) closeBtn.addEventListener('click', () => document.getElementById('installBanner').classList.add('hidden'));

    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.register('sw.js').catch(() => {});
    }
  },
  async install() {
    if (!this.deferredPrompt) return;
    this.deferredPrompt.prompt();
    await this.deferredPrompt.userChoice;
    this.deferredPrompt = null;
    document.getElementById('installBanner').classList.add('hidden');
  },
};

/* ────────────────────────────────────────────────────────────────
   MODULE : NAVIGATION
──────────────────────────────────────────────────────────────── */
const Nav = {
  currentSection: 'dashboard',
  TITLES: {
    dashboard: 'Dashboard',
    generator: 'Générateur de mots de passe',
    analyzer: 'Analyseur de force',
    crypto: 'Laboratoire Crypto',
    vault: 'Coffre-fort Sécurisé',
    lab: 'Security Lab',
    export: 'Export / Import',
  },

  go(sectionId) {
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => {
      n.classList.toggle('active', n.dataset.section === sectionId);
      n.setAttribute('aria-current', n.dataset.section === sectionId ? 'page' : 'false');
    });
    const target = document.getElementById('sec-' + sectionId);
    if (target) target.classList.add('active');
    document.getElementById('topbarTitle').textContent = this.TITLES[sectionId] || sectionId;
    this.currentSection = sectionId;

    // Hooks par section
    if (sectionId === 'dashboard') Dashboard.refresh();
    if (sectionId === 'vault') VaultUI.showLockScreen();
    if (sectionId === 'crypto') CryptoUI.init();

    // Fermer sidebar sur mobile
    if (window.innerWidth <= 768) {
      document.getElementById('sidebar').classList.remove('open');
      const overlay = document.getElementById('sidebarOverlay');
      if (overlay) overlay.classList.remove('visible');
    }

    document.getElementById('content').focus();
  },
};

/* ────────────────────────────────────────────────────────────────
   INITIALISATION PRINCIPALE
──────────────────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {

  /* ── LOADER ── */
  const loaderSteps = [
    [10, 'Initialisation du chiffrement…'],
    [30, 'Vérification des clés…'],
    [55, 'Chargement du vault…'],
    [75, 'Préparation de l\'interface…'],
    [95, 'Finalisation…'],
    [100, 'Prêt.'],
  ];
  let stepIdx = 0;
  const loaderInterval = setInterval(() => {
    if (stepIdx >= loaderSteps.length) {
      clearInterval(loaderInterval);
      setTimeout(() => {
        document.getElementById('loader').classList.add('fade-out');
        setTimeout(() => {
          document.getElementById('loader').classList.add('hidden');
          document.getElementById('app').classList.remove('hidden');
          Dashboard.refresh();
        }, 600);
      }, 200);
      return;
    }
    const [pct, status] = loaderSteps[stepIdx++];
    document.getElementById('loaderBar').style.width = pct + '%';
    document.getElementById('loaderStatus').textContent = status;
  }, 320);

  /* ── TOAST ── */
  Toast.init();

  /* ── CLOCK ── */
  const clockEl = document.getElementById('topbarTime');
  const updateClock = () => { if (clockEl) clockEl.textContent = Utils.clock(); };
  updateClock(); setInterval(updateClock, 1000);

  /* ── SIDEBAR MOBILE ── */
  const sidebar = document.getElementById('sidebar');
  const menuBtn = document.getElementById('menuBtn');
  const sidebarToggle = document.getElementById('sidebarToggle');

  // Créer overlay mobile
  const overlay = document.createElement('div');
  overlay.id = 'sidebarOverlay';
  overlay.className = 'sidebar-overlay';
  document.body.appendChild(overlay);

  const openSidebar = () => {
    sidebar.classList.add('open');
    overlay.classList.add('visible');
    menuBtn.setAttribute('aria-expanded', 'true');
  };
  const closeSidebar = () => {
    sidebar.classList.remove('open');
    overlay.classList.remove('visible');
    menuBtn.setAttribute('aria-expanded', 'false');
  };

  menuBtn.addEventListener('click', () => sidebar.classList.contains('open') ? closeSidebar() : openSidebar());
  sidebarToggle.addEventListener('click', closeSidebar);
  overlay.addEventListener('click', closeSidebar);

  /* ── NAVIGATION ── */
  document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', (e) => {
      e.preventDefault();
      Nav.go(item.dataset.section);
    });
  });
  document.querySelectorAll('.stat-card[data-nav]').forEach(card => {
    card.addEventListener('click', () => Nav.go(card.dataset.nav));
  });

  /* ── GENERATOR ── */
  const genTabBtns = document.querySelectorAll('.gen-tab');
  genTabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      genTabBtns.forEach(b => { b.classList.remove('active'); b.setAttribute('aria-selected', 'false'); });
      btn.classList.add('active'); btn.setAttribute('aria-selected', 'true');
      document.querySelectorAll('.gen-panel').forEach(p => p.classList.remove('active'));
      document.getElementById('panel-' + btn.dataset.mode).classList.add('active');
    });
  });

  const lengthSlider = document.getElementById('genLength');
  const lengthVal = document.getElementById('genLengthVal');
  lengthSlider.addEventListener('input', () => {
    lengthVal.textContent = lengthSlider.value;
    lengthSlider.setAttribute('aria-valuenow', lengthSlider.value);
  });

  const caesarSlider = document.getElementById('caesarShift');
  caesarSlider.addEventListener('input', () => {
    document.getElementById('caesarShiftVal').textContent = caesarSlider.value;
  });

  let genResults = [];
  let genFavorites = Storage.get('gen_favorites', []);
  let genHistory = Storage.get('gen_history', []);

  function renderGenResults(passwords) {
    const el = document.getElementById('genResults');
    if (!passwords.length) {
      el.innerHTML = '<div class="results-placeholder"><span>◈</span><p>Cliquez sur Générer pour créer des mots de passe.</p></div>';
      return;
    }
    el.innerHTML = passwords.map((pw, i) => {
      const strength = StrengthAnalyzer.analyze(pw);
      const isFav = genFavorites.includes(pw);
      return `<div class="pw-result-item" style="animation-delay:${i * 0.06}s">
        <div class="pw-result-text">${Utils.sanitize(pw)}</div>
        <div class="pw-result-actions">
          <span style="font-size:0.72rem;color:${strength.color};white-space:nowrap">${strength.level}</span>
          <button class="pw-action-btn ${isFav ? 'fav-active' : ''}" data-action="fav" data-pw="${Utils.sanitize(pw)}" title="Favori" aria-label="Ajouter aux favoris">★</button>
          <button class="pw-action-btn" data-action="copy" data-pw="${Utils.sanitize(pw)}" title="Copier" aria-label="Copier le mot de passe">Copier</button>
        </div>
      </div>`;
    }).join('');
  }

  function renderHistory() {
    const recentEl = document.getElementById('historyRecent');
    const favEl = document.getElementById('historyFav');
    const hist = Storage.get('gen_history', []);

    if (!hist.length) {
      recentEl.innerHTML = '<div class="history-empty-msg">Aucun historique.</div>';
    } else {
      recentEl.innerHTML = hist.slice(0, 15).map(pw => `
        <div class="history-item">
          <span class="history-pw">${Utils.sanitize(pw)}</span>
          <button class="history-copy" data-pw="${Utils.sanitize(pw)}" aria-label="Copier">Copier</button>
        </div>`).join('');
    }

    const favs = Storage.get('gen_favorites', []);
    if (!favs.length) {
      favEl.innerHTML = '<div class="history-empty-msg">Aucun favori.</div>';
    } else {
      favEl.innerHTML = favs.map(pw => `
        <div class="history-item">
          <span class="history-pw" style="color:var(--accent-yellow)">${Utils.sanitize(pw)}</span>
          <button class="history-copy" data-pw="${Utils.sanitize(pw)}" aria-label="Copier">Copier</button>
        </div>`).join('');
    }
  }

  document.getElementById('btnGenerate').addEventListener('click', () => {
    const activeMode = document.querySelector('.gen-tab.active')?.dataset.mode;
    let passwords = [];

    if (activeMode === 'smart') {
      passwords = Generator.generateSmart({
        keyword: document.getElementById('genKeyword').value,
        date: document.getElementById('genDate').value,
        city: document.getElementById('genCity').value,
        extra: document.getElementById('genExtra').value,
      });
    } else {
      const opts = {
        length: parseInt(lengthSlider.value),
        upper: document.getElementById('optUppercase').checked,
        lower: document.getElementById('optLowercase').checked,
        numbers: document.getElementById('optNumbers').checked,
        symbols: document.getElementById('optSymbols').checked,
        excludeAmbiguous: document.getElementById('optAmbiguous').checked,
        exclude: document.getElementById('optExclude').value,
      };
      for (let i = 0; i < 5; i++) passwords.push(Generator.generateRandom(opts));
    }

    genResults = passwords;
    renderGenResults(passwords);

    const hist = Storage.get('gen_history', []);
    hist.unshift(...passwords);
    Storage.set('gen_history', hist.slice(0, 50));
    Storage.increment('gen_count');
    renderHistory();
    Dashboard.refreshStats();
    Activity.log('Mots de passe générés : ' + passwords.length);
    Toast.success(`${passwords.length} mot(s) de passe générés.`);
  });

  document.getElementById('btnClearGen').addEventListener('click', () => {
    document.getElementById('genKeyword').value = '';
    document.getElementById('genDate').value = '';
    document.getElementById('genCity').value = '';
    document.getElementById('genExtra').value = '';
    genResults = [];
    renderGenResults([]);
  });

  document.getElementById('btnClearHistory').addEventListener('click', () => {
    Storage.remove('gen_history');
    renderHistory();
    Toast.info('Historique effacé.');
  });

  // History tabs
  document.querySelectorAll('.htab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.htab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById('historyRecent').classList.toggle('hidden', tab.dataset.htab !== 'recent');
      document.getElementById('historyFav').classList.toggle('hidden', tab.dataset.htab !== 'fav');
    });
  });

  // Gen results delegation
  document.getElementById('genResults').addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-action]');
    if (!btn) return;
    const pw = btn.dataset.pw;
    if (btn.dataset.action === 'copy') {
      await Utils.copy(pw);
      Toast.success('Mot de passe copié.');
    }
    if (btn.dataset.action === 'fav') {
      const favs = Storage.get('gen_favorites', []);
      const idx = favs.indexOf(pw);
      if (idx >= 0) { favs.splice(idx, 1); btn.classList.remove('fav-active'); }
      else { favs.unshift(pw); btn.classList.add('fav-active'); }
      Storage.set('gen_favorites', favs.slice(0, 50));
      renderHistory();
    }
  });

  document.getElementById('historyRecent').addEventListener('click', async (e) => {
    const btn = e.target.closest('.history-copy');
    if (btn) { await Utils.copy(btn.dataset.pw); Toast.success('Copié.'); }
  });
  document.getElementById('historyFav').addEventListener('click', async (e) => {
    const btn = e.target.closest('.history-copy');
    if (btn) { await Utils.copy(btn.dataset.pw); Toast.success('Copié.'); }
  });

  renderHistory();

  /* ── ANALYZER ── */
  const analyzerInput = document.getElementById('analyzerInput');
  const toggleVis = document.getElementById('toggleAnalyzerVis');
  toggleVis.addEventListener('click', () => {
    const isPass = analyzerInput.type === 'password';
    analyzerInput.type = isPass ? 'text' : 'password';
    document.getElementById('eyeIcon').textContent = isPass ? '◎' : '◉';
    toggleVis.setAttribute('aria-pressed', String(isPass));
  });

  function updateAnalyzer(pw) {
    const a = StrengthAnalyzer.analyze(pw);

    // Barre
    const fill = document.getElementById('strengthFill');
    fill.style.width = a.score + '%';
    fill.style.background = a.color;
    document.getElementById('strengthLabel').textContent = a.level;
    document.getElementById('strengthLabel').style.color = a.color;
    document.getElementById('strengthScore').textContent = pw ? `Score : ${a.score}/100` : '';

    // Score ring
    const arc = document.getElementById('scoreArc');
    const offset = 314 - (314 * a.score / 100);
    arc.style.strokeDashoffset = offset;
    document.getElementById('scoreNumber').textContent = a.score;
    document.getElementById('analyzerBar').setAttribute('aria-valuenow', a.score);

    // Critères
    document.getElementById('scoreCriteria').innerHTML = a.criteria.map(c =>
      `<div class="criterion ${c.pass ? 'pass' : 'fail'}">
        <span class="criterion-icon">${c.pass ? '✓' : '○'}</span>
        <span>${Utils.sanitize(c.text)}</span>
      </div>`
    ).join('');

    // Bruteforce
    document.getElementById('bfTime').textContent = a.bruteforce;
    document.getElementById('bfDetails').innerHTML = pw ? `
      <div class="bf-row">Entropie : ${a.entropy} bits</div>
      <div class="bf-row">Charset : ${a.charset} symboles</div>
      <div class="bf-row">Longueur : ${a.len} caractères</div>
    ` : '';

    // Feedback
    const fbEl = document.getElementById('analysisFeedback');
    if (!pw) {
      fbEl.innerHTML = '<div class="feedback-placeholder">Saisissez un mot de passe pour commencer l\'analyse.</div>';
      return;
    }
    fbEl.innerHTML = a.feedback.map(f =>
      `<div class="feedback-item ${f.type}">
        <span class="feedback-icon">${f.type === 'success' ? '✓' : f.type === 'warning' ? '⚠' : '✕'}</span>
        <span>${Utils.sanitize(f.msg)}</span>
      </div>`
    ).join('');
  }

  analyzerInput.addEventListener('input', () => updateAnalyzer(analyzerInput.value));
  updateAnalyzer('');

  /* ── CRYPTO ── */
  document.querySelectorAll('.method-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.method-tab').forEach(t => { t.classList.remove('active'); t.setAttribute('aria-selected', 'false'); });
      tab.classList.add('active'); tab.setAttribute('aria-selected', 'true');
      CryptoUI.currentMethod = tab.dataset.method;
      CryptoUI.updateMethodUI();
    });
  });
  document.getElementById('btnEncrypt').addEventListener('click', () => CryptoUI.operate('encrypt'));
  document.getElementById('btnDecrypt').addEventListener('click', () => CryptoUI.operate('decrypt'));
  document.getElementById('btnHash').addEventListener('click', () => CryptoUI.operate('hash'));
  document.getElementById('btnCopyCrypto').addEventListener('click', async () => {
    const val = document.getElementById('cryptoOutput').value;
    if (!val) { Toast.error('Aucun résultat à copier.'); return; }
    await Utils.copy(val);
    Toast.success('Résultat copié.');
  });
  document.getElementById('btnDownloadCrypto').addEventListener('click', () => {
    const val = document.getElementById('cryptoOutput').value;
    if (!val) { Toast.error('Aucun résultat à télécharger.'); return; }
    const blob = new Blob([val], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cipherix-crypto-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    Toast.success('Fichier téléchargé.');
  });
  document.getElementById('btnClearCrypto').addEventListener('click', () => {
    document.getElementById('cryptoInput').value = '';
    document.getElementById('cryptoOutput').value = '';
    document.getElementById('cryptoMeta').textContent = '';
  });
  document.getElementById('toggleCryptoKey').addEventListener('click', () => {
    const inp = document.getElementById('cryptoKey');
    inp.type = inp.type === 'password' ? 'text' : 'password';
  });

  /* ── VAULT ── */
  if (!Vault.hasPIN()) {
    document.getElementById('setPinModal').classList.remove('hidden');
  }

  // PIN Grid principal
  document.getElementById('pinGrid').addEventListener('click', (e) => {
    const btn = e.target.closest('.pin-btn');
    if (!btn) return;
    if (btn.id === 'pinClear') { VaultUI.handlePinClear('pin'); return; }
    if (btn.id === 'pinSubmit') { VaultUI.submitPin(); return; }
    if (btn.dataset.digit !== undefined) VaultUI.handlePinDigit('pin', btn.dataset.digit);
  });

  // Set PIN Grid
  document.getElementById('setPinGrid').addEventListener('click', (e) => {
    const btn = e.target.closest('.pin-btn');
    if (!btn) return;
    if (btn.id === 'setPinClear') { VaultUI.handlePinClear('set'); return; }
    if (btn.id === 'setPinSubmit') { VaultUI.submitSetPin(); return; }
    if (btn.dataset.digit !== undefined) VaultUI.handlePinDigit('set', btn.dataset.digit);
  });

  // Support clavier pour PIN
  document.addEventListener('keydown', (e) => {
    const vaultVisible = !document.getElementById('vaultLockScreen').classList.contains('hidden');
    const pinModalVisible = !document.getElementById('setPinModal').classList.contains('hidden');
    if (vaultVisible && !pinModalVisible) {
      if (e.key >= '0' && e.key <= '9') VaultUI.handlePinDigit('pin', e.key);
      if (e.key === 'Backspace') VaultUI.handlePinClear('pin');
      if (e.key === 'Enter') VaultUI.submitPin();
    }
    if (pinModalVisible) {
      if (e.key >= '0' && e.key <= '9') VaultUI.handlePinDigit('set', e.key);
      if (e.key === 'Backspace') VaultUI.handlePinClear('set');
      if (e.key === 'Enter') VaultUI.submitSetPin();
    }
  });

  document.getElementById('btnAddEntry').addEventListener('click', () => VaultUI.openAddModal());
  document.getElementById('btnSaveEntry').addEventListener('click', () => VaultUI.saveEntry());
  document.getElementById('btnCancelVault').addEventListener('click', () => VaultUI.closeModal());
  document.getElementById('vaultModalClose').addEventListener('click', () => VaultUI.closeModal());

  document.getElementById('btnLockVault').addEventListener('click', () => {
    Vault.lock();
    Toast.info('Vault verrouillé.');
    Activity.log('Vault verrouillé manuellement.');
  });

  document.getElementById('btnResetVault').addEventListener('click', async () => {
    const ok = await Confirm.show('Réinitialiser le vault supprimera TOUTES les données. Cette action est irréversible.', 'Réinitialiser le Vault');
    if (!ok) return;
    Vault.reset();
    Toast.success('Vault réinitialisé.');
    Activity.log('Vault réinitialisé.');
    document.getElementById('setPinModal').classList.remove('hidden');
    VaultUI.setPinBuffer = [];
    VaultUI.renderPinDots('set');
  });

  document.getElementById('vaultSearch').addEventListener('input', () => VaultUI.render());
  document.getElementById('vaultCategoryFilter').addEventListener('change', () => VaultUI.render());

  // Entry password strength live
  document.getElementById('entryPassword').addEventListener('input', (e) => {
    const a = StrengthAnalyzer.analyze(e.target.value);
    const bar = document.getElementById('entryStrengthBar');
    bar.innerHTML = `<div class="mini-strength-fill" style="width:${a.score}%;background:${a.color}"></div>`;
  });
  document.getElementById('toggleEntryPw').addEventListener('click', () => {
    const inp = document.getElementById('entryPassword');
    inp.type = inp.type === 'password' ? 'text' : 'password';
  });

  // Vault card actions delegation
  document.getElementById('vaultGrid').addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-action]');
    if (!btn) return;
    const id = btn.dataset.id;
    const entry = Vault.entries.find(en => en.id === id);
    if (!entry) return;

    if (btn.dataset.action === 'copy') {
      await Utils.copy(entry.password);
      Toast.success('Mot de passe copié.');
      Vault.resetLockTimer();
    }
    if (btn.dataset.action === 'edit') { VaultUI.openEditModal(id); }
    if (btn.dataset.action === 'delete') {
      const ok = await Confirm.show(`Supprimer "${entry.title}" ? Action irréversible.`, 'Supprimer l\'entrée');
      if (!ok) return;
      await Vault.remove(id);
      VaultUI.render();
      Dashboard.refresh();
      Activity.log(`Entrée supprimée : ${entry.title}`);
      Toast.success('Entrée supprimée.');
    }
    if (btn.dataset.action === 'fav') {
      entry.favorite = !entry.favorite;
      await Vault.saveEntries();
      VaultUI.render();
    }
    if (btn.dataset.action === 'toggle-pw') {
      if (VaultUI.shownPasswords.has(id)) VaultUI.shownPasswords.delete(id);
      else VaultUI.shownPasswords.add(id);
      VaultUI.render();
      Vault.resetLockTimer();
    }
  });

  /* ── CONFIRM MODAL ── */
  document.getElementById('confirmOk').addEventListener('click', () => Confirm.ok());
  document.getElementById('confirmCancel').addEventListener('click', () => Confirm.cancel());
  document.getElementById('confirmClose').addEventListener('click', () => Confirm.cancel());

  // Close modals on overlay click
  document.querySelectorAll('.modal-overlay').forEach(overlay => {
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) {
        if (overlay.id === 'vaultModal') VaultUI.closeModal();
        if (overlay.id === 'confirmModal') Confirm.cancel();
      }
    });
  });

  /* ── SECURITY LAB ── */
  document.getElementById('btnRunSim').addEventListener('click', async () => {
    const pw = document.getElementById('labPassword').value;
    if (!pw) { Toast.error('Entrez un mot de passe à simuler.'); return; }
    document.getElementById('terminalBody').innerHTML = '<div class="term-line term-prompt">$ init bruteforce_simulation</div>';
    await SecurityLab.runBruteforceSim(pw);
    Activity.log('Simulation bruteforce lancée.');
  });
  document.getElementById('labPassword').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') document.getElementById('btnRunSim').click();
  });

  // Animate scan grid cells
  document.querySelectorAll('.sg-cell').forEach((cell, i) => {
    cell.style.setProperty('--i', i.toString());
  });

  // Init comparison with placeholder
  SecurityLab.renderComparison('');

  /* ── EXPORT / IMPORT ── */
  document.getElementById('btnExport').addEventListener('click', () => ExportImport.exportData());
  document.getElementById('btnImport').addEventListener('click', () => ExportImport.importData());

  const dropZone = document.getElementById('dropZone');
  const fileInput = document.getElementById('importFileInput');

  dropZone.addEventListener('click', () => fileInput.click());
  dropZone.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') fileInput.click(); });
  dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('drag-over'); });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (file) ExportImport.loadFile(file);
  });
  fileInput.addEventListener('change', () => {
    if (fileInput.files[0]) ExportImport.loadFile(fileInput.files[0]);
  });

  /* ── PWA ── */
  PWA.init();

  /* ── KEYBOARD NAVIGATION ── */
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      if (!document.getElementById('vaultModal').classList.contains('hidden')) VaultUI.closeModal();
      if (!document.getElementById('confirmModal').classList.contains('hidden')) Confirm.cancel();
    }
  });

  /* ── INITIAL STATE ── */
  Nav.go('dashboard');
  VaultUI.showLockScreen();

  // Scan cell animation randomize
  setInterval(() => {
    const cells = document.querySelectorAll('.sg-cell');
    if (cells.length) {
      const i = Utils.randomInt(cells.length);
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
      cells[i].textContent = chars[Utils.randomInt(chars.length)] + chars[Utils.randomInt(chars.length)];
    }
  }, 150);

  console.log('%cCIPHERIX v2.1 — All cryptography powered by Web Crypto API. Zero external dependencies.', 'color:#00ffe7;font-weight:bold;font-size:14px;');
});
