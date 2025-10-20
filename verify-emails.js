#!/usr/bin/env node
/**
 * Verificador de emails: Sintaxis + MX + (opcional) RCPT TO + catch-all
 * - Sin p-limit (compat Node CJS).
 * - Autodetecta la columna de email (con o sin cabecera).
 * - Filtra filas del CSV original (no añade columnas).
 * - Resumen de eliminaciones por status y reason.
 *
 * Modo OFFLINE (sin internet):
 *   --offline | --noNet | --noNetwork
 *   Solo validaciones locales (sintaxis/role/disposable/typos). Marca 'syntax-ok'.
 *
 * Validación online SIN abrir puertos raros (solo HTTPS 443):
 *   --dnsOnly --doh [--dohEndpoint ...]
 *   Comprueba MX por DoH (y A/AAAA como fallback). Marca 'mx-ok'. Sin SMTP.
 *
 * Validación completa (requiere salida TCP 25):
 *   (sin --dnsOnly) Probar RCPT TO + catch-all (puede chocar con reputación IP).
 *
 * Uso:
 *   node verify-emails.js input.csv --out clean.csv [opciones]
 *
 * Opciones:
 *   --keep valid,catch_all,unknown,policy,mx-ok,syntax-ok   (default: 'valid' o 'syntax-ok' si --offline)
 *   --emailColName Email     Nombre de columna
 *   --emailColIndex 2        Índice de columna (0-based)
 *   --delimiter ";"          Forzar delimitador
 *   --fixTypos               Corrige typos comunes en dominios (local)
 *   --noRole                 No marcar role@ como 'role'
 *   --offline | --noNet | --noNetwork   Solo checks locales (sin DNS/SMTP)
 *   --dnsOnly | --skipSmtp   Solo DNS (MX/A) sin SMTP; marca 'mx-ok'
 *   --doh                    Usa DNS-over-HTTPS (443) en lugar de DNS del sistema
 *   --dohEndpoint https://dns.google/resolve  Endpoint DoH (JSON). Ej: Cloudflare: https://cloudflare-dns.com/dns-query
 *   --from verificador@tudominio.com
 *   --nullFrom               Usar MAIL FROM:<> (remitente nulo)
 *   --ehlo mail.tudominio.com
 *   --concurrency 5
 *   --timeout 10000
 *   --topReasons 10
 */

const fs = require('fs/promises');
const net = require('net');
const dns = require('dns').promises;
const https = require('https');
const { parse: parseCSV } = require('csv-parse/sync');
const { stringify } = require('csv-stringify/sync');
const validator = require('validator');
const crypto = require('crypto');
const punycode = require('node:punycode');

const argv = require('node:process').argv.slice(2);

// ---- CLI ----
function getFlag(name, def = undefined) {
  const i = argv.findIndex(a => a === `--${name}`);
  if (i !== -1) return argv[i + 1];
  return def;
}
function hasFlag(name) { return argv.includes(`--${name}`); }

const infile = argv.find(a => !a.startsWith('--'));
if (!infile) {
  console.error('Uso: node verify-emails.js <input.csv> --out salida.csv [opciones]');
  process.exit(1);
}
const outfile = getFlag('out', 'verified.csv');
const EMAIL_COL_NAME = getFlag('emailColName', null);
const EMAIL_COL_INDEX = getFlag('emailColIndex', null) !== null ? Number(getFlag('emailColIndex')) : null;
const DELIMITER = getFlag('delimiter', null);
const FROM = getFlag('from', 'bounce@example.com');
const NULL_FROM = hasFlag('nullFrom');
const EHLO_DOMAIN = getFlag('ehlo', null);
const CONCURRENCY = Number(getFlag('concurrency', 5));
const TIMEOUT_MS = Number(getFlag('timeout', 10000));
const MARK_ROLE = !hasFlag('noRole');
const FIX_TYPOS = hasFlag('fixTypos');
const TOP_REASONS = Number(getFlag('topReasons', 10));
const DNS_ONLY = hasFlag('dnsOnly') || hasFlag('skipSmtp');
const OFFLINE = hasFlag('offline') || hasFlag('noNet') || hasFlag('noNetwork');
const USE_DOH = hasFlag('doh') || hasFlag('dnsOverHttps');
const DOH_ENDPOINT = getFlag('dohEndpoint', 'https://dns.google/resolve');

// Estados a conservar (por defecto: 'valid', o 'syntax-ok' si OFFLINE)
const DEFAULT_KEEP = OFFLINE ? 'syntax-ok' : 'valid';
const KEEP_STATUSES = new Set(
  (getFlag('keep', DEFAULT_KEEP) || DEFAULT_KEEP)
    .split(',')
    .map(s => s.trim().toLowerCase())
    .filter(Boolean)
);

// ---- utilidades ----
const ROLE_LOCALPARTS = new Set([
  'abuse','admin','billing','compliance','devnull','dns','ftp','hostmaster',
  'info','marketing','noc','noreply','no-reply','postmaster','sales','security',
  'support','sysadmin','tech','webmaster','contact','help','hello','team'
]);

const DISPOSABLES = new Set([
  'mailinator.com','guerrillamail.com','10minutemail.com','tempmail.email',
  'yopmail.com','trashmail.com','emailondeck.com','getnada.com'
]);

function isRole(email) {
  const lp = email.split('@')[0].toLowerCase();
  return ROLE_LOCALPARTS.has(lp);
}
function isDisposable(domain) {
  return DISPOSABLES.has(domain.toLowerCase());
}
function fixCommonDomainTypos(domain) {
  const d = domain.toLowerCase().replace(/\s+/g, '');
  const table = {
    'gmal.com':'gmail.com','gmial.com':'gmail.com','gnail.com':'gmail.com',
    'gmail.co':'gmail.com','gmail.con':'gmail.com','gmai.com':'gmail.com',
    'hotnail.com':'hotmail.com','hotmai.com':'hotmail.com','hotmail.co':'hotmail.com',
    'outlok.com':'outlook.com','outlook.co':'outlook.com',
    'yaho.com':'yahoo.com','yhoo.com':'yahoo.com','yahoo.co':'yahoo.com',
    'icloud.co':'icloud.com','icoud.com':'icloud.com',
    'proton.co':'proton.me','protonmail.co':'proton.me'
  };
  return table[d] || d;
}

function domainFromEmail(e) {
  const s = String(e || '');
  const at = s.lastIndexOf('@');
  return at > -1 ? s.slice(at + 1) : null;
}

// Remitente para SMTP (soporta nulo)
function buildMailFrom(fromArg) {
  if (NULL_FROM || fromArg === '<>' || fromArg === '') return 'MAIL FROM:<>'
  return `MAIL FROM:<${fromArg}>`;
}

// ---- DNS over HTTPS (DoH) ----
async function dohResolve(name, type, endpoint = DOH_ENDPOINT) {
  return new Promise((resolve, reject) => {
    const sep = endpoint.includes('?') ? '&' : '?';
    const url = `${endpoint}${sep}name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
    https.get(url, { headers: { 'accept': 'application/dns-json' } }, res => {
      let data = '';
      res.on('data', chunk => (data += chunk));
      res.on('end', () => {
        try {
          const j = JSON.parse(data);
          resolve(j.Answer || []); // Google/Cloudflare JSON DNS
        } catch (e) { reject(e); }
      });
    }).on('error', reject);
  });
}

function parseMxFromDohAnswers(answers) {
  // data ej: "10 mx1.example.com."
  const recs = answers.map(a => {
    const m = /^(\d+)\s+(.+)\.?$/.exec(a.data || '');
    return m ? { priority: Number(m[1]), exchange: m[2].replace(/\.$/, '') } : null;
  }).filter(Boolean);
  recs.sort((a, b) => a.priority - b.priority);
  return recs.length ? recs[0].exchange : null;
}

async function getMx(domain) {
  try {
    if (USE_DOH) {
      const ans = await dohResolve(domain, 'MX');
      if (!ans.length) return null;
      return parseMxFromDohAnswers(ans);
    } else {
      const mx = await dns.resolveMx(domain);
      if (!mx?.length) return null;
      mx.sort((a, b) => a.priority - b.priority);
      return mx[0].exchange;
    }
  } catch {
    return null;
  }
}

// Detecta bloqueos de política/reputación (SMTP)
function isPolicyBlock(text) {
  const s = String(text || '').toLowerCase();
  return /tss\d|service unavailable|client .*blocked|rbl|blacklist|block(?:ed|list)|rejected due to list|access denied|dynamic\.clie|sender address rejected|sender verify failed|policy/.test(s);
}

function talkSMTP(host, commands, timeoutMs = TIMEOUT_MS) {
  const ehloFqdn = EHLO_DOMAIN || domainFromEmail(FROM) || 'verify.local';
  return new Promise((resolve) => {
    const socket = net.createConnection(25, host);
    let done = false;
    let buf = '';
    let timer = setTimeout(finish('timeout'), timeoutMs);
    const lines = [];

    socket.on('error', err => finish(err.message)());
    socket.on('close', () => finish('closed')());

    socket.on('connect', async () => {
      try {
        const banner = await readOnce(); // 220
        if (!/^220\b/.test(banner)) return finish('no-220')();

        await send(`EHLO ${ehloFqdn}`); let l = await readOnce();
        if (!/^250[-\s]/.test(l)) { await send(`HELO ${ehloFqdn}`); l = await readOnce(); }
        if (!/^250[-\s]/.test(l)) return finish('helo-failed')();

        for (const cmd of commands) {
          await send(cmd);
          const resp = await readOnce();
          lines.push(resp);
          if (!/^(250|251|252|354)/.test(resp) && !cmd.startsWith('QUIT')) {
            await send('QUIT');
            return finish(null, { ok: false, last: resp, lines })();
          }
        }
        await send('QUIT');
        return finish(null, { ok: true, lines })();
      } catch (e) {
        return finish(e.message)();
      }
    });

    function send(s) { socket.write(s + '\r\n'); }

    function readOnce() {
      return new Promise((res) => {
        function onData(d) {
          buf += d.toString();
          while (true) {
            const idx = buf.indexOf('\n');
            if (idx === -1) break;
            const line = buf.slice(0, idx + 1).trim();
            buf = buf.slice(idx + 1);
            if (/^\d{3}\s/.test(line)) { // fin de bloque (no 250-)
              socket.off('data', onData);
              res(line);
              return;
            }
          }
        }
        socket.on('data', onData);
      });
    }

    function finish(reason, payload) {
      return () => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        try { socket.destroy(); } catch {}
        if (payload) resolve(payload);
        else resolve({ ok: false, lines, reason });
      };
    }
  });
}

// ---- Verificación de un email ----
async function verifyOne(email, options = {}) {
  const t0 = Date.now();
  const row = {
    email_original: email,
    email_normalized: '',
    status: 'unknown',
    reason: '',
    mx: '',
    elapsed_ms: 0
  };

  let e = String(email || '').trim();
  if (!e) { row.status = 'bad'; row.reason = 'empty'; return finish(); }
  e = e.toLowerCase();

  const at = e.lastIndexOf('@');
  if (at === -1) { row.status = 'syntax'; row.reason = 'no-@'; return finish(); }
  let local = e.slice(0, at);
  let domain = e.slice(at + 1);

  if (FIX_TYPOS) domain = fixCommonDomainTypos(domain);

  // Soporte IDN: convertir dominio a ASCII (punycode) antes de validar
  if (/[^\x00-\x7F]/.test(domain)) {
    try { domain = punycode.toASCII(domain); } catch {}
  }

  const normalized = `${local}@${domain}`;
  row.email_normalized = normalized;

  // Validación local de sintaxis
  if (!validator.isEmail(normalized)) { row.status = 'syntax'; row.reason = 'validator'; return finish(); }

  // Role y disposable (listas locales)
  if (MARK_ROLE && isRole(normalized)) { row.status = 'role'; row.reason = 'role-address'; return finish(); }
  if (isDisposable(domain)) { row.status = 'disposable'; row.reason = 'temp-domain'; return finish(); }

  // Modo OFFLINE: sin DNS ni SMTP, solo checks locales
  if (OFFLINE) { row.status = 'syntax-ok'; row.reason = 'offline'; return finish(); }

  // Conectividad requerida a partir de aquí (DNS/SMTP)
  let mx = await getMx(domain);

  // Fallback A/AAAA por DoH cuando no hay MX (RFC: entrega a A/AAAA)
  if (!mx && USE_DOH) {
    try {
      const aAns = await dohResolve(domain, 'A');
      const aaaaAns = aAns?.length ? [] : await dohResolve(domain, 'AAAA');
      if ((aAns && aAns.length) || (aaaaAns && aaaaAns.length)) {
        mx = domain; // host implícito
      }
    } catch { /* ignore */ }
  }

  if (!mx) { row.status = 'no-mx'; row.reason = 'no-mx-record'; return finish(); }
  row.mx = mx;

  // DNS-only: sin RCPT TO (no SMTP)
  if (DNS_ONLY) { row.status = 'mx-ok'; row.reason = USE_DOH ? 'dns-only(doh)' : 'dns-only'; return finish(); }

  // SMTP RCPT TO (requiere TCP 25 saliente)
  const from = buildMailFrom(options.from || FROM);
  const rcpt = `RCPT TO:<${normalized}>`;
  const r1 = await talkSMTP(mx, [from, rcpt]);

  if (r1.ok) {
    // Prueba de catch-all con destinatario aleatorio
    const fakeLocal = crypto.randomBytes(8).toString('hex');
    const fake = `RCPT TO:<${fakeLocal}@${domain}>`;
    const r2 = await talkSMTP(mx, [from, fake]);

    if (r2.ok || (r2.last && /^250/.test(r2.last))) {
      row.status = 'catch_all'; row.reason = 'accepts-random'; return finish();
    }
    row.status = 'valid'; row.reason = '250'; return finish();
  }

  if (r1.last) {
    const code = Number(r1.last.slice(0, 3));
    if (code >= 500) {
      if (isPolicyBlock(r1.last)) { row.status = 'policy'; row.reason = r1.last; return finish(); }
      row.status = 'bad'; row.reason = r1.last; return finish();
    }
    if (code >= 400) { row.status = 'unknown'; row.reason = r1.last; return finish(); }
  }

  row.status = 'unknown'; row.reason = r1.reason || 'smtp-error'; return finish();

  function finish() { row.elapsed_ms = Date.now() - t0; return row; }
}

// ---- CSV + autodetección ----
async function loadEmailsFromCSV(filePath) {
  const raw = await fs.readFile(filePath, 'utf8');
  const candidates = DELIMITER ? [DELIMITER] : [',', ';', '\t', '|'];
  let best = null;

  for (const delim of candidates) {
    try {
      const rows = parseCSV(raw, {
        delimiter: delim,
        relax_column_count: true,
        skip_empty_lines: true
      });
      const score = (rows[0]?.length || 1) * rows.length;
      if (!best || score > best.score) best = { delim, rows, score };
    } catch { /* next */ }
  }
  if (!best) throw new Error('No se pudo parsear el CSV.');

  const { rows, delim } = best;

  if (EMAIL_COL_NAME !== null) {
    const header = rows[0].map(String);
    const idx = header.findIndex(h => h.toLowerCase().trim() === EMAIL_COL_NAME.toLowerCase().trim());
    if (idx === -1) throw new Error(`No existe columna "${EMAIL_COL_NAME}".`);
    const emails = rows.slice(1).map(r => (r[idx] ?? '').toString().trim());
    return { rows, emails, delimiter: delim, detectedIndex: idx, headerUsed: true };
  }

  if (EMAIL_COL_INDEX !== null) {
    const emails = rows.map(r => (r[EMAIL_COL_INDEX] ?? '').toString().trim());
    return { rows, emails, delimiter: delim, detectedIndex: EMAIL_COL_INDEX, headerUsed: false };
  }

  const maxCols = Math.max(...rows.map(r => r.length));
  let bestCol = 0, bestCount = -1;
  for (let c = 0; c < maxCols; c++) {
    let count = 0;
    for (let i = 0; i < Math.min(rows.length, 2000); i++) {
      const v = (rows[i][c] ?? '').toString().trim();
      if (v && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) count++;
    }
    if (count > bestCount) { bestCount = count; bestCol = c; }
  }
  const emails = rows.map(r => (r[bestCol] ?? '').toString().trim());
  return { rows, emails, delimiter: delim, detectedIndex: bestCol, headerUsed: false };
}

// ---- Pool de concurrencia propio ----
async function runPool(concurrency, items, worker) {
  const results = [];
  let i = 0;
  const total = items.length;
  const workers = Array.from({ length: Math.min(concurrency, Math.max(1, total)) }, () => (async function loop() {
    while (true) {
      const idx = i++;
      if (idx >= total) break;
      results[idx] = await worker(items[idx], idx);
    }
  })());
  await Promise.all(workers);
  return results;
}

// ---- helpers resumen ----
function countBy(items, keyFn) {
  const map = new Map();
  for (const it of items) {
    const k = keyFn(it) ?? 'unknown';
    map.set(k, (map.get(k) || 0) + 1);
  }
  return Array.from(map.entries()).sort((a, b) => b[1] - a[1]);
}
function pct(n, d) {
  if (!d) return '0.0%';
  return (Math.round((n * 1000) / d) / 10).toFixed(1) + '%';
}
function padRight(s, w) { return String(s).padEnd(w); }

// ---- main ----
(async function main() {
  console.time('verify');
  console.log('Leyendo CSV…');

  const { rows, detectedIndex, headerUsed, delimiter: detectedDelimiter } = await loadEmailsFromCSV(infile);

  // ¿La primera fila es cabecera?
  const firstCell = ((rows[0] ?? [])[detectedIndex] ?? '').toString().trim();
  const emailRegex = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
  const hasHeader = headerUsed || !emailRegex.test(firstCell);

  // Prepara items a verificar (excluye cabecera si la hay)
  const dataStart = hasHeader ? 1 : 0;
  const items = rows.slice(dataStart).map((r, idx) => ({
    rowIndex: idx + dataStart,
    email: (r[detectedIndex] ?? '').toString().trim()
  }));

  const total = items.length;
  let done = 0;

  console.log(`Delimitador detectado: "${detectedDelimiter}"`);
  console.log(`Columna email: ${headerUsed ? `por nombre (idx ${detectedIndex})` : `idx ${detectedIndex}`} | filas: ${total}${hasHeader ? ' (+1 cabecera)' : ''}`);
  if (OFFLINE) console.log('Modo OFFLINE activado: solo validaciones locales (sin DNS/SMTP).');
  if (DNS_ONLY && USE_DOH) console.log('DNS-only con DoH: validación de MX/A vía HTTPS 443.');

  const tick = setInterval(() => {
    process.stdout.write(`\rProgreso: ${done}/${total}`);
  }, 1000);

  const results = await runPool(CONCURRENCY, items, async (it) => {
    const r = await verifyOne(it.email, { from: FROM });
    done++;
    return { ...r, rowIndex: it.rowIndex };
  });

  clearInterval(tick);
  process.stdout.write(`\rProgreso: ${total}/${total}\n`);

  // Filas a conservar según estados
  const keepRowIndex = new Set(
    results
      .filter(r => KEEP_STATUSES.has((r.status || '').toLowerCase()))
      .map(r => r.rowIndex)
  );

  const filteredRows = [];
  if (hasHeader) filteredRows.push(rows[0]);
  for (let i = dataStart; i < rows.length; i++) {
    if (keepRowIndex.has(i)) filteredRows.push(rows[i]);
  }

  // Escribe salida con el mismo delimitador, sin columnas nuevas
  const csvOut = stringify(filteredRows, {
    delimiter: detectedDelimiter
  });

  await fs.writeFile(outfile, csvOut);

  // ---- Resumen ----
  const kept = results.filter(r => KEEP_STATUSES.has((r.status || '').toLowerCase()));
  const removed = results.filter(r => !KEEP_STATUSES.has((r.status || '').toLowerCase()));

  const removedByStatus = countBy(removed, r => (r.status || 'unknown').toLowerCase());
  const removedByReason = countBy(removed, r => (r.reason || 'unknown'));

  console.log('\n=== Resumen ===');
  console.log(`Procesadas: ${total}`);
  console.log(`Conservadas: ${kept.length} (${pct(kept.length, total)})`);
  console.log(`Eliminadas:  ${removed.length} (${pct(removed.length, total)})`);

  if (removed.length) {
    const col1 = Math.max(6, ...removedByStatus.map(([k]) => k.length)) + 2;
    console.log('\nEliminadas por STATUS:');
    console.log(padRight('status', col1) + padRight('count', 8) + padRight('%elim', 8) + '%total');
    for (const [status, n] of removedByStatus) {
      console.log(padRight(status, col1) + padRight(String(n), 8) + padRight(pct(n, removed.length), 8) + pct(n, total));
    }

    const top = removedByReason.slice(0, Math.max(0, TOP_REASONS));
    const colR = Math.min(60, Math.max(6, ...top.map(([k]) => String(k).length))) + 2;
    console.log(`\nTop REASONS que eliminaron (top ${TOP_REASONS}):`);
    console.log(padRight('reason', colR) + padRight('count', 8) + padRight('%elim', 8) + '%total');
    for (const [reason, n] of top) {
      const rLabel = String(reason).slice(0, colR - 2);
      console.log(padRight(rLabel, colR) + padRight(String(n), 8) + padRight(pct(n, removed.length), 8) + pct(n, total));
    }
  } else {
    console.log('\nNo hubo filas eliminadas con la configuración de --keep actual.');
  }

  console.timeEnd('verify');
  console.log(`Listo: ${filteredRows.length} filas -> ${outfile}`);
})().catch(err => {
  console.error('\nERROR:', err.message || err);
  process.exit(1);
});
