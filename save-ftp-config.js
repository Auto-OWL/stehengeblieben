/**
 * stehengeblieben.de — FTP Konfiguration speichern
 * POST /api/save-ftp-config
 *
 * AES-256-GCM Verschlüsselung + HMAC-SHA256 Integritätsprüfung.
 * Klartext-Zugangsdaten verlassen diese Funktion nie.
 */

const crypto = require('crypto');

const SUPA_URL       = process.env.SUPABASE_URL;
const SUPA_KEY       = process.env.SUPABASE_SERVICE_KEY;
const ENC_KEY        = process.env.FTP_ENCRYPTION_KEY; // 64 hex = 32 bytes
const HMAC_SECRET    = process.env.FTP_HMAC_SECRET;    // 64 hex = 32 bytes

// ── AES-256-GCM encrypt ───────────────────────────────────────────────────────
function encrypt(plaintext) {
  const key    = Buffer.from(ENC_KEY, 'hex');
  const iv     = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc    = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag    = cipher.getAuthTag();
  return iv.toString('hex') + tag.toString('hex') + enc.toString('hex');
}

// ── HMAC-SHA256 sign ──────────────────────────────────────────────────────────
function sign(data) {
  return crypto
    .createHmac('sha256', Buffer.from(HMAC_SECRET, 'hex'))
    .update(JSON.stringify(data))
    .digest('hex');
}

// ── Supabase fetch ────────────────────────────────────────────────────────────
async function supa(path, method, body) {
  const r = await fetch(`${SUPA_URL}/rest/v1/${path}`, {
    method,
    headers: {
      'apikey': SUPA_KEY, 'Authorization': `Bearer ${SUPA_KEY}`,
      'Content-Type': 'application/json', 'Prefer': 'return=minimal'
    },
    body: body ? JSON.stringify(body) : undefined
  });
  if (!r.ok) throw new Error(await r.text());
  return r;
}

// ── Handler ───────────────────────────────────────────────────────────────────
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', 'https://stehengeblieben.de');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  if (!ENC_KEY || !HMAC_SECRET || !SUPA_URL || !SUPA_KEY)
    return res.status(500).json({ error: 'Serverkonfiguration unvollständig' });

  // ── Auth: JWT verifizieren ─────────────────────────────────────────────────
  const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ error: 'Nicht autorisiert' });

  const userRes = await fetch(`${SUPA_URL}/auth/v1/user`, {
    headers: { 'apikey': SUPA_KEY, 'Authorization': `Bearer ${token}` }
  });
  if (!userRes.ok) return res.status(401).json({ error: 'Ungültiger Token' });
  const { email: dealerEmail } = await userRes.json();
  if (!dealerEmail) return res.status(401).json({ error: 'E-Mail nicht ermittelbar' });

  // ── Body ───────────────────────────────────────────────────────────────────
  let b;
  try { b = typeof req.body === 'string' ? JSON.parse(req.body) : req.body; }
  catch { return res.status(400).json({ error: 'Ungültiger JSON-Body' }); }

  // ── Validierung ────────────────────────────────────────────────────────────
  const errs = [];
  if (!b.ftp_host?.trim()) errs.push('FTP-Host fehlt');
  if (!b.ftp_user?.trim()) errs.push('FTP-Benutzer fehlt');
  if (!b.ftp_pass)         errs.push('FTP-Passwort fehlt');
  const port = parseInt(b.ftp_port);
  if (isNaN(port) || port < 1 || port > 65535) errs.push('Ungültiger Port');
  if (errs.length) return res.status(400).json({ error: errs.join(' | ') });

  // ── Verschlüsseln ──────────────────────────────────────────────────────────
  const enc = {
    ftp_host_enc: encrypt(b.ftp_host.trim()),
    ftp_user_enc: encrypt(b.ftp_user.trim()),
    ftp_pass_enc: encrypt(b.ftp_pass),
  };
  const hmac = sign(enc); // Integritätsprüfung über alle verschlüsselten Felder

  // ── Speichern ──────────────────────────────────────────────────────────────
  const record = {
    dealer_email:        dealerEmail,
    ...enc,
    hmac_signature:      hmac,
    ftp_port:            port,
    use_sftp:            b.use_sftp === true || b.use_sftp === 'true',
    passive_mode:        b.passive_mode !== false && b.passive_mode !== 'false',
    remote_path:         (b.remote_path || '/').trim(),
    filename_pattern:    (b.filename_pattern || '%.csv').trim(),
    sync_interval_hours: parseInt(b.sync_interval_hours) || 6,
    is_active:           true,
    updated_at:          new Date().toISOString()
  };

  try {
    const existing = await fetch(
      `${SUPA_URL}/rest/v1/dealer_ftp_configs?dealer_email=eq.${encodeURIComponent(dealerEmail)}&select=id`,
      { headers: { 'apikey': SUPA_KEY, 'Authorization': `Bearer ${SUPA_KEY}` } }
    );
    const rows = await existing.json();

    if (rows?.length > 0) {
      await supa(`dealer_ftp_configs?dealer_email=eq.${encodeURIComponent(dealerEmail)}`, 'PATCH', record);
    } else {
      await supa('dealer_ftp_configs', 'POST', record);
    }

    return res.status(200).json({
      success: true,
      message: 'FTP-Konfiguration sicher gespeichert',
      config: {
        ftp_host_masked:     b.ftp_host.slice(0, 4) + '****',
        ftp_user_masked:     b.ftp_user.slice(0, 2) + '****',
        ftp_port:            port,
        use_sftp:            record.use_sftp,
        passive_mode:        record.passive_mode,
        remote_path:         record.remote_path,
        sync_interval_hours: record.sync_interval_hours,
      }
    });
  } catch (err) {
    console.error('[save-ftp-config]', err.message);
    return res.status(500).json({ error: 'Datenbankfehler beim Speichern' });
  }
};
