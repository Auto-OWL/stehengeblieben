/**
 * stehengeblieben.de — FTP-Zugangsdaten speichern
 * POST /api/save-ftp-config
 *
 * Testet die FTP-Verbindung und prüft ob die angegebene Datei existiert,
 * BEVOR die Zugangsdaten gespeichert werden. Passwort wird AES-256-GCM
 * verschlüsselt in Supabase abgelegt.
 */

const { Client } = require('basic-ftp');
const crypto = require('crypto');

const SUPA_URL    = process.env.SUPABASE_URL;
const SUPA_KEY    = process.env.SUPABASE_SERVICE_KEY;
const ENC_KEY_HEX = process.env.FTP_ENCRYPTION_KEY;

function encryptPassword(plain) {
  const key = Buffer.from(ENC_KEY_HEX, 'hex');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let enc = cipher.update(plain, 'utf8', 'hex');
  enc += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');
  return `${iv.toString('hex')}:${tag}:${enc}`;
}

async function testFtpConnection({ host, port, user, password, secure, remotePath }) {
  const client = new Client(10000);
  client.ftp.verbose = false;
  try {
    await client.access({ host, port: port || 21, user, password, secure: !!secure });
    // Prüfen ob die Datei existiert (Größe abfragen)
    const size = await client.size(remotePath);
    return { ok: true, fileSize: size };
  } finally {
    client.close();
  }
}

async function supa(path, method, body) {
  const r = await fetch(`${SUPA_URL}/rest/v1/${path}`, {
    method,
    headers: { apikey: SUPA_KEY, Authorization: `Bearer ${SUPA_KEY}`, 'Content-Type': 'application/json', Prefer: 'return=minimal' },
    body: body ? JSON.stringify(body) : undefined
  });
  if (!r.ok) throw new Error(await r.text());
  return r;
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', 'https://stehengeblieben.de');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  if (!SUPA_URL || !SUPA_KEY || !ENC_KEY_HEX) return res.status(500).json({ error: 'Serverkonfiguration unvollständig' });

  const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ error: 'Nicht autorisiert' });
  const userRes = await fetch(`${SUPA_URL}/auth/v1/user`, { headers: { apikey: SUPA_KEY, Authorization: `Bearer ${token}` } });
  if (!userRes.ok) return res.status(401).json({ error: 'Ungültiger Token' });
  const { email: dealerEmail } = await userRes.json();
  if (!dealerEmail) return res.status(401).json({ error: 'E-Mail nicht gefunden' });

  let b;
  try { b = typeof req.body === 'string' ? JSON.parse(req.body) : req.body; }
  catch { return res.status(400).json({ error: 'Ungültiger JSON-Body' }); }

  const { ftp_host, ftp_port, ftp_user, ftp_password, ftp_secure, remote_path } = b;

  if (!ftp_host || !ftp_user || !ftp_password || !remote_path) {
    return res.status(400).json({ error: 'Bitte Host, Benutzername, Passwort und Dateipfad angeben' });
  }

  // Verbindung testen BEVOR gespeichert wird
  try {
    const test = await testFtpConnection({
      host: ftp_host.trim(), port: parseInt(ftp_port) || 21,
      user: ftp_user.trim(), password: ftp_password,
      secure: !!ftp_secure, remotePath: remote_path.trim(),
    });
    if (!test.ok) throw new Error('Verbindung fehlgeschlagen');
  } catch (e) {
    return res.status(400).json({ error: `FTP-Verbindung fehlgeschlagen: ${e.message}. Bitte Zugangsdaten und Dateipfad prüfen.` });
  }

  const record = {
    dealer_email: dealerEmail,
    ftp_host: ftp_host.trim(),
    ftp_port: parseInt(ftp_port) || 21,
    ftp_user: ftp_user.trim(),
    ftp_password_enc: encryptPassword(ftp_password),
    ftp_secure: !!ftp_secure,
    remote_path: remote_path.trim(),
    is_active: true,
    updated_at: new Date().toISOString(),
  };

  try {
    const existing = await fetch(
      `${SUPA_URL}/rest/v1/dealer_ftp_configs?dealer_email=eq.${encodeURIComponent(dealerEmail)}&select=id`,
      { headers: { apikey: SUPA_KEY, Authorization: `Bearer ${SUPA_KEY}` } }
    );
    const rows = await existing.json();

    if (rows?.length > 0) {
      await supa(`dealer_ftp_configs?dealer_email=eq.${encodeURIComponent(dealerEmail)}`, 'PATCH', record);
    } else {
      await supa('dealer_ftp_configs', 'POST', record);
    }

    return res.status(200).json({
      success: true,
      message: 'FTP-Verbindung erfolgreich getestet und gespeichert. Erster Sync startet in Kürze.',
    });
  } catch (err) {
    console.error('[save-ftp-config]', err.message);
    return res.status(500).json({ error: 'Datenbankfehler: ' + err.message });
  }
};  const port = parseInt(b.ftp_port);
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
