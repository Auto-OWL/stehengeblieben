/**
 * stehengeblieben.de — CSV-URL Konfiguration speichern
 * POST /api/save-csv-url
 *
 * Händler trägt die Autrado Download-URL ein.
 * URL wird validiert und in Supabase gespeichert.
 */

const SUPA_URL = process.env.SUPABASE_URL;
const SUPA_KEY = process.env.SUPABASE_SERVICE_KEY;

async function supa(path, method, body) {
  const r = await fetch(`${SUPA_URL}/rest/v1/${path}`, {
    method,
    headers: {
      'apikey': SUPA_KEY,
      'Authorization': `Bearer ${SUPA_KEY}`,
      'Content-Type': 'application/json',
      'Prefer': 'return=minimal'
    },
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

  if (!SUPA_URL || !SUPA_KEY) return res.status(500).json({ error: 'Serverkonfiguration unvollständig' });

  // Auth
  const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ error: 'Nicht autorisiert' });
  const userRes = await fetch(`${SUPA_URL}/auth/v1/user`, {
    headers: { 'apikey': SUPA_KEY, 'Authorization': `Bearer ${token}` }
  });
  if (!userRes.ok) return res.status(401).json({ error: 'Ungültiger Token' });
  const { email: dealerEmail } = await userRes.json();
  if (!dealerEmail) return res.status(401).json({ error: 'E-Mail nicht gefunden' });

  // Body
  let b;
  try { b = typeof req.body === 'string' ? JSON.parse(req.body) : req.body; }
  catch { return res.status(400).json({ error: 'Ungültiger JSON-Body' }); }

  const { csv_url, sync_interval_hours } = b;

  // Validierung
  if (!csv_url || !csv_url.startsWith('http')) {
    return res.status(400).json({ error: 'Bitte eine gültige HTTPS-URL eingeben' });
  }

  // URL kurz testen (HEAD request)
  try {
    const test = await fetch(csv_url, { method: 'HEAD' });
    if (!test.ok && test.status !== 405) {
      return res.status(400).json({ error: `URL nicht erreichbar (HTTP ${test.status})` });
    }
  } catch (e) {
    return res.status(400).json({ error: `URL nicht erreichbar: ${e.message}` });
  }

  const record = {
    dealer_email: dealerEmail,
    csv_url: csv_url.trim(),
    sync_interval_hours: parseInt(sync_interval_hours) || 6,
    is_active: true,
    updated_at: new Date().toISOString(),
  };

  try {
    // Prüfen ob bereits vorhanden
    const existing = await fetch(
      `${SUPA_URL}/rest/v1/dealer_csv_urls?dealer_email=eq.${encodeURIComponent(dealerEmail)}&select=id`,
      { headers: { 'apikey': SUPA_KEY, 'Authorization': `Bearer ${SUPA_KEY}` } }
    );
    const rows = await existing.json();

    if (rows?.length > 0) {
      await supa(`dealer_csv_urls?dealer_email=eq.${encodeURIComponent(dealerEmail)}`, 'PATCH', record);
    } else {
      await supa('dealer_csv_urls', 'POST', record);
    }

    return res.status(200).json({
      success: true,
      message: 'CSV-URL gespeichert. Erster Sync startet in Kürze.',
      csv_url: csv_url.trim(),
      sync_interval_hours: record.sync_interval_hours
    });
  } catch (err) {
    console.error('[save-csv-url]', err.message);
    return res.status(500).json({ error: 'Datenbankfehler: ' + err.message });
  }
};
