/**
 * stehengeblieben.de — Autrado CSV-URL Sync
 * ─────────────────────────────────────────
 * GET  /api/csv-url-sync              → Status aller konfigurierten URLs
 * POST /api/csv-url-sync              → Manueller Sync (alle oder einzeln)
 * POST /api/csv-url-sync?dealer=EMAIL → Einzelnen Händler syncen
 *
 * Vercel Cron: läuft automatisch alle 6 Stunden
 * Ablauf:
 *   1. Lädt alle aktiven CSV-URLs aus Supabase (dealer_csv_urls Tabelle)
 *   2. Fetched die CSV-Datei von der Autrado-URL
 *   3. Parst Mobile.de Extended CSV
 *   4. Sync: Neu → INSERT | Geändert → UPDATE | Weg → soft DELETE | Gleich → skip
 *   5. Schreibt Ergebnis in sync_logs
 */

const SUPA_URL  = process.env.SUPABASE_URL;
const SUPA_KEY  = process.env.SUPABASE_SERVICE_KEY;
const CRON_SECRET = process.env.CRON_SECRET;

// Validierungsregeln (identisch mit manuellem Import)
const MIN_DISCOUNT_PCT = 20;
const MAX_AGE_MONTHS   = 24;

// ── Supabase Helper ───────────────────────────────────────────────────────────
async function supaGet(path) {
  const r = await fetch(`${SUPA_URL}/rest/v1/${path}`, {
    headers: { 'apikey': SUPA_KEY, 'Authorization': `Bearer ${SUPA_KEY}` }
  });
  if (!r.ok) throw new Error(`Supabase GET ${path}: ${await r.text()}`);
  return r.json();
}

async function supaPost(path, body) {
  const r = await fetch(`${SUPA_URL}/rest/v1/${path}`, {
    method: 'POST',
    headers: {
      'apikey': SUPA_KEY,
      'Authorization': `Bearer ${SUPA_KEY}`,
      'Content-Type': 'application/json',
      'Prefer': 'return=minimal'
    },
    body: JSON.stringify(body)
  });
  if (!r.ok) throw new Error(`Supabase POST ${path}: ${await r.text()}`);
}

async function supaPatch(path, body) {
  const r = await fetch(`${SUPA_URL}/rest/v1/${path}`, {
    method: 'PATCH',
    headers: {
      'apikey': SUPA_KEY,
      'Authorization': `Bearer ${SUPA_KEY}`,
      'Content-Type': 'application/json',
      'Prefer': 'return=minimal'
    },
    body: JSON.stringify(body)
  });
  if (!r.ok) throw new Error(`Supabase PATCH ${path}: ${await r.text()}`);
}

// ── CSV Download ──────────────────────────────────────────────────────────────
async function downloadCSV(url) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000); // 30s timeout
  try {
    const r = await fetch(url, {
      signal: controller.signal,
      headers: { 'User-Agent': 'stehengeblieben.de/1.0 CSV-Importer' }
    });
    if (!r.ok) throw new Error(`HTTP ${r.status} beim Abrufen der CSV`);
    const text = await r.text();
    if (!text || text.length < 100) throw new Error('CSV-Datei ist leer oder zu klein');
    return text;
  } finally {
    clearTimeout(timeout);
  }
}

// ── Mobile.de Extended CSV Parser ────────────────────────────────────────────
function parseCSV(csvText) {
  const lines = csvText.split('\n').map(l => l.trim()).filter(l => l.length > 5);
  const vehicles = [];

  for (const line of lines) {
    // Semikolon-getrennt, Anführungszeichen beachten
    const fields = [];
    let current = '';
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (c === '"') {
        if (inQuotes && line[i + 1] === '"') { current += '"'; i++; }
        else inQuotes = !inQuotes;
      } else if (c === ';' && !inQuotes) {
        fields.push(current.trim());
        current = '';
      } else {
        current += c;
      }
    }
    fields.push(current.trim());

    if (fields.length < 15) continue;

    function p(v) { return parseFloat(String(v || '0').replace(',', '.')) || 0; }
    function parseDate(d) {
      if (!d) return null;
      const s = String(d).replace(/['"]/g, '').trim();
      const m2 = s.match(/^(\d{2})\.(\d{4})$/);
      if (m2) return `${m2[2]}-${m2[1]}-01`;
      const m3 = s.match(/^(\d{2})\.(\d{2})\.(\d{4})$/);
      if (m3) return `${m3[3]}-${m3[2]}-${m3[1]}`;
      return null;
    }

    const fuelMap = { '1': 'Benzin', '2': 'Diesel', '3': 'Autogas', '4': 'Erdgas', '6': 'Elektro', '7': 'Hybrid', '8': 'Wasserstoff', '10': 'Hybrid-Diesel', '0': 'Andere' };
    const transMap = { '1': 'Schaltgetriebe', '2': 'Halbautomatik', '3': 'Automatik', '0': 'Andere' };

    vehicles.push({
      internal_id:        fields[1] || '',
      brand:              fields[3] || '',
      model:              fields[4] || '',
      price:              p(fields[10]),
      list_price:         p(fields[287]) || p(fields[10]),
      first_registration: parseDate(fields[8]),
      mileage:            parseInt(fields[9]) || 0,
      fuel_type:          fuelMap[fields[109]] || 'Benzin',
      transmission:       transMap[fields[110]] || 'Automatik',
      color:              fields[16] || null,
      description:        fields[25] || null,
      is_day_registration: fields[112] === '1',
    });
  }
  return vehicles;
}

// ── Validierung ───────────────────────────────────────────────────────────────
function validate(v) {
  const reasons = [];
  if (!v.brand || !v.model)           reasons.push('Marke/Modell fehlt');
  if (!v.first_registration)          reasons.push('Erstzulassung fehlt');
  if (!v.list_price || v.list_price <= 0) reasons.push('Listenpreis fehlt');
  if (!v.price || v.price <= 0)       reasons.push('Preis fehlt');
  if (reasons.length) return { valid: false, reasons };

  if (v.price >= v.list_price)        reasons.push('Preis >= Listenpreis');

  const disc = ((v.list_price - v.price) / v.list_price) * 100;
  if (disc < MIN_DISCOUNT_PCT)        reasons.push(`Nachlass ${disc.toFixed(1)}% < ${MIN_DISCOUNT_PCT}%`);

  const reg = new Date(v.first_registration);
  const now = new Date();
  const months = (now.getFullYear() - reg.getFullYear()) * 12 + (now.getMonth() - reg.getMonth());
  if (reg > now)      reasons.push('EZ in der Zukunft');
  if (months > MAX_AGE_MONTHS) reasons.push(`${months} Monate alt > ${MAX_AGE_MONTHS}`);

  if (reasons.length) return { valid: false, reasons };
  v.discount_pct = Math.round(disc * 10) / 10;
  return { valid: true, reasons: [] };
}

// ── Haupt-Sync ────────────────────────────────────────────────────────────────
async function syncDealer(config) {
  const start = Date.now();
  const stats = { imported: 0, updated: 0, deleted: 0, skipped: 0, skipped_reasons: [] };

  // 1. CSV herunterladen
  const csvText = await downloadCSV(config.csv_url);

  // 2. Parsen
  const csvVehicles = parseCSV(csvText);
  if (csvVehicles.length === 0) throw new Error('CSV enthält keine verwertbaren Fahrzeuge');

  // 3. Bestehende Fahrzeuge dieses Händlers laden
  const existing = await supaGet(
    `vehicles?dealer_email=eq.${encodeURIComponent(config.dealer_email)}&select=id,internal_id,price,list_price,discount_pct,status&status=neq.deleted`
  );
  const existingMap = new Map(existing.map(v => [v.internal_id, v]));
  const csvIds = new Set();

  // 4. Jedes CSV-Fahrzeug verarbeiten
  for (const v of csvVehicles) {
    if (!v.internal_id) { stats.skipped++; continue; }
    csvIds.add(v.internal_id);

    const { valid, reasons } = validate(v);
    if (!valid) {
      stats.skipped++;
      stats.skipped_reasons.push({ id: v.internal_id, brand: v.brand, model: v.model, reasons });
      continue;
    }

    const record = {
      ...v,
      dealer_email: config.dealer_email,
      status: 'active',
      source: 'csv_url_sync',
      updated_at: new Date().toISOString(),
    };
    delete record.internal_id;

    const ex = existingMap.get(v.internal_id);
    if (!ex) {
      await supaPost('vehicles', { ...record, internal_id: v.internal_id, created_at: new Date().toISOString() });
      stats.imported++;
    } else if (parseFloat(ex.price) !== v.price || parseFloat(ex.list_price) !== v.list_price) {
      await supaPatch(`vehicles?id=eq.${ex.id}`, { ...record, internal_id: v.internal_id });
      stats.updated++;
    }
    // Unverändert → nichts tun
  }

  // 5. Nicht mehr in CSV → soft DELETE
  for (const [internalId, ex] of existingMap) {
    if (!csvIds.has(internalId) && ex.status === 'active') {
      await supaPatch(`vehicles?id=eq.${ex.id}`, { status: 'sold', updated_at: new Date().toISOString() });
      stats.deleted++;
    }
  }

  const duration = Date.now() - start;

  // 6. Status aktualisieren
  await supaPatch(
    `dealer_csv_urls?dealer_email=eq.${encodeURIComponent(config.dealer_email)}`,
    {
      last_sync_at: new Date().toISOString(),
      last_sync_status: 'success',
      last_sync_message: `+${stats.imported} neu · ↺${stats.updated} aktualisiert · −${stats.deleted} entfernt · ${stats.skipped} übersprungen`,
      last_sync_imported: stats.imported,
      last_sync_updated: stats.updated,
      last_sync_deleted: stats.deleted,
      last_sync_skipped: stats.skipped,
    }
  );

  // 7. Log schreiben
  await supaPost('csv_sync_logs', {
    dealer_email: config.dealer_email,
    csv_url: config.csv_url,
    status: 'success',
    ...stats,
    skipped_reasons: stats.skipped_reasons.slice(0, 50),
    duration_ms: duration,
  });

  return stats;
}

// ── Request Handler ───────────────────────────────────────────────────────────
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', 'https://stehengeblieben.de');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Cron-Secret');
  if (req.method === 'OPTIONS') return res.status(200).end();

  if (!SUPA_URL || !SUPA_KEY) return res.status(500).json({ error: 'Serverkonfiguration unvollständig' });

  const targetDealer = req.query.dealer || null;

  // ── GET: Status abfragen ───────────────────────────────────────────────────
  if (req.method === 'GET') {
    const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
    if (!token) return res.status(401).json({ error: 'Nicht autorisiert' });
    const userRes = await fetch(`${SUPA_URL}/auth/v1/user`, {
      headers: { 'apikey': SUPA_KEY, 'Authorization': `Bearer ${token}` }
    });
    if (!userRes.ok) return res.status(401).json({ error: 'Ungültiger Token' });
    const { email } = await userRes.json();

    try {
      const configs = await supaGet(
        `dealer_csv_urls?dealer_email=eq.${encodeURIComponent(email)}&select=csv_url,sync_interval_hours,last_sync_at,last_sync_status,last_sync_message,last_sync_imported,last_sync_updated,last_sync_deleted,last_sync_skipped,is_active`
      );
      const logs = await supaGet(
        `csv_sync_logs?dealer_email=eq.${encodeURIComponent(email)}&order=synced_at.desc&limit=10`
      );
      return res.status(200).json({ config: configs[0] || null, logs });
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  }

  // ── POST: Sync ausführen ───────────────────────────────────────────────────
  if (req.method === 'POST') {
    // Auth: Cron-Secret (automatisch) oder Händler-JWT (manuell)
    const cronSecret = req.headers['x-cron-secret'];
    let dealerEmail = null;

    if (cronSecret) {
      if (CRON_SECRET && cronSecret !== CRON_SECRET)
        return res.status(401).json({ error: 'Ungültiges Cron-Secret' });
      dealerEmail = targetDealer;
    } else {
      const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
      if (!token) return res.status(401).json({ error: 'Nicht autorisiert' });
      const userRes = await fetch(`${SUPA_URL}/auth/v1/user`, {
        headers: { 'apikey': SUPA_KEY, 'Authorization': `Bearer ${token}` }
      });
      if (!userRes.ok) return res.status(401).json({ error: 'Ungültiger Token' });
      const userData = await userRes.json();
      dealerEmail = userData.email;
    }

    // URLs laden
    const query = dealerEmail
      ? `dealer_csv_urls?dealer_email=eq.${encodeURIComponent(dealerEmail)}&is_active=eq.true`
      : `dealer_csv_urls?is_active=eq.true`;

    let configs;
    try { configs = await supaGet(query); }
    catch (e) { return res.status(500).json({ error: e.message }); }

    if (!configs || configs.length === 0)
      return res.status(404).json({ error: 'Keine aktive CSV-URL konfiguriert' });

    const results = [];
    for (const config of configs) {
      try {
        const stats = await syncDealer(config);
        results.push({ dealer: config.dealer_email, success: true, ...stats });
      } catch (err) {
        console.error(`[csv-url-sync] Fehler für ${config.dealer_email}:`, err.message);
        try {
          await supaPatch(
            `dealer_csv_urls?dealer_email=eq.${encodeURIComponent(config.dealer_email)}`,
            { last_sync_at: new Date().toISOString(), last_sync_status: 'error', last_sync_message: err.message }
          );
          await supaPost('csv_sync_logs', {
            dealer_email: config.dealer_email,
            csv_url: config.csv_url,
            status: 'error',
            error_message: err.message,
            duration_ms: 0,
          });
        } catch (logErr) { console.error('[csv-url-sync] Log-Fehler:', logErr.message); }
        results.push({ dealer: config.dealer_email, success: false, error: err.message });
      }
    }

    return res.status(200).json({ synced: results.length, results });
  }

  return res.status(405).json({ error: 'Method not allowed' });
};
