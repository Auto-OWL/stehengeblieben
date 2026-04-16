/**
 * stehengeblieben.de — FTP Sync Engine
 * POST /api/ftp-sync
 * POST /api/ftp-sync?dealer=email   → einzelnen Händler
 * GET  /api/ftp-sync?dealer=email   → Status abfragen
 *
 * Sync-Logik:
 *   interne_nummer in CSV + nicht in DB  → INSERT
 *   interne_nummer in CSV + in DB        → UPDATE wenn Preis/Daten geändert
 *   interne_nummer NICHT in CSV + in DB  → soft DELETE (status='sold')
 *   Kriterien nicht erfüllt              → skip + log
 */

const crypto    = require('crypto');
const FTPClient = require('basic-ftp').Client;

const SUPA_URL    = process.env.SUPABASE_URL;
const SUPA_KEY    = process.env.SUPABASE_SERVICE_KEY;
const ENC_KEY     = process.env.FTP_ENCRYPTION_KEY;
const HMAC_SECRET = process.env.FTP_HMAC_SECRET;
const CRON_SECRET = process.env.CRON_SECRET; // optionaler Schutz für Cron-Aufrufe

// Validierungsregeln
const MIN_DISCOUNT_PCT = 20;
const MAX_AGE_MONTHS   = 24;

// ── Entschlüsselung ───────────────────────────────────────────────────────────
function decrypt(ciphertext) {
  const key     = Buffer.from(ENC_KEY, 'hex');
  const iv      = Buffer.from(ciphertext.slice(0, 32), 'hex');
  const tag     = Buffer.from(ciphertext.slice(32, 64), 'hex');
  const enc     = Buffer.from(ciphertext.slice(64), 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return decipher.update(enc) + decipher.final('utf8');
}

// ── HMAC verifizieren ─────────────────────────────────────────────────────────
function verifyHmac(data, signature) {
  const expected = crypto
    .createHmac('sha256', Buffer.from(HMAC_SECRET, 'hex'))
    .update(JSON.stringify(data))
    .digest('hex');
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
}

// ── Supabase Helper ───────────────────────────────────────────────────────────
async function supaGet(path) {
  const r = await fetch(`${SUPA_URL}/rest/v1/${path}`, {
    headers: { 'apikey': SUPA_KEY, 'Authorization': `Bearer ${SUPA_KEY}` }
  });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}
async function supaPost(path, body) {
  const r = await fetch(`${SUPA_URL}/rest/v1/${path}`, {
    method: 'POST',
    headers: {
      'apikey': SUPA_KEY, 'Authorization': `Bearer ${SUPA_KEY}`,
      'Content-Type': 'application/json', 'Prefer': 'return=minimal'
    },
    body: JSON.stringify(body)
  });
  if (!r.ok) throw new Error(await r.text());
}
async function supaPatch(path, body) {
  const r = await fetch(`${SUPA_URL}/rest/v1/${path}`, {
    method: 'PATCH',
    headers: {
      'apikey': SUPA_KEY, 'Authorization': `Bearer ${SUPA_KEY}`,
      'Content-Type': 'application/json', 'Prefer': 'return=minimal'
    },
    body: JSON.stringify(body)
  });
  if (!r.ok) throw new Error(await r.text());
}

// ── Mobile.de CSV Parser ──────────────────────────────────────────────────────
// Felder laut Mobile.de Extended CSV Spec (Feldnummern 0-642)
function parseCSV(csvText) {
  // ISO-8859-15 → bereits als UTF-8 gelesen, Semikolon-getrennt
  const lines = csvText.split('\n').map(l => l.trim()).filter(l => l.length > 0);
  const vehicles = [];

  for (const line of lines) {
    // Felder mit Semikolon trennen, Anführungszeichen beachten
    const fields = [];
    let current = '';
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (c === '"') {
        if (inQuotes && line[i+1] === '"') { current += '"'; i++; } // escaped quote
        else inQuotes = !inQuotes;
      } else if (c === ';' && !inQuotes) {
        fields.push(current.trim()); current = '';
      } else {
        current += c;
      }
    }
    fields.push(current.trim());

    if (fields.length < 15) continue; // zu wenig Felder → überspringen

    // Mobile.de Extended CSV Feldmapping
    const raw = {
      internal_id:       fields[1]  || '',   // interne_nummer (Pflicht, eindeutig)
      category:          fields[2]  || '',   // kategorie
      brand:             fields[3]  || '',   // marke
      model:             fields[4]  || '',   // modell
      power_kw:          fields[5]  || '',   // leistung KW
      first_reg:         fields[8]  || '',   // ez (Erstzulassung MM.JJJJ)
      mileage:           fields[9]  || '0',  // kilometer
      price:             fields[10] || '0',  // preis (Inseratspreis)
      color:             fields[16] || '',   // farbe
      is_day_reg:        fields[112] === '1', // tageszulassung
      fuel_raw:          fields[109] || '0', // kraftstoffart (1=Benzin, 2=Diesel, etc.)
      trans_raw:         fields[110] || '0', // getriebeart (1=Schalt, 2=Halb, 3=Auto)
      description:       fields[25] || '',   // bemerkung
      doors:             fields[42] || '',   // tueren
      seats:             fields[60] || '',   // sitze
      list_price_uvp:    fields[287] || '0', // ehem. preisempfehlung UVP (Feld 287)
      variant:           fields[288] || '',  // ausstattungslinie
      // Ausstattungsmerkmale aus 0/1 Feldern
      has_navi:          fields[37] === '1',
      has_climate:       ['1','2'].includes(fields[17]),
      has_climate_auto:  fields[17] === '2',
      has_abs:           fields[33] === '1',
      has_esp:           fields[32] === '1',
      has_alu:           fields[31] === '1',
      has_ahk:           fields[34] === '1',
      has_sunroof:       fields[38] === '1',
      has_pdc_front:     fields[199] === '1',
      has_pdc_rear:      fields[200] === '1',
      has_pdc_camera:    fields[201] === '1',
      has_bluetooth:     fields[174] === '1',
      has_cruise:        fields[64] === '1',
      has_acc:           fields[251] === '1',
      has_led:           fields[252] === '1',
      has_xenon:         fields[100] === '1',
      has_seat_heat:     fields[101] === '1',
      has_seat_heat_rear:fields[215] === '1',
      has_android_auto:  fields[221] === '1',
      has_carplay:       fields[222] === '1',
      has_wireless_charge:fields[223] === '1',
      has_head_up:       fields[178] === '1',
      has_lane_assist:   fields[250] === '1',
      has_night_vision:  fields[269] === '1',
      has_360_camera:    fields[284] === '1',
      has_panorama:      fields[185] === '1',
      has_leather:       fields[156] === '1' || fields[156] === '2',
      has_sport_seats:   fields[184] === '1',
      has_heated_steering:fields[248] === '1',
      has_keyless:       fields[280] === '1',
      has_elec_tailgate: fields[261] === '1',
      has_dab:           fields[260] === '1',
      emission_class:    fields[61]  || '',  // schadstoff 1-7=Euro1-7
      co2_emission:      fields[99]  || '',  // emission g/km
      consumption_combined: fields[98] || '', // verbrauch kombiniert
      energy_efficiency: fields[169] || '',  // energieeffizienzklasse
    };

    // Kraftstoff mappen
    const fuelMap = {'1':'Benzin','2':'Diesel','3':'Autogas','4':'Erdgas',
                     '6':'Elektro','7':'Hybrid','8':'Wasserstoff','10':'Hybrid-Diesel','0':'Andere'};
    const transMap = {'1':'Schaltgetriebe','2':'Halbautomatik','3':'Automatik','0':'Andere'};

    // Datum parsen: MM.JJJJ oder TT.MM.JJJJ → YYYY-MM-DD
    function parseDate(d) {
      if (!d) return null;
      const s = d.replace(/['"]/g, '').trim();
      const m2 = s.match(/^(\d{2})\.(\d{4})$/);
      if (m2) return `${m2[2]}-${m2[1]}-01`;
      const m3 = s.match(/^(\d{2})\.(\d{2})\.(\d{4})$/);
      if (m3) return `${m3[3]}-${m3[2]}-${m3[1]}`;
      return null;
    }

    // Preis bereinigen (Komma → Punkt)
    function parsePrice(v) { return parseFloat(String(v).replace(',','.')) || 0; }

    // Ausstattungs-Array aufbauen
    const equipment = [];
    if (raw.has_navi)          equipment.push('Navigationssystem');
    if (raw.has_climate_auto)  equipment.push('Klimaautomatik');
    else if (raw.has_climate)  equipment.push('Klimaanlage');
    if (raw.has_abs)           equipment.push('ABS');
    if (raw.has_esp)           equipment.push('ESP');
    if (raw.has_alu)           equipment.push('Leichtmetallfelgen');
    if (raw.has_ahk)           equipment.push('Anhängerkupplung');
    if (raw.has_sunroof)       equipment.push('Schiebedach');
    if (raw.has_pdc_camera)    equipment.push('Einparkhilfe Kamera');
    else if (raw.has_pdc_rear) equipment.push('Einparkhilfe hinten');
    if (raw.has_pdc_front)     equipment.push('Einparkhilfe vorne');
    if (raw.has_bluetooth)     equipment.push('Bluetooth');
    if (raw.has_cruise)        equipment.push('Tempomat');
    if (raw.has_acc)           equipment.push('Abstandstempomat (ACC)');
    if (raw.has_led)           equipment.push('LED-Scheinwerfer');
    if (raw.has_xenon)         equipment.push('Xenon-Scheinwerfer');
    if (raw.has_seat_heat)     equipment.push('Sitzheizung vorne');
    if (raw.has_seat_heat_rear)equipment.push('Sitzheizung hinten');
    if (raw.has_android_auto)  equipment.push('Android Auto');
    if (raw.has_carplay)       equipment.push('Apple CarPlay');
    if (raw.has_wireless_charge)equipment.push('Induktionsladen');
    if (raw.has_head_up)       equipment.push('Head-Up Display');
    if (raw.has_lane_assist)   equipment.push('Spurhalteassistent');
    if (raw.has_night_vision)  equipment.push('Nachtsicht-Assistent');
    if (raw.has_360_camera)    equipment.push('360°-Kamera');
    if (raw.has_panorama)      equipment.push('Panoramadach');
    if (raw.has_leather)       equipment.push('Lederausstattung');
    if (raw.has_sport_seats)   equipment.push('Sportsitze');
    if (raw.has_heated_steering)equipment.push('Beheizbares Lenkrad');
    if (raw.has_keyless)       equipment.push('Keyless Entry');
    if (raw.has_elec_tailgate) equipment.push('Elektrische Heckklappe');
    if (raw.has_dab)           equipment.push('DAB Radio');

    vehicles.push({
      internal_id:       raw.internal_id,
      brand:             raw.brand,
      model:             raw.model,
      variant:           raw.variant || raw.description?.slice(0, 100) || null,
      first_registration: parseDate(raw.first_reg),
      mileage:           parseInt(raw.mileage) || 0,
      fuel_type:         fuelMap[raw.fuel_raw] || 'Benzin',
      transmission:      transMap[raw.trans_raw] || 'Automatik',
      color:             raw.color || null,
      list_price:        parsePrice(raw.list_price_uvp),
      price:             parsePrice(raw.price),
      description:       raw.description || null,
      is_day_registration: raw.is_day_reg,
      doors:             parseInt(raw.doors) || null,
      seats:             parseInt(raw.seats) || null,
      equipment:         equipment,
      power_kw:          parseInt(raw.power_kw) || null,
      co2_emission:      parseInt(raw.co2_emission) || null,
      consumption_combined: parsePrice(raw.consumption_combined) || null,
      energy_efficiency: raw.energy_efficiency || null,
    });
  }

  return vehicles;
}

// ── Validierung gegen stehengeblieben.de Kriterien ────────────────────────────
function validate(v) {
  const reasons = [];

  if (!v.brand || !v.model) {
    reasons.push('Marke oder Modell fehlt');
    return { valid: false, reasons };
  }
  if (!v.first_registration) {
    reasons.push('Erstzulassung fehlt (Pflichtfeld)');
    return { valid: false, reasons };
  }
  if (!v.list_price || v.list_price <= 0) {
    reasons.push('Listenneupreis fehlt oder ungültig (Pflichtfeld)');
    return { valid: false, reasons };
  }
  if (!v.price || v.price <= 0) {
    reasons.push('Inseratspreis fehlt oder ungültig (Pflichtfeld)');
    return { valid: false, reasons };
  }
  if (v.price >= v.list_price) {
    reasons.push(`Inseratspreis (${v.price}€) muss unter Listenpreis (${v.list_price}€) liegen`);
  }

  const discPct = ((v.list_price - v.price) / v.list_price) * 100;
  if (discPct < MIN_DISCOUNT_PCT) {
    reasons.push(`Nachlass ${discPct.toFixed(1)}% unter dem Minimum von ${MIN_DISCOUNT_PCT}%`);
  }

  const regDate = new Date(v.first_registration);
  const now = new Date();
  const monthsOld = (now.getFullYear() - regDate.getFullYear()) * 12
                  + (now.getMonth() - regDate.getMonth());
  if (monthsOld > MAX_AGE_MONTHS) {
    reasons.push(`Fahrzeug ${monthsOld} Monate alt — Maximum ${MAX_AGE_MONTHS} Monate`);
  }
  if (regDate > now) {
    reasons.push('Erstzulassung liegt in der Zukunft');
  }

  if (reasons.length > 0) return { valid: false, reasons };

  v.discount_pct = Math.round(discPct * 10) / 10;
  return { valid: true, reasons: [] };
}

// ── FTP Download ──────────────────────────────────────────────────────────────
async function downloadCSV(config) {
  const client = new FTPClient();
  client.ftp.verbose = false;
  client.ftp.timeout = 30000; // 30s Timeout

  try {
    await client.access({
      host:     config.host,
      port:     config.port,
      user:     config.user,
      password: config.pass,
      secure:   config.use_sftp, // TLS/FTPS
      secureOptions: { rejectUnauthorized: false }
    });

    if (config.passive_mode) {
      client.ftp.pasv = true;
    }

    // In Verzeichnis wechseln
    if (config.remote_path && config.remote_path !== '/') {
      await client.cd(config.remote_path);
    }

    // Neueste CSV-Datei finden die dem Pattern entspricht
    const list = await client.list();
    const pattern = config.filename_pattern.replace('%', '.*').replace('?', '.');
    const regex = new RegExp(pattern, 'i');
    const csvFiles = list
      .filter(f => f.type === 1 && regex.test(f.name)) // type 1 = file
      .sort((a, b) => b.modifiedAt - a.modifiedAt);    // neueste zuerst

    if (csvFiles.length === 0) throw new Error('Keine CSV-Datei im FTP-Verzeichnis gefunden');

    // Datei als Buffer herunterladen
    const chunks = [];
    const writable = {
      write(chunk) { chunks.push(chunk); return true; },
      end() {},
      on() { return this; },
      once() { return this; },
      emit() {},
    };

    // basic-ftp erwartet einen Writable Stream
    const { Writable } = require('stream');
    const bufferStream = new Writable({
      write(chunk, encoding, callback) {
        chunks.push(chunk);
        callback();
      }
    });

    await client.downloadTo(bufferStream, csvFiles[0].name);
    return Buffer.concat(chunks).toString('latin1'); // ISO-8859-15 → latin1

  } finally {
    client.close();
  }
}

// ── Haupt-Sync Funktion ───────────────────────────────────────────────────────
async function syncDealer(ftpConfig, dealerEmail) {
  const startTime = Date.now();
  const stats = { imported: 0, updated: 0, deleted: 0, skipped: 0, skipped_reasons: [] };

  // HMAC verifizieren bevor wir entschlüsseln
  const encFields = {
    ftp_host_enc: ftpConfig.ftp_host_enc,
    ftp_user_enc: ftpConfig.ftp_user_enc,
    ftp_pass_enc: ftpConfig.ftp_pass_enc,
  };
  if (!verifyHmac(encFields, ftpConfig.hmac_signature)) {
    throw new Error('HMAC-Verifikation fehlgeschlagen — Konfiguration wurde möglicherweise verändert');
  }

  // Entschlüsseln (nur im RAM, nie loggen)
  const credentials = {
    host:         decrypt(ftpConfig.ftp_host_enc),
    user:         decrypt(ftpConfig.ftp_user_enc),
    pass:         decrypt(ftpConfig.ftp_pass_enc),
    port:         ftpConfig.ftp_port,
    use_sftp:     ftpConfig.use_sftp,
    passive_mode: ftpConfig.passive_mode,
    remote_path:  ftpConfig.remote_path,
    filename_pattern: ftpConfig.filename_pattern,
  };

  // CSV herunterladen
  const csvText = await downloadCSV(credentials);

  // Credentials sofort aus dem Scope entfernen
  credentials.pass = null;

  // CSV parsen
  const csvVehicles = parseCSV(csvText);
  if (csvVehicles.length === 0) throw new Error('CSV enthält keine verwertbaren Fahrzeuge');

  // Bestehende Fahrzeuge dieses Händlers aus Supabase laden
  const existing = await supaGet(
    `vehicles?dealer_email=eq.${encodeURIComponent(dealerEmail)}&select=id,internal_id,price,list_price,discount_pct,status&status=neq.deleted`
  );
  const existingMap = new Map(existing.map(v => [v.internal_id, v]));
  const csvIds = new Set();

  // Jedes CSV-Fahrzeug verarbeiten
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
      dealer_email: dealerEmail,
      status:       'active',
      source:       'ftp_sync',
      updated_at:   new Date().toISOString(),
    };
    delete record.internal_id; // nicht nochmal als Feld speichern

    const existingVehicle = existingMap.get(v.internal_id);

    if (!existingVehicle) {
      // NEU → INSERT
      await supaPost('vehicles', {
        ...record,
        internal_id: v.internal_id,
        created_at: new Date().toISOString(),
      });
      stats.imported++;
    } else if (
      parseFloat(existingVehicle.price) !== v.price ||
      parseFloat(existingVehicle.list_price) !== v.list_price ||
      parseFloat(existingVehicle.discount_pct) !== v.discount_pct
    ) {
      // GEÄNDERT → UPDATE
      await supaPatch(
        `vehicles?id=eq.${existingVehicle.id}`,
        { ...record, internal_id: v.internal_id }
      );
      stats.updated++;
    }
    // GLEICH → nichts tun
  }

  // GELÖSCHT → Fahrzeuge die nicht mehr in CSV sind auf 'sold' setzen
  for (const [internalId, existing] of existingMap) {
    if (!csvIds.has(internalId) && existing.status === 'active') {
      await supaPatch(`vehicles?id=eq.${existing.id}`, {
        status:     'sold',
        updated_at: new Date().toISOString()
      });
      stats.deleted++;
    }
  }

  const duration = Date.now() - startTime;

  // Sync-Status in dealer_ftp_configs updaten
  await supaPatch(
    `dealer_ftp_configs?dealer_email=eq.${encodeURIComponent(dealerEmail)}`,
    {
      last_sync_at:       new Date().toISOString(),
      last_sync_status:   'success',
      last_sync_message:  `${stats.imported} neu, ${stats.updated} aktualisiert, ${stats.deleted} entfernt, ${stats.skipped} übersprungen`,
      last_sync_imported: stats.imported,
      last_sync_updated:  stats.updated,
      last_sync_deleted:  stats.deleted,
      last_sync_skipped:  stats.skipped,
    }
  );

  // Sync-Log schreiben
  await supaPost('ftp_sync_logs', {
    dealer_email:    dealerEmail,
    status:          'success',
    imported:        stats.imported,
    updated:         stats.updated,
    deleted:         stats.deleted,
    skipped:         stats.skipped,
    skipped_reasons: stats.skipped_reasons.slice(0, 50), // max 50 Einträge loggen
    duration_ms:     duration,
  });

  return stats;
}

// ── Request Handler ───────────────────────────────────────────────────────────
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', 'https://stehengeblieben.de');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Cron-Secret');
  if (req.method === 'OPTIONS') return res.status(200).end();

  if (!ENC_KEY || !HMAC_SECRET || !SUPA_URL || !SUPA_KEY)
    return res.status(500).json({ error: 'Serverkonfiguration unvollständig' });

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

    const config = await supaGet(
      `dealer_ftp_configs?dealer_email=eq.${encodeURIComponent(email)}&select=ftp_port,use_sftp,passive_mode,remote_path,sync_interval_hours,last_sync_at,last_sync_status,last_sync_message,last_sync_imported,last_sync_updated,last_sync_deleted,last_sync_skipped,is_active`
    );
    const logs = await supaGet(
      `ftp_sync_logs?dealer_email=eq.${encodeURIComponent(email)}&order=synced_at.desc&limit=10&select=synced_at,status,imported,updated,deleted,skipped,error_message,duration_ms`
    );
    return res.status(200).json({ config: config[0] || null, logs });
  }

  // ── POST: Sync ausführen ───────────────────────────────────────────────────
  if (req.method === 'POST') {
    // Auth: entweder Cron-Secret (automatisch) oder Händler-JWT (manuell)
    const cronSecret = req.headers['x-cron-secret'];
    let dealerEmail = null;

    if (cronSecret) {
      // Automatischer Cron-Aufruf
      if (CRON_SECRET && cronSecret !== CRON_SECRET)
        return res.status(401).json({ error: 'Ungültiges Cron-Secret' });
      dealerEmail = targetDealer;
    } else {
      // Manueller Aufruf durch Händler
      const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
      if (!token) return res.status(401).json({ error: 'Nicht autorisiert' });
      const userRes = await fetch(`${SUPA_URL}/auth/v1/user`, {
        headers: { 'apikey': SUPA_KEY, 'Authorization': `Bearer ${token}` }
      });
      if (!userRes.ok) return res.status(401).json({ error: 'Ungültiger Token' });
      const userData = await userRes.json();
      dealerEmail = userData.email;
    }

    // Konfigurationen laden
    const query = dealerEmail
      ? `dealer_ftp_configs?dealer_email=eq.${encodeURIComponent(dealerEmail)}&is_active=eq.true`
      : `dealer_ftp_configs?is_active=eq.true`;

    const configs = await supaGet(query);
    if (configs.length === 0)
      return res.status(404).json({ error: 'Keine aktive FTP-Konfiguration gefunden' });

    const results = [];

    for (const config of configs) {
      try {
        const stats = await syncDealer(config, config.dealer_email);
        results.push({ dealer: config.dealer_email, success: true, ...stats });
      } catch (err) {
        console.error(`[ftp-sync] Fehler für ${config.dealer_email}:`, err.message);

        // Fehler in DB loggen
        try {
          await supaPatch(
            `dealer_ftp_configs?dealer_email=eq.${encodeURIComponent(config.dealer_email)}`,
            { last_sync_at: new Date().toISOString(), last_sync_status: 'error', last_sync_message: err.message }
          );
          await supaPost('ftp_sync_logs', {
            dealer_email:  config.dealer_email,
            status:        'error',
            error_message: err.message,
            duration_ms:   0,
          });
        } catch (logErr) {
          console.error('[ftp-sync] Log-Fehler:', logErr.message);
        }

        results.push({ dealer: config.dealer_email, success: false, error: err.message });
      }
    }

    return res.status(200).json({ synced: results.length, results });
  }

  return res.status(405).json({ error: 'Method not allowed' });
};
