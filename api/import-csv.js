// api/import-csv.js
// Vercel Serverless Function — stehengeblieben.de CSV Import
// Kompatibel mit: Mobile-Extended Format, Stock2Net, Generic DMS CSV
// Kein FTP-Server nötig — Händler laden CSV direkt hoch

export const config = {
  api: {
    bodyParser: false, // Wir parsen den multipart/form-data selbst
  },
};

// ─── Feldmapping: DMS-Spaltennamen → internes Format ────────────────────────
// Unterstützt alle gängigen DMS-Exportformate (Autrado, Audaris, Loco-Soft)
const FIELD_MAP = {
  // Mobile-Extended Format
  'marke':              'brand',
  'make':               'brand',
  'hersteller':         'brand',
  'modell':             'model',
  'model':              'model',
  'fahrzeugbeschreibung': 'description',
  'description':        'description',
  'ez':                 'first_registration',
  'erstzulassung':      'first_registration',
  'first_registration': 'first_registration',
  'km':                 'mileage',
  'kilometerstand':     'mileage',
  'mileage':            'mileage',
  'preis':              'price',
  'price':              'price',
  'verkaufspreis':      'price',
  'uvp':                'list_price',
  'listenpreis':        'list_price',
  'list_price':         'list_price',
  'neupreis':           'list_price',
  'kraftstoff':         'fuel_type',
  'fuel':               'fuel_type',
  'fuel_type':          'fuel_type',
  'antrieb':            'drive_type',
  'getriebe':           'transmission',
  'transmission':       'transmission',
  'leistung_kw':        'power_kw',
  'leistung':           'power_kw',
  'ps':                 'power_ps',
  'kw':                 'power_kw',
  'farbe':              'color',
  'color':              'color',
  'aussenfarbe':        'color',
  'fin':                'vin',
  'vin':                'vin',
  'fahrgestellnummer':  'vin',
  'typ':                'body_type',
  'karosserieform':     'body_type',
  'body_type':          'body_type',
  'tageszulassung':     'is_day_registration',
  'day_registration':   'is_day_registration',
  'zulassungsdatum':    'registration_date',
  'hu':                 'next_inspection',
  'hauptuntersuchung':  'next_inspection',
  'ausstattung':        'equipment',
  'extras':             'equipment',
  'bilder':             'images',
  'images':             'images',
  'haendler_id':        'dealer_id',
  'dealer_id':          'dealer_id',
  'standort':           'location',
  'location':           'location',
  'innenfarbe':         'interior_color',
  'sitze':              'seats',
  'tueren':             'doors',
  'umweltplakette':     'emission_badge',
};

// ─── CSV Parser ──────────────────────────────────────────────────────────────
function parseCSV(csvText) {
  const lines = csvText.split(/\r?\n/).filter(l => l.trim());
  if (lines.length < 2) throw new Error('CSV leer oder kein Header gefunden');

  // Trennzeichen erkennen (Semikolon oder Komma)
  const firstLine = lines[0];
  const delimiter = firstLine.split(';').length > firstLine.split(',').length ? ';' : ',';

  // Header normalisieren
  const rawHeaders = lines[0].split(delimiter).map(h =>
    h.replace(/^["']|["']$/g, '').toLowerCase().trim()
  );

  const vehicles = [];
  const errors = [];

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) continue;

    // CSV-Zeile parsen (Anführungszeichen-aware)
    const values = parseCSVLine(line, delimiter);

    // Rohdaten → internes Format mappen
    const raw = {};
    rawHeaders.forEach((header, idx) => {
      const mappedKey = FIELD_MAP[header] || header;
      raw[mappedKey] = values[idx]?.replace(/^["']|["']$/g, '').trim() || '';
    });

    // Validierung
    const validation = validateVehicle(raw, i + 1);
    if (!validation.valid) {
      errors.push(validation.error);
      continue;
    }

    // Nachlass berechnen (Kernfeature!)
    const price = parseFloat(raw.price?.replace(',', '.').replace(/[^\d.]/g, '')) || 0;
    const listPrice = parseFloat(raw.list_price?.replace(',', '.').replace(/[^\d.]/g, '')) || 0;
    const discount_pct = listPrice > 0 && price > 0
      ? Math.round(((listPrice - price) / listPrice) * 100 * 10) / 10
      : 0;

    vehicles.push({
      ...raw,
      price: price,
      list_price: listPrice,
      discount_pct: discount_pct,
      is_day_registration: ['ja', 'yes', '1', 'true', 'x'].includes(
        (raw.is_day_registration || '').toLowerCase()
      ),
      imported_at: new Date().toISOString(),
      source: 'csv_import',
      status: 'active',
    });
  }

  return { vehicles, errors };
}

// ─── Hilfsfunktionen ─────────────────────────────────────────────────────────
function parseCSVLine(line, delimiter) {
  const result = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      inQuotes = !inQuotes;
    } else if (ch === delimiter && !inQuotes) {
      result.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  result.push(current);
  return result;
}

function validateVehicle(vehicle, lineNum) {
  if (!vehicle.brand && !vehicle.model) {
    return { valid: false, error: `Zeile ${lineNum}: Marke und Modell fehlen` };
  }
  if (!vehicle.price && !vehicle.list_price) {
    return { valid: false, error: `Zeile ${lineNum}: Kein Preis vorhanden (${vehicle.brand} ${vehicle.model})` };
  }
  return { valid: true };
}

// ─── Hauptfunktion ───────────────────────────────────────────────────────────
export default async function handler(req, res) {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Nur POST erlaubt' });

  // Auth-Check (Händler-Token aus Header oder Body)
  const authHeader = req.headers.authorization || '';
  const dealerToken = authHeader.replace('Bearer ', '') || req.headers['x-dealer-token'];

  if (!dealerToken) {
    return res.status(401).json({ error: 'Kein Händler-Token. Bitte einloggen.' });
  }

  try {
    // Body als Text lesen (kein bodyParser)
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString('utf-8');

    // Multipart form-data parsen — CSV-Inhalt extrahieren
    let csvContent = '';
    const contentType = req.headers['content-type'] || '';

    if (contentType.includes('multipart/form-data')) {
      // Boundary extrahieren
      const boundary = contentType.split('boundary=')[1]?.trim();
      if (!boundary) return res.status(400).json({ error: 'Ungültiger multipart Content-Type' });

      // CSV-Part finden
      const parts = body.split(`--${boundary}`);
      for (const part of parts) {
        if (part.includes('filename=') && (part.includes('.csv') || part.includes('.txt'))) {
          const contentStart = part.indexOf('\r\n\r\n');
          if (contentStart !== -1) {
            csvContent = part.slice(contentStart + 4).replace(/\r\n--$/, '').trim();
            break;
          }
        }
      }
    } else if (contentType.includes('text/csv') || contentType.includes('text/plain')) {
      csvContent = body;
    } else if (contentType.includes('application/json')) {
      const json = JSON.parse(body);
      csvContent = json.csv || json.data || '';
    }

    if (!csvContent) {
      return res.status(400).json({ error: 'Keine CSV-Daten gefunden' });
    }

    // BOM entfernen (Windows-Exporte)
    csvContent = csvContent.replace(/^\uFEFF/, '');

    // Parsen
    const { vehicles, errors } = parseCSV(csvContent);

    if (vehicles.length === 0) {
      return res.status(400).json({
        error: 'Keine gültigen Fahrzeuge importiert',
        details: errors,
      });
    }

    // TODO: Hier Fahrzeuge in Datenbank speichern
    // Aktuell: Gibt geparste Daten zurück (für MVP ausreichend)
    // Später: await db.vehicles.insertMany(vehicles)

    return res.status(200).json({
      success: true,
      imported: vehicles.length,
      skipped: errors.length,
      errors: errors.length > 0 ? errors : undefined,
      vehicles: vehicles, // Im Produktivbetrieb weglassen
      summary: {
        brands: [...new Set(vehicles.map(v => v.brand))].filter(Boolean),
        avg_discount: vehicles.length > 0
          ? Math.round(vehicles.reduce((s, v) => s + v.discount_pct, 0) / vehicles.length * 10) / 10
          : 0,
        day_registrations: vehicles.filter(v => v.is_day_registration).length,
      }
    });

  } catch (err) {
    console.error('CSV Import Fehler:', err);
    return res.status(500).json({
      error: 'Interner Fehler beim Import',
      detail: err.message,
    });
  }
}
