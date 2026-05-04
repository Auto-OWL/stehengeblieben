module.exports = async function handler(req, res) {
  try {
    const r = await fetch(
      process.env.SUPABASE_URL + '/rest/v1/vehicles?select=id&limit=1',
      { headers: { 'apikey': process.env.SUPABASE_SERVICE_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImNsYmhnYXVoZ3VoZXZtY2N6YXd2Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzQ3MTY3NTQsImV4cCI6MjA5MDI5Mjc1NH0.Onf8t_NkW7J9VTdaBnuRVflFRpr2vjvbbOHUbCJaj9Y' } }
    );
    res.status(200).json({ ok: true, status: r.status });
  } catch(e) {
    res.status(500).json({ ok: false, error: e.message });
  }
};
