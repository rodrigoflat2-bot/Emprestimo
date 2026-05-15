const { createClient } = require('@supabase/supabase-js');

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;

let supabase = null;

if (supabaseUrl && supabaseAnonKey) {
  supabase = createClient(supabaseUrl, supabaseAnonKey);
} else {
  console.warn('AVISO: SUPABASE_URL e SUPABASE_ANON_KEY não configurados.');
  console.warn('Crie um arquivo .env baseado no .env.example ou defina as variáveis de ambiente.');
}

module.exports = supabase;
