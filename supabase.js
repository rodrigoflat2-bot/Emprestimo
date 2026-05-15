const { createClient } = require('@supabase/supabase-js');

const supabaseUrl = (process.env.SUPABASE_URL || '').trim();
const supabaseAnonKey = (process.env.SUPABASE_ANON_KEY || '').trim();

let supabase = null;

if (supabaseUrl && supabaseAnonKey) {
  try {
    supabase = createClient(supabaseUrl, supabaseAnonKey);
  } catch (e) {
    console.error('ERRO ao criar cliente Supabase:', e.message);
  }
} else {
  console.warn('AVISO: SUPABASE_URL e SUPABASE_ANON_KEY não configurados.');
  console.warn('Crie um arquivo .env baseado no .env.example ou defina as variáveis de ambiente.');
}

module.exports = supabase;
