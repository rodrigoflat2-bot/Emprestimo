-- Execute this SQL in the Supabase SQL Editor (https://supabase.com/dashboard/project/_/sql/new)

CREATE TABLE IF NOT EXISTS clientes (
  id SERIAL PRIMARY KEY,
  nome TEXT NOT NULL,
  telefone TEXT DEFAULT '',
  endereco TEXT DEFAULT '',
  valor_emprestimo DECIMAL(12,2) NOT NULL DEFAULT 0,
  taxa_juros DECIMAL(5,2) DEFAULT 0,
  numero_parcelas INTEGER DEFAULT 0,
  valor_parcela DECIMAL(12,2) DEFAULT 0,
  data_primeiro_vencimento DATE,
  tipo TEXT DEFAULT 'mensal',
  multa_atraso DECIMAL(10,2) DEFAULT 0,
  observacao TEXT DEFAULT '',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS pagamentos (
  id SERIAL PRIMARY KEY,
  cliente_id INTEGER NOT NULL REFERENCES clientes(id) ON DELETE CASCADE,
  numero_parcela INTEGER NOT NULL,
  data_vencimento DATE NOT NULL,
  data_pagamento DATE,
  valor DECIMAL(12,2) NOT NULL DEFAULT 0,
  status TEXT DEFAULT 'pendente',
  valor_pago DECIMAL(12,2),
  restante DECIMAL(12,2),
  acrescimo DECIMAL(12,2) DEFAULT 0,
  valor_original DECIMAL(12,2),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pagamentos_cliente_id ON pagamentos(cliente_id);
CREATE INDEX IF NOT EXISTS idx_pagamentos_status ON pagamentos(status);

CREATE TABLE IF NOT EXISTS usuarios (
  id SERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
