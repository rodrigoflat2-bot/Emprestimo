if (!process.env.VERCEL) {
  require('dotenv').config();
}

const express = require('express');
const path = require('path');
const os = require('os');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const supabase = require('./supabase');

const app = express();

const JWT_SECRET = process.env.JWT_SECRET || 'emprestimos-app-secret-dev-2026';

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.resolve(__dirname, 'public')));
app.use(cookieParser());
app.set('view engine', 'ejs');
app.set('views', path.resolve(__dirname, 'views'));

// Debug route (before auth/middleware blocks)
app.get('/_debug', (req, res) => {
  const su = process.env.SUPABASE_URL;
  const sk = process.env.SUPABASE_ANON_KEY;
  res.json({
    SUPABASE_URL: su ? su.substring(0, 20) + '...' : '(vazio)',
    SUPABASE_ANON_KEY: sk ? sk.substring(0, 10) + '...' : '(vazio)',
    supabase_loaded: supabase !== null,
    VERCEL: process.env.VERCEL || '(não definido)',
    NODE_ENV: process.env.NODE_ENV || '(não definido)',
    cwd: process.cwd()
  });
});

function checkSupabase(req, res, next) {
  if (!supabase) {
    const su = process.env.SUPABASE_URL;
    const sk = process.env.SUPABASE_ANON_KEY;
    return res.status(500).send(`
      <style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f8f9fa}.card{background:#fff;padding:2rem;border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,.1);max-width:500px;text-align:center}h3{color:#dc3545}code{background:#e9ecef;padding:2px 6px;border-radius:4px;font-size:.9em}ol{text-align:left}pre{text-align:left;font-size:.8em;background:#f5f5f5;padding:8px;border-radius:6px}</style>
      <div class="card">
        <h3>Erro de configuração</h3>
        <p>Supabase não configurado. Defina as variáveis <strong>SUPABASE_URL</strong> e <strong>SUPABASE_ANON_KEY</strong>.</p>
        <hr>
        <p style="font-size:.9em"><strong>Na Vercel:</strong></p>
        <ol style="font-size:.85em;color:#555">
          <li>Acesse o <strong>Dashboard da Vercel</strong></li>
          <li>Seu projeto → <strong>Settings</strong> → <strong>Environment Variables</strong></li>
          <li>Adicione:
            <br><code>SUPABASE_URL</code>
            <br><code>SUPABASE_ANON_KEY</code>
          </li>
          <li>Marque a opção <strong>Production</strong></li>
          <li>Clique em <strong>Save</strong> e faça um <strong>Redeploy</strong></li>
        </ol>
        <hr>
        <p style="font-size:.85em;color:#999">Debug:</p>
        <pre>SUPABASE_URL: ${su ? su.substring(0, 25) + '...' : '(vazio)'}
SUPABASE_ANON_KEY: ${sk ? sk.substring(0, 10) + '... (' + sk.length + ' chars)' : '(vazio)'}
VERCEL: ${process.env.VERCEL || 'não'}
cwd: ${process.cwd()}
__dirname: ${__dirname}</pre>
      </div>
    `);
  }
  next();
}

app.use(checkSupabase);

// Auth middleware
function requireAuth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.redirect('/login');
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    res.locals.usuario = req.user.username;
    next();
  } catch (e) {
    res.clearCookie('token');
    return res.redirect('/login');
  }
}

// ====== AUTH ROUTES (public) ======

// Login page - if no users exist, show setup form
app.get('/login', async (req, res) => {
  try {
    if (req.cookies.token) {
      try {
        jwt.verify(req.cookies.token, JWT_SECRET);
        return res.redirect('/');
      } catch (e) {
        res.clearCookie('token');
      }
    }

    const { count, error } = await supabase
      .from('usuarios')
      .select('*', { count: 'exact', head: true });

    if (error) throw error;

    res.render('login', {
      semUsuarios: (count || 0) === 0,
      erro: req.query.erro || null
    });
  } catch (e) {
    console.error('Erro ao carregar login:', e.message);
    res.render('login', { semUsuarios: true, erro: 'Erro ao conectar com banco de dados' });
  }
});

// Login form submit
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.redirect('/login?erro=Preencha usuário e senha');
    }

    const { data: user, error } = await supabase
      .from('usuarios')
      .select('*')
      .eq('username', username)
      .single();

    if (error || !user) {
      return res.redirect('/login?erro=Usuário ou senha inválidos');
    }

    const senhaValida = await bcrypt.compare(password, user.password);
    if (!senhaValida) {
      return res.redirect('/login?erro=Usuário ou senha inválidos');
    }

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, sameSite: 'strict', maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.redirect('/');
  } catch (e) {
    console.error('Erro no login:', e.message);
    res.redirect('/login?erro=Erro ao fazer login');
  }
});

// Register first user (only when no users exist)
app.post('/register', async (req, res) => {
  try {
    const { count } = await supabase
      .from('usuarios')
      .select('*', { count: 'exact', head: true });

    if ((count || 0) > 0) {
      return res.redirect('/login?erro=Já existe um administrador');
    }

    const { username, password } = req.body;
    if (!username || !password || password.length < 4) {
      return res.redirect('/login?erro=Senha deve ter no mínimo 4 caracteres');
    }

    const senhaHash = await bcrypt.hash(password, 10);

    const { data: user, error } = await supabase
      .from('usuarios')
      .insert({ username, password: senhaHash })
      .select()
      .single();

    if (error) {
      if (error.code === '23505') {
        return res.redirect('/login?erro=Usuário já existe');
      }
      throw error;
    }

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, sameSite: 'strict', maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.redirect('/');
  } catch (e) {
    console.error('Erro no registro:', e.message);
    res.redirect('/login?erro=Erro ao criar administrador');
  }
});

// Logout
app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
});

// ====== PROTECTED ROUTES (require auth) ======

app.use(requireAuth);

function hoje() {
  return new Date().toISOString().split('T')[0];
}

function addMeses(dataStr, meses) {
  const [ano, mes, dia] = dataStr.split('-').map(Number);
  let novoAno = ano;
  let novoMes = mes + meses;
  novoAno += Math.floor((novoMes - 1) / 12);
  novoMes = ((novoMes - 1) % 12) + 1;
  const ultimoDia = new Date(novoAno, novoMes, 0).getDate();
  const diaAjustado = Math.min(dia, ultimoDia);
  return `${novoAno}-${String(novoMes).padStart(2, '0')}-${String(diaAjustado).padStart(2, '0')}`;
}

function addDias(dataStr, dias) {
  const d = new Date(dataStr + 'T12:00:00');
  d.setDate(d.getDate() + dias);
  const ano = d.getFullYear();
  const mes = String(d.getMonth() + 1).padStart(2, '0');
  const dia = String(d.getDate()).padStart(2, '0');
  return `${ano}-${mes}-${dia}`;
}

const rotulosTipo = {
  diario: 'Diário',
  semanal: 'Semanal',
  mensal: 'Mensal'
};

function calcularValorParcela(valorTotal, taxaMensal, numParcelas) {
  if (taxaMensal === 0) return (valorTotal / numParcelas).toFixed(2);
  const i = taxaMensal / 100;
  const pmt = valorTotal * (i * Math.pow(1 + i, numParcelas)) / (Math.pow(1 + i, numParcelas) - 1);
  return pmt.toFixed(2);
}

function getDiasAteVencimento(dataVenc) {
  const hojeDate = new Date(hoje());
  const venc = new Date(dataVenc);
  const diff = Math.ceil((venc - hojeDate) / (1000 * 60 * 60 * 24));
  return diff;
}

function getStatusCliente(cliente) {
  const pagamentos = cliente.pagamentos || [];
  if (pagamentos.length === 0) return 'sem-parcelas';
  let temAtrasado = false;
  let temProximo = false;
  for (const p of pagamentos) {
    if (p.status === 'pago' || p.status === 'parcial') continue;
    const dias = getDiasAteVencimento(p.data_vencimento);
    if (dias < 0) temAtrasado = true;
    if (dias <= 5 && dias >= 0) temProximo = true;
  }
  if (temAtrasado) return 'atrasado';
  if (temProximo) return 'proximo';
  return 'em-dia';
}

function getCorStatusCliente(status) {
  const cores = {
    atrasado: 'danger',
    proximo: 'warning',
    'em-dia': 'success',
    'sem-parcelas': 'secondary'
  };
  return cores[status] || 'secondary';
}

function getRotuloStatusPagamento(pagamento) {
  if (pagamento.status === 'pago') return { texto: 'Pago', cor: 'success' };
  if (pagamento.status === 'parcial') {
    const restante = pagamento.restante || 0;
    return { texto: `Parcial (resta R$ ${restante.toFixed(2)})`, cor: 'info' };
  }
  const dias = getDiasAteVencimento(pagamento.data_vencimento);
  if (dias < 0) return { texto: `Atrasado ${Math.abs(dias)} dias`, cor: 'danger' };
  if (dias === 0) return { texto: 'Vence hoje', cor: 'warning' };
  if (dias <= 5) return { texto: `Vence em ${dias} dias`, cor: 'warning' };
  return { texto: `Vence em ${dias} dias`, cor: 'secondary' };
}

function getValorComMulta(pagamento, cliente) {
  const base = pagamento.valor || 0;
  const multa = (cliente.tipo === 'diario' && cliente.multa_atraso > 0 && getDiasAteVencimento(pagamento.data_vencimento) < 0) ? cliente.multa_atraso : 0;
  return { base, multa, total: base + multa, temMulta: multa > 0 };
}

function getLocalIP() {
  const interfaces = os.networkInterfaces();
  for (const nome of Object.keys(interfaces)) {
    for (const iface of interfaces[nome]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return 'localhost';
}

// Dashboard
app.get('/', async (req, res) => {
  try {
    const { data: clientes, error } = await supabase
      .from('clientes')
      .select('*, pagamentos(*)')
      .order('id', { ascending: true });

    if (error) throw error;
    const lista = clientes || [];

    let totalClientes = lista.length;
    let totalEmprestado = 0;
    let totalReceber = 0;
    let parcelasVencendo = [];
    let parcelasAtrasadas = [];
    let resumoStatus = { atrasado: 0, proximo: 0, 'em-dia': 0, 'sem-parcelas': 0 };

    for (const c of lista) {
      c.pagamentos = (c.pagamentos || []).sort((a, b) => a.numero_parcela - b.numero_parcela);
      totalEmprestado += c.valor_emprestimo || 0;
      const status = getStatusCliente(c);
      resumoStatus[status] = (resumoStatus[status] || 0) + 1;

      for (const p of (c.pagamentos || [])) {
        if (p.status === 'pago' || p.status === 'parcial') continue;
        totalReceber += p.valor || 0;
        const dias = getDiasAteVencimento(p.data_vencimento);
        if (dias < 0) {
          parcelasAtrasadas.push({ cliente: c, pagamento: p, dias: Math.abs(dias) });
        } else if (dias <= 5) {
          parcelasVencendo.push({ cliente: c, pagamento: p, dias });
        }
      }
    }

    parcelasVencendo.sort((a, b) => a.dias - b.dias);
    parcelasAtrasadas.sort((a, b) => b.dias - a.dias);

    res.render('index', {
      totalClientes, totalEmprestado, totalReceber,
      parcelasVencendo, parcelasAtrasadas, resumoStatus,
      getRotuloStatusPagamento, getCorStatusCliente,
      getStatusCliente, getValorComMulta, rotulosTipo
    });
  } catch (e) {
    console.error('Erro no dashboard:', e.message);
    res.render('index', {
      totalClientes: 0, totalEmprestado: 0, totalReceber: 0,
      parcelasVencendo: [], parcelasAtrasadas: [],
      resumoStatus: { atrasado: 0, proximo: 0, 'em-dia': 0, 'sem-parcelas': 0 },
      getRotuloStatusPagamento, getCorStatusCliente,
      getStatusCliente, getValorComMulta, rotulosTipo
    });
  }
});

// Lista de clientes
app.get('/clientes', async (req, res) => {
  try {
    const busca = (req.query.busca || '').toLowerCase();
    let query = supabase.from('clientes').select('*').order('id', { ascending: true });

    if (busca) {
      query = query.or(`nome.ilike.%${busca}%,telefone.ilike.%${busca}%`);
    }

    const { data: clientes, error } = await query;
    if (error) throw error;

    res.render('clientes', {
      clientes: clientes || [], busca,
      getStatusCliente, getCorStatusCliente, hoje, rotulosTipo
    });
  } catch (e) {
    console.error('Erro ao listar clientes:', e.message);
    res.render('clientes', {
      clientes: [], busca: '',
      getStatusCliente, getCorStatusCliente, hoje, rotulosTipo
    });
  }
});

// Formulário novo cliente
app.get('/clientes/novo', (req, res) => {
  res.render('novo-cliente', { rotulosTipo });
});

// Criar cliente
app.post('/clientes/novo', async (req, res) => {
  try {
    const {
      nome, telefone, endereco,
      valor_emprestimo, valor_parcela,
      numero_parcelas, data_primeiro_vencimento,
      taxa_juros, multa_atraso, observacao, tipo
    } = req.body;

    if (!nome || !valor_emprestimo || !numero_parcelas || !data_primeiro_vencimento) {
      return res.redirect('/clientes/novo?erro=Preencha todos os campos obrigatórios');
    }

    const tipoEmprestimo = tipo || 'mensal';
    const numParcelas = parseInt(numero_parcelas);

    let valorParcela = parseFloat(valor_parcela) || 0;
    if (valorParcela === 0 && tipoEmprestimo === 'mensal' && parseFloat(taxa_juros || 0) > 0) {
      valorParcela = parseFloat(calcularValorParcela(
        parseFloat(valor_emprestimo),
        parseFloat(taxa_juros) || 0,
        numParcelas
      ));
    }
    if (valorParcela === 0) {
      valorParcela = (parseFloat(valor_emprestimo) / numParcelas).toFixed(2);
    }

    const dataInicio = data_primeiro_vencimento;

    const { data: cliente, error: errCliente } = await supabase
      .from('clientes')
      .insert({
        nome,
        telefone: telefone || '',
        endereco: endereco || '',
        valor_emprestimo: parseFloat(valor_emprestimo),
        taxa_juros: parseFloat(taxa_juros) || 0,
        numero_parcelas: numParcelas,
        valor_parcela: parseFloat(valorParcela),
        data_primeiro_vencimento: dataInicio,
        tipo: tipoEmprestimo,
        multa_atraso: parseFloat(multa_atraso) || 0,
        observacao: observacao || ''
      })
      .select()
      .single();

    if (errCliente) throw errCliente;

    const clienteId = cliente.id;
    const pagamentos = [];

    for (let i = 1; i <= numParcelas; i++) {
      let dataVenc;
      if (i === 1) {
        dataVenc = dataInicio;
      } else if (tipoEmprestimo === 'diario') {
        dataVenc = addDias(dataInicio, i - 1);
      } else if (tipoEmprestimo === 'semanal') {
        dataVenc = addDias(dataInicio, (i - 1) * 7);
      } else {
        dataVenc = addMeses(dataInicio, i - 1);
      }
      pagamentos.push({
        cliente_id: clienteId,
        numero_parcela: i,
        data_vencimento: dataVenc,
        data_pagamento: null,
        valor: parseFloat(valorParcela),
        status: 'pendente'
      });
    }

    const { error: errPags } = await supabase.from('pagamentos').insert(pagamentos);
    if (errPags) throw errPags;

    res.redirect(`/clientes/${clienteId}?sucesso=Cliente cadastrado com sucesso!`);
  } catch (e) {
    console.error('Erro ao criar cliente:', e.message);
    res.redirect('/clientes/novo?erro=Erro ao cadastrar cliente');
  }
});

// Detalhe do cliente
app.get('/clientes/:id', async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const { data: cliente, error } = await supabase
      .from('clientes')
      .select('*, pagamentos(*)')
      .eq('id', id)
      .single();

    if (error || !cliente) {
      return res.redirect('/clientes?erro=Cliente não encontrado');
    }

    cliente.pagamentos = (cliente.pagamentos || []).sort((a, b) => a.numero_parcela - b.numero_parcela);

    let totalPago = 0;
    let totalPendente = 0;
    for (const p of cliente.pagamentos) {
      if (p.status === 'pago') totalPago += p.valor;
      else if (p.status === 'parcial') {
        totalPago += p.valor_pago || 0;
        totalPendente += (p.restante || 0);
      } else totalPendente += p.valor;
    }

    res.render('cliente', {
      cliente, totalPago, totalPendente,
      getRotuloStatusPagamento, getStatusCliente,
      getCorStatusCliente, getValorComMulta, rotulosTipo
    });
  } catch (e) {
    console.error('Erro ao buscar cliente:', e.message);
    res.redirect('/clientes?erro=Erro ao carregar cliente');
  }
});

// Formulário editar cliente
app.get('/clientes/:id/editar', async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const { data: cliente, error } = await supabase
      .from('clientes')
      .select('*')
      .eq('id', id)
      .single();

    if (error || !cliente) return res.redirect('/clientes?erro=Cliente não encontrado');

    res.render('novo-cliente', { cliente, editando: true, rotulosTipo });
  } catch (e) {
    console.error('Erro ao buscar cliente:', e.message);
    res.redirect('/clientes?erro=Erro ao carregar cliente');
  }
});

// Salvar edição do cliente
app.post('/clientes/:id/editar', async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const { nome, telefone, endereco, observacao, multa_atraso } = req.body;
    if (!nome) return res.redirect(`/clientes/${id}/editar?erro=Nome é obrigatório`);

    const updates = { nome, telefone: telefone || '', endereco: endereco || '', observacao: observacao || '' };
    if (multa_atraso !== undefined) updates.multa_atraso = parseFloat(multa_atraso) || 0;

    const { error } = await supabase.from('clientes').update(updates).eq('id', id);
    if (error) throw error;

    res.redirect(`/clientes/${id}?sucesso=Cliente atualizado!`);
  } catch (e) {
    console.error('Erro ao atualizar cliente:', e.message);
    res.redirect(`/clientes/${req.params.id}/editar?erro=Erro ao atualizar`);
  }
});

// Deletar cliente
app.post('/clientes/:id/deletar', async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const { error } = await supabase.from('clientes').delete().eq('id', id);
    if (error) throw error;
    res.redirect('/clientes?sucesso=Cliente removido!');
  } catch (e) {
    console.error('Erro ao deletar cliente:', e.message);
    res.redirect('/clientes?erro=Erro ao remover cliente');
  }
});

// Marcar pagamento como pago (total ou parcial)
app.post('/pagamentos/:id/pagar', async (req, res) => {
  try {
    const pagId = parseInt(req.params.id);
    const clienteId = parseInt(req.body.cliente_id);
    const valorPago = parseFloat(req.body.valor_pago) || 0;

    const { data: pagamento, error: errPag } = await supabase
      .from('pagamentos')
      .select('*')
      .eq('id', pagId)
      .single();

    if (errPag || !pagamento) {
      return res.redirect(`/clientes/${clienteId}?erro=Pagamento não encontrado`);
    }

    const dataPag = req.body.data_pagamento || hoje();

    if (valorPago <= 0 || valorPago >= pagamento.valor) {
      const { error } = await supabase
        .from('pagamentos')
        .update({ status: 'pago', data_pagamento: dataPag, valor_pago: pagamento.valor, restante: 0 })
        .eq('id', pagId);
      if (error) throw error;
      return res.redirect(`/clientes/${clienteId}?sucesso=Pagamento total de R$ ${pagamento.valor.toFixed(2)} registrado!`);
    }

    const restante = parseFloat((pagamento.valor - valorPago).toFixed(2));

    const { error: errUpdate } = await supabase
      .from('pagamentos')
      .update({ status: 'pago', data_pagamento: dataPag, valor_pago: valorPago, restante: 0 })
      .eq('id', pagId);
    if (errUpdate) throw errUpdate;

    const { data: cliente, error: errCli } = await supabase
      .from('clientes').select('*').eq('id', clienteId).single();
    if (errCli) throw errCli;

    const { count, error: errCount } = await supabase
      .from('pagamentos').select('*', { count: 'exact', head: true }).eq('cliente_id', clienteId);
    if (errCount) throw errCount;

    const taxa = (cliente.taxa_juros || 0) / 100;
    const novoValor = parseFloat((restante * (1 + taxa)).toFixed(2));
    const tipo = cliente.tipo || 'mensal';
    let dataVenc;
    if (tipo === 'diario') dataVenc = addDias(pagamento.data_vencimento, 1);
    else if (tipo === 'semanal') dataVenc = addDias(pagamento.data_vencimento, 7);
    else dataVenc = addMeses(pagamento.data_vencimento, 1);

    const { error: errNewPag } = await supabase.from('pagamentos').insert({
      cliente_id: clienteId,
      numero_parcela: (count || 0) + 1,
      data_vencimento: dataVenc,
      data_pagamento: null,
      valor: novoValor,
      status: 'pendente'
    });
    if (errNewPag) throw errNewPag;

    await supabase.from('clientes').update({ numero_parcelas: (count || 0) + 1 }).eq('id', clienteId);

    const msgJuros = cliente.taxa_juros > 0 ? ` (R$ ${restante.toFixed(2)} + ${cliente.taxa_juros}% = R$ ${novoValor.toFixed(2)})` : '';
    res.redirect(`/clientes/${clienteId}?sucesso=Pagamento de R$ ${valorPago.toFixed(2)} recebido! Nova parcela de R$ ${novoValor.toFixed(2)} criada${msgJuros}.`);
  } catch (e) {
    console.error('Erro ao registrar pagamento:', e.message);
    res.redirect(`/clientes/${req.body.cliente_id}?erro=Erro ao registrar pagamento`);
  }
});

// Desmarcar pagamento
app.post('/pagamentos/:id/desmarcar', async (req, res) => {
  try {
    const pagId = parseInt(req.params.id);
    const clienteId = parseInt(req.body.cliente_id);

    const { data: pagamento, error } = await supabase
      .from('pagamentos').select('*').eq('id', pagId).single();
    if (error || !pagamento) {
      return res.redirect(`/clientes/${clienteId}?erro=Pagamento não encontrado`);
    }

    await supabase.from('pagamentos').update({
      status: 'pendente', data_pagamento: null, valor_pago: 0, restante: 0
    }).eq('id', pagId);

    res.redirect(`/clientes/${clienteId}?sucesso=Pagamento desmarcado!`);
  } catch (e) {
    console.error('Erro ao desmarcar pagamento:', e.message);
    res.redirect(`/clientes/${req.body.cliente_id}?erro=Erro ao desmarcar`);
  }
});

// Deletar parcela
app.post('/pagamentos/:id/deletar', async (req, res) => {
  try {
    const pagId = parseInt(req.params.id);
    const clienteId = parseInt(req.body.cliente_id);
    const { error } = await supabase.from('pagamentos').delete().eq('id', pagId);
    if (error) throw error;
    res.redirect(`/clientes/${clienteId}?sucesso=Parcela removida!`);
  } catch (e) {
    console.error('Erro ao deletar parcela:', e.message);
    res.redirect(`/clientes/${req.body.cliente_id}?erro=Erro ao remover parcela`);
  }
});

// Adicionar parcela manualmente
app.post('/clientes/:id/add-parcela', async (req, res) => {
  try {
    const clienteId = parseInt(req.params.id);
    const valor = parseFloat(req.body.valor) || 0;
    const dataVenc = req.body.data_vencimento;
    if (valor <= 0 || !dataVenc) {
      return res.redirect(`/clientes/${clienteId}?erro=Preencha valor e data`);
    }

    const { count, error: errCount } = await supabase
      .from('pagamentos').select('*', { count: 'exact', head: true }).eq('cliente_id', clienteId);
    if (errCount) throw errCount;

    const totalParcelas = (count || 0) + 1;

    const { error } = await supabase.from('pagamentos').insert({
      cliente_id: clienteId, numero_parcela: totalParcelas,
      data_vencimento: dataVenc, data_pagamento: null,
      valor, status: 'pendente'
    });
    if (error) throw error;

    await supabase.from('clientes').update({ numero_parcelas: totalParcelas }).eq('id', clienteId);
    res.redirect(`/clientes/${clienteId}?sucesso=Parcela adicionada!`);
  } catch (e) {
    console.error('Erro ao adicionar parcela:', e.message);
    res.redirect(`/clientes/${req.params.id}?erro=Erro ao adicionar parcela`);
  }
});

// Editar parcela
app.post('/pagamentos/:id/editar', async (req, res) => {
  try {
    const pagId = parseInt(req.params.id);
    const clienteId = parseInt(req.body.cliente_id);

    const { data: pagamento, error: errFind } = await supabase
      .from('pagamentos').select('*').eq('id', pagId).single();
    if (errFind || !pagamento) {
      return res.redirect(`/clientes/${clienteId}?erro=Parcela não encontrada`);
    }

    const valor = parseFloat(req.body.valor) || 0;
    const dataVenc = req.body.data_vencimento;
    const updates = {};
    if (valor > 0) updates.valor = valor;
    if (dataVenc) updates.data_vencimento = dataVenc;

    const { error } = await supabase.from('pagamentos').update(updates).eq('id', pagId);
    if (error) throw error;

    res.redirect(`/clientes/${clienteId}?sucesso=Parcela atualizada!`);
  } catch (e) {
    console.error('Erro ao editar parcela:', e.message);
    res.redirect(`/clientes/${req.body.cliente_id}?erro=Erro ao editar parcela`);
  }
});

// Resumo
app.get('/resumo', async (req, res) => {
  try {
    const { data: clientes, error } = await supabase
      .from('clientes').select('*, pagamentos(*)');
    if (error) throw error;
    const lista = clientes || [];

    const resumoClientes = lista.map(c => {
      c.pagamentos = (c.pagamentos || []).sort((a, b) => a.numero_parcela - b.numero_parcela);
      const pagamentos = c.pagamentos || [];
      let totalPago = 0;
      for (const p of pagamentos) {
        if (p.status === 'pago') totalPago += p.valor;
        else if (p.status === 'parcial') totalPago += p.valor_pago || 0;
      }
      const totalPendente = pagamentos.filter(p => p.status === 'pendente').reduce((s, p) => s + p.valor, 0);
      const parcelasPagas = pagamentos.filter(p => p.status === 'pago' || p.status === 'parcial').length;
      const primeiroVenc = pagamentos.length > 0 ? pagamentos[0].data_vencimento : null;
      const ultimoVenc = pagamentos.length > 0 ? pagamentos[pagamentos.length - 1].data_vencimento : null;
      const hojeDate = new Date(hoje());
      const dataFim = ultimoVenc ? new Date(ultimoVenc) : hojeDate;
      const diffDias = Math.ceil((dataFim - new Date(primeiroVenc)) / (1000 * 60 * 60 * 24)) + 1;
      return {
        nome: c.nome, valor_emprestimo: c.valor_emprestimo, tipo: c.tipo,
        totalPago, totalPendente, totalParcelas: pagamentos.length,
        parcelasPagas, primeiroVenc, totalDias: diffDias > 0 ? diffDias : 0
      };
    });

    const meses = {};
    for (const c of lista) {
      const mesAno = c.created_at ? c.created_at.substring(0, 7) : null;
      if (!mesAno) continue;
      if (!meses[mesAno]) meses[mesAno] = { emprestado: 0, recebido: 0 };
      meses[mesAno].emprestado += c.valor_emprestimo || 0;
      for (const p of (c.pagamentos || [])) {
        if (p.status === 'pago' || p.status === 'parcial') {
          if (p.data_pagamento) {
            const mesPag = p.data_pagamento.substring(0, 7);
            if (!meses[mesPag]) meses[mesPag] = { emprestado: 0, recebido: 0 };
            meses[mesPag].recebido += (p.valor_pago || p.valor || 0);
          }
        }
      }
    }

    const mesesArray = Object.keys(meses).sort().map(m => ({
      mes: m, emprestado: meses[m].emprestado, recebido: meses[m].recebido
    }));

    res.render('resumo', { resumoClientes, mesesArray, rotulosTipo });
  } catch (e) {
    console.error('Erro no resumo:', e.message);
    res.render('resumo', { resumoClientes: [], mesesArray: [], rotulosTipo });
  }
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('UNHANDLED ERROR:', err);
  res.status(500).send(`
    <style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f8f9fa}.card{background:#fff;padding:2rem;border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,.1);max-width:600px}</style>
    <div class="card">
      <h3>Internal Server Error</h3>
      <p style="color:#666">${err.message}</p>
      <hr>
      <pre style="font-size:.8em;color:#999;overflow:auto;max-height:300px">${err.stack}</pre>
    </div>
  `);
});

// Export for Vercel serverless
module.exports = app;

// Local / Render: start server
if (!process.env.VERCEL) {
  const PORT = process.env.PORT || 3000;
  const localIP = getLocalIP();
  app.listen(PORT, '0.0.0.0', () => {
    console.log('='.repeat(50));
    console.log('  GERENCIADOR DE EMPRÉSTIMOS');
    console.log('='.repeat(50));
    console.log(`  Local:  http://localhost:${PORT}`);
    console.log(`  Rede:   http://${localIP}:${PORT}`);
    console.log('-'.repeat(50));
    console.log('  Acesse pelo celular na mesma rede Wi-Fi');
    console.log('='.repeat(50));
  });
}
