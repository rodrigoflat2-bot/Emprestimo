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

// Debug route
app.get('/_debug', async (req, res) => {
  const su = process.env.SUPABASE_URL;
  const sk = process.env.SUPABASE_ANON_KEY;
  const testResult = await supabase.count('usuarios').then(r => r).catch(e => 'ERRO: ' + e.message);
  res.json({
    SUPABASE_URL: su ? su.substring(0, 20) + '...' : '(vazio)',
    SUPABASE_ANON_KEY: sk ? sk.substring(0, 10) + '...' : '(vazio)',
    supabase_loaded: !!supabase.getApiUrl(),
    VERCEL: process.env.VERCEL || '(não definido)',
    node: process.version,
    test_count_usuarios: testResult
  });
});

function checkSupabase(req, res, next) {
  if (!supabase.getApiUrl()) {
    const su = process.env.SUPABASE_URL;
    const sk = process.env.SUPABASE_ANON_KEY;
    return res.status(500).send(`
      <style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f8f9fa}.card{background:#fff;padding:2rem;border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,.1);max-width:500px}</style>
      <div class="card">
        <h3>Erro de configuração</h3>
        <p>Supabase não configurado. Defina as variáveis <strong>SUPABASE_URL</strong> e <strong>SUPABASE_ANON_KEY</strong>.</p>
        <hr>
        <p style="font-size:.9em"><strong>Na Vercel:</strong></p>
        <ol style="font-size:.85em">
          <li>Dashboard Vercel → Settings → Environment Variables</li>
          <li>Adicione <code>SUPABASE_URL</code> e <code>SUPABASE_ANON_KEY</code></li>
          <li>Marque <strong>Production</strong> e <strong>Save</strong></li>
          <li>Redeploy</li>
        </ol>
        <pre style="font-size:.8em;background:#f5f5f5;padding:8px;border-radius:6px">
SUPABASE_URL: ${su ? su.substring(0,25)+'...' : '(vazio)'}
SUPABASE_ANON_KEY: ${sk ? sk.substring(0,10)+'... ('+sk.length+' chars)' : '(vazio)'}
        </pre>
      </div>
    `);
  }
  next();
}

app.use(checkSupabase);

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

// ====== AUTH ROUTES ======

app.get('/login', async (req, res) => {
  try {
    if (req.cookies.token) {
      try { jwt.verify(req.cookies.token, JWT_SECRET); return res.redirect('/'); }
      catch (e) { res.clearCookie('token'); }
    }
    const total = await supabase.count('usuarios');
    res.render('login', { semUsuarios: total === 0, erro: req.query.erro || null });
  } catch (e) {
    console.error('Erro login:', e.message);
    res.render('login', { semUsuarios: true, erro: 'Erro ao conectar: ' + e.message });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.redirect('/login?erro=Preencha usuário e senha');

    const users = await supabase.select('usuarios', { eq: { field: 'username', value: username } });
    const user = users && users[0];
    if (!user) return res.redirect('/login?erro=Usuário ou senha inválidos');

    const valida = await bcrypt.compare(password, user.password);
    if (!valida) return res.redirect('/login?erro=Usuário ou senha inválidos');

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, sameSite: 'strict', maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.redirect('/');
  } catch (e) {
    console.error('Erro login:', e.message);
    res.redirect('/login?erro=Erro ao fazer login');
  }
});

app.post('/register', async (req, res) => {
  try {
    const total = await supabase.count('usuarios');
    if (total > 0) return res.redirect('/login?erro=Já existe um administrador');

    const { username, password } = req.body;
    if (!username || !password || password.length < 4) {
      return res.redirect('/login?erro=Senha deve ter mínimo 4 caracteres');
    }

    const hash = await bcrypt.hash(password, 10);
    await supabase.insert('usuarios', { username, password: hash });

    const users = await supabase.select('usuarios', { eq: { field: 'username', value: username } });
    const user = users && users[0];
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, sameSite: 'strict', maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.redirect('/');
  } catch (e) {
    console.error('Erro register:', e.message);
    res.redirect('/login?erro=Erro ao criar administrador');
  }
});

app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
});

// ====== PROTECTED ROUTES ======

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

const rotulosTipo = { diario: 'Diário', semanal: 'Semanal', mensal: 'Mensal' };

function calcularValorParcela(valorTotal, taxaMensal, numParcelas) {
  if (taxaMensal === 0) return (valorTotal / numParcelas).toFixed(2);
  const i = taxaMensal / 100;
  const pmt = valorTotal * (i * Math.pow(1 + i, numParcelas)) / (Math.pow(1 + i, numParcelas) - 1);
  return pmt.toFixed(2);
}

function getDiasAteVencimento(dataVenc) {
  const hojeDate = new Date(hoje());
  const venc = new Date(dataVenc);
  return Math.ceil((venc - hojeDate) / (1000 * 60 * 60 * 24));
}

function getStatusCliente(cliente) {
  const pagamentos = cliente.pagamentos || [];
  if (pagamentos.length === 0) return 'sem-parcelas';
  let atrasado = false, proximo = false;
  for (const p of pagamentos) {
    if (p.status === 'pago' || p.status === 'parcial') continue;
    const dias = getDiasAteVencimento(p.data_vencimento);
    if (dias < 0) atrasado = true;
    if (dias >= 0 && dias <= 5) proximo = true;
  }
  if (atrasado) return 'atrasado';
  if (proximo) return 'proximo';
  return 'em-dia';
}

function getCorStatusCliente(status) {
  return { atrasado: 'danger', proximo: 'warning', 'em-dia': 'success', 'sem-parcelas': 'secondary' }[status] || 'secondary';
}

function getRotuloStatusPagamento(pagamento) {
  if (pagamento.status === 'pago') return { texto: 'Pago', cor: 'success' };
  if (pagamento.status === 'parcial') {
    return { texto: `Parcial (resta R$ ${(pagamento.restante||0).toFixed(2)})`, cor: 'info' };
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
      if (iface.family === 'IPv4' && !iface.internal) return iface.address;
    }
  }
  return 'localhost';
}

// Dashboard
app.get('/', async (req, res) => {
  try {
    const lista = await supabase.select('clientes', { related: 'pagamentos', order: { field: 'id' } }) || [];
    let totalClientes = lista.length, totalEmprestado = 0, totalReceber = 0;
    const parcelasVencendo = [], parcelasAtrasadas = [];
    const resumoStatus = { atrasado: 0, proximo: 0, 'em-dia': 0, 'sem-parcelas': 0 };

    for (const c of lista) {
      c.pagamentos = (c.pagamentos || []).sort((a, b) => a.numero_parcela - b.numero_parcela);
      totalEmprestado += c.valor_emprestimo || 0;
      const status = getStatusCliente(c);
      resumoStatus[status] = (resumoStatus[status] || 0) + 1;
      for (const p of (c.pagamentos || [])) {
        if (p.status === 'pago' || p.status === 'parcial') continue;
        totalReceber += p.valor || 0;
        const dias = getDiasAteVencimento(p.data_vencimento);
        if (dias < 0) parcelasAtrasadas.push({ cliente: c, pagamento: p, dias: Math.abs(dias) });
        else if (dias <= 5) parcelasVencendo.push({ cliente: c, pagamento: p, dias });
      }
    }
    parcelasVencendo.sort((a, b) => a.dias - b.dias);
    parcelasAtrasadas.sort((a, b) => b.dias - a.dias);

    res.render('index', { totalClientes, totalEmprestado, totalReceber, parcelasVencendo, parcelasAtrasadas, resumoStatus, getRotuloStatusPagamento, getCorStatusCliente, getStatusCliente, getValorComMulta, rotulosTipo });
  } catch (e) {
    console.error('Erro dashboard:', e.message);
    res.render('index', { totalClientes:0, totalEmprestado:0, totalReceber:0, parcelasVencendo:[], parcelasAtrasadas:[], resumoStatus:{atrasado:0,proximo:0,'em-dia':0,'sem-parcelas':0}, getRotuloStatusPagamento, getCorStatusCliente, getStatusCliente, getValorComMulta, rotulosTipo });
  }
});

// Lista de clientes
app.get('/clientes', async (req, res) => {
  try {
    const busca = (req.query.busca || '').toLowerCase();
    let clientes = await supabase.select('clientes', { order: { field: 'id' } }) || [];
    if (busca) {
      clientes = clientes.filter(c =>
        c.nome.toLowerCase().includes(busca) || (c.telefone || '').includes(busca)
      );
    }
    res.render('clientes', { clientes, busca, getStatusCliente, getCorStatusCliente, hoje, rotulosTipo });
  } catch (e) {
    console.error('Erro listar:', e.message);
    res.render('clientes', { clientes:[], busca:'', getStatusCliente, getCorStatusCliente, hoje, rotulosTipo });
  }
});

app.get('/clientes/novo', (req, res) => {
  res.render('novo-cliente', { rotulosTipo });
});

app.post('/clientes/novo', async (req, res) => {
  try {
    const { nome, telefone, endereco, valor_emprestimo, valor_parcela, numero_parcelas, data_primeiro_vencimento, taxa_juros, multa_atraso, observacao, tipo } = req.body;
    if (!nome || !valor_emprestimo || !numero_parcelas || !data_primeiro_vencimento) {
      return res.redirect('/clientes/novo?erro=Preencha todos os campos obrigatórios');
    }
    const tipoEmprestimo = tipo || 'mensal';
    const numParcelas = parseInt(numero_parcelas);
    let valorParcela = parseFloat(valor_parcela) || 0;
    if (valorParcela === 0 && tipoEmprestimo === 'mensal' && parseFloat(taxa_juros||0) > 0) {
      valorParcela = parseFloat(calcularValorParcela(parseFloat(valor_emprestimo), parseFloat(taxa_juros)||0, numParcelas));
    }
    if (valorParcela === 0) valorParcela = (parseFloat(valor_emprestimo) / numParcelas).toFixed(2);
    const dataInicio = data_primeiro_vencimento;

    const created = await supabase.insert('clientes', {
      nome, telefone: telefone||'', endereco: endereco||'',
      valor_emprestimo: parseFloat(valor_emprestimo), taxa_juros: parseFloat(taxa_juros)||0,
      numero_parcelas: numParcelas, valor_parcela: parseFloat(valorParcela),
      data_primeiro_vencimento: dataInicio, tipo: tipoEmprestimo,
      multa_atraso: parseFloat(multa_atraso)||0, observacao: observacao||''
    });
    const clienteId = created && created[0] && created[0].id;
    if (!clienteId) throw new Error('Falha ao criar cliente');

    const pagamentos = [];
    for (let i = 1; i <= numParcelas; i++) {
      let dataVenc;
      if (i === 1) dataVenc = dataInicio;
      else if (tipoEmprestimo === 'diario') dataVenc = addDias(dataInicio, i - 1);
      else if (tipoEmprestimo === 'semanal') dataVenc = addDias(dataInicio, (i - 1) * 7);
      else dataVenc = addMeses(dataInicio, i - 1);
      pagamentos.push({ cliente_id: clienteId, numero_parcela: i, data_vencimento: dataVenc, data_pagamento: null, valor: parseFloat(valorParcela), status: 'pendente' });
    }
    await supabase.insert('pagamentos', pagamentos);
    res.redirect(`/clientes/${clienteId}?sucesso=Cliente cadastrado com sucesso!`);
  } catch (e) {
    console.error('Erro criar cliente:', e.message);
    res.redirect('/clientes/novo?erro=Erro ao cadastrar cliente');
  }
});

app.get('/clientes/:id', async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const rows = await supabase.select('clientes', { related: 'pagamentos', eq: { field: 'id', value: id } });
    const cliente = rows && rows[0];
    if (!cliente) return res.redirect('/clientes?erro=Cliente não encontrado');
    cliente.pagamentos = (cliente.pagamentos || []).sort((a, b) => a.numero_parcela - b.numero_parcela);

    let totalPago = 0, totalPendente = 0;
    for (const p of cliente.pagamentos) {
      if (p.status === 'pago') totalPago += p.valor;
      else if (p.status === 'parcial') { totalPago += p.valor_pago||0; totalPendente += p.restante||0; }
      else totalPendente += p.valor;
    }
    res.render('cliente', { cliente, totalPago, totalPendente, getRotuloStatusPagamento, getStatusCliente, getCorStatusCliente, getValorComMulta, rotulosTipo });
  } catch (e) {
    console.error('Erro cliente:', e.message);
    res.redirect('/clientes?erro=Erro ao carregar cliente');
  }
});

app.get('/clientes/:id/editar', async (req, res) => {
  try {
    const rows = await supabase.select('clientes', { eq: { field: 'id', value: parseInt(req.params.id) } });
    const cliente = rows && rows[0];
    if (!cliente) return res.redirect('/clientes?erro=Cliente não encontrado');
    res.render('novo-cliente', { cliente, editando: true, rotulosTipo });
  } catch (e) {
    res.redirect('/clientes?erro=Erro ao carregar cliente');
  }
});

app.post('/clientes/:id/editar', async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const { nome, telefone, endereco, observacao, multa_atraso } = req.body;
    if (!nome) return res.redirect(`/clientes/${id}/editar?erro=Nome é obrigatório`);
    const updates = { nome, telefone: telefone||'', endereco: endereco||'', observacao: observacao||'' };
    if (multa_atraso !== undefined) updates.multa_atraso = parseFloat(multa_atraso)||0;
    await supabase.update('clientes', updates, id);
    res.redirect(`/clientes/${id}?sucesso=Cliente atualizado!`);
  } catch (e) {
    res.redirect(`/clientes/${req.params.id}/editar?erro=Erro ao atualizar`);
  }
});

app.post('/clientes/:id/deletar', async (req, res) => {
  try {
    await supabase.remove('clientes', parseInt(req.params.id));
    res.redirect('/clientes?sucesso=Cliente removido!');
  } catch (e) {
    res.redirect('/clientes?erro=Erro ao remover cliente');
  }
});

app.post('/pagamentos/:id/pagar', async (req, res) => {
  try {
    const pagId = parseInt(req.params.id);
    const clienteId = parseInt(req.body.cliente_id);
    const valorPago = parseFloat(req.body.valor_pago) || 0;

    const pags = await supabase.select('pagamentos', { eq: { field: 'id', value: pagId } });
    const pagamento = pags && pags[0];
    if (!pagamento) return res.redirect(`/clientes/${clienteId}?erro=Pagamento não encontrado`);

    const dataPag = req.body.data_pagamento || hoje();

    if (valorPago <= 0 || valorPago >= pagamento.valor) {
      await supabase.update('pagamentos', { status: 'pago', data_pagamento: dataPag, valor_pago: pagamento.valor, restante: 0 }, pagId);
      return res.redirect(`/clientes/${clienteId}?sucesso=Pagamento total de R$ ${pagamento.valor.toFixed(2)} registrado!`);
    }

    const restante = parseFloat((pagamento.valor - valorPago).toFixed(2));
    await supabase.update('pagamentos', { status: 'pago', data_pagamento: dataPag, valor_pago: valorPago, restante: 0 }, pagId);

    const clientes = await supabase.select('clientes', { eq: { field: 'id', value: clienteId } });
    const cliente = clientes && clientes[0];
    if (!cliente) throw new Error('Cliente não encontrado');

    const totalPags = await supabase.count('pagamentos', { eq: { field: 'cliente_id', value: clienteId } });

    const taxa = (cliente.taxa_juros || 0) / 100;
    const novoValor = parseFloat((restante * (1 + taxa)).toFixed(2));
    const tipo = cliente.tipo || 'mensal';
    let dataVenc;
    if (tipo === 'diario') dataVenc = addDias(pagamento.data_vencimento, 1);
    else if (tipo === 'semanal') dataVenc = addDias(pagamento.data_vencimento, 7);
    else dataVenc = addMeses(pagamento.data_vencimento, 1);

    await supabase.insert('pagamentos', {
      cliente_id: clienteId, numero_parcela: totalPags + 1,
      data_vencimento: dataVenc, data_pagamento: null,
      valor: novoValor, status: 'pendente'
    });
    await supabase.update('clientes', { numero_parcelas: totalPags + 1 }, clienteId);

    const msgJuros = cliente.taxa_juros > 0 ? ` (R$ ${restante.toFixed(2)} + ${cliente.taxa_juros}% = R$ ${novoValor.toFixed(2)})` : '';
    res.redirect(`/clientes/${clienteId}?sucesso=Pagamento de R$ ${valorPago.toFixed(2)} recebido! Nova parcela de R$ ${novoValor.toFixed(2)} criada${msgJuros}.`);
  } catch (e) {
    console.error('Erro pagar:', e.message);
    res.redirect(`/clientes/${req.body.cliente_id}?erro=Erro ao registrar pagamento`);
  }
});

app.post('/pagamentos/:id/desmarcar', async (req, res) => {
  try {
    const pagId = parseInt(req.params.id);
    const clienteId = parseInt(req.body.cliente_id);
    await supabase.update('pagamentos', { status: 'pendente', data_pagamento: null, valor_pago: 0, restante: 0 }, pagId);
    res.redirect(`/clientes/${clienteId}?sucesso=Pagamento desmarcado!`);
  } catch (e) {
    res.redirect(`/clientes/${req.body.cliente_id}?erro=Erro ao desmarcar`);
  }
});

app.post('/pagamentos/:id/deletar', async (req, res) => {
  try {
    await supabase.remove('pagamentos', parseInt(req.params.id));
    res.redirect(`/clientes/${req.body.cliente_id}?sucesso=Parcela removida!`);
  } catch (e) {
    res.redirect(`/clientes/${req.body.cliente_id}?erro=Erro ao remover parcela`);
  }
});

app.post('/clientes/:id/add-parcela', async (req, res) => {
  try {
    const clienteId = parseInt(req.params.id);
    const valor = parseFloat(req.body.valor) || 0;
    const dataVenc = req.body.data_vencimento;
    if (valor <= 0 || !dataVenc) return res.redirect(`/clientes/${clienteId}?erro=Preencha valor e data`);

    const totalPags = await supabase.count('pagamentos', { eq: { field: 'cliente_id', value: clienteId } });
    const novaNum = totalPags + 1;

    await supabase.insert('pagamentos', {
      cliente_id: clienteId, numero_parcela: novaNum,
      data_vencimento: dataVenc, data_pagamento: null,
      valor, status: 'pendente'
    });
    await supabase.update('clientes', { numero_parcelas: novaNum }, clienteId);
    res.redirect(`/clientes/${clienteId}?sucesso=Parcela adicionada!`);
  } catch (e) {
    res.redirect(`/clientes/${req.params.id}?erro=Erro ao adicionar parcela`);
  }
});

app.post('/pagamentos/:id/editar', async (req, res) => {
  try {
    const pagId = parseInt(req.params.id);
    const clienteId = parseInt(req.body.cliente_id);
    const valor = parseFloat(req.body.valor) || 0;
    const dataVenc = req.body.data_vencimento;
    const updates = {};
    if (valor > 0) updates.valor = valor;
    if (dataVenc) updates.data_vencimento = dataVenc;
    await supabase.update('pagamentos', updates, pagId);
    res.redirect(`/clientes/${clienteId}?sucesso=Parcela atualizada!`);
  } catch (e) {
    res.redirect(`/clientes/${req.body.cliente_id}?erro=Erro ao editar parcela`);
  }
});

app.get('/resumo', async (req, res) => {
  try {
    const lista = await supabase.select('clientes', { related: 'pagamentos' }) || [];
    const resumoClientes = lista.map(c => {
      c.pagamentos = (c.pagamentos || []).sort((a, b) => a.numero_parcela - b.numero_parcela);
      const pags = c.pagamentos || [];
      let totalPago = 0;
      for (const p of pags) {
        if (p.status === 'pago') totalPago += p.valor;
        else if (p.status === 'parcial') totalPago += p.valor_pago || 0;
      }
      const totalPendente = pags.filter(p => p.status === 'pendente').reduce((s, p) => s + p.valor, 0);
      const pagas = pags.filter(p => p.status === 'pago' || p.status === 'parcial').length;
      const prim = pags.length > 0 ? pags[0].data_vencimento : null;
      const ult = pags.length > 0 ? pags[pags.length - 1].data_vencimento : null;
      const diff = Math.ceil(((ult ? new Date(ult) : new Date(hoje())) - new Date(prim)) / (1000*60*60*24)) + 1;
      return { nome: c.nome, valor_emprestimo: c.valor_emprestimo, tipo: c.tipo, totalPago, totalPendente, totalParcelas: pags.length, parcelasPagas: pagas, primeiroVenc: prim, totalDias: diff > 0 ? diff : 0 };
    });

    const meses = {};
    for (const c of lista) {
      const ma = c.created_at ? c.created_at.substring(0, 7) : null;
      if (!ma) continue;
      if (!meses[ma]) meses[ma] = { emprestado: 0, recebido: 0 };
      meses[ma].emprestado += c.valor_emprestimo || 0;
      for (const p of (c.pagamentos || [])) {
        if ((p.status === 'pago' || p.status === 'parcial') && p.data_pagamento) {
          const mp = p.data_pagamento.substring(0, 7);
          if (!meses[mp]) meses[mp] = { emprestado: 0, recebido: 0 };
          meses[mp].recebido += (p.valor_pago || p.valor || 0);
        }
      }
    }
    const mesesArray = Object.keys(meses).sort().map(m => ({ mes: m, emprestado: meses[m].emprestado, recebido: meses[m].recebido }));
    res.render('resumo', { resumoClientes, mesesArray, rotulosTipo });
  } catch (e) {
    console.error('Erro resumo:', e.message);
    res.render('resumo', { resumoClientes:[], mesesArray:[], rotulosTipo });
  }
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('UNHANDLED ERROR:', err);
  res.status(500).send(`<style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;background:#f8f9fa}.card{background:#fff;padding:2rem;border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,.1);max-width:600px}</style><div class="card"><h3>Internal Server Error</h3><p style="color:#666">${err.message}</p><pre style="font-size:.8em;color:#999;overflow:auto;max-height:300px">${err.stack || ''}</pre></div>`);
});

module.exports = app;

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
