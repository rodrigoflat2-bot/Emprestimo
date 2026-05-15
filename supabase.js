const https = require('https');

const supabaseUrl = (process.env.SUPABASE_URL || '').trim();
const supabaseAnonKey = (process.env.SUPABASE_ANON_KEY || '').trim();

function getApiUrl() {
  if (!supabaseUrl) return null;
  return supabaseUrl.replace(/\/$/, '') + '/rest/v1';
}

function request(method, path, body) {
  return new Promise((resolve, reject) => {
    const apiUrl = getApiUrl();
    if (!apiUrl) return reject(new Error('Supabase não configurado'));

    const urlObj = new URL(apiUrl + path);

    const options = {
      hostname: urlObj.hostname,
      path: urlObj.pathname + urlObj.search,
      method,
      headers: {
        'apikey': supabaseAnonKey,
        'Authorization': `Bearer ${supabaseAnonKey}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      timeout: 15000
    };

    if (method === 'POST' || method === 'PATCH') {
      options.headers['Prefer'] = 'return=representation';
    }

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve(data ? JSON.parse(data) : null);
          } else {
            const errMsg = `Supabase ${method} ${path}: ${res.statusCode} ${data.substring(0,200)}`;
            reject(new Error(errMsg));
          }
        } catch (e) {
          reject(new Error(`Erro ao parsear resposta: ${e.message}`));
        }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });

    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

function select(table, options = {}) {
  let path = `/${table}?select=`;
  if (options.related) {
    path += `*,${options.related}(*)`;
  } else {
    path += '*';
  }

  if (options.eq) {
    path += `&${options.eq.field}=eq.${encodeURIComponent(options.eq.value)}`;
  }
  if (options.order) {
    path += `&order=${options.order.field}.${options.order.dir || 'asc'}`;
  }
  if (options.single) {
    path += '&limit=1';
  }
  if (options.ilike) {
    path += `&${options.ilike.field}=ilike.${encodeURIComponent(options.ilike.value)}`;
  }
  if (options.or) {
    path += `&or=(${encodeURIComponent(options.or)})`;
  }

  return request('GET', path);
}

async function count(table, options = {}) {
  try {
    const apiUrl = getApiUrl();
    if (!apiUrl) return 0;
    let path = `/${table}?select=id&limit=0`;
    if (options.eq) {
      path += `&${options.eq.field}=eq.${encodeURIComponent(options.eq.value)}`;
    }
    const urlObj = new URL(apiUrl + path);

    const result = await new Promise((resolve) => {
      const req = https.request({
        hostname: urlObj.hostname,
        path: urlObj.pathname + urlObj.search,
        method: 'HEAD',
        headers: {
          'apikey': supabaseAnonKey,
          'Authorization': `Bearer ${supabaseAnonKey}`,
          'Accept': 'application/json',
          'Prefer': 'count=exact'
        },
        timeout: 10000
      }, (res) => {
        const cr = res.headers['content-range'] || '';
        const total = parseInt(cr.split('/')[1], 10);
        resolve(isNaN(total) ? 0 : total);
      });
      req.on('error', () => resolve(0));
      req.on('timeout', () => { req.destroy(); resolve(0); });
      req.end();
    });
    return result;
  } catch { return 0; }
}

function insert(table, data) {
  return request('POST', `/${table}`, data);
}

function update(table, data, id) {
  return request('PATCH', `/${table}?id=eq.${id}`, data);
}

function remove(table, id) {
  return request('DELETE', `/${table}?id=eq.${id}`);
}

module.exports = { select, count, insert, update, remove, getApiUrl };
