const sample = `name: ecommerce-api
description: Example intentionally vulnerable architecture
components:
  - name: frontend
    type: web
    internet_facing: true
  - name: api
    type: backend
    internet_facing: true
  - name: database
    type: postgres
    sensitive_data: true
connections:
  - frontend -> api
  - api -> database`;

const input = document.querySelector('#architecture-input');
const count = document.querySelector('#char-count');
const button = document.querySelector('#analyze-button');
const errorBox = document.querySelector('#error-message');
const emptyState = document.querySelector('#empty-state');
const report = document.querySelector('#report');

input.value = sample;
updateCount();
input.addEventListener('input', updateCount);
document.querySelector('#load-sample').addEventListener('click', () => { input.value = sample; updateCount(); input.focus(); });
button.addEventListener('click', runAnalysis);

function updateCount() { count.textContent = `${input.value.length} chars`; }

async function runAnalysis() {
  button.disabled = true;
  button.innerHTML = '<span class="button-icon">…</span> Analysing architecture';
  errorBox.hidden = true;
  try {
    const response = await fetch('/v1/analyze', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({architecture: input.value}) });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.detail || 'The architecture could not be analysed.');
    renderReport(payload);
  } catch (error) {
    errorBox.textContent = error.message;
    errorBox.hidden = false;
  } finally {
    button.disabled = false;
    button.innerHTML = '<span class="button-icon">→</span> Analyse architecture';
  }
}

function parseInput(value) {
  try { return JSON.parse(value); } catch (_) { return parseSimpleYaml(value); }
}

function parseSimpleYaml(value) {
  const lines = value.split(/\r?\n/);
  const result = {components: [], connections: []};
  let section = '';
  let current = null;
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    if (line === 'components:') { section = 'components'; continue; }
    if (line === 'connections:') { section = 'connections'; current = null; continue; }
    if (section === 'components' && line.startsWith('- ')) { current = {}; result.components.push(current); const pair = line.slice(2).split(':'); if (pair.length > 1) current[pair[0].trim()] = yamlValue(pair.slice(1).join(':').trim()); continue; }
    if (section === 'connections' && line.startsWith('- ')) { result.connections.push(line.slice(2).trim()); continue; }
    const pair = line.split(':');
    if (pair.length < 2) continue;
    const key = pair.shift().trim(); const val = yamlValue(pair.join(':').trim());
    if (section === 'components' && current) current[key] = val; else result[key] = val;
  }
  if (!result.name || !result.components.length) throw new Error('Enter a valid JSON or YAML architecture with a name and components.');
  return result;
}

function yamlValue(value) {
  if (value === 'true') return true;
  if (value === 'false') return false;
  return value.replace(/^['"]|['"]$/g, '');
}

function renderReport(data) {
  emptyState.hidden = true;
  report.hidden = false;
  document.querySelector('#report-title').textContent = `${data.application} report`;
  document.querySelector('#application-name').textContent = data.application;
  document.querySelector('#threat-count').textContent = data.threat_count;
  document.querySelector('#finding-count').textContent = `(${data.threat_count})`;
  document.querySelector('#severity-grid').innerHTML = ['CRITICAL','HIGH','MEDIUM','LOW'].map(level => `<div class="severity-card ${level.toLowerCase()}"><strong>${data.summary[level] || 0}</strong><small>${level}</small></div>`).join('');
  document.querySelector('#threat-list').innerHTML = data.threats.length ? data.threats.map((threat, index) => `<article class="threat-row"><span class="threat-number">${String(index + 1).padStart(2, '0')}</span><div><h3 class="threat-title">${escapeHtml(threat.title)}</h3><div class="threat-meta"><span>${escapeHtml(threat.category)}</span><span>${escapeHtml(threat.affected_asset)}</span><span>${escapeHtml(threat.cwe || 'No CWE')}</span></div></div><span class="badge ${threat.severity.toLowerCase()}">${threat.severity}</span></article>`).join('') : '<p class="path-note">No deterministic threats found for this architecture.</p>';
  document.querySelector('#attack-path-list').innerHTML = data.attack_paths.length ? data.attack_paths.map(path => `<article class="attack-path"><div class="path-chain">${path.path.map(escapeHtml).join(' <b>→</b> ')}</div><p class="path-note">${escapeHtml(path.rationale)}</p></article>`).join('') : '<p class="path-note">No high-impact attack paths identified.</p>';
  report.scrollIntoView({behavior: 'smooth', block: 'start'});
}

function escapeHtml(value) { return String(value).replace(/[&<>'"]/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char])); }
