/* ==========================================================
   NetSentinel — Frontend Logic
   ========================================================== */

const dropZone   = document.getElementById('dropZone');
const fileInput  = document.getElementById('fileInput');
const fileInfo   = document.getElementById('fileInfo');
const fileName   = document.getElementById('fileName');
const fileSize   = document.getElementById('fileSize');
const clearBtn   = document.getElementById('clearBtn');
const analyzeBtn = document.getElementById('analyzeBtn');
const browseBtn  = document.getElementById('browseBtn');

const uploadCard    = document.getElementById('uploadCard');
const loadingSection = document.getElementById('loadingSection');
const errorSection  = document.getElementById('errorSection');
const errorMsg      = document.getElementById('errorMsg');
const retryBtn      = document.getElementById('retryBtn');
const resultsSection = document.getElementById('resultsSection');
const searchInput   = document.getElementById('searchInput');
const resultsBody   = document.getElementById('resultsBody');
const rowCount      = document.getElementById('rowCount');

let selectedFile = null;
let chartInstance = null;
let allResults   = [];

// ── File sizing helper ──────────────────────────────────────
function formatBytes(b) {
  if (b < 1024) return b + ' B';
  if (b < 1024 * 1024) return (b / 1024).toFixed(1) + ' KB';
  return (b / (1024 * 1024)).toFixed(2) + ' MB';
}

// ── MDP risk level ──────────────────────────────────────────
function riskLevel(mdp) {
  if (mdp >= 75) return 'danger';
  if (mdp >= 50) return 'warn';
  return 'safe';
}

// ── Set selected file ───────────────────────────────────────
function setFile(file) {
  if (!file || !file.name.toLowerCase().endsWith('.pcap')) {
    alert('Please select a valid .pcap file.');
    return;
  }
  selectedFile = file;
  fileName.textContent = file.name;
  fileSize.textContent = formatBytes(file.size);
  fileInfo.style.display = 'block';
  analyzeBtn.disabled = false;
  dropZone.classList.add('has-file');
}

// ── Clear file ──────────────────────────────────────────────
function clearFile() {
  selectedFile = null;
  fileInput.value = '';
  fileInfo.style.display = 'none';
  analyzeBtn.disabled = true;
  dropZone.classList.remove('has-file');
}

// ── Drag & drop ─────────────────────────────────────────────
dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropZone.classList.add('drag-over');
});
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) setFile(file);
});
dropZone.addEventListener('click', (e) => {
  if (e.target === browseBtn || e.target.closest('.browse-btn')) return;
  fileInput.click();
});
browseBtn.addEventListener('click', (e) => {
  e.stopPropagation();
  fileInput.click();
});
fileInput.addEventListener('change', () => {
  if (fileInput.files.length) setFile(fileInput.files[0]);
});
clearBtn.addEventListener('click', (e) => {
  e.stopPropagation();
  clearFile();
});

// ── Retry button ─────────────────────────────────────────────
retryBtn.addEventListener('click', () => {
  errorSection.style.display = 'none';
  uploadCard.style.display = 'block';
});

// ── Analyze ──────────────────────────────────────────────────
analyzeBtn.addEventListener('click', async () => {
  if (!selectedFile) return;

  // Show loading
  uploadCard.style.display = 'none';
  loadingSection.style.display = 'block';
  errorSection.style.display = 'none';
  resultsSection.style.display = 'none';

  const formData = new FormData();
  formData.append('file', selectedFile);

  try {
    const res = await fetch('/upload', { method: 'POST', body: formData });
    const json = await res.json();

    loadingSection.style.display = 'none';

    if (!res.ok || json.error) {
      errorMsg.textContent = json.error || 'Unexpected server error.';
      errorSection.style.display = 'block';
      uploadCard.style.display = 'block';
      return;
    }

    allResults = json.results || [];
    renderResults(allResults);
    resultsSection.style.display = 'block';
    resultsSection.classList.add('fade-in');
    uploadCard.style.display = 'block';

  } catch (err) {
    loadingSection.style.display = 'none';
    errorMsg.textContent = err.message || 'Could not connect to server.';
    errorSection.style.display = 'block';
    uploadCard.style.display = 'block';
  }
});

// ── Search ───────────────────────────────────────────────────
searchInput.addEventListener('input', () => {
  const q = searchInput.value.trim().toLowerCase();
  const filtered = q ? allResults.filter(r => r.ip.includes(q) || r.mac.toLowerCase().includes(q)) : allResults;
  renderTable(filtered);
});

// ── Render all results ────────────────────────────────────────
function renderResults(results) {
  renderSummaryCards(results);
  renderChart(results);
  renderTable(results);
}

// ── Summary cards ─────────────────────────────────────────────
function renderSummaryCards(results) {
  const total    = results.length;
  const highRisk = results.filter(r => r.mdp >= 50).length;
  const critical = results.filter(r => r.mdp >= 75).length;
  const avg      = total ? (results.reduce((s, r) => s + r.mdp, 0) / total).toFixed(1) : '0.0';

  document.getElementById('totalIPs').textContent   = total;
  document.getElementById('highRiskIPs').textContent = highRisk;
  document.getElementById('criticalIPs').textContent  = critical;
  document.getElementById('avgMDP').textContent      = avg + '%';
}

// ── Chart ─────────────────────────────────────────────────────
function renderChart(results) {
  const ctx = document.getElementById('mdpChart').getContext('2d');

  if (chartInstance) { chartInstance.destroy(); chartInstance = null; }

  // Show top 20 IPs max for readability
  const display = results.slice(0, 20);

  const labels = display.map(r => r.ip);
  const data   = display.map(r => r.mdp);
  const colors = display.map(r => {
    const lvl = riskLevel(r.mdp);
    if (lvl === 'danger') return 'rgba(255,68,68,0.85)';
    if (lvl === 'warn')   return 'rgba(255,170,0,0.85)';
    return 'rgba(0,255,157,0.75)';
  });
  const borderColors = display.map(r => {
    const lvl = riskLevel(r.mdp);
    if (lvl === 'danger') return '#ff4444';
    if (lvl === 'warn')   return '#ffaa00';
    return '#00ff9d';
  });

  chartInstance = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'MDP (%)',
        data,
        backgroundColor: colors,
        borderColor: borderColors,
        borderWidth: 1.5,
        borderRadius: 4,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: 'rgba(6,12,24,0.95)',
          borderColor: 'rgba(0,210,255,0.3)',
          borderWidth: 1,
          titleFont: { family: 'JetBrains Mono', size: 12 },
          bodyFont:  { family: 'JetBrains Mono', size: 12 },
          callbacks: {
            label: ctx => ` MDP: ${ctx.parsed.y}%`,
          }
        }
      },
      scales: {
        x: {
          ticks: {
            color: '#6a8aaa',
            font: { family: 'JetBrains Mono', size: 10 },
            maxRotation: 45,
          },
          grid: { color: 'rgba(255,255,255,0.04)' },
        },
        y: {
          min: 0,
          max: 100,
          ticks: {
            color: '#6a8aaa',
            font: { family: 'JetBrains Mono', size: 11 },
            callback: v => v + '%',
          },
          grid: { color: 'rgba(255,255,255,0.05)' },
        }
      }
    }
  });
}

// ── Table ─────────────────────────────────────────────────────
function renderTable(results) {
  resultsBody.innerHTML = '';
  results.forEach(r => {
    const tr = document.createElement('tr');
    const lvl = riskLevel(r.mdp);

    // Rule badges
    const ruleCells = r.rules.map(v =>
      `<td style="text-align:center"><span class="rule-badge ${v ? 'fail' : 'pass'}">${v ? '✕' : '✓'}</span></td>`
    ).join('');

    // MDP bar
    const mdpBar = `
      <td class="mdp-cell">
        <div class="mdp-wrap">
          <div class="mdp-bar-bg">
            <div class="mdp-bar-fill ${lvl}" style="width:${r.mdp}%"></div>
          </div>
          <span class="mdp-pct ${lvl}">${r.mdp}%</span>
        </div>
      </td>`;

    tr.innerHTML = `
      <td class="ip-cell">${r.ip}</td>
      <td class="mac-cell">${r.mac}</td>
      ${ruleCells}
      ${mdpBar}
    `;
    resultsBody.appendChild(tr);
  });

  rowCount.textContent = `${results.length} result${results.length !== 1 ? 's' : ''}`;
}
