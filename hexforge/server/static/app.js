/**
 * NEXA-HexForge Local Console - Main Application
 * Handles UI state, API communication, and module interactions
 */

// ─── Configuration ───
const API_BASE = '/api';
const DEFAULT_PORT = 8765;

// ─── State ───
const state = {
  currentFile: null,
  currentModule: 'dashboard',
  recentActivity: [],
  serverStatus: 'connected',
  sessionToken: null,
  custodyRecordId: null,
};

// ─── DOM Elements ───
const elements = {
  sidebar: document.getElementById('sidebar'),
  menuToggle: document.getElementById('menu-toggle'),
  mainContent: document.getElementById('main-content'),
  navItems: document.querySelectorAll('.nav-item'),
  modulePanels: document.querySelectorAll('.module-panel'),
  evidenceFile: document.getElementById('evidence-file'),
  selectedFileName: document.getElementById('selected-file-name'),
  fileInfo: document.getElementById('file-info'),
  btnAnalyze: document.getElementById('btn-analyze'),
  btnReport: document.getElementById('btn-report'),
  statusDot: document.getElementById('status-dot'),
  statusText: document.getElementById('status-text'),
  toastContainer: document.getElementById('toast-container'),
  loadingOverlay: document.getElementById('loading-overlay'),
  loadingText: document.getElementById('loading-text'),
};

// ─── Utility Functions ───
function showLoading(text = 'Procesando...') {
  elements.loadingText.textContent = text;
  elements.loadingOverlay.classList.remove('hidden');
}

function hideLoading() {
  elements.loadingOverlay.classList.add('hidden');
}

function showToast(message, type = 'info', duration = 4000) {
  const icons = {
    success: '<svg class="toast-icon" viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41L9 16.17z"/></svg>',
    error: '<svg class="toast-icon" viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm2.07-7.75l-.9.92C13.45 12.9 13 13.5 13 15h-2v-.5c0-1.1.45-2.1 1.17-2.83l1.24-1.21c.37-.36.59-.86.59-1.41 0-1.1-.9-2-2-2s-2 .9-2 2H8c0-2.21 1.79-4 4-4s4 1.79 4 4c0 .88-.36 1.68-.93 2.25z"/></svg>',
    warning: '<svg class="toast-icon" viewBox="0 0 24 24"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>',
    info: '<svg class="toast-icon" viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>',
  };

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `${icons[type]}<span class="toast-message">${message}</span><button class="toast-close" aria-label="Cerrar"><svg viewBox="0 0 24 24" width="16" height="16"><path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/></svg></button>`;

  toast.querySelector('.toast-close').addEventListener('click', () => toast.remove());
  elements.toastContainer.appendChild(toast);

  setTimeout(() => toast.remove(), duration);
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KiB', 'MiB', 'GiB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatNumber(num) {
  return new Intl.NumberFormat('es-ES').format(num);
}

function addActivity(module, action, detail = '') {
  const activity = {
    time: new Date().toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
    module,
    action,
    detail,
  };
  state.recentActivity.unshift(activity);
  if (state.recentActivity.length > 50) state.recentActivity.pop();
  renderActivity();
}

/**
 * Formatea una entrada de actividad basada en el estado real del backend.
 * Respeta los cinco estados: completed, no_findings, not_applicable, pending, error.
 * @param {string} module - Nombre del módulo para el registro
 * @param {object} data - Respuesta del backend
 * @param {object} [detailOverrides] - Sobrescrituras opcionales para detalles específicos del módulo
 */
function formatActivity(module, data, detailOverrides = {}) {
  const stateLabels = {
    'pending': 'Pendiente',
    'not_applicable': 'No aplicable',
    'no_findings': 'Sin hallazgos',
    'completed': 'Completado',
    'error': 'Error',
  };

  const state = data.state || (data.status === 'no_import_directory' ? 'not_applicable' : 'completed');
  const action = stateLabels[state] || 'Desconocido';

  let detail = '';

  if (state === 'completed') {
    // Usar sobrescrituras si existen, sino construir desde data
    if (detailOverrides.completed) {
      detail = detailOverrides.completed(data);
    }
  } else if (state === 'no_findings') {
    // Mostrar razón del backend si existe
    detail = data.reason ? escapeHtml(data.reason) : (detailOverrides.no_findings ? detailOverrides.no_findings(data) : '');
  } else if (state === 'not_applicable') {
    // Mostrar razón del backend (requisitos)
    detail = data.reason ? escapeHtml(data.reason) : (detailOverrides.not_applicable ? detailOverrides.not_applicable(data) : '');
  } else if (state === 'error') {
    detail = data.reason ? escapeHtml(data.reason) : 'Error en el análisis';
  }
  // pending: sin detalle adicional

  return { action, detail };
}

function renderActivity() {
  const container = document.getElementById('recent-activity');
  if (state.recentActivity.length === 0) {
    container.innerHTML = '<p style="color: var(--text-muted);">Sin actividad reciente</p>';
    return;
  }
  container.innerHTML = state.recentActivity.slice(0, 10).map(a => `
    <div style="padding: 8px 0; border-bottom: 1px solid var(--border-color); display: flex; gap: 12px; align-items: center;">
      <span style="color: var(--text-muted); font-family: var(--font-mono); font-size: 11px; min-width: 70px;">${a.time}</span>
      <span style="color: var(--accent-cyan); font-size: 12px; min-width: 100px;">${escapeHtml(a.module)}</span>
      <span style="color: var(--text-primary); font-size: 12px;">${escapeHtml(a.action)}</span>
      <span style="color: var(--text-muted); font-size: 11px;">${escapeHtml(a.detail)}</span>
    </div>
  `).join('');
}

// ─── API Client ───
async function apiRequest(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  const config = {
    headers: {
      'Content-Type': 'application/json',
      ...(state.sessionToken ? {'X-HexForge-Token': state.sessionToken} : {}),
      ...options.headers,
    },
    ...options,
  };

  if (config.body && typeof config.body === 'object') {
    config.body = JSON.stringify(config.body);
  }

  try {
    const response = await fetch(url, config);
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.detail || `HTTP ${response.status}`);
    }

    return data;
  } catch (error) {
    if (error instanceof TypeError && error.message.includes('fetch')) {
      throw new Error('No se puede conectar al servidor. ¿Está en ejecución?');
    }
    throw error;
  }
}

// ─── Module Handlers ───
const moduleHandlers = {
  dashboard: {
    async analyze() {
      if (!state.currentFile) return;
      await Promise.all([
        moduleHandlers.inspector.analyze(),
        moduleHandlers.pe.analyze(),
        moduleHandlers.imports.analyze(),
        moduleHandlers.strings.analyze(),
        moduleHandlers.indicators.analyze(),
        moduleHandlers.hexview.analyze(),
      ]);
      updateDashboardStats();
    },
  },

  inspector: {
    async analyze() {
      if (!state.currentFile) return;
      showLoading('Inspeccionando archivo...');
      try {
        const data = await apiRequest('/inspect', {
          method: 'POST',
          body: {
            file_id: state.currentFile.id,
            preview_bytes: parseInt(document.getElementById('inspect-preview').value) || 256,
            report_mode: document.getElementById('inspect-report-mode').value,
          },
        });
        renderInspector(data);
        // Track completion if successful
        if (!data.state || data.state === 'completed') {
          markModuleCompleted('Inspector');
        }
        const { action, detail } = formatActivity('Inspector', data, {
          completed: d => `${formatBytes(d.size_bytes)} • ${escapeHtml(d.file_signature)}`,
        });
        addActivity('Inspector', action, detail);
      } catch (error) {
        showToast(error.message, 'error');
      } finally {
        hideLoading();
      }
    },
  },

  pe: {
    async analyze() {
      if (!state.currentFile) return;
      showLoading('Analizando estructura PE...');
      try {
        const data = await apiRequest('/pe', {
          method: 'POST',
          body: { file_id: state.currentFile.id },
        });
        renderPe(data);
        // Track completion if successful (state === 'completed' or legacy success)
        if (!data.state || data.state === 'completed') {
          markModuleCompleted('PE');
        }
        const { action, detail } = formatActivity('PE', data, {
          completed: d => `${escapeHtml(d.format)} • ${d.section_count} secciones`,
        });
        addActivity('PE', action, detail);
      } catch (error) {
        showToast(error.message, 'error');
      } finally {
        hideLoading();
      }
    },
  },

  imports: {
    async analyze() {
      if (!state.currentFile) return;
      showLoading('Analizando importaciones...');
      try {
        const data = await apiRequest('/imports', {
          method: 'POST',
          body: { file_id: state.currentFile.id },
        });
        renderImports(data);
        // Track completion if successful
        if (!data.state || data.state === 'completed') {
          markModuleCompleted('Imports');
        }
        const { action, detail } = formatActivity('Imports', data, {
          completed: d => {
            const fnCount = d.imports?.reduce((sum, dll) => sum + dll.functions.length, 0) || 0;
            return `${d.imports?.length || 0} DLLs • ${fnCount} funciones`;
          },
        });
        addActivity('Imports', action, detail);
      } catch (error) {
        showToast(error.message, 'error');
      } finally {
        hideLoading();
      }
    },
  },

  strings: {
    async analyze() {
      if (!state.currentFile) return;
      showLoading('Extrayendo cadenas...');
      try {
        const data = await apiRequest('/strings', {
          method: 'POST',
          body: {
            file_id: state.currentFile.id,
            min_length: parseInt(document.getElementById('strings-min-length').value) || 5,
            max_results: parseInt(document.getElementById('strings-max-results').value) || 200,
          },
        });
        renderStrings(data);
        // Track completion if successful
        if (!data.state || data.state === 'completed') {
          markModuleCompleted('Strings');
        }
        const { action, detail } = formatActivity('Strings', data, {
          completed: d => `${d.strings?.length || 0} cadenas`,
        });
        addActivity('Strings', action, detail);
      } catch (error) {
        showToast(error.message, 'error');
      } finally {
        hideLoading();
      }
    },
  },

  indicators: {
    async analyze() {
      if (!state.currentFile) return;
      showLoading('Analizando indicadores...');
      try {
        const data = await apiRequest('/indicators', {
          method: 'POST',
          body: { file_id: state.currentFile.id },
        });
        renderIndicators(data);
        // Track completion if successful
        if (!data.state || data.state === 'completed') {
          markModuleCompleted('Indicators');
          // Store for dashboard stats
          state.lastIndicatorsData = data;
        }
        const { action, detail } = formatActivity('Indicators', data, {
          completed: d => {
            const reviewCount = d.indicators?.filter(i => i.severity === 'review').length || 0;
            return `${reviewCount} para revisión`;
          },
        });
        addActivity('Indicators', action, detail);
      } catch (error) {
        showToast(error.message, 'error');
      } finally {
        hideLoading();
      }
    },
  },

  hexview: {
    async analyze() {
      if (!state.currentFile) return;
      const offsetStr = document.getElementById('hex-offset').value.trim();
      const offset = offsetStr.startsWith('0x') ? parseInt(offsetStr, 16) : parseInt(offsetStr) || 0;
      const length = parseInt(document.getElementById('hex-length').value) || 256;
      const width = parseInt(document.getElementById('hex-width').value) || 16;

      showLoading('Cargando vista hex...');
      try {
        const data = await apiRequest('/hexview', {
          method: 'POST',
          body: { file_id: state.currentFile.id, offset, length, width },
        });
        renderHexView(data, offset, width);
      } catch (error) {
        showToast(error.message, 'error');
      } finally {
        hideLoading();
      }
    },
  },

  artifacts: {
    async analyze() {
      if (!state.currentFile) return;
      showLoading('Procesando artefactos...');
      try {
        const data = await apiRequest('/artifacts', {
          method: 'POST',
          body: { file_id: state.currentFile.id },
        });
        renderArtifacts(data);
        // Track completion if successful (check export state)
        const exportState = data.export?.state;
        if ((!exportState || exportState === 'completed') && (!data.timeline?.state || data.timeline.state === 'completed')) {
          markModuleCompleted('Artifacts (C1)');
        }
        const { action, detail } = formatActivity('Artifacts (C1)', data.export || data, {
          completed: d => `${d.count || d.timeline?.count || 0} eventos`,
        });
        addActivity('Artifacts (C1)', action, detail);
      } catch (error) {
        showToast(error.message, 'error');
      } finally {
        hideLoading();
      }
    },
  },

  timeline: {
    async analyze() {
      if (!state.currentFile) return;
      const windowSeconds = parseInt(document.getElementById('timeline-window').value) || 300;
      showLoading('Correlacionando cronología...');
      try {
        const data = await apiRequest('/timeline', {
          method: 'POST',
          body: { file_id: state.currentFile.id, window_seconds: windowSeconds },
        });
        renderTimeline(data);
        // Track completion if successful
        if (!data.state || data.state === 'completed') {
          markModuleCompleted('Timeline (C2)');
        }
        const { action, detail } = formatActivity('Timeline (C2)', data, {
          completed: d => `${d.correlation_count || 0} correlaciones`,
        });
        addActivity('Timeline (C2)', action, detail);
      } catch (error) {
        showToast(error.message, 'error');
      } finally {
        hideLoading();
      }
    },
  },

  custody: {
    async register(formData) {
      showLoading('Registrando evidencia...');
      try {
        const data = await apiRequest('/custody/register', {
          method: 'POST',
          body: {
            file_id: state.currentFile.id,
            evidence_id: formData.evidence_id,
            actor: formData.actor,
            timestamp: formData.timestamp || null,
          },
        });
        state.custodyRecordId = data.record_id;
        document.getElementById('custody-register-result').innerHTML = renderJson(data);
        showToast('Evidencia registrada correctamente', 'success');
        const { action, detail } = formatActivity('Custody (C3)', data, {
          completed: d => d.evidence_id,
        });
        addActivity('Custody (C3)', action, detail);
      } catch (error) {
        showToast(error.message, 'error');
      } finally {
        hideLoading();
      }
    },

    async append(formData) {
      showLoading('Añadiendo evento...');
      try {
        const data = await apiRequest('/custody/append', {
          method: 'POST',
          body: {...formData, record_id: state.custodyRecordId},
        });
        document.getElementById('custody-append-result').innerHTML = renderJson(data);
        showToast('Evento añadido a la cadena', 'success');
        addActivity('Custody (C3)', 'Evento añadido', escapeHtml(formData.action));
      } catch (error) {
        showToast(error.message, 'error');
      } finally {
        hideLoading();
      }
    },

    async verify(formData) {
      showLoading('Verificando cadena de custodia...');
      try {
        const data = await apiRequest('/custody/verify', {
          method: 'POST',
          body: {
            record_id: state.custodyRecordId,
            file_id: state.currentFile.id,
          },
        });
        document.getElementById('custody-verify-result').innerHTML = renderJson(data);
        const match = data.evidence_hash_matches ? '✓ Coincide' : '✗ No coincide';
        showToast(`Verificación: ${match}`, data.evidence_hash_matches ? 'success' : 'error');
        const { action, detail } = formatActivity('Custody (C3)', data, {
          completed: () => match,
        });
        addActivity('Custody (C3)', action, detail);
      } catch (error) {
        showToast(error.message, 'error');
      } finally {
        hideLoading();
      }
    },
  },

  registry: {
    async analyze() {
      if (!state.currentFile) return;
      showLoading('Analizando registro...');
      try {
        const data = await apiRequest('/registry', {
          method: 'POST',
          body: { file_id: state.currentFile.id },
        });
        renderRegistry(data);
        // Track completion if successful
        if (!data.state || data.state === 'completed') {
          markModuleCompleted('Registry');
        }
        const { action, detail } = formatActivity('Registry', data, {
          completed: d => `${d.review_count || 0} para revisión de ${d.count || 0}`,
        });
        addActivity('Registry', action, detail);
      } catch (error) {
        showToast(error.message, 'error');
      } finally {
        hideLoading();
      }
    },
  },

  // Academy modules
  'academy-base': {
    async convert() {
      const value = document.getElementById('base-value').value.trim();
      const fromBase = document.getElementById('base-from').value;
      if (!value) return showToast('Ingrese un valor', 'warning');

      showLoading('Convirtiendo...');
      try {
        const endpoint = fromBase === 'hex' ? '/academy/hex2bin' : '/academy/bin2hex';
        const data = await apiRequest(endpoint, {
          method: 'POST',
          body: { value },
        });
        document.getElementById('base-result').innerHTML = renderJson(data);
        addActivity('Academy A1', 'Convertido', fromBase === 'hex' ? 'HEX → Bin/Dec' : 'Bin → HEX');
      } catch (error) {
        showToast(error.message, 'error');
      } finally {
        hideLoading();
      }
    },
  },

  'academy-byte': {
    async inspect() {
      if (!state.currentFile) return showToast('Seleccione un archivo', 'warning');
      const offsetStr = document.getElementById('byte-offset').value.trim();
      const offset = offsetStr.startsWith('0x') ? parseInt(offsetStr, 16) : parseInt(offsetStr) || 0;

      showLoading('Inspeccionando byte...');
      try {
        const data = await apiRequest('/academy/byte', {
          method: 'POST',
          body: { file_id: state.currentFile.id, offset },
        });
        document.getElementById('byte-result').innerHTML = renderJson(data);
        addActivity('Academy A2', 'Byte inspeccionado', `Offset 0x${offset.toString(16).toUpperCase()}`);
      } catch (error) {
        showToast(error.message, 'error');
      } finally {
        hideLoading();
      }
    },
  },

  'academy-pe': {
    async explore() {
      if (!state.currentFile) return showToast('Seleccione un archivo PE', 'warning');
      showLoading('Explorando PE...');
      try {
        const data = await apiRequest('/academy/pe', {
          method: 'POST',
          body: { file_id: state.currentFile.id },
        });
        document.getElementById('pe-explore-result').innerHTML = renderJson(data);
        addActivity('Academy A3', 'PE explorado', data.format);
      } catch (error) {
        showToast(error.message, 'error');
      } finally {
        hideLoading();
      }
    },
  },

  'academy-entropy': {
    async analyze() {
      if (!state.currentFile) return showToast('Seleccione un archivo PE', 'warning');
      const sectionIndex = parseInt(document.getElementById('entropy-section').value) || 0;
      showLoading('Calculando entropía...');
      try {
        const data = await apiRequest('/academy/entropy', {
          method: 'POST',
          body: { file_id: state.currentFile.id, section_index: sectionIndex },
        });
        document.getElementById('entropy-result').innerHTML = renderJson(data);
        addActivity('Academy A4', 'Entropía calculada', `Sección ${sectionIndex}: ${data.entropy_bits_per_byte} bits/byte`);
      } catch (error) {
        showToast(error.message, 'error');
      } finally {
        hideLoading();
      }
    },
  },

  'academy-imports': {
    async explain() {
      if (!state.currentFile) return showToast('Seleccione un archivo PE', 'warning');
      showLoading('Explicando importaciones...');
      try {
        const data = await apiRequest('/academy/imports', {
          method: 'POST',
          body: { file_id: state.currentFile.id },
        });
        document.getElementById('imports-explain-result').innerHTML = renderJson(data);
        addActivity('Academy A5', 'Imports explicados', `${data.dll_count} DLLs • ${data.function_count} funciones`);
      } catch (error) {
        showToast(error.message, 'error');
      } finally {
        hideLoading();
      }
    },
  },

  'academy-rva': {
    async map() {
      if (!state.currentFile) return showToast('Seleccione un archivo PE', 'warning');
      const rvaStr = document.getElementById('rva-value').value.trim();
      const rva = rvaStr.startsWith('0x') ? parseInt(rvaStr, 16) : parseInt(rvaStr) || 0;
      showLoading('Mapeando RVA...');
      try {
        const data = await apiRequest('/academy/rva', {
          method: 'POST',
          body: { file_id: state.currentFile.id, rva },
        });
        document.getElementById('rva-result').innerHTML = renderJson(data);
        addActivity('Academy A6', 'RVA mapeado', `RVA 0x${rva.toString(16).toUpperCase()} → ${data.result?.file_offset || 'N/A'}`);
      } catch (error) {
        showToast(error.message, 'error');
      } finally {
        hideLoading();
      }
    },
  },

  reports: {
    async export() {
      if (!state.currentFile) return showToast('Seleccione evidencia primero', 'warning');
      const mode = document.getElementById('inspect-report-mode')?.value || 'redacted';
      const filename = 'hexforge-' + Date.now() + '.json';
      try {
        const result = await apiRequest('/report/write', {method: 'POST',
          body: {file_id: state.currentFile.id, report_mode: mode, filename}});
        const a = document.createElement('a');
        a.href = '/api/report/download/' + encodeURIComponent(result.filename);
        a.download = result.filename;
        document.body.appendChild(a); a.click(); a.remove();
        showToast('Informe generado', 'success');
      } catch (error) { showToast(error.message, 'error'); }
    },
  },
};

// ─── Renderers ───
function renderInspector(data) {
  const container = document.getElementById('inspector-result');
  const limitations = data.limitations?.map(l => `<li>${l}</li>`).join('') || '';
  const preview = data.report_mode === 'redacted' ? '(redactado)' : (data.hex_preview || '(sin preview)');

  container.innerHTML = `
    <table class="result-table">
      <thead><tr><th>Campo</th><th>Valor</th></tr></thead>
      <tbody>
        <tr><td>Tamaño</td><td>${formatBytes(data.size_bytes)} (${formatNumber(data.size_bytes)} bytes)</td></tr>
        <tr><td>SHA-256</td><td><code style="font-size: 11px;">${data.sha256}</code></td></tr>
        <tr><td>SHA-512</td><td><code style="font-size: 11px;">${data.sha512}</code></td></tr>
        <tr><td>Firma</td><td>${escapeHtml(data.file_signature)}</td></tr>
        <tr><td>Entropía</td><td>${data.entropy_bits_per_byte} bits/byte</td></tr>
        <tr><td>Preview Hex</td><td><code style="font-size: 10px;">${preview}</code></td></tr>
        <tr><td>Preview ASCII</td><td><code style="font-size: 10px;">${data.report_mode === 'redacted' ? '(redactado)' : (data.ascii_preview || '(sin preview)')}</code></td></tr>
        <tr><td>Modo reporte</td><td><span class="tag tag-${data.report_mode === 'forense' ? 'informational' : data.report_mode === 'shareable' ? 'moderate' : 'review'}">${data.report_mode}</span></td></tr>
        <tr><td>Observado (UTC)</td><td>${data.observed_at_utc}</td></tr>
      </tbody>
    </table>
    ${limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${limitations}</ul></details>` : ''}
  `;
}

function renderPe(data) {
  const container = document.getElementById('pe-result');

  // Handle state-based responses
  if (data.state) {
    const stateLabels = {
      'pending': 'PENDIENTE',
      'not_applicable': 'NO APLICABLE',
      'no_findings': 'SIN HALLAZGOS',
      'completed': 'COMPLETADO',
      'error': 'ERROR',
    };
    const label = stateLabels[data.state] || data.state.toUpperCase();
    const tagClass = data.state === 'error' ? 'tag-error' : data.state === 'not_applicable' ? 'tag-warning' : 'tag-informational';

    // For completed: show badge + full results
    if (data.state === 'completed') {
      const sections = data.sections?.map(s => `
        <tr>
          <td>${escapeHtml(s.name)}</td>
          <td>${s.virtual_address}</td>
          <td>${s.raw_offset}</td>
          <td>${formatBytes(s.raw_size)}</td>
          <td>${formatBytes(s.virtual_size)}</td>
          <td>${s.characteristics}</td>
          <td>${s.executable ? '✓' : '✗'}</td>
          <td>${s.writable ? '✓' : '✗'}</td>
        </tr>
      `).join('') || '<tr><td colspan="8">Sin secciones</td></tr>';

      container.innerHTML = `
        <div style="margin-bottom: 16px;">
          <span class="tag ${tagClass}" style="font-size: 14px; padding: 8px 16px;">${label}</span>
        </div>
        <table class="result-table">
          <thead><tr><th>Campo</th><th>Valor</th></tr></thead>
          <tbody>
            <tr><td>Formato</td><td>${escapeHtml(data.format)}</td></tr>
            <tr><td>Machine</td><td>${escapeHtml(data.machine)}</td></tr>
            <tr><td>Characteristics</td><td>${escapeHtml(data.characteristics)}</td></tr>
            <tr><td>PE Header Offset</td><td>0x${data.pe_header_offset.toString(16).toUpperCase()}</td></tr>
            <tr><td>Entry Point RVA</td><td>${escapeHtml(data.entry_point_rva)}</td></tr>
            <tr><td>Image Base</td><td>${escapeHtml(data.image_base)}</td></tr>
            <tr><td>Section Count</td><td>${escapeHtml(data.section_count)}</td></tr>
          </tbody>
        </table>
        <h4 style="margin: 16px 0 8px; color: var(--text-secondary);">Secciones</h4>
        <table class="result-table">
          <thead><tr><th>Nombre</th><th>Virtual Addr</th><th>Raw Offset</th><th>Raw Size</th><th>Virtual Size</th><th>Flags</th><th>Exe</th><th>Wrt</th></tr></thead>
          <tbody>${sections}</tbody>
        </table>
        ${data.reason ? `<p style="margin-top: 16px; color: var(--text-secondary);">${escapeHtml(data.reason)}</p>` : ''}
        ${data.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${data.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
      `;
      return;
    }

    // For no_findings: show badge + reason + available data (if any)
    if (data.state === 'no_findings') {
      const sections = data.sections?.map(s => `
        <tr>
          <td>${escapeHtml(s.name)}</td>
          <td>${s.virtual_address}</td>
          <td>${s.raw_offset}</td>
          <td>${formatBytes(s.raw_size)}</td>
          <td>${formatBytes(s.virtual_size)}</td>
          <td>${s.characteristics}</td>
          <td>${s.executable ? '✓' : '✗'}</td>
          <td>${s.writable ? '✓' : '✗'}</td>
        </tr>
      `).join('') || '';

      container.innerHTML = `
        <div style="margin-bottom: 16px;">
          <span class="tag ${tagClass}" style="font-size: 14px; padding: 8px 16px;">${label}</span>
        </div>
        ${data.reason ? `<p style="margin-top: 16px; color: var(--text-secondary);">${escapeHtml(data.reason)}</p>` : ''}
        ${sections ? `
        <h4 style="margin: 16px 0 8px; color: var(--text-secondary);">Secciones</h4>
        <table class="result-table">
          <thead><tr><th>Nombre</th><th>Virtual Addr</th><th>Raw Offset</th><th>Raw Size</th><th>Virtual Size</th><th>Flags</th><th>Exe</th><th>Wrt</th></tr></thead>
          <tbody>${sections}</tbody>
        </table>
        ` : ''}
        ${data.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${data.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
      `;
      return;
    }

    // For not_applicable: explanation + requirements
    if (data.state === 'not_applicable') {
      container.innerHTML = `
        <div style="text-align: center; padding: 40px 20px;">
          <span class="tag ${tagClass}" style="font-size: 14px; padding: 8px 16px;">${label}</span>
          ${data.reason ? `<p style="margin-top: 16px; color: var(--text-secondary);">${escapeHtml(data.reason)}</p>` : ''}
          <p style="margin-top: 16px; color: var(--text-secondary);">Requiere: archivo PE válido con firma MZ y PE correcta</p>
          ${data.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${data.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
        </div>
      `;
      return;
    }

    // For pending/error: show state only
    container.innerHTML = `
      <div style="text-align: center; padding: 40px 20px;">
        <span class="tag ${tagClass}" style="font-size: 14px; padding: 8px 16px;">${label}</span>
        ${data.reason ? `<p style="margin-top: 16px; color: var(--text-secondary);">${escapeHtml(data.reason)}</p>` : ''}
        ${data.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${data.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
      </div>
    `;
    return;
  }

  // Legacy response without state field (backward compatibility)
  const sections = data.sections?.map(s => `
    <tr>
      <td>${escapeHtml(s.name)}</td>
      <td>${s.virtual_address}</td>
      <td>${s.raw_offset}</td>
      <td>${formatBytes(s.raw_size)}</td>
      <td>${formatBytes(s.virtual_size)}</td>
      <td>${s.characteristics}</td>
      <td>${s.executable ? '✓' : '✗'}</td>
      <td>${s.writable ? '✓' : '✗'}</td>
    </tr>
  `).join('') || '<tr><td colspan="8">Sin secciones</td></tr>';

  container.innerHTML = `
    <table class="result-table">
      <thead><tr><th>Campo</th><th>Valor</th></tr></thead>
      <tbody>
        <tr><td>Formato</td><td>${escapeHtml(data.format)}</td></tr>
        <tr><td>Machine</td><td>${escapeHtml(data.machine)}</td></tr>
        <tr><td>Characteristics</td><td>${escapeHtml(data.characteristics)}</td></tr>
        <tr><td>PE Header Offset</td><td>0x${data.pe_header_offset.toString(16).toUpperCase()}</td></tr>
        <tr><td>Entry Point RVA</td><td>${escapeHtml(data.entry_point_rva)}</td></tr>
        <tr><td>Image Base</td><td>${escapeHtml(data.image_base)}</td></tr>
        <tr><td>Section Count</td><td>${escapeHtml(data.section_count)}</td></tr>
      </tbody>
    </table>
    <h4 style="margin: 16px 0 8px; color: var(--text-secondary);">Secciones</h4>
    <table class="result-table">
      <thead><tr><th>Nombre</th><th>Virtual Addr</th><th>Raw Offset</th><th>Raw Size</th><th>Virtual Size</th><th>Flags</th><th>Exe</th><th>Wrt</th></tr></thead>
      <tbody>${sections}</tbody>
    </table>
    ${data.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${data.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
  `;
}

function renderImports(data) {
  const container = document.getElementById('imports-result');

  // Handle state-based responses
  if (data.state) {
    const stateLabels = {
      'pending': 'PENDIENTE',
      'not_applicable': 'NO APLICABLE',
      'no_findings': 'SIN HALLAZGOS',
      'completed': 'COMPLETADO',
      'error': 'ERROR',
    };
    const label = stateLabels[data.state] || data.state.toUpperCase();
    const tagClass = data.state === 'error' ? 'tag-error' : data.state === 'not_applicable' ? 'tag-warning' : 'tag-informational';

    // For completed: show badge + full results
    if (data.state === 'completed') {
      const imports = data.imports?.map(dll => `
        <details style="margin: 8px 0; padding: 8px; background: var(--bg-tertiary); border-radius: var(--radius-sm);">
          <summary style="cursor:pointer;font-weight:600;color:var(--accent-cyan);">${escapeHtml(dll.dll)} (${dll.functions.length} funciones)</summary>
          <table class="result-table" style="margin-top:8px;font-size:11px;">
            <thead><tr><th>Función</th><th>Tipo</th></tr></thead>
            <tbody>
              ${dll.functions.map(f => `
                <tr>
                  <td>${escapeHtml(f.name || `ORDINAL #${f.ordinal}`)}</td>
                  <td>${f.name ? 'Name' : 'Ordinal'}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </details>
      `).join('') || 'Sin importaciones';

      container.innerHTML = `
        <div style="margin-bottom: 16px;">
          <span class="tag ${tagClass}" style="font-size: 14px; padding: 8px 16px;">${label}</span>
        </div>
        ${imports}
        ${data.reason ? `<p style="margin-top: 16px; color: var(--text-secondary);">${escapeHtml(data.reason)}</p>` : ''}
        ${data.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${data.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
      `;
      return;
    }

    // For no_findings: show badge + reason + available data
    if (data.state === 'no_findings') {
      const imports = data.imports?.map(dll => `
        <details style="margin: 8px 0; padding: 8px; background: var(--bg-tertiary); border-radius: var(--radius-sm);">
          <summary style="cursor:pointer;font-weight:600;color:var(--accent-cyan);">${escapeHtml(dll.dll)} (${dll.functions.length} funciones)</summary>
          <table class="result-table" style="margin-top:8px;font-size:11px;">
            <thead><tr><th>Función</th><th>Tipo</th></tr></thead>
            <tbody>
              ${dll.functions.map(f => `
                <tr>
                  <td>${escapeHtml(f.name || `ORDINAL #${f.ordinal}`)}</td>
                  <td>${f.name ? 'Name' : 'Ordinal'}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </details>
      `).join('') || '';

      container.innerHTML = `
        <div style="margin-bottom: 16px;">
          <span class="tag ${tagClass}" style="font-size: 14px; padding: 8px 16px;">${label}</span>
        </div>
        ${data.reason ? `<p style="margin-top: 16px; color: var(--text-secondary);">${escapeHtml(data.reason)}</p>` : ''}
        ${imports ? imports : '<p style="color: var(--text-muted);">No hay importaciones para mostrar</p>'}
        ${data.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${data.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
      `;
      return;
    }

    // For not_applicable: explanation + requirements
    if (data.state === 'not_applicable') {
      container.innerHTML = `
        <div style="text-align: center; padding: 40px 20px;">
          <span class="tag ${tagClass}" style="font-size: 14px; padding: 8px 16px;">${label}</span>
          ${data.reason ? `<p style="margin-top: 16px; color: var(--text-secondary);">${escapeHtml(data.reason)}</p>` : ''}
          <p style="margin-top: 16px; color: var(--text-secondary);">Requiere: archivo PE válido con directorio de importaciones</p>
          ${data.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${data.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
        </div>
      `;
      return;
    }

    // For pending/error: show state only
    container.innerHTML = `
      <div style="text-align: center; padding: 40px 20px;">
        <span class="tag ${tagClass}" style="font-size: 14px; padding: 8px 16px;">${label}</span>
        ${data.reason ? `<p style="margin-top: 16px; color: var(--text-secondary);">${escapeHtml(data.reason)}</p>` : ''}
        ${data.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${data.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
      </div>
    `;
    return;
  }

  // Legacy response without state field (backward compatibility)
  if (data.status === 'no_import_directory') {
    container.innerHTML = '<div class="json-viewer">Sin directorio de importaciones</div>';
    return;
  }

  const imports = data.imports?.map(dll => `
    <details style="margin: 8px 0; padding: 8px; background: var(--bg-tertiary); border-radius: var(--radius-sm);">
      <summary style="cursor:pointer;font-weight:600;color:var(--accent-cyan);">${escapeHtml(dll.dll)} (${dll.functions.length} funciones)</summary>
      <table class="result-table" style="margin-top:8px;font-size:11px;">
        <thead><tr><th>Función</th><th>Tipo</th></tr></thead>
        <tbody>
          ${dll.functions.map(f => `
            <tr>
              <td>${escapeHtml(f.name || `ORDINAL #${f.ordinal}`)}</td>
              <td>${f.name ? 'Name' : 'Ordinal'}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </details>
  `).join('') || 'Sin importaciones';

  container.innerHTML = `
    <div style="margin-bottom: 16px;">
      <span class="tag tag-${data.status === 'parsed' ? 'moderate' : 'informational'}">${escapeHtml(data.status)}</span>
    </div>
    ${imports}
    ${data.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${data.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
  `;
}

function renderStrings(data) {
  const container = document.getElementById('strings-result');
  const strings = data.strings?.map(s => `
    <div class="string-item">
      <span class="string-offset">${s.offset} (0x${s.offset.toString(16).toUpperCase()})</span>
      <span class="string-encoding">${s.encoding}</span>
      <span class="string-value">${escapeHtml(s.value)}</span>
      ${s.truncated ? '<span class="string-truncated">[truncado]</span>' : ''}
    </div>
  `).join('') || '<div class="string-item" style="color:var(--text-muted);">No se encontraron cadenas</div>';

  container.innerHTML = `
    <div class="strings-list">${strings}</div>
    <div style="padding: 12px; border-top: 1px solid var(--border-color); color: var(--text-muted); font-size: 12px;">
      Total: ${data.strings?.length || 0} cadenas
    </div>
  `;
}

function renderIndicators(data) {
  const container = document.getElementById('indicators-result');

  // Handle state-based responses
  if (data.state) {
    const stateLabels = {
      'pending': 'PENDIENTE',
      'not_applicable': 'NO APLICABLE',
      'no_findings': 'SIN HALLAZGOS',
      'completed': 'COMPLETADO',
      'error': 'ERROR',
    };
    const label = stateLabels[data.state] || data.state.toUpperCase();
    const tagClass = data.state === 'error' ? 'tag-error' : data.state === 'not_applicable' ? 'tag-warning' : 'tag-informational';

    // For completed: show badge + full results
    if (data.state === 'completed') {
      const sections = data.sections?.map(s => `
        <tr>
          <td>${escapeHtml(s.name)}</td>
          <td>${s.entropy.toFixed(4)}</td>
          <td>${formatBytes(s.raw_size)}</td>
        </tr>
      `).join('') || '';

      const findings = data.indicators?.map(f => `
        <tr>
          <td>${escapeHtml(f.section)}</td>
          <td><span class="tag tag-${f.severity === 'review' ? 'review' : 'informational'}">${escapeHtml(f.rule)}</span></td>
          <td>${escapeHtml(f.reason)}</td>
        </tr>
      `).join('') || '<tr><td colspan="3">Sin hallazgos</td></tr>';

      container.innerHTML = `
        <div style="margin-bottom: 16px;">
          <span class="tag ${tagClass}" style="font-size: 14px; padding: 8px 16px;">${label}</span>
        </div>
        <h4 style="margin: 16px 0 8px; color: var(--text-secondary);">Entropía por Sección</h4>
        <table class="result-table">
          <thead><tr><th>Sección</th><th>Entropía</th><th>Tamaño</th></tr></thead>
          <tbody>${sections}</tbody>
        </table>
        <h4 style="margin: 24px 0 8px; color: var(--text-secondary);">Indicadores</h4>
        <table class="result-table">
          <thead><tr><th>Sección</th><th>Regla</th><th>Razón</th></tr></thead>
          <tbody>${findings}</tbody>
        </table>
        <div style="margin-top: 16px; padding: 12px; background: var(--bg-tertiary); border-radius: var(--radius-sm); color: var(--text-muted); font-size: 12px;">
          Veredicto: <strong style="color: var(--accent-amber);">${escapeHtml(data.verdict)}</strong> — Los indicadores son señales para revisión, no veredictos de malware.
        </div>
        ${data.reason ? `<p style="margin-top: 16px; color: var(--text-secondary);">${escapeHtml(data.reason)}</p>` : ''}
        ${data.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${data.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
      `;
      return;
    }

    // For no_findings: show badge + reason + available data (sections, no indicators)
    if (data.state === 'no_findings') {
      const sections = data.sections?.map(s => `
        <tr>
          <td>${escapeHtml(s.name)}</td>
          <td>${s.entropy.toFixed(4)}</td>
          <td>${formatBytes(s.raw_size)}</td>
        </tr>
      `).join('') || '';

      container.innerHTML = `
        <div style="margin-bottom: 16px;">
          <span class="tag ${tagClass}" style="font-size: 14px; padding: 8px 16px;">${label}</span>
        </div>
        ${data.reason ? `<p style="margin-top: 16px; color: var(--text-secondary);">${escapeHtml(data.reason)}</p>` : ''}
        ${sections ? `
        <h4 style="margin: 16px 0 8px; color: var(--text-secondary);">Entropía por Sección</h4>
        <table class="result-table">
          <thead><tr><th>Sección</th><th>Entropía</th><th>Tamaño</th></tr></thead>
          <tbody>${sections}</tbody>
        </table>
        ` : ''}
        <h4 style="margin: 24px 0 8px; color: var(--text-secondary);">Indicadores</h4>
        <p style="color: var(--text-muted);">No se detectaron indicadores</p>
        ${data.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${data.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
      `;
      return;
    }

    // For not_applicable: explanation + requirements
    if (data.state === 'not_applicable') {
      container.innerHTML = `
        <div style="text-align: center; padding: 40px 20px;">
          <span class="tag ${tagClass}" style="font-size: 14px; padding: 8px 16px;">${label}</span>
          ${data.reason ? `<p style="margin-top: 16px; color: var(--text-secondary);">${escapeHtml(data.reason)}</p>` : ''}
          <p style="margin-top: 16px; color: var(--text-secondary);">Requiere: archivo PE válido con secciones analizables</p>
          ${data.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${data.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
        </div>
      `;
      return;
    }

    // For pending/error: show state only
    container.innerHTML = `
      <div style="text-align: center; padding: 40px 20px;">
        <span class="tag ${tagClass}" style="font-size: 14px; padding: 8px 16px;">${label}</span>
        ${data.reason ? `<p style="margin-top: 16px; color: var(--text-secondary);">${escapeHtml(data.reason)}</p>` : ''}
        ${data.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${data.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
      </div>
    `;
    return;
  }

  // Legacy response without state field (backward compatibility)
  const sections = data.sections?.map(s => `
    <tr>
      <td>${escapeHtml(s.name)}</td>
      <td>${s.entropy.toFixed(4)}</td>
      <td>${formatBytes(s.raw_size)}</td>
    </tr>
  `).join('') || '';

  const findings = data.indicators?.map(f => `
    <tr>
      <td>${escapeHtml(f.section)}</td>
      <td><span class="tag tag-${f.severity === 'review' ? 'review' : 'informational'}">${escapeHtml(f.rule)}</span></td>
      <td>${escapeHtml(f.reason)}</td>
    </tr>
  `).join('') || '<tr><td colspan="3">Sin hallazgos</td></tr>';

  container.innerHTML = `
    <h4 style="margin: 16px 0 8px; color: var(--text-secondary);">Entropía por Sección</h4>
    <table class="result-table">
      <thead><tr><th>Sección</th><th>Entropía</th><th>Tamaño</th></tr></thead>
      <tbody>${sections}</tbody>
    </table>
    <h4 style="margin: 24px 0 8px; color: var(--text-secondary);">Indicadores</h4>
    <table class="result-table">
      <thead><tr><th>Sección</th><th>Regla</th><th>Razón</th></tr></thead>
      <tbody>${findings}</tbody>
    </table>
    <div style="margin-top: 16px; padding: 12px; background: var(--bg-tertiary); border-radius: var(--radius-sm); color: var(--text-muted); font-size: 12px;">
      Veredicto: <strong style="color: var(--accent-amber);">${escapeHtml(data.verdict)}</strong> — Los indicadores son señales para revisión, no veredictos de malware.
    </div>
    ${data.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${data.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
  `;
}

function renderHexView(data, baseOffset, width) {
  const container = document.getElementById('hexview-result');
  const rows = data.rows?.map(row => `
    <div class="hex-row">
      <span class="hex-offset">${row.offset_hex}</span>
      <span class="hex-bytes">${row.hex}</span>
      <span class="hex-ascii">${escapeHtml(row.ascii)}</span>
    </div>
  `).join('') || '<div style="padding:20px;text-align:center;color:var(--text-muted);">Sin datos en este rango</div>';

  container.innerHTML = `<div class="hex-view">${rows}</div>`;
}

function renderArtifacts(data) {
  const container = document.getElementById('artifacts-result');
  const exportData = data.export || {};
  const timeline = data.timeline || {};

  // Handle state-based responses for export
  if (exportData.state) {
    const stateLabels = {
      'pending': 'PENDIENTE',
      'not_applicable': 'NO APLICABLE',
      'no_findings': 'SIN HALLAZGOS',
      'completed': 'COMPLETADO',
      'error': 'ERROR',
    };
    const label = stateLabels[exportData.state] || exportData.state.toUpperCase();
    const tagClass = exportData.state === 'error' ? 'tag-error' : exportData.state === 'not_applicable' ? 'tag-warning' : 'tag-informational';

    // For completed: show badge + full results
    if (exportData.state === 'completed') {
      container.innerHTML = `
        <div style="margin-bottom: 16px;">
          <span class="tag ${tagClass}" style="font-size: 14px; padding: 8px 16px;">Export: ${label}</span>
        </div>
        <table class="result-table">
          <thead><tr><th>Campo</th><th>Valor</th></tr></thead>
          <tbody>
            <tr><td>Export SHA-256</td><td><code style="font-size: 11px;">${escapeHtml(exportData.source_sha256 || 'N/A')}</code></td></tr>
            <tr><td>Registros</td><td>${escapeHtml(exportData.record_count || 0)}</td></tr>
            <tr><td>Eventos en timeline</td><td>${timeline.count || 0}</td></tr>
          </tbody>
        </table>
        <h4 style="margin: 16px 0 8px; color: var(--text-secondary);">Timeline (primeros 20)</h4>
        <div class="strings-list" style="max-height: 400px;">
          ${timeline.events?.slice(0, 20).map(e => `
            <div class="string-item">
              <span class="string-offset">${escapeHtml(e.observed_time_utc)}</span>
              <span class="string-encoding">${escapeHtml(e.source)}</span>
              <span class="string-value">${escapeHtml(e.file_path)}</span>
            </div>
          `).join('') || '<div class="string-item" style="color:var(--text-muted);">Sin eventos</div>'}
        </div>
        ${exportData.reason ? `<p style="margin-top: 16px; color: var(--text-secondary);">${escapeHtml(exportData.reason)}</p>` : ''}
        ${exportData.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${exportData.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
        ${timeline.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones (Timeline)</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${timeline.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
      `;
      return;
    }

    // For no_findings: show badge + reason + available data
    if (exportData.state === 'no_findings') {
      container.innerHTML = `
        <div style="margin-bottom: 16px;">
          <span class="tag ${tagClass}" style="font-size: 14px; padding: 8px 16px;">Export: ${label}</span>
        </div>
        ${exportData.reason ? `<p style="margin-top: 16px; color: var(--text-secondary);">${escapeHtml(exportData.reason)}</p>` : ''}
        <table class="result-table">
          <thead><tr><th>Campo</th><th>Valor</th></tr></thead>
          <tbody>
            <tr><td>Export SHA-256</td><td><code style="font-size: 11px;">${escapeHtml(exportData.source_sha256 || 'N/A')}</code></td></tr>
            <tr><td>Registros</td><td>${escapeHtml(exportData.record_count || 0)}</td></tr>
          </tbody>
        </table>
        ${exportData.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${exportData.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
      `;
      return;
    }

    // For not_applicable: explanation + requirements
    if (exportData.state === 'not_applicable') {
      container.innerHTML = `
        <div style="text-align: center; padding: 40px 20px;">
          <span class="tag ${tagClass}" style="font-size: 14px; padding: 8px 16px;">Export: ${label}</span>
          ${exportData.reason ? `<p style="margin-top: 16px; color: var(--text-secondary);">${escapeHtml(exportData.reason)}</p>` : ''}
          <p style="margin-top: 16px; color: var(--text-secondary);">Requiere: exportación CSV válida con columnas obligatorias</p>
          ${exportData.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${exportData.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
        </div>
      `;
      return;
    }

    // For pending/error: show state only
    container.innerHTML = `
      <div style="text-align: center; padding: 40px 20px;">
        <span class="tag ${tagClass}" style="font-size: 14px; padding: 8px 16px;">Export: ${label}</span>
        ${exportData.reason ? `<p style="margin-top: 16px; color: var(--text-secondary);">${escapeHtml(exportData.reason)}</p>` : ''}
        ${exportData.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${exportData.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
      </div>
    `;
    return;
  }

  // Handle state-based responses for timeline
  if (timeline.state) {
    const stateLabels = {
      'pending': 'PENDIENTE',
      'not_applicable': 'NO APLICABLE',
      'no_findings': 'SIN HALLAZGOS',
      'completed': 'COMPLETADO',
      'error': 'ERROR',
    };
    const label = stateLabels[timeline.state] || timeline.state.toUpperCase();
    const tagClass = timeline.state === 'error' ? 'tag-error' : timeline.state === 'not_applicable' ? 'tag-warning' : 'tag-informational';

    // For completed: show badge + full results
    if (timeline.state === 'completed') {
      container.innerHTML = `
        <div style="margin-bottom: 16px;">
          <span class="tag ${tagClass}" style="font-size: 14px; padding: 8px 16px;">Timeline: ${label}</span>
        </div>
        <table class="result-table">
          <thead><tr><th>Campo</th><th>Valor</th></tr></thead>
          <tbody>
            <tr><td>Export SHA-256</td><td><code style="font-size: 11px;">${escapeHtml(exportData.source_sha256 || 'N/A')}</code></td></tr>
            <tr><td>Registros</td><td>${escapeHtml(exportData.record_count || 0)}</td></tr>
            <tr><td>Eventos en timeline</td><td>${escapeHtml(timeline.count || 0)}</td></tr>
          </tbody>
        </table>
        <h4 style="margin: 16px 0 8px; color: var(--text-secondary);">Timeline (primeros 20)</h4>
        <div class="strings-list" style="max-height: 400px;">
          ${timeline.events?.slice(0, 20).map(e => `
            <div class="string-item">
              <span class="string-offset">${escapeHtml(e.observed_time_utc)}</span>
              <span class="string-encoding">${escapeHtml(e.source)}</span>
              <span class="string-value">${escapeHtml(e.file_path)}</span>
            </div>
          `).join('') || '<div class="string-item" style="color:var(--text-muted);">Sin eventos</div>'}
        </div>
        ${timeline.reason ? `<p style="margin-top: 16px; color: var(--text-secondary);">${escapeHtml(timeline.reason)}</p>` : ''}
        ${exportData.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones (Export)</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${exportData.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
        ${timeline.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones (Timeline)</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${timeline.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
      `;
      return;
    }

    // For no_findings: show badge + reason + available data
    if (timeline.state === 'no_findings') {
      container.innerHTML = `
        <div style="margin-bottom: 16px;">
          <span class="tag ${tagClass}" style="font-size: 14px; padding: 8px 16px;">Timeline: ${label}</span>
        </div>
        ${timeline.reason ? `<p style="margin-top: 16px; color: var(--text-secondary);">${escapeHtml(timeline.reason)}</p>` : ''}
        <table class="result-table">
          <thead><tr><th>Campo</th><th>Valor</th></tr></thead>
          <tbody>
            <tr><td>Export SHA-256</td><td><code style="font-size: 11px;">${escapeHtml(exportData.source_sha256 || 'N/A')}</code></td></tr>
            <tr><td>Registros</td><td>${escapeHtml(exportData.record_count || 0)}</td></tr>
          </tbody>
        </table>
        ${exportData.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones (Export)</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${exportData.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
        ${timeline.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones (Timeline)</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${timeline.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
      `;
      return;
    }

    // For not_applicable: explanation + requirements
    if (timeline.state === 'not_applicable') {
      container.innerHTML = `
        <div style="text-align: center; padding: 40px 20px;">
          <span class="tag ${tagClass}" style="font-size: 14px; padding: 8px 16px;">Timeline: ${label}</span>
          ${timeline.reason ? `<p style="margin-top: 16px; color: var(--text-secondary);">${escapeHtml(timeline.reason)}</p>` : ''}
          <p style="margin-top: 16px; color: var(--text-secondary);">Requiere: exportación con eventos para construir timeline</p>
          ${exportData.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones (Export)</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${exportData.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
          ${timeline.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones (Timeline)</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${timeline.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
        </div>
      `;
      return;
    }

    // For pending/error: show state only
    container.innerHTML = `
      <div style="text-align: center; padding: 40px 20px;">
        <span class="tag ${tagClass}" style="font-size: 14px; padding: 8px 16px;">Timeline: ${label}</span>
        ${timeline.reason ? `<p style="margin-top: 16px; color: var(--text-secondary);">${escapeHtml(timeline.reason)}</p>` : ''}
        ${exportData.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones (Export)</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${exportData.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
        ${timeline.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones (Timeline)</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${timeline.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
      </div>
    `;
    return;
  }

  // Legacy response without state fields
  container.innerHTML = `
    <table class="result-table">
      <thead><tr><th>Campo</th><th>Valor</th></tr></thead>
      <tbody>
        <tr><td>Export SHA-256</td><td><code style="font-size: 11px;">${escapeHtml(exportData.source_sha256 || 'N/A')}</code></td></tr>
        <tr><td>Registros</td><td>${escapeHtml(exportData.record_count || 0)}</td></tr>
        <tr><td>Eventos en timeline</td><td>${escapeHtml(timeline.count || 0)}</td></tr>
      </tbody>
    </table>
    <h4 style="margin: 16px 0 8px; color: var(--text-secondary);">Timeline (primeros 20)</h4>
    <div class="strings-list" style="max-height: 400px;">
      ${timeline.events?.slice(0, 20).map(e => `
        <div class="string-item">
          <span class="string-offset">${escapeHtml(e.observed_time_utc)}</span>
          <span class="string-encoding">${escapeHtml(e.source)}</span>
          <span class="string-value">${escapeHtml(e.file_path)}</span>
        </div>
      `).join('') || '<div class="string-item" style="color:var(--text-muted);">Sin eventos</div>'}
    </div>
    ${exportData.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${exportData.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
  `;
}

function renderTimeline(data) {
  const container = document.getElementById('timeline-result');

  // Handle state-based responses
  if (data.state) {
    const stateLabels = {
      'pending': 'PENDIENTE',
      'not_applicable': 'NO APLICABLE',
      'no_findings': 'SIN HALLAZGOS',
      'completed': 'COMPLETADO',
      'error': 'ERROR',
    };
    const label = stateLabels[data.state] || data.state.toUpperCase();
    const tagClass = data.state === 'error' ? 'tag-error' : data.state === 'not_applicable' ? 'tag-warning' : 'tag-informational';

    // For completed: show badge + full results
    if (data.state === 'completed') {
      const correlations = data.correlations?.map(c => `
        <tr>
          <td>${escapeHtml(c.left_artifact)} → ${escapeHtml(c.right_artifact)}</td>
          <td>${escapeHtml(c.match_basis)}</td>
          <td>${escapeHtml(c.time_delta_seconds)}s</td>
          <td><span class="tag tag-${c.confidence}">${escapeHtml(c.confidence)}</span></td>
          <td>${escapeHtml(c.corroboration)}</td>
        </tr>
      `).join('') || '<tr><td colspan="5">Sin correlaciones</td></tr>';

      container.innerHTML = `
        <div style="margin-bottom: 16px;">
          <span class="tag ${tagClass}" style="font-size: 14px; padding: 8px 16px;">${label}</span>
        </div>
        <table class="result-table">
          <thead><tr><th>Campo</th><th>Valor</th></tr></thead>
          <tbody>
            <tr><td>Ventana</td><td>${escapeHtml(data.window_seconds)}s</td></tr>
            <tr><td>Eventos</td><td>${escapeHtml(data.events?.length || 0)}</td></tr>
            <tr><td>Correlaciones</td><td>${escapeHtml(data.correlation_count || 0)}</td></tr>
            <tr><td>Export SHA-256</td><td><code style="font-size: 11px;">${escapeHtml(data.source_export_sha256 || 'N/A')}</code></td></tr>
          </tbody>
        </table>
        <h4 style="margin: 16px 0 8px; color: var(--text-secondary);">Correlaciones</h4>
        <table class="result-table">
          <thead><tr><th>Artefactos</th><th>Base</th><th>Δ Tiempo</th><th>Confianza</th><th>Tipo</th></tr></thead>
          <tbody>${correlations}</tbody>
        </table>
        ${data.reason ? `<p style="margin-top: 16px; color: var(--text-secondary);">${escapeHtml(data.reason)}</p>` : ''}
        ${data.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${data.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
      `;
      return;
    }

    // For no_findings: show badge + reason + available data (summary table, no correlations)
    if (data.state === 'no_findings') {
      container.innerHTML = `
        <div style="margin-bottom: 16px;">
          <span class="tag ${tagClass}" style="font-size: 14px; padding: 8px 16px;">${label}</span>
        </div>
        ${data.reason ? `<p style="margin-top: 16px; color: var(--text-secondary);">${escapeHtml(data.reason)}</p>` : ''}
        <table class="result-table">
          <thead><tr><th>Campo</th><th>Valor</th></tr></thead>
          <tbody>
            <tr><td>Ventana</td><td>${escapeHtml(data.window_seconds)}s</td></tr>
            <tr><td>Eventos</td><td>${escapeHtml(data.events?.length || 0)}</td></tr>
            <tr><td>Correlaciones</td><td>${escapeHtml(data.correlation_count || 0)}</td></tr>
            <tr><td>Export SHA-256</td><td><code style="font-size: 11px;">${escapeHtml(data.source_export_sha256 || 'N/A')}</code></td></tr>
          </tbody>
        </table>
        <h4 style="margin: 16px 0 8px; color: var(--text-secondary);">Correlaciones</h4>
        <p style="color: var(--text-muted);">No se encontraron correlaciones en la ventana especificada</p>
        ${data.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${data.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
      `;
      return;
    }

    // For not_applicable: explanation + requirements
    if (data.state === 'not_applicable') {
      container.innerHTML = `
        <div style="text-align: center; padding: 40px 20px;">
          <span class="tag ${tagClass}" style="font-size: 14px; padding: 8px 16px;">${label}</span>
          ${data.reason ? `<p style="margin-top: 16px; color: var(--text-secondary);">${escapeHtml(data.reason)}</p>` : ''}
          <p style="margin-top: 16px; color: var(--text-secondary);">Requiere: exportación con eventos para correlación temporal</p>
          ${data.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${data.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
        </div>
      `;
      return;
    }

    // For pending/error: show state only
    container.innerHTML = `
      <div style="text-align: center; padding: 40px 20px;">
        <span class="tag ${tagClass}" style="font-size: 14px; padding: 8px 16px;">${label}</span>
        ${data.reason ? `<p style="margin-top: 16px; color: var(--text-secondary);">${escapeHtml(data.reason)}</p>` : ''}
        ${data.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${data.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
      </div>
    `;
    return;
  }

  // Legacy response without state field
  const correlations = data.correlations?.map(c => `
    <tr>
      <td>${escapeHtml(c.left_artifact)} → ${escapeHtml(c.right_artifact)}</td>
      <td>${escapeHtml(c.match_basis)}</td>
      <td>${escapeHtml(c.time_delta_seconds)}s</td>
      <td><span class="tag tag-${c.confidence}">${escapeHtml(c.confidence)}</span></td>
      <td>${escapeHtml(c.corroboration)}</td>
    </tr>
  `).join('') || '<tr><td colspan="5">Sin correlaciones</td></tr>';

  container.innerHTML = `
    <table class="result-table">
      <thead><tr><th>Campo</th><th>Valor</th></tr></thead>
      <tbody>
        <tr><td>Ventana</td><td>${escapeHtml(data.window_seconds)}s</td></tr>
        <tr><td>Eventos</td><td>${escapeHtml(data.events?.length || 0)}</td></tr>
        <tr><td>Correlaciones</td><td>${escapeHtml(data.correlation_count || 0)}</td></tr>
        <tr><td>Export SHA-256</td><td><code style="font-size: 11px;">${escapeHtml(data.source_export_sha256 || 'N/A')}</code></td></tr>
      </tbody>
    </table>
    <h4 style="margin: 16px 0 8px; color: var(--text-secondary);">Correlaciones</h4>
    <table class="result-table">
      <thead><tr><th>Artefactos</th><th>Base</th><th>Δ Tiempo</th><th>Confianza</th><th>Tipo</th></tr></thead>
      <tbody>${correlations}</tbody>
    </table>
    ${data.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${data.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
  `;
}

function renderRegistry(data) {
  const container = document.getElementById('registry-result');

  // Handle state-based responses
  if (data.state) {
    const stateLabels = {
      'pending': 'PENDIENTE',
      'not_applicable': 'NO APLICABLE',
      'no_findings': 'SIN HALLAZGOS',
      'completed': 'COMPLETADO',
      'error': 'ERROR',
    };
    const label = stateLabels[data.state] || data.state.toUpperCase();
    const tagClass = data.state === 'error' ? 'tag-error' : data.state === 'not_applicable' ? 'tag-warning' : 'tag-informational';

    // For completed: show badge + full results
    if (data.state === 'completed') {
      const events = data.events?.map(e => `
        <tr>
          <td>${escapeHtml(e.event_id)} (${escapeHtml(e.operation)})</td>
          <td>${escapeHtml(e.timestamp_utc || 'N/A')}</td>
          <td>${escapeHtml(e.target_object)}</td>
          <td>${escapeHtml(e.registry_root || 'N/A')}</td>
          <td>${e.registry_root_assumed ? '<span class="tag tag-warning">asumido</span>' : ''}</td>
          <td>${e.possible_persistence_location ? '<span class="tag tag-review">Sí</span>' : '<span class="tag tag-informational">No</span>'}</td>
          <td>${escapeHtml(e.matched_rules?.join(', ') || '—')}</td>
          <td><span class="tag tag-${e.assessment === 'review' ? 'review' : 'informational'}">${escapeHtml(e.assessment)}</span></td>
        </tr>
      `).join('') || '<tr><td colspan="9">Sin eventos</td></tr>';

      container.innerHTML = `
        <div style="margin-bottom: 16px;">
          <span class="tag ${tagClass}" style="font-size: 14px; padding: 8px 16px;">${label}</span>
        </div>
        <table class="result-table">
          <thead><tr><th>Campo</th><th>Valor</th></tr></thead>
          <tbody>
            <tr><td>Módulo</td><td>${escapeHtml(data.module)}</td></tr>
            <tr><td>Total eventos</td><td>${escapeHtml(data.count)}</td></tr>
            <tr><td>Para revisión</td><td>${escapeHtml(data.review_count)}</td></tr>
            <tr><td>Monitoreo en vivo</td><td>${escapeHtml(data.live_monitoring ? 'Sí' : 'No')}</td></tr>
          </tbody>
        </table>
        <h4 style="margin: 16px 0 8px; color: var(--text-secondary);">Eventos</h4>
        <div style="overflow-x: auto;">
          <table class="result-table">
            <thead><tr><th>Evento</th><th>Timestamp</th><th>Target Object</th><th>Root</th><th>Asumido</th><th>Persistencia</th><th>Reglas</th><th>Assessment</th></tr></thead>
            <tbody>${events}</tbody>
          </table>
        </div>
        ${data.reason ? `<p style="margin-top: 16px; color: var(--text-secondary);">${escapeHtml(data.reason)}</p>` : ''}
        ${data.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${data.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
      `;
      return;
    }

    // For no_findings: show badge + reason + available data (summary table, no events)
    if (data.state === 'no_findings') {
      container.innerHTML = `
        <div style="margin-bottom: 16px;">
          <span class="tag ${tagClass}" style="font-size: 14px; padding: 8px 16px;">${label}</span>
        </div>
        ${data.reason ? `<p style="margin-top: 16px; color: var(--text-secondary);">${escapeHtml(data.reason)}</p>` : ''}
        <table class="result-table">
          <thead><tr><th>Campo</th><th>Valor</th></tr></thead>
          <tbody>
            <tr><td>Módulo</td><td>${escapeHtml(data.module)}</td></tr>
            <tr><td>Total eventos</td><td>${escapeHtml(data.count)}</td></tr>
            <tr><td>Para revisión</td><td>${escapeHtml(data.review_count)}</td></tr>
            <tr><td>Monitoreo en vivo</td><td>${escapeHtml(data.live_monitoring ? 'Sí' : 'No')}</td></tr>
          </tbody>
        </table>
        <h4 style="margin: 16px 0 8px; color: var(--text-secondary);">Eventos</h4>
        <p style="color: var(--text-muted);">No hay eventos para mostrar</p>
        ${data.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${data.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
      `;
      return;
    }

    // For not_applicable: explanation + requirements
    if (data.state === 'not_applicable') {
      container.innerHTML = `
        <div style="text-align: center; padding: 40px 20px;">
          <span class="tag ${tagClass}" style="font-size: 14px; padding: 8px 16px;">${label}</span>
          ${data.reason ? `<p style="margin-top: 16px; color: var(--text-secondary);">${escapeHtml(data.reason)}</p>` : ''}
          <p style="margin-top: 16px; color: var(--text-secondary);">Requiere: exportación Sysmon JSON normalizada con eventos de registro</p>
          ${data.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${data.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
        </div>
      `;
      return;
    }

    // For pending/error: show state only
    container.innerHTML = `
      <div style="text-align: center; padding: 40px 20px;">
        <span class="tag ${tagClass}" style="font-size: 14px; padding: 8px 16px;">${label}</span>
        ${data.reason ? `<p style="margin-top: 16px; color: var(--text-secondary);">${escapeHtml(data.reason)}</p>` : ''}
        ${data.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${data.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join('')}</ul></details>` : ''}
      </div>
    `;
    return;
  }

  // Legacy response without state field
  const events = data.events?.map(e => `
    <tr>
      <td>${escapeHtml(e.event_id)} (${escapeHtml(e.operation)})</td>
      <td>${escapeHtml(e.timestamp_utc || 'N/A')}</td>
      <td>${escapeHtml(e.target_object)}</td>
      <td>${escapeHtml(e.registry_root || 'N/A')}</td>
      <td>${e.registry_root_assumed ? '<span class="tag tag-warning">asumido</span>' : ''}</td>
      <td>${e.possible_persistence_location ? '<span class="tag tag-review">Sí</span>' : '<span class="tag tag-informational">No</span>'}</td>
      <td>${escapeHtml(e.matched_rules?.join(', ') || '—')}</td>
      <td><span class="tag tag-${e.assessment === 'review' ? 'review' : 'informational'}">${escapeHtml(e.assessment)}</span></td>
    </tr>
  `).join('') || '<tr><td colspan="9">Sin eventos</td></tr>';

  container.innerHTML = `
    <table class="result-table">
      <thead><tr><th>Campo</th><th>Valor</th></tr></thead>
      <tbody>
        <tr><td>Módulo</td><td>${data.module}</td></tr>
        <tr><td>Total eventos</td><td>${data.count}</td></tr>
        <tr><td>Para revisión</td><td>${data.review_count}</td></tr>
        <tr><td>Monitoreo en vivo</td><td>${data.live_monitoring ? 'Sí' : 'No'}</td></tr>
      </tbody>
    </table>
    <h4 style="margin: 16px 0 8px; color: var(--text-secondary);">Eventos</h4>
    <div style="overflow-x: auto;">
      <table class="result-table">
        <thead><tr><th>Evento</th><th>Timestamp</th><th>Target Object</th><th>Root</th><th>Asumido</th><th>Persistencia</th><th>Reglas</th><th>Assessment</th></tr></thead>
        <tbody>${events}</tbody>
      </table>
    </div>
    ${data.limitations ? `<details style="margin-top: 16px;"><summary style="cursor:pointer;color:var(--text-secondary);">Limitaciones</summary><ul style="margin-top:8px;padding-left:20px;color:var(--text-muted);font-size:12px;">${data.limitations.map(l => `<li>${l}</li>`).join('')}</ul></details>` : ''}
  `;
}

function renderJson(data) {
  const json = JSON.stringify(data, null, 2);
  return `<div class="json-viewer">${escapeHtml(json)
    .replace(/"([^"]+)":/g, '<span class="json-key">"$1"</span>:')
    .replace(/:\s*"([^"]*)"/g, ': <span class="json-string">"$1"</span>')
    .replace(/:\s*(\d+\.?\d*)/g, ': <span class="json-number">$1</span>')
    .replace(/:\s*(true|false)/g, ': <span class="json-boolean">$1</span>')
    .replace(/:\s*null/g, ': <span class="json-null">null</span>')}</div>`;
}

function escapeHtml(text) {
  if (text === null || text === undefined) return '';
  return String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

// ─── UI Navigation ───
function showModule(moduleName) {
  // Update nav
  elements.navItems.forEach(item => {
    item.classList.toggle('active', item.dataset.module === moduleName);
  });

  // Update panels
  elements.modulePanels.forEach(panel => {
    panel.classList.toggle('active', panel.dataset.module === moduleName);
  });

  state.currentModule = moduleName;

  // Close mobile sidebar
  elements.sidebar.classList.remove('open');
}

// ─── File Handling ───
async function handleFileSelect(file) {
  showLoading('Subiendo archivo...');
  try {
    const formData = new FormData();
    formData.append('file', file);

    const response = await fetch(`${API_BASE}/upload`, {
      method: 'POST',
      headers: {'X-HexForge-Token': state.sessionToken || ''},
      body: formData,
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.detail || 'Error al subir archivo');
    }

    // Reset module tracking for new file
    resetModuleTracking();

    state.currentFile = {...data, id: data.file_id};
    state.custodyRecordId = null;
    elements.selectedFileName.textContent = data.filename;
    elements.fileInfo.textContent = `${formatBytes(data.size)} • SHA256: ${data.sha256.substring(0, 16)}...`;
    elements.btnAnalyze.disabled = false;
    elements.btnReport.disabled = false;

    showToast(`Archivo cargado: ${data.filename}`, 'success');
    addActivity('Sistema', 'Archivo cargado', data.filename);

    // Auto-analyze on dashboard
    if (state.currentModule === 'dashboard') {
      await moduleHandlers.dashboard.analyze();
    }
  } catch (error) {
    showToast(error.message, 'error');
  } finally {
    hideLoading();
  }
}

// ─── Event Listeners ───
function setupEventListeners() {
  // Navigation
  elements.navItems.forEach(item => {
    item.addEventListener('click', (e) => {
      e.preventDefault();
      showModule(item.dataset.module);
    });
  });

  // Mobile menu toggle
  elements.menuToggle.addEventListener('click', () => {
    elements.sidebar.classList.toggle('open');
  });

  // File input
  elements.evidenceFile.addEventListener('change', (e) => {
    if (e.target.files[0]) {
      handleFileSelect(e.target.files[0]);
      e.target.value = ''; // Allow re-selecting same file
    }
  });

  // Analyze button
  elements.btnAnalyze.addEventListener('click', async () => {
    const handler = moduleHandlers[state.currentModule];
    if (handler?.analyze) {
      await handler.analyze();
    } else {
      showToast('Este módulo no tiene análisis automático', 'info');
    }
  });

  // Report button
  elements.btnReport.addEventListener('click', () => {
    showModule('reports');
  });

  // Module-specific buttons
  document.getElementById('btn-base-convert')?.addEventListener('click', () => moduleHandlers['academy-base'].convert());
  document.getElementById('btn-byte-inspect')?.addEventListener('click', () => moduleHandlers['academy-byte'].inspect());
  document.getElementById('btn-pe-explore')?.addEventListener('click', () => moduleHandlers['academy-pe'].explore());
  document.getElementById('btn-entropy-analyze')?.addEventListener('click', () => moduleHandlers['academy-entropy'].analyze());
  document.getElementById('btn-imports-explain')?.addEventListener('click', () => moduleHandlers['academy-imports'].explain());
  document.getElementById('btn-rva-map')?.addEventListener('click', () => moduleHandlers['academy-rva'].map());
  document.getElementById('btn-export-report')?.addEventListener('click', () => moduleHandlers.reports.export());
  elements.btnReport?.addEventListener('click', () => moduleHandlers.reports.export());

  // Custody tabs
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(btn.dataset.tab).classList.add('active');
    });
  });

  // Custody forms
  document.getElementById('form-custody-register')?.addEventListener('submit', (e) => {
    e.preventDefault();
    const formData = Object.fromEntries(new FormData(e.target).entries());
    moduleHandlers.custody.register(formData);
  });

  document.getElementById('form-custody-append')?.addEventListener('submit', (e) => {
    e.preventDefault();
    const formData = Object.fromEntries(new FormData(e.target).entries());
    moduleHandlers.custody.append(formData);
  });

  document.getElementById('form-custody-verify')?.addEventListener('submit', (e) => {
    e.preventDefault();
    const formData = Object.fromEntries(new FormData(e.target).entries());
    moduleHandlers.custody.verify(formData);
  });

  // Stop server button
  document.getElementById('btn-stop-server')?.addEventListener('click', async () => {
    if (confirm('¿Detener el servidor local?')) {
      try {
        await apiRequest('/server/stop', { method: 'POST' });
        showToast('Servidor detenido', 'success');
        setTimeout(() => window.close(), 1000);
      } catch {
        window.close();
      }
    }
  });

  // Keyboard shortcuts
  document.addEventListener('keydown', (e) => {
    if (e.ctrlKey || e.metaKey) {
      switch (e.key) {
        case 'o':
          e.preventDefault();
          elements.evidenceFile.click();
          break;
        case 'Enter':
          e.preventDefault();
          elements.btnAnalyze.click();
          break;
      }
    }
  });
}

// ─── Dashboard Stats ───
function updateDashboardStats() {
  document.getElementById('stat-files').textContent = state.currentFile ? '1' : '0';

  // Count modules completed for current file (sum of all Sets in the Map)
  let completedModules = 0;
  if (state.completedModules && state.currentFile) {
    const fileModules = state.completedModules.get(state.currentFile.id);
    if (fileModules) {
      completedModules = fileModules.size;
    }
  }
  document.getElementById('stat-modules').textContent = completedModules;

  // Count reports generated (tracked separately)
  const reportsGenerated = state.reportsGenerated || 0;
  document.getElementById('stat-reports').textContent = reportsGenerated;

  // Count indicators with severity 'review'
  let indicatorsReview = 0;
  if (state.lastIndicatorsData?.indicators) {
    indicatorsReview = state.lastIndicatorsData.indicators.filter(i => i.severity === 'review').length;
  }
  document.getElementById('stat-indicators').textContent = indicatorsReview;
}

// Track completed modules per file
function markModuleCompleted(moduleName) {
  if (!state.currentFile) return;

  if (!state.completedModules) {
    state.completedModules = new Map();
  }

  const fileKey = state.currentFile.id;
  if (!state.completedModules.has(fileKey)) {
    state.completedModules.set(fileKey, new Set());
  }

  const modules = state.completedModules.get(fileKey);
  if (!modules.has(moduleName)) {
    modules.add(moduleName);
    updateDashboardStats();
  }
}

// Reset module tracking when file changes
function resetModuleTracking() {
  state.completedModules = new Map();
  state.reportsGenerated = 0;
  state.lastIndicatorsData = null;
  updateDashboardStats();
}

// ─── Health Check ───
async function checkHealth() {
  try {
    const data = await apiRequest('/health');
    elements.statusText.textContent = 'Conectado';
    elements.statusDot.style.background = 'var(--accent-green)';
    elements.statusDot.style.boxShadow = '0 0 8px var(--accent-green)';
    return true;
  } catch {
    elements.statusText.textContent = 'Desconectado';
    elements.statusDot.style.background = 'var(--accent-red)';
    elements.statusDot.style.boxShadow = '0 0 8px var(--accent-red)';
    return false;
  }
}

// ─── Splash Screen ───
function initSplashScreen() {
  const splashScreen = document.getElementById('splash-screen');
  const splashBtn = document.getElementById('splash-btn');

  // Check if welcome was shown in this session (sessionStorage)
  const welcomeShown = sessionStorage.getItem('nexahf_welcome_shown');

  if (welcomeShown === 'true') {
    // Hide splash screen immediately
    splashScreen.classList.add('hidden');
  } else {
    // Show splash screen (already visible by default)
    splashScreen.classList.remove('hidden');
  }

  // Button handler
  splashBtn.addEventListener('click', () => {
    // Mark as shown for this session
    sessionStorage.setItem('nexahf_welcome_shown', 'true');
    // Hide splash with animation
    splashScreen.style.opacity = '0';
    splashScreen.style.transition = 'opacity 0.3s ease';
    setTimeout(() => {
      splashScreen.classList.add('hidden');
    }, 300);
  });
}

// ─── Initialization ───
async function init() {
  // Initialize splash screen first (before async operations)
  initSplashScreen();

  setupEventListeners();
  try { const session = await apiRequest('/session'); state.sessionToken = session.token; }
  catch (e) { showToast('No se pudo inicializar la sesión local', 'error'); }

  // Initial health check
  await checkHealth();

  // Periodic health check
  setInterval(checkHealth, 30000);

  // Load any saved settings
  const savedPort = localStorage.getItem('nexahf_port');
  if (savedPort) {
    document.getElementById('setting-port').value = savedPort;
  }

  const savedAutoBrowser = localStorage.getItem('nexahf_autobrowser');
  if (savedAutoBrowser !== null) {
    document.getElementById('setting-autobrowser').checked = savedAutoBrowser === 'true';
  }

  const savedStrictCors = localStorage.getItem('nexahf_strictcors');
  if (savedStrictCors !== null) {
    document.getElementById('setting-strict-cors').checked = savedStrictCors === 'true';
  }

  // Save settings on change
  document.getElementById('setting-port')?.addEventListener('change', (e) => {
    localStorage.setItem('nexahf_port', e.target.value);
  });
  document.getElementById('setting-autobrowser')?.addEventListener('change', (e) => {
    localStorage.setItem('nexahf_autobrowser', e.target.checked);
  });
  document.getElementById('setting-strict-cors')?.addEventListener('change', (e) => {
    localStorage.setItem('nexahf_strictcors', e.target.checked);
  });

  console.log('NEXA-HexForge Local Console initialized');
}

// Start
init();