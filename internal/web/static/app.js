const state = {
  agents: [],
  events: [],
};

const connectionState = document.getElementById('connection-state');
const eventLog = document.getElementById('event-log');
const alertLog = document.getElementById('alert-log');
const agentList = document.getElementById('agent-list');
const signAgent = document.getElementById('sign-agent');
const commandOutput = document.getElementById('command-output');
const lookupForm = document.getElementById('lookup-form');
const signForm = document.getElementById('sign-form');
const refreshSnapshot = document.getElementById('refresh-snapshot');
const lookupInput = document.getElementById('lookup-hash');
const signPathInput = document.getElementById('sign-path');

lookupInput.value = '8f32f0f1086f954eceda8ce9b8f6a8d89f5cb9184160a95c31a01d10b191ed32';
signPathInput.value = '/Applications/Safari.app/Contents/MacOS/Safari';

let socket;
connect();

function connect() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  socket = new WebSocket(`${protocol}//${window.location.host}/ws`);

  socket.addEventListener('open', () => setConnection('Connected', true));
  socket.addEventListener('close', () => {
    setConnection('Disconnected', false);
    setTimeout(connect, 1500);
  });
  socket.addEventListener('error', () => setConnection('Error', false));
  socket.addEventListener('message', (event) => handleMessage(JSON.parse(event.data)));
}

function setConnection(label, online) {
  connectionState.textContent = label;
  connectionState.classList.toggle('online', online);
}

function handleMessage(message) {
  switch (message.type) {
    case 'snapshot':
      applySnapshot(message.snapshot);
      break;
    case 'event':
      if (message.event) {
        pushEvent(message.event);
      }
      break;
    case 'command_result':
      renderCommandResult(message.action, message.payload);
      if (message.action === 'get_agent_snapshot' && message.snapshot) {
        applySnapshot(message.snapshot);
      }
      break;
    case 'command_error':
      renderCommandError(message.action, message.error);
      break;
    default:
      break;
  }
}

function applySnapshot(snapshot) {
  if (!snapshot) {
    return;
  }
  state.agents = snapshot.agents || [];
  state.events = snapshot.events || [];
  renderStats(snapshot.stats || {});
  renderAgents();
  renderEvents();
  populateAgentSelect();
}

function renderStats(stats) {
  setText('stat-total-agents', stats.total_agents || 0);
  setText('stat-connected-agents', stats.connected_agents || 0);
  setText('stat-total-events', stats.total_events || 0);
  setText('stat-alert-events', stats.alert_events || 0);
}

function renderAgents() {
  if (state.agents.length === 0) {
    agentList.innerHTML = '<p class="empty">No agents connected yet.</p>';
    return;
  }

  agentList.innerHTML = state.agents.map((agent) => `
    <article class="agent-card ${agent.connected ? 'connected' : 'offline'}">
      <div>
        <h3>${escapeHtml(agent.hostname || agent.agent_id)}</h3>
        <p>${escapeHtml(agent.agent_id)}</p>
      </div>
      <div class="agent-meta">
        <span class="status ${agent.connected ? 'up' : 'down'}">${agent.connected ? 'online' : 'offline'}</span>
        <span>posture ${agent.security_posture_score}</span>
      </div>
      <dl>
        <div><dt>OS</dt><dd>${escapeHtml(agent.os_version || '-')}</dd></div>
        <div><dt>Events</dt><dd>${agent.total_streamed_events}</dd></div>
        <div><dt>Alerts</dt><dd>${agent.alert_events}</dd></div>
        <div><dt>Last Seen</dt><dd>${formatTime(agent.last_seen)}</dd></div>
      </dl>
    </article>
  `).join('');
}

function renderEvents() {
  renderEventGroup(eventLog, state.events.filter((event) => event.type !== 'security_alert'));
  renderEventGroup(alertLog, state.events.filter((event) => event.type === 'security_alert'));
}

function renderEventGroup(target, events) {
  const sliced = events.slice(-18).reverse();
  if (sliced.length === 0) {
    target.innerHTML = '<p class="empty">No events yet.</p>';
    return;
  }

  target.innerHTML = sliced.map((event) => {
    const meta = [];
    if (event.hostname) meta.push(event.hostname);
    if (event.data && event.data.path) meta.push(event.data.path);
    return `
      <article class="event-row ${event.type === 'security_alert' ? 'alert' : ''}">
        <div class="event-row-top">
          <strong>${escapeHtml(event.message)}</strong>
          <span>${formatTime(event.timestamp)}</span>
        </div>
        <p>${escapeHtml(meta.join(' | '))}</p>
      </article>
    `;
  }).join('');
}

function pushEvent(event) {
  state.events.push(event);
  state.events = state.events.slice(-100);

  if (event.type === 'agent_enrolled' || event.type === 'agent_disconnected') {
    requestSnapshot();
  }
  if (event.type === 'process_event' || event.type === 'security_alert') {
    const totalEvents = parseInt(document.getElementById('stat-total-events').textContent, 10) || 0;
    setText('stat-total-events', totalEvents + (event.type === 'process_event' ? 1 : 0));
    if (event.type === 'security_alert') {
      const totalAlerts = parseInt(document.getElementById('stat-alert-events').textContent, 10) || 0;
      setText('stat-alert-events', totalAlerts + 1);
    }
  }
  renderEvents();
}

function populateAgentSelect() {
  const options = state.agents.map((agent) => `<option value="${escapeHtml(agent.agent_id)}">${escapeHtml(agent.hostname)} (${escapeHtml(agent.agent_id)})</option>`);
  signAgent.innerHTML = options.join('');
}

lookupForm.addEventListener('submit', (event) => {
  event.preventDefault();
  sendCommand('lookup_hash', { hash: lookupInput.value.trim() });
});

signForm.addEventListener('submit', (event) => {
  event.preventDefault();
  sendCommand('check_sign_status', {
    agent_id: signAgent.value,
    path: signPathInput.value.trim(),
  });
});

refreshSnapshot.addEventListener('click', () => requestSnapshot());

function requestSnapshot() {
  sendCommand('get_agent_snapshot', {});
}

function sendCommand(action, payload) {
  if (!socket || socket.readyState !== WebSocket.OPEN) {
    renderCommandError(action, 'WebSocket belum terhubung.');
    return;
  }
  socket.send(JSON.stringify({ action, payload }));
}

function renderCommandResult(action, payload) {
  if (action === 'lookup_hash') {
    const malicious = payload.verdict === 'MALICIOUS';
    commandOutput.innerHTML = `
      <article class="result-card ${malicious ? 'is-bad' : 'is-good'}">
        <div class="result-head">
          <span class="result-label">Lookup Hash</span>
          <strong>${escapeHtml(payload.verdict || '-')}</strong>
        </div>
        <p class="result-title">${escapeHtml(payload.threat_name || (malicious ? 'Malicious file detected' : 'No threat label available'))}</p>
        <dl class="result-grid">
          <div><dt>Hash</dt><dd>${escapeHtml(payload.hash || '-')}</dd></div>
          <div><dt>Detail</dt><dd>${escapeHtml(payload.detail || '-')}</dd></div>
        </dl>
      </article>
    `;
    return;
  }

  if (action === 'check_sign_status') {
    const signed = Boolean(payload.signed);
    commandOutput.innerHTML = `
      <article class="result-card ${signed ? 'is-good' : 'is-bad'}">
        <div class="result-head">
          <span class="result-label">Check Sign Status</span>
          <strong>${signed ? 'SIGNED' : 'UNSIGNED'}</strong>
        </div>
        <p class="result-title">${escapeHtml(payload.path || '-')}</p>
        <dl class="result-grid">
          <div><dt>Apple Signed</dt><dd>${payload.apple_signed ? 'Yes' : 'No'}</dd></div>
          <div><dt>Identifier</dt><dd>${escapeHtml(payload.signing_identifier || '-')}</dd></div>
          <div><dt>Team ID</dt><dd>${escapeHtml(payload.team_id || '-')}</dd></div>
          <div><dt>Detail</dt><dd>${escapeHtml(payload.detail || '-')}</dd></div>
        </dl>
      </article>
    `;
    return;
  }

  commandOutput.innerHTML = `
    <article class="result-card">
      <div class="result-head">
        <span class="result-label">${escapeHtml(action || 'Command Result')}</span>
      </div>
      <pre>${escapeHtml(JSON.stringify(payload, null, 2))}</pre>
    </article>
  `;
}

function renderCommandError(action, error) {
  commandOutput.innerHTML = `
    <article class="result-card is-bad">
      <div class="result-head">
        <span class="result-label">Command Error</span>
        <strong>${escapeHtml(action || '-')}</strong>
      </div>
      <p class="result-title">${escapeHtml(error || 'Unknown error')}</p>
    </article>
  `;
}

function setText(id, value) {
  document.getElementById(id).textContent = value;
}

function formatTime(value) {
  if (!value) {
    return '-';
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString();
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}
