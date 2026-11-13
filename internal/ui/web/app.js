// SPDX-License-Identifier: AGPL-3.0-only

// the minimal UI of decerter: every request goes through decerter ui to the control API under /api/v1 (api/openapi.yaml)
// payloads and flow fields are attacker controlled: they reach the page only as text nodes, never as HTML

const api = '/api/v1';
// the bytes of a payload shown at once, the API's default window
const windowLength = 4096;
// the event stream reconnects after this when it failed for good (decerter stopped, a 403)
const reconnectDelay = 3000;

const state = {
  filter: '',
  flows: new Map(),
  flowsCursor: '',
  flowId: null,
  messages: [],
  messagesCursor: '',
  messageId: null,
  offset: 0,
  view: 'text',
  holds: [],
  editing: null,
};

const byId = (id) => document.getElementById(id);

// an element with text children; props sets properties and listeners, nothing is parsed as HTML
function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);

  for (const [key, value] of Object.entries(props)) {
    if (key === 'class') {
      node.className = value;
    } else if (key.startsWith('on')) {
      node.addEventListener(key.slice(2), value);
    } else {
      node[key] = value;
    }
  }

  node.append(...children.map((child) => (child instanceof Node ? child : String(child))));
  return node;
}

function showError(error) {
  const node = byId('error');
  node.textContent = error ? String(error.message || error) : '';
  node.hidden = !error;
}

// one call of the API, the JSON answer or null for 204; an error answer throws with the API's message
async function call(method, path, body) {
  const init = { method, headers: {}, credentials: 'same-origin', cache: 'no-store' };

  if (body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }

  const response = await fetch(api + path, init);

  if (response.status === 204) {
    return null;
  }

  const text = await response.text();
  let data = null;

  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }

  if (!response.ok) {
    throw new Error(`${method} ${path}: ${(data && data.error) || `${response.status} ${text}`}`);
  }

  return data;
}

// run an action of a button or form, its error goes to the error line
function action(run) {
  return async (event) => {
    if (event) {
      event.preventDefault();
    }

    try {
      showError(null);
      await run(event);
    } catch (error) {
      showError(error);
    }
  };
}

// at most one run per animation frame or per delay, for event bursts
function debounce(run, delay = 0) {
  let timer = null;
  return () => {
    if (timer === null) {
      timer = setTimeout(() => {
        timer = null;
        run().catch(showError);
      }, delay);
    }
  };
}

// payload formats

function bytesOfHex(hex) {
  const bytes = new Uint8Array(hex.length / 2);

  for (let index = 0; index < bytes.length; index++) {
    bytes[index] = parseInt(hex.substr(index * 2, 2), 16);
  }

  return bytes;
}

function hexOfBytes(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

// the API's escaped form: printable ASCII as it is, \\ \n \r \t, \xNN for any other byte; a line break after every \n so it reads like the payload
function escapeBytes(bytes) {
  const parts = [];

  for (const byte of bytes) {
    if (byte === 0x5c) {
      parts.push('\\\\');
    } else if (byte === 0x0a) {
      parts.push('\\n\n');
    } else if (byte === 0x0d) {
      parts.push('\\r');
    } else if (byte === 0x09) {
      parts.push('\\t');
    } else if (byte >= 0x20 && byte < 0x7f) {
      parts.push(String.fromCharCode(byte));
    } else {
      parts.push('\\x' + byte.toString(16).padStart(2, '0'));
    }
  }

  return parts.join('');
}

// the bytes of escaped text: line breaks are only layout (a newline byte is \n), other characters are UTF-8
function unescapeText(text) {
  const bytes = [];
  const encoder = new TextEncoder();

  for (let index = 0; index < text.length; index++) {
    const character = text[index];

    if (character === '\n' || character === '\r') {
      continue;
    }

    if (character !== '\\') {
      const codePoint = text.codePointAt(index);

      if (codePoint > 0xffff) {
        index++;
      }

      bytes.push(...encoder.encode(String.fromCodePoint(codePoint)));
      continue;
    }

    const next = text[index + 1];
    const simple = { '\\': 0x5c, n: 0x0a, r: 0x0d, t: 0x09 }[next];

    if (simple !== undefined) {
      bytes.push(simple);
      index++;
    } else if (next === 'x' && /^[0-9a-fA-F]{2}$/.test(text.substr(index + 2, 2))) {
      bytes.push(parseInt(text.substr(index + 2, 2), 16));
      index += 3;
    } else {
      throw new Error(`invalid escape at character ${index + 1}: use \\\\ \\n \\r \\t or \\xNN`);
    }
  }

  return Uint8Array.from(bytes);
}

// hex digits, white space between them is ignored
function bytesOfHexText(text) {
  const hex = text.replace(/\s+/g, '');

  if (!/^([0-9a-fA-F]{2})*$/.test(hex)) {
    throw new Error('the hex payload needs pairs of hex digits');
  }

  return bytesOfHex(hex);
}

// 16 bytes per line in groups of two, for editing
function hexLines(bytes) {
  const lines = [];

  for (let start = 0; start < bytes.length; start += 16) {
    const line = [];

    for (let index = start; index < Math.min(start + 16, bytes.length); index += 2) {
      line.push(hexOfBytes(bytes.subarray(index, Math.min(index + 2, bytes.length))));
    }

    lines.push(line.join(' '));
  }

  return lines.join('\n');
}

// offset, 16 bytes in hex and the printable ones
function hexDump(bytes, offset) {
  const lines = [];

  for (let start = 0; start < bytes.length; start += 16) {
    const row = bytes.subarray(start, start + 16);
    const hex = Array.from(row, (byte) => byte.toString(16).padStart(2, '0'));
    const left = hex.slice(0, 8).join(' ');
    const right = hex.slice(8).join(' ');
    const text = Array.from(row, (byte) => (byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : '.')).join('');
    lines.push(`${(offset + start).toString(16).padStart(8, '0')}  ${left.padEnd(23)}  ${right.padEnd(23)}  |${text}|`);
  }

  return lines.join('\n');
}

function formatBytes(count) {
  if (count < 1024) {
    return `${count} B`;
  }

  if (count < 1024 * 1024) {
    return `${(count / 1024).toFixed(1)} KiB`;
  }

  return `${(count / 1024 / 1024).toFixed(1)} MiB`;
}

function formatTime(time) {
  const date = new Date(time);
  return `${date.toLocaleTimeString([], { hour12: false })}.${String(date.getMilliseconds()).padStart(3, '0')}`;
}

// status and intercept

// the header line; the intercept form only on a resync, so a refresh does not overwrite what is being typed
async function loadStatus(withIntercept) {
  const status = await call('GET', '/status');
  const node = byId('status');
  node.textContent = `${status.mode} · ${status.processing} · ${status.platform} · ${status.history.flows} flows in the history, ${status.history.open_flows} open`;
  node.title = `decerter ${status.version}`;

  if (withIntercept) {
    showIntercept(status.intercept);
  }
}

const refreshStatus = debounce(() => loadStatus(false), 1000);

function showIntercept(intercept) {
  const form = byId('intercept-form');

  for (const input of form.elements) {
    input.disabled = !intercept.available;
  }

  if (!intercept.available) {
    byId('intercept-state').textContent = 'Holding messages needs decerter run --intercept.';
    return;
  }

  byId('intercept-enabled').checked = intercept.enabled;
  byId('intercept-filter').value = intercept.filter;
  byId('intercept-direction').value = intercept.direction;
  byId('intercept-state').textContent = `${intercept.enabled ? 'On' : 'Off'}; a held message goes on unchanged after ${intercept.hold_timeout_seconds} s.`;
}

async function applyIntercept() {
  const intercept = await call('PUT', '/intercept', {
    enabled: byId('intercept-enabled').checked,
    filter: byId('intercept-filter').value.trim(),
    direction: byId('intercept-direction').value,
  });
  showIntercept(intercept);
}

// the flow list

function flowQuery(cursor) {
  const query = new URLSearchParams();

  if (state.filter) {
    query.set('filter', state.filter);
  }

  if (cursor) {
    query.set('cursor', cursor);
  }

  const text = query.toString();
  return text ? `/flows?${text}` : '/flows';
}

// the first page again, keeping the rows of the pages after it
async function loadFlows(isReset) {
  const list = await call('GET', flowQuery(''));

  if (isReset) {
    state.flows.clear();
    state.flowsCursor = list.next_cursor || '';
  }

  for (const flow of list.flows) {
    state.flows.set(flow.id, flow);
  }

  renderFlows();
}

async function moreFlows() {
  const list = await call('GET', flowQuery(state.flowsCursor));
  state.flowsCursor = list.next_cursor || '';

  for (const flow of list.flows) {
    state.flows.set(flow.id, flow);
  }

  renderFlows();
}

// a flow event: a known row is updated; a new flow is added when no filter is set, with one the server decides, so the first page is read again
const refreshFlows = debounce(() => loadFlows(false), 300);

function onFlow(flow) {
  refreshStatus();

  if (state.flows.has(flow.id) || !state.filter) {
    state.flows.set(flow.id, flow);
    renderFlowsSoon();
  } else {
    refreshFlows();
  }

  if (flow.id === state.flowId) {
    renderFlowInfo(flow);
  }
}

const renderFlowsSoon = debounce(async () => renderFlows(), 50);

function renderFlows() {
  const rows = [...state.flows.values()].sort((a, b) => b.id - a.id).map((flow) => {
    const row = el('tr', { class: flow.id === state.flowId ? 'selected' : '', onclick: action(() => selectFlow(flow.id)) },
      el('td', {}, flow.id),
      el('td', {}, flow.state),
      el('td', {}, flow.layer && flow.layer !== flow.protocol ? `${flow.protocol}/${flow.layer}` : flow.protocol),
      el('td', {}, `${flow.process.comm} (${flow.process.uid})`),
      el('td', {}, flow.destination),
      el('td', {}, flow.tls ? flow.tls.server_name : ''),
      el('td', { class: 'number' }, formatBytes(flow.up.bytes)),
      el('td', { class: 'number' }, formatBytes(flow.down.bytes)));
    return row;
  });
  byId('flows').replaceChildren(...rows);
  byId('no-flows').hidden = rows.length > 0;
  byId('more-flows').hidden = !state.flowsCursor;
}

// a flow and its messages

async function selectFlow(id) {
  state.flowId = id;
  state.messageId = null;
  byId('message-view').hidden = true;
  const flow = await call('GET', `/flows/${id}`);
  state.flows.set(flow.id, flow);
  renderFlowInfo(flow);
  renderFlows();
  const list = await call('GET', `/flows/${id}/messages`);
  state.messages = list.messages;
  state.messagesCursor = list.next_cursor || '';
  renderMessages();
}

function renderFlowInfo(flow) {
  byId('flow-title').textContent = `Flow ${flow.id}: ${flow.protocol} ${flow.client} → ${flow.destination}`;
  const fields = [
    ['state', flow.closed ? `${flow.state}, ${formatTime(flow.opened)} to ${formatTime(flow.closed)}` : `${flow.state} since ${formatTime(flow.opened)}`],
    ['process', `${flow.process.comm}, pid ${flow.process.pid}, uid ${flow.process.uid}, gid ${flow.process.gid}`],
    ['command', flow.process.cmdline],
    ['executable', flow.process.exe],
    ['layer', flow.layer || 'no messages yet'],
    ['up', `${formatBytes(flow.up.bytes)}, ${flow.up.messages} messages`],
    ['down', `${formatBytes(flow.down.bytes)}, ${flow.down.messages} messages`],
  ];

  if (flow.tls) {
    fields.push(['tls', [flow.tls.version || flow.tls.offered_version, flow.tls.cipher_suite, flow.tls.server_name && `SNI ${flow.tls.server_name}`, flow.tls.alpn && `ALPN ${flow.tls.alpn}`].filter(Boolean).join(', ')]);
  }

  if (flow.truncated) {
    fields.push(['history', 'truncated, some messages or bytes were not kept']);
  }

  byId('flow-info').replaceChildren(...fields.flatMap(([name, value]) => [el('dt', {}, name), el('dd', {}, value || '')]));
}

async function moreMessages() {
  const list = await call('GET', `/flows/${state.flowId}/messages?cursor=${encodeURIComponent(state.messagesCursor)}`);
  state.messages.push(...list.messages);
  state.messagesCursor = list.next_cursor || '';
  renderMessages();
}

// a message event of the shown flow goes at the end once every page is read
function onMessage(message) {
  if (message.flow_id === state.flowId && !state.messagesCursor && !state.messages.some((known) => known.id === message.id)) {
    state.messages.push(message);
    renderMessagesSoon();
  }
}

const renderMessagesSoon = debounce(async () => renderMessages(), 50);

function renderMessages() {
  const rows = state.messages.map((message) => el('tr', { class: message.id === state.messageId ? 'selected' : '', onclick: action(() => selectMessage(message.id, 0)) },
    el('td', {}, message.id),
    el('td', {}, formatTime(message.time)),
    el('td', { class: message.direction }, message.direction === 'up' ? '↑ up' : '↓ down'),
    el('td', {}, message.layer),
    el('td', { class: 'number' }, message.length === message.original_length ? message.length : `${message.original_length} → ${message.length}`),
    el('td', {}, [message.verdict, message.edited ? 'edited' : '', message.origin !== 'rules' ? message.origin : ''].filter(Boolean).join(', '))));
  byId('messages').replaceChildren(...rows);
  byId('messages-table').hidden = false;
  byId('more-messages').hidden = !state.messagesCursor;
}

// a window of a message's payload, or of what the peer sent when it was changed
async function selectMessage(id, offset) {
  const detail = await call('GET', `/messages/${id}?offset=${offset}&length=${windowLength}`);
  state.messageId = id;
  state.offset = detail.payload.offset;
  state.detail = detail;
  renderMessages();
  renderPayload();
}

function renderPayload() {
  const detail = state.detail;
  const showOriginal = byId('original').checked && detail.original;
  const payload = showOriginal ? detail.original : detail.payload;
  const bytes = bytesOfHex(payload.hex);
  byId('message-view').hidden = false;
  byId('message-title').textContent = `Message ${detail.id}${showOriginal ? ', as the peer sent it' : ''}`;
  byId('original-label').hidden = !detail.original;
  byId('window-range').textContent = payload.total === 0 ? 'empty' : `bytes ${payload.offset}–${payload.offset + payload.length} of ${payload.total}`;
  byId('previous-window').disabled = payload.offset === 0;
  byId('next-window').disabled = payload.offset + payload.length >= Math.max(detail.payload.total, detail.original ? detail.original.total : 0);
  byId('payload').textContent = state.view === 'hex' ? hexDump(bytes, payload.offset) : escapeBytes(bytes);
}

// held messages

async function loadHolds() {
  const list = await call('GET', '/holds');
  state.holds = list.holds;
  renderHolds();
}

const refreshHolds = debounce(loadHolds, 100);

function renderHolds() {
  const items = state.holds.map((hold) => el('li', { class: hold.id === (state.editing && state.editing.id) ? 'selected' : '' },
    el('div', {}, `#${hold.id} flow ${hold.flow_id} ${hold.direction} ${hold.layer}, ${formatBytes(hold.length)}${hold.edited ? ', edited' : ''}, `,
      el('span', { class: 'deadline' }, deadlineText(hold))),
    el('div', { class: 'preview' }, escapeBytes(bytesOfHex(hold.payload.hex.slice(0, 160))).split('\n')[0]),
    el('div', { class: 'row' },
      el('button', { type: 'button', onclick: action(() => openEditor(hold.id)) }, 'Edit'),
      el('button', { type: 'button', onclick: action(() => release(hold.id, 'forward')) }, 'Forward'),
      el('button', { type: 'button', class: 'danger', onclick: action(() => release(hold.id, 'drop')) }, 'Drop'))));
  byId('holds').replaceChildren(...items);
  byId('held-count').textContent = state.holds.length ? `(${state.holds.length})` : '';

  if (state.editing && !state.holds.some((hold) => hold.id === state.editing.id)) {
    byId('editor-title').textContent = `Message ${state.editing.id} is no longer held`;

    for (const button of ['editor-save', 'editor-forward', 'editor-drop']) {
      byId(button).disabled = true;
    }
  }
}

function deadlineText(hold) {
  const seconds = Math.max(0, Math.round((Date.parse(hold.deadline) - Date.now()) / 1000));
  return `${seconds} s left`;
}

function tickDeadlines() {
  const nodes = byId('holds').querySelectorAll('.deadline');
  state.holds.forEach((hold, index) => {
    if (nodes[index]) {
      nodes[index].textContent = deadlineText(hold);
    }
  });
}

async function release(id, verdict) {
  await call('POST', `/holds/${id}/${verdict}`);

  if (state.editing && state.editing.id === id) {
    closeEditor();
  }

  await loadHolds();
}

// the editor keeps its text while the held list changes around it

function openEditor(id) {
  const hold = state.holds.find((known) => known.id === id);

  if (!hold) {
    throw new Error(`message ${id} is no longer held`);
  }

  state.editing = { id, mode: 'text' };
  document.querySelector('input[name="edit-mode"][value="text"]').checked = true;
  byId('editor-title').textContent = `Edit held message ${id} (flow ${hold.flow_id}, ${hold.direction})`;
  byId('editor-text').value = escapeBytes(bytesOfHex(hold.payload.hex));
  byId('editor-hint').textContent = editorHint('text');

  for (const button of ['editor-save', 'editor-forward', 'editor-drop']) {
    byId(button).disabled = false;
  }

  byId('editor').hidden = false;
  renderHolds();
}

function editorHint(mode) {
  return mode === 'text'
    ? 'Escaped text: \\r \\n \\t \\\\ and \\xNN are bytes, line breaks are only layout (a newline is \\n).'
    : 'Hex digits, white space is ignored.';
}

function editorBytes() {
  const text = byId('editor-text').value;
  return state.editing.mode === 'text' ? unescapeText(text) : bytesOfHexText(text);
}

function switchEditorMode(mode) {
  const bytes = editorBytes();
  state.editing.mode = mode;
  byId('editor-text').value = mode === 'text' ? escapeBytes(bytes) : hexLines(bytes);
  byId('editor-hint').textContent = editorHint(mode);
}

async function saveEditor() {
  await call('PUT', `/holds/${state.editing.id}`, { payload: { type: 'hex', value: hexOfBytes(editorBytes()) } });
}

function closeEditor() {
  state.editing = null;
  byId('editor').hidden = true;
  renderHolds();
}

// the event stream: a reconnect reads everything again, events can have been missed in between

function connectEvents() {
  const source = new EventSource(`${api}/events`);
  const live = byId('live');
  const json = (handle) => (event) => handle(JSON.parse(event.data));

  source.addEventListener('open', () => {
    live.textContent = 'live';
    live.className = 'badge on';
    resync().catch(showError);
  });
  source.addEventListener('error', () => {
    live.textContent = 'offline';
    live.className = 'badge off';

    // a 403 or 502 ends an EventSource for good, a broken stream reconnects by itself
    if (source.readyState === EventSource.CLOSED) {
      setTimeout(connectEvents, reconnectDelay);
    }
  });
  source.addEventListener('flow_opened', json((event) => onFlow(event.flow)));
  source.addEventListener('flow_closed', json((event) => onFlow(event.flow)));
  source.addEventListener('message', json((event) => onMessage(event.message)));

  for (const type of ['held', 'hold_edited', 'hold_released']) {
    source.addEventListener(type, refreshHolds);
  }

  source.addEventListener('intercept_changed', json((event) => showIntercept(event.intercept)));
  source.addEventListener('overflow', json((event) => showError(`event stream: ${event.reason}`)));
}

async function resync() {
  await Promise.all([loadStatus(true), loadFlows(true), loadHolds()]);

  if (state.flowId !== null) {
    await selectFlow(state.flowId);
  }
}

function start() {
  byId('flow-filter').addEventListener('submit', action(async () => {
    state.filter = byId('filter').value.trim();
    await loadFlows(true);
  }));
  byId('more-flows').addEventListener('click', action(moreFlows));
  byId('more-messages').addEventListener('click', action(moreMessages));
  byId('intercept-form').addEventListener('submit', action(applyIntercept));

  for (const radio of document.querySelectorAll('input[name="view"]')) {
    radio.addEventListener('change', () => {
      state.view = radio.value;
      renderPayload();
    });
  }

  byId('original').addEventListener('change', renderPayload);
  byId('previous-window').addEventListener('click', action(() => selectMessage(state.messageId, Math.max(0, state.offset - windowLength))));
  byId('next-window').addEventListener('click', action(() => selectMessage(state.messageId, state.offset + windowLength)));

  for (const radio of document.querySelectorAll('input[name="edit-mode"]')) {
    radio.addEventListener('change', action(async () => {
      try {
        switchEditorMode(radio.value);
      } catch (error) {
        document.querySelector(`input[name="edit-mode"][value="${state.editing.mode}"]`).checked = true;
        throw error;
      }
    }));
  }

  byId('editor-save').addEventListener('click', action(async () => {
    await saveEditor();
    await loadHolds();
  }));
  byId('editor-forward').addEventListener('click', action(async () => {
    await saveEditor();
    await release(state.editing.id, 'forward');
  }));
  byId('editor-drop').addEventListener('click', action(() => release(state.editing.id, 'drop')));
  byId('editor-close').addEventListener('click', closeEditor);
  setInterval(tickDeadlines, 1000);
  connectEvents();
}

start();
