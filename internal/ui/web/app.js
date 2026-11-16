// SPDX-License-Identifier: AGPL-3.0-only

// the minimal UI of decerter: every request goes through decerter ui to the control API under /api/v1 (api/openapi.yaml)
// payloads and flow fields are attacker controlled: they reach the page only as text nodes, never as HTML

// relative: the page is served under a random path, which its cookie is limited to
const api = 'api/v1';
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
  exchanges: [],
  exchangesCursor: '',
  exchangeId: null,
  exchangeSide: 'request',
  exchangeOffset: 0,
  // the decode tree of the shown message, exchange body, flow handshake and joined stream, see decodePanes
  decodes: { message: null, exchange: null, handshake: null, stream: null },
  handshakeDirection: 'up',
  streamDirection: 'up',
};

// the rows live events may grow a list to: the newest flows, the first messages and exchanges of the shown flow; More reads on past them
const maxListRows = 1000;

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

// a window as spans of one byte each, data-offset its offset in the payload, so the decode tree can mark bytes and a click on one finds its node:
// the hex dump (offset, 16 bytes, the printable ones), or the escaped text
function byteSpans(bytes, offset, view) {
  const fragment = document.createDocumentFragment();
  const span = (kind, index, text) => {
    const node = el('span', { class: kind }, text);
    node.dataset.offset = String(offset + index);
    return node;
  };

  if (view !== 'hex') {
    bytes.forEach((byte, index) => {
      fragment.append(span('char', index, escapeBytes(bytes.subarray(index, index + 1))));
    });
    return fragment;
  }

  for (let start = 0; start < bytes.length; start += 16) {
    const row = bytes.subarray(start, start + 16);
    fragment.append(`${start > 0 ? '\n' : ''}${(offset + start).toString(16).padStart(8, '0')}  `);
    row.forEach((byte, index) => {
      fragment.append(span('byte', start + index, byte.toString(16).padStart(2, '0')), index === 7 ? '  ' : ' ');
    });
    fragment.append(' '.repeat((16 - row.length) * 3 + (row.length <= 8 ? 1 : 0)), ' |');
    row.forEach((byte, index) => {
      fragment.append(span('char', start + index, byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : '.'));
    });
    fragment.append('|');
  }

  return fragment;
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

// what each layer of the intercept settings holds, the select offers every layer the api takes
const interceptLayers = {
  '': 'every record layer',
  tcp: 'tcp reads only',
  tls: 'tls records only',
  udp: 'udp datagrams only',
  dtls: 'dtls records only',
  http: 'whole HTTP messages',
};

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
  byId('intercept-layer').value = intercept.layer || '';
  byId('intercept-state').textContent = `${intercept.enabled ? 'On' : 'Off'}, ${interceptLayers[intercept.layer || ''] || `layer ${intercept.layer}`}; a held message goes on unchanged after ${intercept.hold_timeout_seconds} s.`;
}

async function applyIntercept() {
  const intercept = await call('PUT', '/intercept', {
    enabled: byId('intercept-enabled').checked,
    filter: byId('intercept-filter').value.trim(),
    direction: byId('intercept-direction').value,
    layer: byId('intercept-layer').value,
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

  trimFlows();
  renderFlows();
}

// the newest flows up to the cap: a cursor of the flow list is the id of the oldest flow of a page, so More reads on from the oldest one kept
function trimFlows() {
  if (state.flows.size <= maxListRows) {
    return;
  }

  const ids = [...state.flows.keys()].sort((a, b) => b - a);

  for (const id of ids.slice(maxListRows)) {
    state.flows.delete(id);
  }

  state.flowsCursor = `${ids[maxListRows - 1]}`;
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
    trimFlows();
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
  state.exchangeId = null;
  state.exchanges = [];
  state.exchangesCursor = '';
  byId('message-view').hidden = true;
  byId('exchange-view').hidden = true;
  const flow = await call('GET', `/flows/${id}`);
  state.flows.set(flow.id, flow);
  renderFlowInfo(flow);
  renderFlows();
  await loadHandshake(flow);
  await loadStream(flow);
  const list = await call('GET', `/flows/${id}/messages`);
  state.messages = list.messages;
  state.messagesCursor = list.next_cursor || '';
  renderMessages();
  await loadExchanges();
}

function renderFlowInfo(flow) {
  byId('flow-title').textContent = `Flow ${flow.id}: ${flow.protocol} ${flow.client} → ${flow.destination}`;
  const fields = [
    ['state', flow.closed ? `${flow.state}, ${formatTime(flow.opened)} to ${formatTime(flow.closed)}` : `${flow.state} since ${formatTime(flow.opened)}`],
    ['process', `${flow.process.comm}, pid ${flow.process.pid}, uid ${flow.process.uid}, gid ${flow.process.gid}`],
    ['command', flow.process.cmdline],
    ['executable', flow.process.exe],
    ['layer', flow.layer || 'no messages yet'],
    ['up', trafficText(flow.up)],
    ['down', trafficText(flow.down)],
  ];

  if (flow.tls) {
    fields.push(['tls', [flow.tls.version || flow.tls.offered_version, flow.tls.cipher_suite, flow.tls.server_name && `SNI ${flow.tls.server_name}`, flow.tls.alpn && `ALPN ${flow.tls.alpn}`].filter(Boolean).join(', ')]);
  }

  if (flow.truncated) {
    fields.push(['history', 'truncated, some messages or bytes were not kept']);
  }

  byId('flow-info').replaceChildren(...fields.flatMap(([name, value]) => [el('dt', {}, name), el('dd', {}, value || '')]));
}

function trafficText(traffic) {
  return [formatBytes(traffic.bytes), `${traffic.messages} messages`, traffic.handshake_bytes ? `${formatBytes(traffic.handshake_bytes)} of handshake records` : ''].filter(Boolean).join(', ');
}

// the handshake records the history kept of a TLS or DTLS flow, GET /flows/{id}/decode: the tree of one direction and all its bytes (at most 16 KiB), no paging
async function loadHandshake(flow) {
  const traffic = state.handshakeDirection === 'down' ? flow.down : flow.up;
  const isKept = Boolean(flow.up.handshake_bytes || flow.down.handshake_bytes);
  byId('handshake-view').hidden = !isKept;

  if (!isKept) {
    state.decodes.handshake = null;
    return;
  }

  if (!traffic.handshake_bytes) {
    state.decodes.handshake = { key: '', as: '', result: null, error: `no ${state.handshakeDirection === 'down' ? 'server' : 'client'} handshake records kept`, selected: null, nodes: new Map(), ids: new Map(), elements: new Map() };
    renderDecode('handshake');
    byId('handshake-bytes').replaceChildren();
    byId('handshake-range').textContent = '';
    return;
  }

  // the records of an open flow are decoded again when it kept more
  const decoded = await loadDecode('handshake', `${flow.id} ${state.handshakeDirection} ${traffic.handshake_bytes}`, `/flows/${flow.id}/decode?part=handshake&direction=${state.handshakeDirection}`);
  const data = decoded.result ? decoded.result.data : null;
  byId('handshake-bytes').replaceChildren(data ? byteSpans(bytesOfHex(data.hex), data.offset, 'hex') : '');
  byId('handshake-range').textContent = data ? `${data.total} bytes${decoded.result.cut ? ', cut at 16 KiB' : ''}` : '';
  markBytes('handshake');
}

// the payloads of one direction of a tcp flow joined, GET /flows/{id}/decode?part=stream: decoded when the pane is open; a node marks its bytes in the
// message that has its first byte, the segments of the answer map the stream offsets to the messages
async function loadStream(flow) {
  const view = byId('stream-view');

  if (!flow) {
    return;
  }

  const traffic = state.streamDirection === 'down' ? flow.down : flow.up;
  view.hidden = flow.protocol !== 'tcp' || !(flow.up.messages || flow.down.messages);

  if (view.hidden || !view.open) {
    return;
  }

  if (!traffic.messages) {
    state.decodes.stream = { key: '', as: '', result: null, error: `no ${state.streamDirection === 'down' ? 'server' : 'client'} messages`, selected: null, nodes: new Map(), ids: new Map(), elements: new Map() };
    renderDecode('stream');
    byId('stream-range').textContent = '';
    byId('stream-location').textContent = '';
    return;
  }

  // the stream of an open flow is decoded again when it has more messages
  const decoded = await loadDecode('stream', `${flow.id} ${state.streamDirection} ${traffic.messages}`, `/flows/${flow.id}/decode?part=stream&direction=${state.streamDirection}&length=0`);
  const result = decoded.result;
  byId('stream-range').textContent = result ? `${result.total} bytes of ${result.segments.length} messages${result.cut ? `, ${result.note}` : ''}` : '';
  byId('stream-location').textContent = '';
}

// the messages and their bytes a node of the stream spans: [segment, first, end) per message, offsets of the message's payload
function streamParts(node) {
  const decoded = state.decodes.stream;
  const end = node.offset + Math.max(node.length, 1);
  return (decoded.result.segments || []).filter((segment) => segment.offset < end && node.offset < segment.offset + segment.length)
    .map((segment) => [segment, Math.max(0, node.offset - segment.offset), Math.min(segment.length, end - segment.offset)]);
}

// the stream node's bytes: where they are, and the message with its first byte shown with them marked
async function showStreamNode(node, isPaging) {
  const parts = streamParts(node);
  const location = byId('stream-location');
  location.replaceChildren(...parts.flatMap(([segment, first, end], index) => [index ? ', ' : 'bytes in ', el('button', { type: 'button', class: 'link', onclick: action(() => openStreamPart(segment, first)) }, `message ${segment.message_id} ${first}–${end}`)]));

  if (isPaging && parts.length) {
    await openStreamPart(parts[0][0], parts[0][1]);
  }
}

async function openStreamPart(segment, first) {
  const start = Math.floor(first / windowLength) * windowLength;

  if (state.messageId !== segment.message_id || state.offset !== start) {
    await selectMessage(segment.message_id, start);
  }

  markBytes('stream');
}

async function moreMessages() {
  const list = await call('GET', `/flows/${state.flowId}/messages?cursor=${encodeURIComponent(state.messagesCursor)}`);
  state.messages.push(...list.messages);
  state.messagesCursor = list.next_cursor || '';
  renderMessages();
}

// a message event of the shown flow goes at the end once every page is read; a full list stops there, More reads on after its last message
function onMessage(message) {
  if (message.flow_id !== state.flowId || state.messagesCursor || state.messages.some((known) => known.id === message.id)) {
    return;
  }

  if (state.messages.length >= maxListRows) {
    state.messagesCursor = `${state.messages[state.messages.length - 1].id}`;
  } else {
    state.messages.push(message);
  }

  renderMessagesSoon();
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
  const isOriginal = byId('original').checked && detail.original ? 'true' : 'false';
  await loadDecode('message', `${id} ${isOriginal}`, `/messages/${id}/decode?original=${isOriginal}`);
  markBytes('message');
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
  byId('payload').replaceChildren(byteSpans(bytes, payload.offset, state.view));
  markBytes('message');
}

// the decode trees: GET /messages/{id}/decode and GET /exchanges/{id}/decode, decoded when a message, side, original or Decode As changes, not per window;
// a click on a node marks its bytes (and pages to them), a click on a byte selects the deepest node that has it
const decodePanes = {
  message: { select: 'message-decode-as', summary: 'message-decode-summary', reason: 'message-decode-reason', tree: 'message-decode-tree' },
  exchange: { select: 'exchange-decode-as', summary: 'exchange-decode-summary', reason: 'exchange-decode-reason', tree: 'exchange-decode-tree' },
  handshake: { select: 'handshake-decode-as', summary: 'handshake-decode-summary', reason: 'handshake-decode-reason', tree: 'handshake-decode-tree' },
  stream: { select: 'stream-decode-as', summary: 'stream-decode-summary', reason: 'stream-decode-reason', tree: 'stream-decode-tree' },
};

// the decode of key (the message or exchange side it is of), kept while key stays
async function loadDecode(kind, key, path) {
  const known = state.decodes[kind];

  if (known && known.key === key) {
    return known;
  }

  const as = byId(decodePanes[kind].select).value;
  const decoded = { key, as, result: null, error: '', selected: null, nodes: new Map(), ids: new Map(), elements: new Map() };
  state.decodes[kind] = decoded;

  try {
    decoded.result = await call('GET', `${path}${as ? `&as=${encodeURIComponent(as)}` : ''}`);
  } catch (error) {
    decoded.error = String(error.message || error);
  }

  renderDecode(kind);
  return decoded;
}

function nodeText(node) {
  return node.value ? `${node.label}: ${node.value}` : node.label;
}

function renderDecode(kind) {
  const decoded = state.decodes[kind];
  const pane = decodePanes[kind];
  const select = byId(pane.select);
  const result = decoded.result;
  const protocols = result ? result.protocols || [] : [];
  select.replaceChildren(el('option', { value: '' }, 'auto'), ...protocols.map((protocol) => el('option', { value: protocol }, protocol)));
  select.value = protocols.includes(decoded.as) ? decoded.as : '';
  decoded.nodes = new Map();
  decoded.ids = new Map();
  decoded.elements = new Map();

  if (!result) {
    byId(pane.summary).textContent = '';
    byId(pane.reason).textContent = decoded.error ? `could not decode: ${decoded.error}` : '';
    byId(pane.tree).replaceChildren();
    return;
  }

  const chosen = (result.candidates || [])[0];
  const others = (result.candidates || []).filter((candidate) => candidate.protocol !== result.protocol).map((candidate) => `${candidate.protocol} (${candidate.reason})`);
  byId(pane.summary).textContent = result.summary || result.protocol;
  byId(pane.reason).textContent = [chosen ? `${result.protocol}: ${chosen.reason}` : result.protocol, others.length ? `also: ${others.join(', ')}` : '', result.truncated ? `only the first ${result.length} of ${result.total} bytes` : '', result.error || ''].filter(Boolean).join('; ');
  let count = 0;

  // a node and its children; the roots and their children are open
  const item = (node, depth) => {
    const id = count++;
    const hasChildren = (node.children || []).length > 0;
    const children = hasChildren ? el('ul', { hidden: depth > 0 }, ...node.children.map((child) => item(child, depth + 1))) : null;
    const twisty = hasChildren ? el('button', { type: 'button', class: 'twisty', ariaLabel: 'open or close' }, depth > 0 ? '▸' : '▾') : el('span', { class: 'leaf' }, '');
    const row = el('div', { class: 'node', title: `${node.name}, bytes ${node.offset}–${node.offset + node.length}${node.mask ? `, mask 0x${node.mask.toString(16)}` : ''}` }, twisty, el('span', {}, nodeText(node)));

    if (node.error) {
      row.append(el('span', { class: 'node-error' }, ` [${node.error}]`));
    }

    if (hasChildren) {
      twisty.addEventListener('click', (event) => {
        event.stopPropagation();
        children.hidden = !children.hidden;
        twisty.textContent = children.hidden ? '▸' : '▾';
      });
    }

    row.addEventListener('click', action(() => selectNode(kind, id, true)));
    decoded.nodes.set(id, node);
    decoded.ids.set(node, id);
    decoded.elements.set(id, row);
    return el('li', {}, row, ...(children ? [children] : []));
  };

  byId(pane.tree).replaceChildren(...(result.tree || []).map((node) => item(node, 0)));
}

// the pre whose spans the offsets of kind's tree count in: the payload, the body, the bytes of a request target or the handshake records
function bytesOf(kind) {
  if (kind === 'message') {
    return byId('payload');
  }

  if (kind === 'handshake') {
    return byId('handshake-bytes');
  }

  if (kind === 'stream') {
    return byId('payload');
  }

  const decoded = state.decodes.exchange;
  return decoded && decoded.result && decoded.result.source === 'target' ? byId('exchange-decoded') : byId('exchange-body');
}

// select a node of the tree; isPaging loads the window with its first byte when the window shown has none of them
async function selectNode(kind, id, isPaging) {
  const decoded = state.decodes[kind];

  if (decoded.selected !== null && decoded.elements.has(decoded.selected)) {
    decoded.elements.get(decoded.selected).classList.remove('selected');
  }

  decoded.selected = id;
  const row = decoded.elements.get(id);
  const node = decoded.nodes.get(id);
  row.classList.add('selected');

  // open the branches above it
  for (let list = row.parentElement.parentElement; list && list.id !== decodePanes[kind].tree; list = list.parentElement.parentElement) {
    if (list.hidden) {
      list.hidden = false;
      list.parentElement.querySelector(':scope > .node > .twisty').textContent = '▾';
    }
  }

  row.scrollIntoView({ block: 'nearest' });

  // the stream's bytes are in its messages
  if (kind === 'stream') {
    await showStreamNode(node, isPaging);
    return;
  }

  // the handshake shows all its bytes, scroll to the first marked one
  if (kind === 'handshake') {
    markBytes(kind);
    const first = bytesOf(kind).querySelector('.hl');

    if (isPaging && first) {
      first.scrollIntoView({ block: 'nearest' });
    }

    return;
  }

  if (isPaging && node.length > 0 && !markBytes(kind)) {
    const start = Math.floor(node.offset / windowLength) * windowLength;

    if (kind === 'message' && start !== state.offset) {
      await selectMessage(state.messageId, start);
    } else if (kind === 'exchange' && decoded.result.source !== 'target' && start !== state.exchangeOffset) {
      await selectExchange(state.exchangeId, start);
    }
  }
}

// mark the bytes of the selected node in the window shown, false when none of them is in it
function markBytes(kind) {
  const decoded = state.decodes[kind];
  const container = bytesOf(kind);
  let isShown = false;

  for (const span of container.querySelectorAll('.hl')) {
    span.classList.remove('hl');
  }

  if (!decoded || decoded.selected === null || !decoded.nodes.has(decoded.selected)) {
    return isShown;
  }

  const node = decoded.nodes.get(decoded.selected);
  let first = node.offset;
  let end = node.offset + node.length;

  // a stream node marks its bytes in the message shown
  if (kind === 'stream') {
    const part = streamParts(node).find(([segment]) => segment.message_id === state.messageId);

    if (!part) {
      return isShown;
    }

    [, first, end] = part;
  }

  for (const span of container.querySelectorAll('[data-offset]')) {
    const offset = Number(span.dataset.offset);

    if (offset >= first && offset < end) {
      span.classList.add('hl');
      isShown = true;
    }
  }

  return isShown;
}

// the deepest node with the byte at offset, the first one at each level (the flags before their bits' siblings, like Wireshark)
function deepestNode(kind, offset) {
  const decoded = state.decodes[kind];
  const has = (node) => node.length > 0 && offset >= node.offset && offset < node.offset + node.length;
  let found = null;
  let nodes = decoded.result.tree || [];

  for (let node = nodes.find(has); node; node = nodes.find(has)) {
    found = decoded.ids.get(node);
    nodes = node.children || [];
  }

  return found === undefined ? null : found;
}

function onByteClick(kind, event) {
  const span = event.target.closest('[data-offset]');
  const decoded = state.decodes[kind];

  if (!span || !decoded || !decoded.result) {
    return;
  }

  const id = deepestNode(kind, Number(span.dataset.offset));

  if (id !== null) {
    selectNode(kind, id, false).catch(showError);
    markBytes(kind);
  }
}

// the HTTP exchanges of the shown flow: request line, status, body lengths; a click shows the heads and a window of a body

async function loadExchanges() {
  if (state.flowId === null) {
    return;
  }

  const list = await call('GET', `/flows/${state.flowId}/exchanges`);
  state.exchanges = list.exchanges;
  state.exchangesCursor = list.next_cursor || '';
  renderExchanges();
}

async function moreExchanges() {
  const list = await call('GET', `/flows/${state.flowId}/exchanges?cursor=${encodeURIComponent(state.exchangesCursor)}`);
  state.exchanges.push(...list.exchanges);
  state.exchangesCursor = list.next_cursor || '';
  renderExchanges();
}

const renderExchangesSoon = debounce(async () => renderExchanges(), 50);
const refreshExchange = debounce(async () => {
  if (state.exchangeId !== null) {
    await selectExchange(state.exchangeId, state.exchangeOffset);
  }
}, 300);

// an exchange event of the shown flow updates its row, a new one goes at the end once every page is read; a full list stops there like the messages
function onExchange(exchange) {
  if (exchange.flow_id !== state.flowId) {
    return;
  }

  const index = state.exchanges.findIndex((known) => known.id === exchange.id);

  if (index >= 0) {
    state.exchanges[index] = exchange;
  } else if (!state.exchangesCursor && state.exchanges.length >= maxListRows) {
    state.exchangesCursor = `${state.exchanges[state.exchanges.length - 1].id}`;
  } else if (!state.exchangesCursor) {
    state.exchanges.push(exchange);
  }

  renderExchangesSoon();

  if (exchange.id === state.exchangeId) {
    refreshExchange();
  }
}

function bodyLength(message) {
  if (!message) {
    return '';
  }

  const length = message.body_length === message.original_body_length ? formatBytes(message.body_length) : `${formatBytes(message.original_body_length)} → ${formatBytes(message.body_length)}`;
  return message.state === 'complete' ? length : `${length}, ${message.state}`;
}

function renderExchanges() {
  const rows = state.exchanges.map((exchange) => {
    const request = exchange.request || {};
    const response = exchange.response || {};
    const notes = [...new Set([request.edited || response.edited ? 'edited' : '', request.verdict === 'drop' || response.verdict === 'drop' ? 'dropped' : '', request.note, response.note])].filter(Boolean).join('; ');
    return el('tr', { class: exchange.id === state.exchangeId ? 'selected' : '', onclick: action(() => selectExchange(exchange.id, 0)) },
      el('td', {}, exchange.id),
      el('td', {}, streamText(exchange)),
      el('td', {}, request.method || ''),
      el('td', {}, request.url || request.target || ''),
      el('td', {}, response.status ? `${response.status} ${response.reason || ''}` : ''),
      el('td', { class: 'number' }, bodyLength(exchange.request)),
      el('td', { class: 'number' }, bodyLength(exchange.response)),
      el('td', {}, notes));
  });
  byId('exchanges').replaceChildren(...rows);
  byId('exchanges-table').hidden = rows.length === 0;
  byId('more-exchanges').hidden = !state.exchangesCursor;
}

// the HTTP/2 stream of an exchange, a server push with the stream whose PUSH_PROMISE made it
function streamText(exchange) {
  if (!exchange.stream_id) {
    return '';
  }

  return exchange.promise_stream_id ? `${exchange.stream_id} (push on ${exchange.promise_stream_id})` : `${exchange.stream_id}`;
}

// a window of a gRPC body as text: a line in front of each message that is in the window, its bytes without the 5-byte prefix
function grpcText(bytes, offset, messages) {
  const end = offset + bytes.length;
  const parts = [];

  messages.forEach((message, index) => {
    const dataStart = message.offset + 5;
    const dataEnd = dataStart + message.length;

    if (dataEnd < offset || message.offset >= end || (dataEnd === offset && message.length > 0)) {
      return;
    }

    const flags = [message.compressed ? 'compressed' : '', dataEnd > end ? 'goes on after this window' : ''].filter(Boolean).join(', ');
    parts.push(`── gRPC message ${index + 1}: ${message.length} bytes at body offset ${message.offset}${flags ? ` (${flags})` : ''} ──\n`);
    parts.push(escapeBytes(bytes.slice(Math.max(dataStart, offset) - offset, Math.min(dataEnd, end) - offset)));
    parts.push('\n');
  });

  return parts.length === 0 ? escapeBytes(bytes) : parts.join('');
}

// the start line and fields of a head, one per line as text
function headText(head, isRequest) {
  const start = isRequest ? `${head.method} ${head.target} ${head.version}` : `${head.version} ${head.status} ${head.reason || ''}`;
  return [start, ...(head.headers || []).map((header) => `${header.name}: ${header.value}`)].join('\n');
}

async function selectExchange(id, offset) {
  const exchange = await call('GET', `/exchanges/${id}`);
  const isRequest = state.exchangeSide === 'request';
  const message = isRequest ? exchange.request : exchange.response;
  state.exchangeId = id;
  state.exchangeOffset = offset;
  renderExchanges();
  byId('exchange-view').hidden = false;
  byId('exchange-title').textContent = `Exchange ${id}`;
  byId('exchange-original-label').hidden = !(message && message.edited);

  if (!message) {
    byId('exchange-head').textContent = `No ${state.exchangeSide} yet.`;
    byId('exchange-body').textContent = '';
    byId('exchange-range').textContent = '';
    byId('exchange-decoded').hidden = true;
    byId('exchange-decoded-note').hidden = true;
    state.decodes.exchange = { key: '', as: '', result: null, error: '', selected: null, nodes: new Map(), ids: new Map(), elements: new Map() };
    renderDecode('exchange');
    return;
  }

  const showOriginal = byId('exchange-original').checked && message.edited && message.original;
  const parts = [];

  if (isRequest) {
    parts.push(headText(showOriginal ? message.original : message, true));
  } else {
    for (const interim of exchange.interim || []) {
      parts.push(headText(interim, false), '');
    }

    parts.push(headText(showOriginal ? message.original : message, false));
  }

  if (message.trailers) {
    parts.push('', 'trailers:', ...message.trailers.map((header) => `${header.name}: ${header.value}`));
  }

  if (message.note) {
    parts.push('', `note: ${message.note}`);
  }

  byId('exchange-head').textContent = parts.join('\n');
  const body = await call('GET', `/exchanges/${id}/body?side=${state.exchangeSide}&offset=${offset}&length=${windowLength}`);
  const payload = showOriginal && body.original ? body.original : body.payload;
  const bytes = bytesOfHex(payload.hex);
  byId('exchange-range').textContent = payload.total === 0 ? 'no body kept' : `body bytes ${payload.offset}–${payload.offset + payload.length} of ${payload.total}`;
  byId('exchange-previous').disabled = payload.offset === 0;
  byId('exchange-next').disabled = payload.offset + payload.length >= payload.total;
  const messages = showOriginal ? [] : message.grpc_messages || [];

  if (state.view === 'hex') {
    const starts = messages.filter((grpc) => grpc.offset >= payload.offset && grpc.offset < payload.offset + payload.length).map((grpc) => `${grpc.offset} (${grpc.length} bytes)`);
    byId('exchange-body').replaceChildren(starts.length ? `gRPC messages at body offsets ${starts.join(', ')}\n` : '', byteSpans(bytes, payload.offset, 'hex'));
  } else if (messages.length) {
    byId('exchange-body').textContent = grpcText(bytes, payload.offset, messages);
  } else {
    byId('exchange-body').replaceChildren(byteSpans(bytes, payload.offset, 'text'));
  }

  const isOriginal = showOriginal ? 'true' : 'false';
  // a body still coming in is decoded again when an exchange event shows it grew
  const decoded = await loadDecode('exchange', `${id} ${state.exchangeSide} ${isOriginal} ${message.body_length} ${message.state}`, `/exchanges/${id}/decode?side=${state.exchangeSide}&original=${isOriginal}`);
  const data = decoded.result && decoded.result.source === 'target' ? decoded.result.data : null;
  byId('exchange-decoded').hidden = !data;
  byId('exchange-decoded-note').hidden = !data;

  if (data) {
    byId('exchange-decoded-note').textContent = `decoded from the request target, ${data.total} bytes:`;
    byId('exchange-decoded').replaceChildren(byteSpans(bytesOfHex(data.hex), data.offset, state.view));
  }

  markBytes('exchange');
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
    el('div', {}, `#${hold.id} flow ${hold.flow_id}${hold.exchange_id ? ` exchange ${hold.exchange_id}` : ''} ${hold.direction} ${hold.layer}, ${formatBytes(hold.length)}${hold.edited ? ', edited' : ''}, `,
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
  byId('editor-title').textContent = `Edit held message ${id} (flow ${hold.flow_id}, ${hold.direction}${hold.layer === 'http' ? ', whole HTTP message: Content-Length and chunking are fixed when it goes on' : ''})`;
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

  source.addEventListener('exchange', json((event) => onExchange(event.exchange)));
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
  byId('more-exchanges').addEventListener('click', action(moreExchanges));
  byId('intercept-form').addEventListener('submit', action(applyIntercept));

  for (const radio of document.querySelectorAll('input[name="view"]')) {
    radio.addEventListener('change', () => {
      state.view = radio.value;
      renderPayload();
    });
  }

  byId('original').addEventListener('change', action(() => selectMessage(state.messageId, state.offset)));
  byId('message-decode-as').addEventListener('change', action(() => {
    state.decodes.message = null;
    return selectMessage(state.messageId, state.offset);
  }));
  byId('exchange-decode-as').addEventListener('change', action(() => {
    state.decodes.exchange = null;
    return selectExchange(state.exchangeId, state.exchangeOffset);
  }));
  byId('handshake-decode-as').addEventListener('change', action(() => {
    state.decodes.handshake = null;
    return loadHandshake(state.flows.get(state.flowId));
  }));

  byId('stream-decode-as').addEventListener('change', action(() => {
    state.decodes.stream = null;
    return loadStream(state.flows.get(state.flowId));
  }));
  byId('stream-view').addEventListener('toggle', action(() => loadStream(state.flows.get(state.flowId))));

  for (const radio of document.querySelectorAll('input[name="stream-direction"]')) {
    radio.addEventListener('change', action(() => {
      state.streamDirection = radio.value;
      return loadStream(state.flows.get(state.flowId));
    }));
  }

  for (const radio of document.querySelectorAll('input[name="handshake-direction"]')) {
    radio.addEventListener('change', action(() => {
      state.handshakeDirection = radio.value;
      return loadHandshake(state.flows.get(state.flowId));
    }));
  }

  byId('handshake-bytes').addEventListener('click', (event) => onByteClick('handshake', event));
  byId('payload').addEventListener('click', (event) => onByteClick('message', event));
  byId('exchange-body').addEventListener('click', (event) => onByteClick('exchange', event));
  byId('exchange-decoded').addEventListener('click', (event) => onByteClick('exchange', event));

  for (const radio of document.querySelectorAll('input[name="side"]')) {
    radio.addEventListener('change', action(() => {
      state.exchangeSide = radio.value;
      return selectExchange(state.exchangeId, 0);
    }));
  }

  byId('exchange-original').addEventListener('change', action(() => selectExchange(state.exchangeId, state.exchangeOffset)));
  byId('exchange-previous').addEventListener('click', action(() => selectExchange(state.exchangeId, Math.max(0, state.exchangeOffset - windowLength))));
  byId('exchange-next').addEventListener('click', action(() => selectExchange(state.exchangeId, state.exchangeOffset + windowLength)));
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
