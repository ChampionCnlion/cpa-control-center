const vm = require('vm');

const SDK_GLOBAL_PATCH = 'var SentinelSDK=';
const SDK_GLOBAL_REPLACEMENT = 'globalThis.SentinelSDK=';
const INSTANCE_PATCH = 'var P=new _;';
const INSTANCE_REPLACEMENT = 'var P=new _;globalThis.__debugP=P;';
const EXPOSE_PATCH = 'return o?r?.[n(63)]?ce({so:o,c:r[n(63)]},t):o:null},t.token=ye,t}({});';
const EXPOSE_REPLACEMENT = 'return o?r?.[n(63)]?ce({so:o,c:r[n(63)]},t):o:null},t.token=ye,t.__debug_n=_n,t.__debug_bindProof=D,t}({});';

function patchSdk(source) {
  let sdk = String(source || '');
  sdk = sdk.replace(SDK_GLOBAL_PATCH, SDK_GLOBAL_REPLACEMENT);
  sdk = sdk.replace(INSTANCE_PATCH, INSTANCE_REPLACEMENT);
  sdk = sdk.replace(EXPOSE_PATCH, EXPOSE_REPLACEMENT);
  if (!sdk.includes('globalThis.__debugP')) {
    throw new Error('Sentinel SDK patch failed: __debugP was not injected');
  }
  if (!sdk.includes('__debug_bindProof')) {
    throw new Error('Sentinel SDK patch failed: bindProof was not exposed');
  }
  return sdk;
}

function buildSandbox(payload, sdkSource) {
  return {
    __payload: payload,
    __sdkSource: sdkSource,
    console,
    Math,
    Date,
    JSON,
    Promise,
    Map,
    WeakMap,
    Set,
    Array,
    Object,
    String,
    Number,
    Boolean,
    RegExp,
    Error,
    TypeError,
    Uint8Array,
    ArrayBuffer,
    TextEncoder,
    TextDecoder,
    URL,
    URLSearchParams,
    Buffer,
    setTimeout: (cb) => {
      if (typeof cb === 'function') cb();
      return 1;
    },
    clearTimeout: () => {},
    setInterval: () => 1,
    clearInterval: () => {},
  };
}

function runtimeSource() {
  return String.raw`
function createStorage() {
  const map = new Map();
  return {
    get length() { return map.size; },
    clear() { map.clear(); },
    getItem(key) { return map.has(String(key)) ? map.get(String(key)) : null; },
    setItem(key, value) { map.set(String(key), String(value)); },
    removeItem(key) { map.delete(String(key)); },
  };
}

function createElement(tagName) {
  const tag = String(tagName || 'div').toLowerCase();
  return {
    nodeType: 1,
    tagName: tag.toUpperCase(),
    nodeName: tag.toUpperCase(),
    style: {},
    children: [],
    src: '',
    contentWindow: { postMessage() {} },
    appendChild(child) { this.children.push(child); return child; },
    removeChild(child) { this.children = this.children.filter((x) => x !== child); return child; },
    setAttribute() {},
    getAttribute() { return null; },
    addEventListener(event, cb) { if (event === 'load' && typeof cb === 'function') cb(); },
    removeEventListener() {},
    getBoundingClientRect() {
      return { x: 0, y: 0, width: 0, height: 0, top: 0, left: 0, right: 0, bottom: 0 };
    },
  };
}

function installRuntime(payload) {
  const screen = {
    width: Number(payload.screen_width || 1366),
    height: Number(payload.screen_height || 768),
    availWidth: Number(payload.screen_width || 1366),
    availHeight: Number(payload.screen_height || 768),
    colorDepth: 24,
    pixelDepth: 24,
  };
  const scripts = [];
  const documentElement = createElement('html');
  documentElement.clientWidth = screen.width;
  documentElement.clientHeight = screen.height;

  const document = {
    readyState: 'complete',
    hidden: false,
    visibilityState: 'visible',
    referrer: 'https://auth.openai.com/',
    URL: 'https://auth.openai.com/',
    cookie: 'oai-did=' + encodeURIComponent(payload.device_id || ''),
    scripts,
    currentScript: { src: 'https://sentinel.openai.com/sentinel/sdk.js', getAttribute() { return null; } },
    documentElement,
    body: createElement('body'),
    head: createElement('head'),
    createElement(tag) {
      const el = createElement(tag);
      if (String(tag).toLowerCase() === 'script') scripts.push(el);
      return el;
    },
    createElementNS(_ns, tag) { return this.createElement(tag); },
    querySelector() { return null; },
    querySelectorAll() { return []; },
    getElementById() { return null; },
    getElementsByTagName() { return []; },
    addEventListener() {},
    removeEventListener() {},
    dispatchEvent() { return true; },
  };

  const performance = {
    now: () => Number(payload.performance_now || 12345.67),
    timeOrigin: Number(payload.time_origin || Date.now() - 12345),
    memory: { jsHeapSizeLimit: Number(payload.js_heap_size_limit || 4294967296) },
  };

  globalThis.window = globalThis;
  globalThis.self = globalThis;
  globalThis.top = globalThis;
  globalThis.parent = globalThis;
  globalThis.document = document;
  globalThis.navigator = {
    userAgent: String(payload.user_agent || 'Mozilla/5.0'),
    language: 'en-US',
    languages: ['en-US', 'en'],
    hardwareConcurrency: 12,
    platform: 'Win32',
    vendor: 'Google Inc.',
    webdriver: false,
  };
  globalThis.location = {
    href: 'https://auth.openai.com/',
    origin: 'https://auth.openai.com',
    pathname: '/',
    search: '',
  };
  globalThis.screen = screen;
  globalThis.performance = performance;
  globalThis.localStorage = createStorage();
  globalThis.sessionStorage = createStorage();
  globalThis.__sentinel_init_pending = [];
  globalThis.__sentinel_token_pending = [];
  globalThis.requestIdleCallback = (cb) => {
    if (typeof cb === 'function') cb({ didTimeout: false, timeRemaining: () => 50 });
    return 1;
  };
  globalThis.cancelIdleCallback = () => {};
  globalThis.addEventListener = () => {};
  globalThis.removeEventListener = () => {};
  globalThis.dispatchEvent = () => true;
  globalThis.postMessage = () => {};
  globalThis.atob = (input) => Buffer.from(String(input || ''), 'base64').toString('binary');
  globalThis.btoa = (input) => Buffer.from(String(input || ''), 'binary').toString('base64');
  globalThis.URL = URL;
  globalThis.URLSearchParams = URLSearchParams;
  globalThis.Event = class Event { constructor(type) { this.type = type; } };
  globalThis.CustomEvent = class CustomEvent extends globalThis.Event {
    constructor(type, init) { super(type); this.detail = init && Object.prototype.hasOwnProperty.call(init, 'detail') ? init.detail : null; }
  };
  globalThis.MessageChannel = class MessageChannel {
    constructor() {
      this.port1 = { postMessage() {}, addEventListener() {}, removeEventListener() {}, start() {}, close() {} };
      this.port2 = { postMessage() {}, addEventListener() {}, removeEventListener() {}, start() {}, close() {} };
    }
  };
  globalThis.matchMedia = (query) => ({
    media: String(query || ''),
    matches: false,
    onchange: null,
    addListener() {},
    removeListener() {},
    addEventListener() {},
    removeEventListener() {},
    dispatchEvent() { return false; },
  });
  globalThis.getComputedStyle = () => ({ getPropertyValue() { return ''; } });
  globalThis.history = { length: 1, state: null, back() {}, forward() {}, go() {}, pushState() {}, replaceState() {} };
  globalThis.chrome = { runtime: {}, app: {} };
  globalThis.CSS = { supports() { return true; } };
  globalThis.indexedDB = {
    open() { return { onerror: null, onsuccess: null, onupgradeneeded: null, result: {}, error: null }; },
    deleteDatabase() { return {}; },
  };
  globalThis.fetch = async () => { throw new Error('fetch should not be called inside Sentinel VM'); };
  globalThis.crypto = {
    getRandomValues(arr) {
      for (let i = 0; i < arr.length; i += 1) arr[i] = Math.floor(Math.random() * 256);
      return arr;
    },
  };
}

async function runSentinelAction() {
  const payload = globalThis.__payload || {};
  installRuntime(payload);
  eval(String(globalThis.__sdkSource || ''));

  if (payload.action === 'requirements') {
    const requestP = await globalThis.__debugP.getRequirementsToken();
    return { request_p: requestP };
  }

  if (payload.action === 'solve') {
    const challenge = payload.challenge || {};
    const requestP = String(payload.request_p || '').trim();
    const finalP = await globalThis.__debugP.getEnforcementToken(challenge);
    globalThis.SentinelSDK.__debug_bindProof(challenge, requestP);
    const dx = challenge && challenge.turnstile ? challenge.turnstile.dx : null;
    const tValue = dx ? await globalThis.SentinelSDK.__debug_n(challenge, dx) : null;
    return { final_p: finalP, t: tValue };
  }

  throw new Error('unsupported Sentinel action: ' + payload.action);
}
`;
}

async function main() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  const payload = { ...input, sdkSource: undefined };
  const sdkSource = patchSdk(String(input.sdkSource || ''));
  const sandbox = buildSandbox(payload, sdkSource);
  const context = vm.createContext(sandbox);
  const script = new vm.Script(`${runtimeSource()}\nrunSentinelAction();`);
  const result = await script.runInContext(context, { timeout: 30000 });
  process.stdout.write(JSON.stringify(result || {}));
}

main().catch((err) => {
  process.stderr.write(String(err && err.stack ? err.stack : err) + '\n');
  process.exit(1);
});
