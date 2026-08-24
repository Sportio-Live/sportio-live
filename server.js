const express = require('express');
const cors = require('cors');
const axios = require('axios');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const m3u = require('./m3u.js');
const epgshare = require('./epgshare01.js');

// Without these, Node's default behavior for an unhandled promise rejection
// (Node 15+) is to crash the entire process - and Docker's restart policy
// then takes several seconds to bring it back up. One flaky upstream call
// (an IPTV provider, ESPN, EPGShare01) anywhere in the app would otherwise
// take down every concurrent user's request, not just the one that hit it -
// exactly the "catalog goes blank, works again a few seconds later" pattern.
// Logging and continuing keeps a single bad request/promise from being able
// to do that. uncaughtException is included too for the same reason, even
// though Node's own docs call the process state "undefined" afterward -
// for this app, staying up and serving everyone else is the safer default
// versus a hard crash, and every request handler already isolates its own
// state rather than sharing mutable request-scoped data across requests.
process.on('unhandledRejection', (reason) => {
  console.error('[Process] Unhandled promise rejection (continuing):', reason && reason.stack || reason);
});
process.on('uncaughtException', (err) => {
  console.error('[Process] Uncaught exception (continuing):', err && err.stack || err);
});

// Xtream credentials are encrypted at rest in users.json using this key.
// Must be a 64-character hex string (32 bytes) for AES-256-GCM. Generate one
// with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
//
// Deliberately does NOT crash the app if this is missing - a fresh
// install with no ENCRYPTION_KEY set yet needs to actually start up
// successfully so the first-run setup flow (admin password screen, then
// an in-app key generator) can run at all. A random, in-memory-only key
// is used as a placeholder so encrypt()/decrypt() never throw - but this
// placeholder is NEVER actually relied on for real user data, since
// registration and login are explicitly blocked elsewhere until a real,
// persistent key is configured. Using it for anything real would mean
// silently unreadable accounts the moment the container restarts and
// this random value is gone.
const ENCRYPTION_KEY_HEX = process.env.ENCRYPTION_KEY;
const ENCRYPTION_KEY_CONFIGURED = !!(ENCRYPTION_KEY_HEX && /^[0-9a-fA-F]{64}$/.test(ENCRYPTION_KEY_HEX));
if (!ENCRYPTION_KEY_CONFIGURED) {
  console.error('');
  console.error('WARNING: ENCRYPTION_KEY environment variable is missing or invalid.');
  console.error('The app will start, but account registration/login stay disabled until a real key is set.');
  console.error('Visit the homepage to generate one, or generate it directly with:');
  console.error("  node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\"");
  console.error('Then set it in docker-compose.yml under this service\'s environment section as:');
  console.error('  - ENCRYPTION_KEY=<the generated value>');
  console.error('...and restart the container - this is only read once, at startup.');
  console.error('');
}
const XTREAM_ENCRYPTION_KEY = Buffer.from(
  ENCRYPTION_KEY_CONFIGURED ? ENCRYPTION_KEY_HEX : crypto.randomBytes(32).toString('hex'),
  'hex'
);

// Encrypts a single string value for storage. Returns a self-contained
// 'enc:iv:authTag:ciphertext' string (all base64) so decrypt() can tell
// encrypted values apart from legacy plaintext data during migration.
function encrypt(text) {
  if (text === undefined || text === null) return text;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', XTREAM_ENCRYPTION_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(String(text), 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return `enc:${iv.toString('base64')}:${authTag.toString('base64')}:${encrypted.toString('base64')}`;
}

// Decrypts a value produced by encrypt(). Values without the 'enc:' prefix
// are assumed to be legacy plaintext (pre-encryption data) and are passed
// through unchanged - they get encrypted automatically on the next save.
function decrypt(value) {
  if (value === undefined || value === null) return value;
  if (typeof value !== 'string' || !value.startsWith('enc:')) return value;

  try {
    const parts = value.split(':');
    const iv = Buffer.from(parts[1], 'base64');
    const authTag = Buffer.from(parts[2], 'base64');
    const encryptedData = Buffer.from(parts[3], 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', XTREAM_ENCRYPTION_KEY, iv);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);
    return decrypted.toString('utf8');
  } catch (err) {
    console.error('[Encryption] Failed to decrypt a stored value - wrong ENCRYPTION_KEY, or corrupted data:', err.message);
    return '';
  }
}

function encryptXtreamForStorage(xtream) {
  if (!xtream) return xtream;
  return {
    ...xtream,
    url: xtream.url !== undefined ? encrypt(xtream.url) : xtream.url,
    username: xtream.username !== undefined ? encrypt(xtream.username) : xtream.username,
    password: xtream.password !== undefined ? encrypt(xtream.password) : xtream.password
  };
}

function decryptXtreamFromStorage(xtream) {
  if (!xtream) return xtream;
  return {
    ...xtream,
    url: xtream.url !== undefined ? decrypt(xtream.url) : xtream.url,
    username: xtream.username !== undefined ? decrypt(xtream.username) : xtream.username,
    password: xtream.password !== undefined ? decrypt(xtream.password) : xtream.password
  };
}

// M3U playlist/EPG URLs frequently carry embedded credentials directly in
// the URL itself (e.g. ".../live/username/password/streamid.ts", confirmed
// against real provider output during design) - just as sensitive as
// Xtream's own username/password, so they get the same encryption-at-rest
// treatment, not treated as lesser just because they're "only URLs".
function encryptM3uForStorage(m3u) {
  if (!m3u) return m3u;
  return {
    ...m3u,
    playlistUrl: m3u.playlistUrl !== undefined ? encrypt(m3u.playlistUrl) : m3u.playlistUrl,
    epgUrl: m3u.epgUrl !== undefined ? encrypt(m3u.epgUrl) : m3u.epgUrl
  };
}

function decryptM3uFromStorage(m3u) {
  if (!m3u) return m3u;
  return {
    ...m3u,
    playlistUrl: m3u.playlistUrl !== undefined ? decrypt(m3u.playlistUrl) : m3u.playlistUrl,
    epgUrl: m3u.epgUrl !== undefined ? decrypt(m3u.epgUrl) : m3u.epgUrl
  };
}

const app = express();
// Behind Nginx Proxy Manager (or any reverse proxy), req.protocol/hostname
// need to trust X-Forwarded-* headers to correctly report https - without
// this, self-generated URLs (posters, manifest links) would incorrectly
// say http:// even when the public-facing site is https://.
app.set('trust proxy', true);
const PORT = process.env.PORT || 2323;
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'users.json');
const M3U_SETTINGS_FILE = path.join(DATA_DIR, 'm3u-settings.json');
const EPGSHARE_SETTINGS_FILE = path.join(DATA_DIR, 'epgshare-settings.json');
const ADMIN_CONFIG_FILE = path.join(DATA_DIR, 'admin-config.json');

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  console.log(`[Storage] Created data directory at ${DATA_DIR}`);
}

// Deliberately NOT under DATA_DIR - data/ is gitignored and excluded from
// the Docker build context (instance-local runtime state: accounts,
// admin credentials, caches), but stock presets are curated, shippable
// content an operator explicitly wants committed and distributed with the
// repo. Built from __dirname directly so it can never drift under data/.
// Never written to at runtime (see LOCAL_PRESETS_FILE below for that) -
// this file only ever changes by editing it and shipping a code update.
const PRESETS_DIR = path.join(__dirname, 'presets');
const PRESETS_FILE = path.join(PRESETS_DIR, 'presets.json');

if (!fs.existsSync(PRESETS_DIR)) {
  fs.mkdirSync(PRESETS_DIR, { recursive: true });
  console.log(`[Storage] Created presets directory at ${PRESETS_DIR}`);
}

// The instance-local counterpart to PRESETS_FILE: presets an admin creates
// through this instance's own admin panel. Lives under DATA_DIR precisely
// because it must NOT be shipped/committed - it's this deployment's own
// content, and it must survive pulling a code update that ships a new
// PRESETS_FILE without being clobbered by (or clobbering) that update.
const LOCAL_PRESETS_FILE = path.join(DATA_DIR, 'local-presets.json');

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// --- Login rate limiting ---
// Tracks failed login attempts per IP address in memory.
// After LOGIN_MAX_ATTEMPTS failures within LOGIN_WINDOW_MS, that IP is locked out
// until the window passes. Resets automatically on server restart (intentional
// for a small single-instance deployment like this one).
const loginAttempts = new Map(); // ip -> { count, firstAttempt }
const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_WINDOW_MS = 15 * 60 * 1000; // 15 minutes

// Periodically clear out stale entries so this Map doesn't grow forever.
setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of loginAttempts.entries()) {
    if (now - record.firstAttempt > LOGIN_WINDOW_MS) {
      loginAttempts.delete(ip);
    }
  }
}, LOGIN_WINDOW_MS).unref();

// Shared by every endpoint that checks a password (login, update, delete,
// the EPG tool's endpoints, admin login) - not just /api/user/login.
// Originally only login itself enforced this, which meant the lockout was
// trivially bypassable by brute-forcing the same password through any of
// the other endpoints instead. One shared IP-keyed budget across all of
// them closes that gap.
function isRateLimited(ip) {
  const record = loginAttempts.get(ip);
  return !!(record && (Date.now() - record.firstAttempt < LOGIN_WINDOW_MS) && record.count >= LOGIN_MAX_ATTEMPTS);
}

function getRetryAfterSeconds(ip) {
  const record = loginAttempts.get(ip);
  if (!record) return 0;
  return Math.ceil((LOGIN_WINDOW_MS - (Date.now() - record.firstAttempt)) / 1000);
}

function recordFailedAttempt(ip) {
  const now = Date.now();
  const record = loginAttempts.get(ip);
  if (record && now - record.firstAttempt < LOGIN_WINDOW_MS) {
    record.count++;
  } else {
    loginAttempts.set(ip, { count: 1, firstAttempt: now });
  }
}

function clearFailedAttempts(ip) {
  loginAttempts.delete(ip);
}

// Wraps a legacy single-provider account (top-level connectionType/xtream/
// m3u/sportCategories/selectedSports) into the current providers[] shape.
// Idempotent - already-migrated users (providers is already an array) pass
// through untouched, so this is safe to run unconditionally on every load
// regardless of a given user's migration state. Every field is defended
// with a fallback rather than trusted to be complete, since a legacy record
// could be hand-edited or the product of an earlier partial write.
function migrateUserToProviders(user) {
  if (Array.isArray(user.providers)) return user;

  const { connectionType, xtream, m3u, sportCategories, selectedSports, ...rest } = user;
  const resolvedType = connectionType || 'xtream';
  let resolvedXtream = xtream;
  let resolvedM3u = m3u;

  // Only one of xtream/m3u should ever be populated on a legacy record -
  // if both somehow are, connectionType is the authoritative signal for
  // which one was actually in use (matching how every legacy route already
  // branched), so the other is dropped rather than carried into the new
  // provider object where nothing would ever read it.
  if (xtream && m3u) {
    console.error(`[Migration] User ${user.uuid} had both xtream and m3u set; keeping only the one matching connectionType (${resolvedType}).`);
    if (resolvedType === 'm3u') resolvedXtream = undefined;
    else resolvedM3u = undefined;
  }

  return {
    ...rest,
    providers: [{
      id: 'provider-1',
      label: 'Provider 1',
      connectionType: resolvedType,
      xtream: resolvedXtream,
      m3u: resolvedM3u,
      sportCategories: sportCategories || {},
      selectedSports: selectedSports || []
    }]
  };
}

let userConfigs = {};
if (fs.existsSync(DATA_FILE)) {
  try {
    const raw = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    for (const [uuid, user] of Object.entries(raw)) {
      // Decryption happens on whichever shape this specific record is
      // still in - already-migrated records carry credentials per-provider,
      // legacy records carry them at the top level - before migration
      // wraps a legacy record into providers[], so migrateUserToProviders
      // always receives already-decrypted credentials either way.
      const decrypted = Array.isArray(user.providers)
        ? { ...user, providers: user.providers.map(p => ({ ...p, xtream: decryptXtreamFromStorage(p.xtream), m3u: decryptM3uFromStorage(p.m3u) })) }
        : { ...user, xtream: decryptXtreamFromStorage(user.xtream), m3u: decryptM3uFromStorage(user.m3u) };
      userConfigs[uuid] = migrateUserToProviders(decrypted);
    }
  } catch (err) {
    console.error('[Storage] Error loading users.json:', err.message);
  }
}

// Every in-memory user is guaranteed to have a providers[] array by this
// point (migrateUserToProviders ran unconditionally on load above), so
// saving never needs to branch on shape - just encrypt each provider's own
// credentials independently.
function saveUserConfigs() {
  try {
    const toWrite = {};
    for (const [uuid, user] of Object.entries(userConfigs)) {
      toWrite[uuid] = {
        ...user,
        providers: (user.providers || []).map(p => ({ ...p, xtream: encryptXtreamForStorage(p.xtream), m3u: encryptM3uForStorage(p.m3u) }))
      };
    }
    fs.writeFileSync(DATA_FILE, JSON.stringify(toWrite, null, 2), 'utf8');
  } catch (err) {
    console.error('[Storage] Failed to save users.json:', err.message);
  }
}

// Any accounts loaded with legacy plaintext credentials, or in the legacy
// single-provider shape, get re-saved immediately - so both encryption and
// the providers[] migration are applied automatically without anyone
// needing to re-enter their credentials or take any action.
saveUserConfigs();

// Admin-configured M3U refresh schedule - deliberately a small, separate,
// live-editable JSON file rather than a .env value, since the whole
// point is the admin can change it from the admin page itself without a
// restart. No encryption needed here (unlike users.json) - a schedule
// and a timezone name aren't sensitive the way credentials are.
const DEFAULT_M3U_SETTINGS = { daysOfWeek: ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'], times: ['06:00', '18:00'], timeZone: 'America/New_York' };

function loadM3uSettings() {
  if (!fs.existsSync(M3U_SETTINGS_FILE)) return { ...DEFAULT_M3U_SETTINGS };
  try {
    const raw = JSON.parse(fs.readFileSync(M3U_SETTINGS_FILE, 'utf8'));
    return {
      daysOfWeek: Array.isArray(raw.daysOfWeek) && raw.daysOfWeek.length > 0 ? raw.daysOfWeek : DEFAULT_M3U_SETTINGS.daysOfWeek,
      times: Array.isArray(raw.times) && raw.times.length > 0 ? raw.times : DEFAULT_M3U_SETTINGS.times,
      timeZone: raw.timeZone || DEFAULT_M3U_SETTINGS.timeZone
    };
  } catch (err) {
    console.error('[Storage] Error loading m3u-settings.json, using defaults:', err.message);
    return { ...DEFAULT_M3U_SETTINGS };
  }
}

function saveM3uSettings(settings) {
  try {
    fs.writeFileSync(M3U_SETTINGS_FILE, JSON.stringify(settings, null, 2), 'utf8');
  } catch (err) {
    console.error('[Storage] Failed to save m3u-settings.json:', err.message);
  }
}

let m3uSettings = loadM3uSettings();

// Admin-controlled EPGShare01 source pool - empty by default. This is NOT
// a global "override all EPG" switch: enabling a source here only makes
// its programme data available and keeps it warm in cache (see
// epgshare01.js) - a user still has to separately choose, per channel, to
// actually use one of these sources in place of their provider's own EPG
// (that per-channel picker is a separate, not-yet-built piece of UI).
// Fetching and parsing even one extra XMLTV feed is real, avoidable load,
// so the pool starts empty until an admin explicitly enables sources.
// Shares the M3U refresh schedule above rather than getting its own - one
// schedule panel on the admin page, not two to keep in sync.
const DEFAULT_EPGSHARE_SETTINGS = { enabledSources: [] };

function loadEpgShareSettings() {
  if (!fs.existsSync(EPGSHARE_SETTINGS_FILE)) return { ...DEFAULT_EPGSHARE_SETTINGS };
  try {
    const raw = JSON.parse(fs.readFileSync(EPGSHARE_SETTINGS_FILE, 'utf8'));
    // Re-validated against the known filename convention on every load
    // (not just on save) - epgshare01.refreshEnabledSources builds fetch
    // URLs directly from this list, so a corrupted/hand-edited settings
    // file should never be able to smuggle an arbitrary URL in.
    const enabledSources = Array.isArray(raw.enabledSources)
      ? raw.enabledSources.filter(f => epgshare.isKnownSourceFile(f))
      : [];
    return { enabledSources };
  } catch (err) {
    console.error('[Storage] Error loading epgshare-settings.json, using defaults:', err.message);
    return { ...DEFAULT_EPGSHARE_SETTINGS };
  }
}

function saveEpgShareSettings(settings) {
  try {
    fs.writeFileSync(EPGSHARE_SETTINGS_FILE, JSON.stringify(settings, null, 2), 'utf8');
  } catch (err) {
    console.error('[Storage] Failed to save epgshare-settings.json:', err.message);
  }
}

let epgShareSettings = loadEpgShareSettings();

// Admin-curated presets - a named, iconed bundle of the exact payload
// exportProviderSettings() already produces client-side (index.html):
// category/channel NAMES rather than raw ids (so it's portable across
// accounts the same way a user-to-user export is), never credentials.
// Applied either from the dashboard's Presets/Configs panel (existing
// account) or from the setup wizard's preset step (new account, resolved
// against the connection just tested/imported) - see importProviderSettings
// and applyWizardPreset in index.html.
const ALLOWED_PRESET_ICONS = new Set([
  // Sports & achievement
  'trophy', 'medal', 'award', 'ranking-star', 'futbol', 'basketball', 'baseball', 'football',
  'volleyball', 'hockey-puck', 'golf-ball-tee', 'bowling-ball', 'table-tennis-paddle-ball',
  'dumbbell', 'hand-fist', 'person-running', 'person-biking', 'person-swimming', 'person-skiing',
  'person-snowboarding', 'stopwatch', 'flag-checkered',
  // Media & entertainment
  'tv', 'film', 'video', 'music', 'headphones', 'microphone', 'camera', 'clapperboard',
  'gamepad', 'dice', 'chess', 'chess-king', 'puzzle-piece', 'ticket', 'masks-theater',
  'record-vinyl', 'compact-disc',
  // General objects & symbols
  'star', 'heart', 'fire', 'bolt', 'crown', 'gem', 'shield', 'shield-halved', 'gift', 'key',
  'lock', 'lock-open', 'bell', 'bookmark', 'tag', 'tags', 'box', 'briefcase', 'suitcase',
  'thumbs-up', 'hand', 'peace', 'infinity', 'atom', 'certificate', 'flag', 'circle', 'square',
  'compass',
  // Nature & weather
  'globe', 'sun', 'moon', 'cloud', 'snowflake', 'umbrella', 'mountain', 'tree', 'leaf',
  'water', 'wind', 'cloud-sun', 'cloud-rain', 'temperature-high',
  // Transportation
  'car', 'truck', 'motorcycle', 'bicycle', 'plane', 'ship', 'train', 'rocket', 'bus',
  'van-shuttle', 'anchor',
  // Places & buildings
  'map', 'map-pin', 'location-dot', 'clock', 'calendar', 'calendar-days', 'building', 'city',
  'home', 'landmark', 'university', 'hospital', 'store', 'industry', 'warehouse',
  // Tech
  'satellite', 'satellite-dish', 'wifi', 'signal', 'microchip', 'server', 'desktop', 'mobile',
  'tablet-screen-button',
  // People
  'users', 'user', 'user-group', 'child', 'hat-cowboy', 'mask',
  // Food & drink
  'pizza-slice', 'burger', 'mug-hot', 'beer-mug-empty', 'wine-glass', 'apple-whole', 'carrot',
  // Animals
  'feather', 'paw', 'dragon', 'dog', 'cat', 'fish', 'horse', 'spider', 'frog', 'kiwi-bird',
  'crow', 'dove'
]);

const PRESET_NAME_MAX_LENGTH = 60;

// Re-validated on every load (not just on save), same reasoning as
// epgShareSettings above - a malformed or hand-edited presets.json (this
// file is meant to be hand-editable/mergeable via git, unlike data/*)
// should have its bad entries silently dropped rather than crash the
// whole store or let bad data reach a client.
function isValidStoredPreset(p) {
  return !!p && typeof p === 'object'
    && typeof p.id === 'string'
    && typeof p.name === 'string'
    && ALLOWED_PRESET_ICONS.has(p.icon)
    && (p.connectionType === 'xtream' || p.connectionType === 'm3u')
    && Array.isArray(p.selectedSports) && p.selectedSports.every(s => typeof s === 'string')
    && typeof p.sportCategories === 'object' && p.sportCategories !== null
    && Object.values(p.sportCategories).every(names => Array.isArray(names) && names.every(n => typeof n === 'string'))
    && typeof p.epgOverrides === 'object' && p.epgOverrides !== null
    && Object.values(p.epgOverrides).every(v => typeof v === 'string')
    && (p.epgSources === undefined || (Array.isArray(p.epgSources) && p.epgSources.every(f => typeof f === 'string')));
}

function loadPresets(file, label) {
  if (!fs.existsSync(file)) return [];
  try {
    const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
    return Array.isArray(raw)
      ? raw.filter(isValidStoredPreset).map(p => ({ ...p, epgSources: p.epgSources || [] }))
      : [];
  } catch (err) {
    console.error(`[Storage] Error loading ${label}, using an empty list:`, err.message);
    return [];
  }
}

// Stock presets are never written at runtime - only shipped via the repo -
// so there is deliberately no saveStockPresets. Local presets are this
// instance's own, so they get the usual load/save pair.
function loadStockPresets() {
  return loadPresets(PRESETS_FILE, 'presets.json');
}

function loadLocalPresets() {
  return loadPresets(LOCAL_PRESETS_FILE, 'local-presets.json');
}

function saveLocalPresets(list) {
  try {
    fs.writeFileSync(LOCAL_PRESETS_FILE, JSON.stringify(list, null, 2), 'utf8');
  } catch (err) {
    console.error('[Storage] Failed to save local-presets.json:', err.message);
  }
}

// One-time recovery path for instances that predate the stock/local split
// above. Before that split, admin-created presets were appended directly
// into PRESETS_FILE - a git-tracked file - so updating past this point
// requires that local drift be moved out of git's way first (see the
// README's upgrade note), which backs it up here instead of discarding it.
// On first boot after that, anything in the backup that isn't already
// accounted for as stock or local content is exactly that drift, and gets
// folded into local-presets.json where it belongs from now on. The backup
// is then deleted, so this only ever does something once per instance -
// nothing ever writes here again, so there's nothing left to migrate on
// any later update.
const LEGACY_PRESETS_BACKUP_FILE = path.join(DATA_DIR, 'presets-legacy-backup.json');

function migrateLegacyLocalPresets() {
  if (!fs.existsSync(LEGACY_PRESETS_BACKUP_FILE)) return;
  const backedUp = loadPresets(LEGACY_PRESETS_BACKUP_FILE, 'presets-legacy-backup.json');
  const knownIds = new Set([...stockPresets, ...localPresets].map(p => p.id));
  const recovered = backedUp.filter(p => !knownIds.has(p.id));
  if (recovered.length > 0) {
    localPresets = [...localPresets, ...recovered];
    saveLocalPresets(localPresets);
    console.log(`[Storage] Recovered ${recovered.length} preset(s) created before the stock/local split into local-presets.json.`);
  }
  try {
    fs.unlinkSync(LEGACY_PRESETS_BACKUP_FILE);
  } catch (err) {
    console.error('[Storage] Failed to remove presets-legacy-backup.json after migration:', err.message);
  }
}

let stockPresets = loadStockPresets();
let localPresets = loadLocalPresets();
migrateLegacyLocalPresets();

// The combined view every read site actually serves - callers never need to
// care which file a given preset came from.
function getAllPresets() {
  return [...stockPresets, ...localPresets];
}

// Gates a preset from reaching users (via /api/presets and
// /api/presets/public) until an admin has actually looked at it - a preset
// authored through the admin panel's own create flow (see
// /api/admin/presets/create) already gets that look right there via the
// missing-EPG-source prompt, but presets can also arrive by shipping an
// updated presets.json in a code update, with no admin interaction at all.
// Without a gate, a preset like that goes live for every account the
// instant the update is deployed, EPG overrides included - and if those
// overrides need an EPGShare01 source this admin hasn't enabled, they just
// silently resolve to nothing.
//
// Keyed by preset id -> a content hash, not just a plain "seen it" flag, so
// a later edit to an already-published preset (say, a future update adds
// more EPG overrides to one that's already live) drops it back into
// pending too - editing a live preset is exactly as capable of introducing
// an unreviewed EPG dependency as adding a brand new one. This also means
// there is deliberately no separate "pending" field to remember to set on
// a preset when authoring one by hand - a preset becomes pending purely by
// its id+content not already being in this file, so it can't be forgotten.
const REVIEWED_PRESETS_FILE = path.join(DATA_DIR, 'reviewed-presets.json');

// Object order doesn't reflect anything meaningful (insertion order across
// however presets.json happens to be edited/merged), and JSON.stringify's
// key order for JS objects generally follows insertion order - so without
// sorting, an edit that's a no-op for hashing purposes (a git merge that
// reorders sportCategories keys, for instance) would still flip a preset
// back to pending. Array order is left alone: those lists (selectedSports,
// category names, epgSources) come straight from a real export/authoring
// action, and reordering happens to matter for at least one of them
// downstream, so array order is treated as meaningful content.
function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + stableStringify(value[k])).join(',')}}`;
  }
  return JSON.stringify(value);
}

function hashPresetContent(preset) {
  const content = {
    name: preset.name,
    icon: preset.icon,
    connectionType: preset.connectionType,
    selectedSports: preset.selectedSports,
    sportCategories: preset.sportCategories,
    epgOverrides: preset.epgOverrides,
    epgSources: preset.epgSources || []
  };
  return crypto.createHash('sha256').update(stableStringify(content)).digest('hex');
}

function loadReviewedPresets() {
  if (!fs.existsSync(REVIEWED_PRESETS_FILE)) return null;
  try {
    const raw = JSON.parse(fs.readFileSync(REVIEWED_PRESETS_FILE, 'utf8'));
    return (raw && typeof raw === 'object' && !Array.isArray(raw)) ? raw : {};
  } catch (err) {
    console.error('[Storage] Error loading reviewed-presets.json, treating as empty:', err.message);
    return {};
  }
}

function saveReviewedPresets(map) {
  try {
    fs.writeFileSync(REVIEWED_PRESETS_FILE, JSON.stringify(map, null, 2), 'utf8');
  } catch (err) {
    console.error('[Storage] Failed to save reviewed-presets.json:', err.message);
  }
}

let reviewedPresets = loadReviewedPresets();
if (reviewedPresets === null) {
  // No review file yet - either a fresh install, or an upgrade from before
  // this gate existed. Either way, whatever's already sitting in
  // presets.json predates the concept of review and may already be live
  // for users, so it's grandfathered in as reviewed rather than yanked out
  // from under them. Only presets added or edited from this point on need
  // an actual look.
  reviewedPresets = {};
  getAllPresets().forEach(p => { reviewedPresets[p.id] = hashPresetContent(p); });
  saveReviewedPresets(reviewedPresets);
}

function isPresetReviewed(preset) {
  return reviewedPresets[preset.id] === hashPresetContent(preset);
}

function markPresetReviewed(preset) {
  reviewedPresets = { ...reviewedPresets, [preset.id]: hashPresetContent(preset) };
  saveReviewedPresets(reviewedPresets);
}

function computeMissingSourcesForPreset(preset) {
  const validEpgSources = Array.isArray(preset.epgSources) ? preset.epgSources.filter(f => epgshare.isKnownSourceFile(f)) : [];
  return validEpgSources.filter(f => !epgShareSettings.enabledSources.includes(f));
}

// App-managed admin credentials - lets a fresh install set an admin
// password through the UI itself, rather than requiring a manual
// docker-compose.yml/.env edit and restart before the admin panel is
// usable at all. Password is bcrypt-hashed, same as regular user
// accounts - being local-only config doesn't mean it's fine to store in
// plaintext. ADMIN_USERNAME/ADMIN_PASSWORD env vars, if set, always take
// priority over this file (see isValidAdmin below) - this preserves
// exact existing behavior for any deployment that already configured
// those, so upgrading to this version changes nothing for them.
function loadAdminConfig() {
  if (!fs.existsSync(ADMIN_CONFIG_FILE)) return null;
  try {
    const raw = JSON.parse(fs.readFileSync(ADMIN_CONFIG_FILE, 'utf8'));
    if (!raw.username || !raw.passwordHash) return null;
    return raw;
  } catch (err) {
    console.error('[Storage] Error loading admin-config.json:', err.message);
    return null;
  }
}

function saveAdminConfig(config) {
  try {
    fs.writeFileSync(ADMIN_CONFIG_FILE, JSON.stringify(config, null, 2), 'utf8');
  } catch (err) {
    console.error('[Storage] Failed to save admin-config.json:', err.message);
  }
}

let adminConfig = loadAdminConfig();

const ESPN_ENDPOINTS = {
  NBA: 'https://site.api.espn.com/apis/site/v2/sports/basketball/nba/scoreboard',
  NFL: 'https://site.api.espn.com/apis/site/v2/sports/football/nfl/scoreboard',
  MLB: 'https://site.api.espn.com/apis/site/v2/sports/baseball/mlb/scoreboard',
  NHL: 'https://site.api.espn.com/apis/site/v2/sports/hockey/nhl/scoreboard',
  WNBA: 'https://site.api.espn.com/apis/site/v2/sports/basketball/wnba/scoreboard',
  NCAAMB: 'https://site.api.espn.com/apis/site/v2/sports/basketball/mens-college-basketball/scoreboard',
  NCAAWB: 'https://site.api.espn.com/apis/site/v2/sports/basketball/womens-college-basketball/scoreboard',
  NCAAFB: 'https://site.api.espn.com/apis/site/v2/sports/football/college-football/scoreboard',
  EPL: 'https://site.api.espn.com/apis/site/v2/sports/soccer/eng.1/scoreboard',
  MLS: 'https://site.api.espn.com/apis/site/v2/sports/soccer/usa.1/scoreboard',
  LALIGA: 'https://site.api.espn.com/apis/site/v2/sports/soccer/esp.1/scoreboard',
  WORLDCUP: 'https://site.api.espn.com/apis/site/v2/sports/soccer/fifa.world/scoreboard',
  UFC: 'https://site.api.espn.com/apis/site/v2/sports/mma/ufc/scoreboard',
  AFL: 'https://site.api.espn.com/apis/site/v2/sports/australian-football/afl/scoreboard',
  // Rugby leagues use ESPN's own numeric league id in place of a slug
  // (confirmed live - rugby has no single-table "one league" the way
  // EPL/MLS do, so each competition needs its own id here, the same as
  // any other league in this map).
  URC: 'https://site.api.espn.com/apis/site/v2/sports/rugby/270557/scoreboard',
  PREM: 'https://site.api.espn.com/apis/site/v2/sports/rugby/267979/scoreboard',
  // Cricket, like rugby, has no single "the league" slug - ESPN keys IPL
  // by its own numeric league id (confirmed live against real data: event
  // shape carries the same homeAway/team/logo/color fields every other
  // sport here already relies on, so no special-casing was needed
  // downstream in fetchTodayGames).
  IPL: 'https://site.api.espn.com/apis/site/v2/sports/cricket/8048/scoreboard'
};

// UFC events, unlike every other sport here, don't map to a single
// matchup - one event is a whole card of many individual fights. This
// endpoint gives the main event's own numeric id specifically, needed to
// fetch the Core API event endpoint that identifies which fight on the
// card is actually the main event (matchNumber: 1) - the scoreboard
// endpoint above doesn't expose that field at all.
const ESPN_CORE_EVENT_ENDPOINTS = {
  UFC: 'https://sports.core.api.espn.com/v2/sports/mma/leagues/ufc/events'
};

// NCAA sports have far more teams than the pro leagues, and ESPN's scoreboard
// endpoint silently truncates results unless a broad 'groups' + high 'limit'
// is passed. The pro leagues and single-table soccer leagues don't need this.
const NCAA_SPORTS = new Set(['NCAAMB', 'NCAAWB', 'NCAAFB']);

const ESPN_LEAGUES = {
  NBA: 'nba',
  NFL: 'nfl',
  MLB: 'mlb',
  NHL: 'nhl',
  WNBA: 'wnba',
  NCAAMB: 'mens-college-basketball',
  NCAAWB: 'womens-college-basketball',
  NCAAFB: 'college-football',
  EPL: 'eng.1',
  MLS: 'usa.1',
  LALIGA: 'esp.1',
  WORLDCUP: 'fifa.world',
  UFC: 'ufc',
  AFL: 'afl',
  URC: '270557',
  PREM: '267979',
  IPL: '8048'
};

// The "Upcoming Schedule" placeholder's background image, one per sport
// (several sports share the same graphic, e.g. NBA and NCAAMB both use
// basketball.svg). These are served directly as raw SVG bytes rather than
// base64-embedded into a wrapping SVG, since there's no compositing
// needed here - just static art.
const SCHEDULE_BACKGROUND_FILES = {
  MLB: 'baseball.svg',
  NBA: 'basketball.svg',
  NCAAMB: 'basketball.svg',
  NFL: 'football.svg',
  NCAAFB: 'football.svg',
  NHL: 'hockey.svg',
  WNBA: 'womensbball.svg',
  NCAAWB: 'womensbball.svg',
  EPL: 'soccer.svg',
  MLS: 'soccer.svg',
  LALIGA: 'soccer.svg',
  WORLDCUP: 'soccer.svg',
  AFL: 'afl.svg',
  // Every rugby league shares rugby.svg - add any future rugby league here
  // pointing at the same file rather than giving it its own asset.
  URC: 'rugby.svg',
  PREM: 'rugby.svg',
  IPL: 'cricket.svg'
};

const scheduleBackgroundCache = {};
function getScheduleBackgroundBuffer(sportKey) {
  const filename = SCHEDULE_BACKGROUND_FILES[sportKey];
  if (!filename) return null;
  if (scheduleBackgroundCache[filename]) return scheduleBackgroundCache[filename];
  try {
    const filePath = path.join(__dirname, 'assets', 'background', 'schedule', filename);
    const buffer = fs.readFileSync(filePath);
    scheduleBackgroundCache[filename] = buffer;
    return buffer;
  } catch (err) {
    console.error(`[Schedule Background] Failed to load ${filename}:`, err.message);
    return null;
  }
}

// The landscape background's decorative overlay is spliced directly into
// the outer SVG document as native markup, rather than embedded as a
// nested SVG-in-SVG via a base64 <image> data URI. Nesting a full vector
// document that way turned out not to render at all - a much less
// universally-supported technique than nesting a raster image, unlike the
// team logos below (which really are raster PNGs, so <image> works fine
// for those). This function parses the overlay file's <defs> and drawable
// elements once, prefixes its gradient IDs uniquely to avoid any future
// collision with other defs in this document, and caches the result.
let backgroundOverlayInline = null;
// Shared by every overlay that gets spliced directly into an outer SVG
// document as native markup, rather than embedded as a nested SVG-in-SVG
// via a base64 <image> data URI - nesting a full vector document that way
// turned out not to render at all (confirmed with the landscape
// background's overlay), a much less universally-supported technique than
// nesting a raster image. Parses the file's <defs> and drawable elements
// once, prefixes its gradient/filter ids uniquely (using the caller's own
// prefix, so two different overlay files spliced into two different
// routes can never collide even if their internal ids happen to match),
// and caches the result per file path.
const inlineSvgOverlayCache = {};
function getInlineSvgOverlay(filePath, idPrefix) {
  if (inlineSvgOverlayCache[filePath]) return inlineSvgOverlayCache[filePath];
  try {
    const content = fs.readFileSync(filePath, 'utf8');

    const defsMatch = content.match(/<defs>([\s\S]*?)<\/defs>/);
    let defs = defsMatch ? defsMatch[1] : '';
    let markup = defsMatch ? content.slice(defsMatch.index + defsMatch[0].length) : content;
    markup = markup.replace(/<\/?svg[^>]*>/g, '').trim();

    // Prefix every id="..." this file defines, and every url(#...)
    // reference to it, so it can never collide with ids elsewhere in the
    // outer document this gets spliced into.
    const ids = [...defs.matchAll(/id="([^"]+)"/g)].map(m => m[1]);
    ids.forEach(id => {
      const prefixed = `${idPrefix}-${id}`;
      defs = defs.split(`id="${id}"`).join(`id="${prefixed}"`);
      defs = defs.split(`url(#${id})`).join(`url(#${prefixed})`);
      markup = markup.split(`url(#${id})`).join(`url(#${prefixed})`);
    });

    const result = { defs, markup };
    inlineSvgOverlayCache[filePath] = result;
    return result;
  } catch (err) {
    console.error(`[SVG Overlay] Failed to load ${filePath}:`, err.message);
    return { defs: '', markup: '' };
  }
}

// Replaces every fill="..." within a named group's subtree with a new
// color - the fill can live on a child element deeper in the subtree
// (confirmed directly - the group wrapper itself often has no fill of
// its own, only its inner path does, and a child's own explicit fill
// always wins over anything set on the parent), so this searches the
// whole subtree rather than assuming the fill sits on the group itself.
function recolorSvgGroup(markup, groupId, newColor) {
  const pattern = new RegExp(`(<g id="${groupId}"[^>]*>)([\\s\\S]*?)(</g>)`);
  const match = markup.match(pattern);
  if (!match) return markup;
  const recoloredInner = match[2].replace(/fill="[^"]*"/g, `fill="${newColor}"`);
  return markup.slice(0, match.index) + match[1] + recoloredInner + match[3] + markup.slice(match.index + match[0].length);
}

// display="none" on the group itself correctly cascades to every child
// (confirmed - unlike fill, which only inherits when a child doesn't
// already specify its own), so this only needs to touch the group's own
// opening tag, not search its subtree.
function hideSvgGroup(markup, groupId) {
  const pattern = new RegExp(`<g id="${groupId}"([^>]*)>`);
  return markup.replace(pattern, `<g id="${groupId}"$1 display="none">`);
}

// Replaces an entire marker group (including its contents) with real,
// dynamic markup - unlike hideSvgGroup, which only hides a marker in
// place, this is for cases where the real content needs to render at
// that EXACT position in the document's layer order, not just appended
// at the very end (which would incorrectly place it on top of whatever
// layers come after the marker in the template, like the UFC poster's
// logo/plaque layer that must stay on top of the fighter images).
function replaceSvgGroup(markup, groupId, replacement) {
  const pattern = new RegExp(`<g id="${groupId}"[^>]*>[\\s\\S]*?</g>`);
  return markup.replace(pattern, replacement);
}

// Extracts a named marker group's bounding box for placement purposes -
// e.g. a "home_logo" marker rect defines exactly where and how large to
// place the real, dynamic logo image instead. Looks for the first
// x/y/width/height on any element within the group's subtree.
function getSvgGroupBounds(markup, groupId) {
  const pattern = new RegExp(`<g id="${groupId}"[^>]*>([\\s\\S]*?)</g>`);
  const match = markup.match(pattern);
  if (!match) return null;
  const inner = match[1];
  const x = inner.match(/x="([^"]+)"/);
  const y = inner.match(/y="([^"]+)"/);
  const width = inner.match(/width="([^"]+)"/);
  const height = inner.match(/height="([^"]+)"/);
  if (!x || !y || !width || !height) return null;
  return { x: parseFloat(x[1]), y: parseFloat(y[1]), width: parseFloat(width[1]), height: parseFloat(height[1]) };
}

// Finds a top-level <g id="groupId">...</g> by counting nested <g> depth,
// rather than assuming the first </g> is the match like getSvgGroupBounds/
// replaceSvgGroup do - needed for the UFC template's Layer_1, which nests
// several <g> elements of its own (the hex-pattern group), so a naive
// non-greedy match would close early on one of those instead of the
// layer's real closing tag.
function findSvgGroupRange(markup, groupId) {
  const openMatch = markup.match(new RegExp(`<g id="${groupId}"[^>]*>`));
  if (!openMatch) return null;
  const contentStart = openMatch.index + openMatch[0].length;
  const tagPattern = /<g[\s>]|<\/g>/g;
  tagPattern.lastIndex = contentStart;
  let depth = 1;
  let m;
  while ((m = tagPattern.exec(markup))) {
    if (m[0] === '</g>') {
      depth--;
      if (depth === 0) return { closeStart: m.index };
    } else {
      depth++;
    }
  }
  return null;
}

// Inserts markup as the LAST child of a named group, i.e. rendered on top
// of everything else already in that group - used to layer the UFC
// poster's fighter images above its Layer_1 background/border art.
function appendToSvgGroup(markup, groupId, insertion) {
  const range = findSvgGroupRange(markup, groupId);
  if (!range) return markup;
  return markup.slice(0, range.closeStart) + insertion + markup.slice(range.closeStart);
}

function getBackgroundOverlayInline() {
  const filePath = path.join(__dirname, 'assets', 'background', 'overlay_background.svg');
  return getInlineSvgOverlay(filePath, 'bg-overlay');
}

// For the standard (non-ESPN-provided) team logo fallback URL, most sports
// use their own league slug as the CDN folder, but ESPN buckets ALL soccer
// teams under the literal folder 'soccer' regardless of which league they
// play in - so eng.1/usa.1/esp.1/fifa.world all need this override.
const TEAM_LOGO_BUCKET_OVERRIDES = {
  EPL: 'soccer',
  MLS: 'soccer',
  LALIGA: 'soccer',
  WORLDCUP: 'soccer',
  // Confirmed live for both football and men's basketball - ESPN buckets
  // ALL NCAA team logos under the literal folder 'ncaa', not each sport's
  // own league slug (e.g. NOT 'college-football' or
  // 'mens-college-basketball', which is what the fallback would have
  // used without this override).
  NCAAFB: 'ncaa',
  NCAAMB: 'ncaa',
  NCAAWB: 'ncaa',
  // Confirmed live - ESPN buckets ALL rugby team logos under
  // 'rugby/teams' regardless of competition (not a per-competition
  // folder, and not just 'rugby' either).
  URC: 'rugby/teams',
  PREM: 'rugby/teams',
  // AFL needs no override - ESPN_LEAGUES.AFL ('afl') already matches its
  // real logo bucket folder.
  // Confirmed live - ESPN buckets ALL cricket team logos under the literal
  // folder 'cricket', not the numeric league id ('8048') ESPN_LEAGUES.IPL
  // uses for the scoreboard endpoint itself.
  IPL: 'cricket'
};

function getTeamLogoBucket(sportKey) {
  return TEAM_LOGO_BUCKET_OVERRIDES[sportKey] || ESPN_LEAGUES[sportKey] || 'mlb';
}

// Friendly names for sports whose internal key isn't already a clean label.
// Anything not listed here just displays as its own key (e.g. NBA, MLB).
const SPORT_DISPLAY_NAMES = {
  NCAAMB: 'College Basketball (Mens)',
  NCAAWB: 'College Basketball (Womens)',
  NCAAFB: 'College Football',
  EPL: 'Premier League',
  MLS: 'MLS',
  LALIGA: 'La Liga',
  WORLDCUP: 'FIFA World Cup',
  UFC: 'UFC',
  URC: 'United Rugby Championship',
  PREM: 'Premiership Rugby',
  IPL: 'Indian Premier League'
};

function getSportDisplayName(sportKey) {
  const upper = String(sportKey || '').toUpperCase();
  return SPORT_DISPLAY_NAMES[upper] || upper;
}

async function getBase64Image(url) {
  try {
    const response = await axios.get(url, {
      responseType: 'arraybuffer',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
        'Referer': 'https://www.espn.com/'
      },
      timeout: 5000
    });
    const contentType = response.headers['content-type'] || 'image/png';
    const base64 = Buffer.from(response.data, 'binary').toString('base64');
    return `data:${contentType};base64,${base64}`;
  } catch (err) {
    console.error(`[ImageLoader] Failed to fetch image: ${url}. Error: ${err.message}`);
    return null;
  }
}

// Tries each URL in order, returning the first one that successfully loads.
// Used for the scoreboard-logo -> standard-logo fallback chain.
async function getBase64ImageWithFallback(urls) {
  for (const url of urls) {
    if (!url) continue;
    const data = await getBase64Image(url);
    if (data) return data;
  }
  return null;
}

// PNG format: 8-byte signature, then an IHDR chunk (4-byte length, 4-byte
// type "IHDR", then width/height as 4-byte big-endian ints immediately
// after) - simple, well-defined, no library needed just to read this.
function getPngDimensions(buffer) {
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  if (buffer.length < 24 || !buffer.slice(0, 8).equals(signature)) return null;
  return { width: buffer.readUInt32BE(16), height: buffer.readUInt32BE(20) };
}

// A separate function from getBase64Image, deliberately not a change to
// it - that function is used by every other poster/logo route in the app,
// and this one specifically needs access to the raw buffer (to read real
// pixel dimensions from) before it gets base64-encoded and discarded.
// Needed for the UFC poster's fighter images, which render at their own
// true native resolution rather than being fit into a fixed marker box -
// see the poster route itself for why that needs real dimensions in hand
// rather than relying on the SVG renderer to infer them implicitly.
async function getBase64ImageWithDimensions(url) {
  try {
    const response = await axios.get(url, {
      responseType: 'arraybuffer',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
        'Referer': 'https://www.espn.com/'
      },
      timeout: 5000
    });
    const contentType = response.headers['content-type'] || 'image/png';
    const buffer = Buffer.from(response.data, 'binary');
    const dimensions = getPngDimensions(buffer);
    if (!dimensions) return null;
    const base64 = buffer.toString('base64');
    return { dataUri: `data:${contentType};base64,${base64}`, width: dimensions.width, height: dimensions.height };
  } catch (err) {
    console.error(`[ImageLoader] Failed to fetch image with dimensions: ${url}. Error: ${err.message}`);
    return null;
  }
}

// Finds the tightest bounding box of non-transparent pixels in an RGBA
// PNG - needed because the real UFC league logo pulled from ESPN's CDN is
// a 500x500 canvas where the actual wordmark only occupies its vertical
// center (large transparent margins above/below), so positioning/scaling
// off the raw canvas bounds (like getPngDimensions does) places the
// visible logo well below - and narrower than - where it's meant to sit.
// Only PNGs with an alpha channel can have this kind of padding; anything
// else (a plain RGB/greyscale image, no transparency) has nothing to
// trim, so this returns its full bounds untouched.
function getPngContentBounds(buffer) {
  const dimensions = getPngDimensions(buffer);
  if (!dimensions) return null;
  const fullBounds = { x: 0, y: 0, width: dimensions.width, height: dimensions.height };

  let offset = 8;
  let bitDepth, colorType;
  const idatChunks = [];
  while (offset < buffer.length) {
    const len = buffer.readUInt32BE(offset);
    const type = buffer.toString('ascii', offset + 4, offset + 8);
    const data = buffer.slice(offset + 8, offset + 8 + len);
    if (type === 'IHDR') {
      bitDepth = data.readUInt8(8);
      colorType = data.readUInt8(9);
    } else if (type === 'IDAT') {
      idatChunks.push(data);
    } else if (type === 'IEND') {
      break;
    }
    offset += 8 + len + 4;
  }

  // Only color types 4 (greyscale+alpha) and 6 (RGBA) carry a per-pixel
  // alpha channel; anything else is fully opaque with nothing to trim.
  // Interlaced/non-8-bit PNGs aren't worth the extra decoding complexity
  // for what's just a positioning nicety, so those fall back untrimmed too.
  if (bitDepth !== 8 || (colorType !== 4 && colorType !== 6)) return fullBounds;

  try {
    const { width, height } = dimensions;
    const channels = colorType === 6 ? 4 : 2;
    const stride = width * channels;
    const raw = zlib.inflateSync(Buffer.concat(idatChunks));
    const out = Buffer.alloc(height * stride);
    let rawOffset = 0;
    for (let y = 0; y < height; y++) {
      const filterType = raw[rawOffset]; rawOffset++;
      const rowStart = y * stride;
      const prevRowStart = (y - 1) * stride;
      for (let x = 0; x < stride; x++) {
        const rawByte = raw[rawOffset + x];
        const a = x >= channels ? out[rowStart + x - channels] : 0;
        const b = y > 0 ? out[prevRowStart + x] : 0;
        const c = (y > 0 && x >= channels) ? out[prevRowStart + x - channels] : 0;
        let val;
        switch (filterType) {
          case 0: val = rawByte; break;
          case 1: val = rawByte + a; break;
          case 2: val = rawByte + b; break;
          case 3: val = rawByte + Math.floor((a + b) / 2); break;
          case 4: {
            const p = a + b - c;
            const pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c);
            val = rawByte + ((pa <= pb && pa <= pc) ? a : (pb <= pc ? b : c));
            break;
          }
          default: val = rawByte;
        }
        out[rowStart + x] = val & 0xFF;
      }
      rawOffset += stride;
    }

    let minX = width, maxX = -1, minY = -1, maxY = -1;
    for (let y = 0; y < height; y++) {
      for (let x = 0; x < width; x++) {
        const alpha = out[y * stride + x * channels + (channels - 1)];
        if (alpha > 10) {
          if (minY === -1) minY = y;
          maxY = y;
          if (x < minX) minX = x;
          if (x > maxX) maxX = x;
        }
      }
    }
    if (minY === -1) return fullBounds;
    return { x: minX, y: minY, width: maxX - minX + 1, height: maxY - minY + 1 };
  } catch (err) {
    console.error(`[ImageLoader] Failed to compute PNG content bounds:`, err.message);
    return fullBounds;
  }
}

// Same fetch as getBase64ImageWithDimensions, but also returns the image's
// visible content bounding box (see getPngContentBounds) - needed for the
// UFC poster's league logo, which must be sized/positioned by its actual
// visible artwork, not the padded canvas ESPN serves it on.
async function getBase64ImageWithContentBounds(url) {
  try {
    const response = await axios.get(url, {
      responseType: 'arraybuffer',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
        'Referer': 'https://www.espn.com/'
      },
      timeout: 5000
    });
    const contentType = response.headers['content-type'] || 'image/png';
    const buffer = Buffer.from(response.data, 'binary');
    const dimensions = getPngDimensions(buffer);
    if (!dimensions) return null;
    const contentBounds = getPngContentBounds(buffer);
    const base64 = buffer.toString('base64');
    return {
      dataUri: `data:${contentType};base64,${base64}`,
      width: dimensions.width,
      height: dimensions.height,
      contentBounds
    };
  } catch (err) {
    console.error(`[ImageLoader] Failed to fetch image with content bounds: ${url}. Error: ${err.message}`);
    return null;
  }
}

function escapeXml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

// Splits a name into two roughly-balanced lines at the word boundary
// closest to the middle, so longer team names wrap cleanly instead of
// being squeezed onto one line.
function splitNameForWrap(name) {
  const words = String(name || 'Team').trim().split(/\s+/);
  if (words.length <= 1) return [name || 'Team'];

  let bestIdx = 1;
  let bestDiff = Infinity;
  let cumulative = 0;
  const totalLen = name.length;

  for (let i = 0; i < words.length - 1; i++) {
    cumulative += words[i].length + 1;
    const diff = Math.abs(cumulative - totalLen / 2);
    if (diff < bestDiff) {
      bestDiff = diff;
      bestIdx = i + 1;
    }
  }

  return [words.slice(0, bestIdx).join(' '), words.slice(bestIdx).join(' ')];
}

// Approximate per-character width ratios (relative to font-size) for our
// bold Trebuchet MS/Verdana stack, used to size the poster's time text so
// it reaches a target width through natural font-size scaling rather than
// SVG's textLength attribute, which distorts letterforms to force-fit a
// width. This is an approximation, not exact live text measurement -
// adjust these ratios if real posters render noticeably off-target.
const TIME_CHAR_WIDTH_RATIOS = {
  '0': 0.60, '1': 0.60, '2': 0.60, '3': 0.60, '4': 0.60, '5': 0.60,
  '6': 0.60, '7': 0.60, '8': 0.60, '9': 0.60,
  ':': 0.30, ' ': 0.30,
  'A': 0.68, 'P': 0.62, 'M': 0.85, 'E': 0.60, 'S': 0.60,
  'T': 0.55, 'C': 0.65, 'D': 0.65, 'N': 0.68
};

function estimateTimeFontSize(text, targetWidth) {
  const totalRatio = text.split('').reduce((sum, ch) => {
    return sum + (TIME_CHAR_WIDTH_RATIOS[ch.toUpperCase()] || 0.65);
  }, 0);
  return targetWidth / totalRatio;
}

// Renders a circle with the team's name as text, used in place of the
// team logo image whenever every logo image source fails to load.
function buildLogoFallback(x, y, size, teamName, accentColor, filterAttr = '') {
  const lines = splitNameForWrap(teamName).map(escapeXml);
  const cx = x + size / 2;
  const cy = y + size / 2;
  const r = size / 2;
  const fontSize = Math.round(size * 0.11);
  const lineWidth = Math.round(size * 0.62);
  const lineHeight = fontSize * 1.15;

  const textLines = lines
    .map((line, i) => {
      const offsetIdx = i - (lines.length - 1) / 2;
      const yPos = cy + offsetIdx * lineHeight + fontSize * 0.35;
      return `<text x="${cx}" y="${yPos}" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif" font-size="${fontSize}" font-weight="700" fill="#f8fafc" text-anchor="middle" textLength="${lineWidth}" lengthAdjust="spacingAndGlyphs">${line}</text>`;
    })
    .join('\n      ');

  return `
    <g${filterAttr}>
      <circle cx="${cx}" cy="${cy}" r="${r}" fill="#1e293b" stroke="${accentColor}" stroke-width="4" />
      ${textLines}
    </g>`;
}

function getLocalDateString(timeZone = 'America/New_York') {
  try {
    const formatter = new Intl.DateTimeFormat('en-CA', { timeZone: timeZone || 'America/New_York' });
    return formatter.format(new Date()).replace(/-/g, '');
  } catch (err) {
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const day = String(now.getDate()).padStart(2, '0');
    return `${year}${month}${day}`;
  }
}

function getLocalDateDash(timeZone = 'America/New_York') {
  const dateStr = getLocalDateString(timeZone);
  return `${dateStr.slice(0, 4)}-${dateStr.slice(4, 6)}-${dateStr.slice(6, 8)}`;
}

function formatTeamTime(utcDateStr, timeZone) {
  try {
    const date = new Date(utcDateStr);
    const targetTz = timeZone || 'America/New_York';
    
    const timeFormatter = new Intl.DateTimeFormat('en-US', { timeZone: targetTz, hour: 'numeric', minute: '2-digit', hour12: true });
    const tzFormatter = new Intl.DateTimeFormat('en-US', { timeZone: targetTz, timeZoneName: 'short' });

    const timeStr = timeFormatter.format(date).toLowerCase();
    const tzParts = tzFormatter.formatToParts(date);
    const tzName = tzParts.find(p => p.type === 'timeZoneName')?.value || '';

    return `${timeStr} ${tzName}`;
  } catch (err) {
    return null;
  }
}

function formatDateYYYYMMDD(dateObj, timeZone) {
  try {
    const formatter = new Intl.DateTimeFormat('en-CA', { timeZone: timeZone || 'America/New_York' });
    return formatter.format(dateObj).replace(/-/g, '');
  } catch (err) {
    return '';
  }
}

// Human-readable date (e.g. "August 11, 2026") for the description's
// second line - in the user's configured timezone, same as formatTeamTime,
// so the date and time shown always agree with each other.
function formatReadableDate(utcDateStr, timeZone) {
  try {
    const date = new Date(utcDateStr);
    const formatter = new Intl.DateTimeFormat('en-US', { timeZone: timeZone || 'America/New_York', month: 'long', day: 'numeric', year: 'numeric' });
    return formatter.format(date);
  } catch (err) {
    return null;
  }
}

function formatGameDateLabel(utcDateStr, timeZone) {
  try {
    const date = new Date(utcDateStr);
    const formatter = new Intl.DateTimeFormat('en-US', {
      timeZone: timeZone || 'America/New_York',
      weekday: 'short',
      month: 'short',
      day: 'numeric'
    });
    return formatter.format(date);
  } catch (err) {
    return '';
  }
}

// Looks ahead across a date range (ESPN's scoreboard endpoint only accepts a
// single day or a range, not "next N games" directly) and returns up to
// `limit` upcoming games in chronological order.
async function fetchUpcomingGames(sport, userTimeZone = 'America/New_York', limit = 20) {
  const endpoint = ESPN_ENDPOINTS[sport.toUpperCase()];
  if (!endpoint) return [];

  try {
    const now = new Date();
    const isNcaa = NCAA_SPORTS.has(sport.toUpperCase());
    // NCAA sports have hundreds of teams playing multiple games a week, so a
    // short window still comfortably finds `limit` games - and keeps the
    // query (with groups=50 covering all of Division I) fast and light.
    const lookaheadDays = isNcaa ? 21 : 90;
    const rangeStart = new Date(now.getTime() + 1 * 24 * 60 * 60 * 1000); // start tomorrow, excluding today's games
    const rangeEnd = new Date(now.getTime() + lookaheadDays * 24 * 60 * 60 * 1000);
    const startStr = formatDateYYYYMMDD(rangeStart, userTimeZone);
    const endStr = formatDateYYYYMMDD(rangeEnd, userTimeZone);
    const ncaaParams = isNcaa ? '&groups=50&limit=500' : '';

    const res = await axios.get(`${endpoint}?dates=${startStr}-${endStr}${ncaaParams}`, {
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
      timeout: 8000
    });

    const events = res.data?.events || [];
    const sorted = [...events].sort((a, b) => new Date(a.date) - new Date(b.date));

    return sorted.slice(0, limit).map(event => {
      const competition = event.competitions?.[0] || {};
      const competitors = competition.competitors || [];
      const home = competitors.find(c => c.homeAway === 'home') || {};
      const away = competitors.find(c => c.homeAway === 'away') || {};
      const homeTeam = home.team || {};
      const awayTeam = away.team || {};

      const homeNick = homeTeam.name || homeTeam.shortDisplayName || homeTeam.displayName || 'Home';
      const awayNick = awayTeam.name || awayTeam.shortDisplayName || awayTeam.displayName || 'Away';
      const startTime = formatTeamTime(event.date, userTimeZone) || 'TBD';
      return `${formatGameDateLabel(event.date, userTimeZone)}: ${awayNick} at ${homeNick} - ${startTime}`;
    });
  } catch (err) {
    console.error(`[ESPN] Error fetching upcoming schedule for ${sport}:`, err.message);
    return [];
  }
}

function getUfcPosterTemplateInline() {
  const filePath = path.join(__dirname, 'assets', 'posters', 'ufc_poster_template.svg');
  return getInlineSvgOverlay(filePath, 'ufc-poster');
}

// Registered BEFORE the generic team-based poster route below, since both
// have the same number of path segments (/poster/X/Y/Z.svg) - Express
// matches routes in registration order, so the more specific UFC route
// needs to come first or it would never be reached.
app.get('/poster/ufc/:fighterAId/:fighterBId.svg', async (req, res) => {
  const fighterAName = req.query.home || 'Fighter A';
  const fighterBName = req.query.away || 'Fighter B';
  const gameUtcDate = req.query.date || null;
  const userTz = req.query.tz || 'America/New_York';
  const { fighterAId, fighterBId } = req.params;

  // Fighter A (home) uses their LEFT stance image, Fighter B (away) uses
  // their RIGHT stance image - both rendered 700px tall, scaled
  // proportionately (real pixel dimensions needed up front for that, not
  // left to the SVG renderer to infer implicitly, given known quirks in
  // how some Stremio-ecosystem clients handle SVG), and each horizontally
  // centered within its own half of the poster (home in x:0-300, away in
  // x:300-600), 100px from the top edge.
  const [homeImage, awayImage] = await Promise.all([
    getBase64ImageWithDimensions(`https://a.espncdn.com/i/headshots/mma/players/stance/left/${fighterAId}.png`),
    getBase64ImageWithDimensions(`https://a.espncdn.com/i/headshots/mma/players/stance/right/${fighterBId}.png`)
  ]);

  // Real UFC league logo, same source already confirmed working for the
  // /logo/ufc.svg route - rendered 130px wide, scaled proportionately, so
  // its real pixel dimensions are needed too (not just fit into a fixed
  // box via preserveAspectRatio alone). Its content bounds are needed on
  // top of that: the raw PNG ESPN serves is a 500x500 canvas with the
  // wordmark occupying only its vertical center, so sizing/positioning
  // off the padded canvas (rather than the visible artwork) would put
  // the "top of the logo" well below where it's meant to sit.
  const ufcLogoUrl = await getRealLeagueLogoUrl('UFC');
  const ufcLogoData = ufcLogoUrl ? await getBase64ImageWithContentBounds(ufcLogoUrl) : null;

  const template = getUfcPosterTemplateInline();
  let markup = template.markup;

  const FIGHTER_IMAGE_HEIGHT = 700;
  const FIGHTER_IMAGE_TOP = 100;

  const awayWidth = awayImage ? awayImage.width * (FIGHTER_IMAGE_HEIGHT / awayImage.height) : 0;
  const awayX = 300 + (300 - awayWidth) / 2;
  const awayImageMarkup = awayImage
    ? `<image href="${awayImage.dataUri}" x="${awayX}" y="${FIGHTER_IMAGE_TOP}" width="${awayWidth}" height="${FIGHTER_IMAGE_HEIGHT}" />`
    : buildLogoFallback(450, FIGHTER_IMAGE_TOP, 300, fighterBName, '#c0392b');
  markup = appendToSvgGroup(markup, 'Layer_1', awayImageMarkup);

  const homeWidth = homeImage ? homeImage.width * (FIGHTER_IMAGE_HEIGHT / homeImage.height) : 0;
  const homeX = (300 - homeWidth) / 2;
  const homeImageMarkup = homeImage
    ? `<image href="${homeImage.dataUri}" x="${homeX}" y="${FIGHTER_IMAGE_TOP}" width="${homeWidth}" height="${FIGHTER_IMAGE_HEIGHT}" />`
    : buildLogoFallback(150, FIGHTER_IMAGE_TOP, 300, fighterAName, '#2a2a2a');
  markup = appendToSvgGroup(markup, 'Layer_1', homeImageMarkup);

  const UFC_LOGO_WIDTH = 130;
  const UFC_LOGO_TOP = 21;
  const ufcLogoX = (600 - UFC_LOGO_WIDTH) / 2;
  // A nested <svg> crops the padded source image down to just its content
  // bounds: viewBox positions/sizes the crop window in the source image's
  // own pixel space, while this element's own x/y/width/height place that
  // cropped result on the poster - so the box the browser actually lays
  // out (and that x="..." y="..." positions) is the visible logo itself.
  const ufcLogoMarkup = ufcLogoData
    ? (() => {
        const { x: cx, y: cy, width: cw, height: ch } = ufcLogoData.contentBounds;
        const displayHeight = ch * (UFC_LOGO_WIDTH / cw);
        return `<svg x="${ufcLogoX}" y="${UFC_LOGO_TOP}" width="${UFC_LOGO_WIDTH}" height="${displayHeight}" viewBox="${cx} ${cy} ${cw} ${ch}"><image href="${ufcLogoData.dataUri}" x="0" y="0" width="${ufcLogoData.width}" height="${ufcLogoData.height}" /></svg>`;
      })()
    : `<text x="300" y="${UFC_LOGO_TOP + 40}" font-family="'Trebuchet MS', Verdana, sans-serif" font-size="32" font-weight="800" fill="#ffffff" text-anchor="middle">UFC</text>`;

  // The plaque itself is already fully rendered, visible static art from
  // the template (an unnamed rounded-rect path, part of the "keep 2"
  // group) - not a hidden marker to replace, just real estate to center
  // text on top of. Bounds computed once by parsing the path's own
  // geometry precisely, not eyeballed - confirmed exact: x 47.02-552.98,
  // y 817.29-900.
  const plaqueBounds = { x: 47.02, y: 817.29, width: 505.96, height: 82.71 };
  const timeLine = gameUtcDate ? (formatTeamTime(gameUtcDate, userTz) || 'TBD') : 'FIGHT TIME TBD';
  const timeFontSize = Math.max(24, Math.min(plaqueBounds.height * 0.6, Math.round(estimateTimeFontSize(timeLine, plaqueBounds.width * 0.85))));
  const timeMarkup = `<text x="${plaqueBounds.x + plaqueBounds.width / 2}" y="${plaqueBounds.y + plaqueBounds.height / 2 + timeFontSize * 0.35}" font-family="'Trebuchet MS', Verdana, sans-serif" font-size="${timeFontSize}" font-weight="700" fill="#ffffff" text-anchor="middle" letter-spacing="0.5">${escapeXml(timeLine)}</text>`;

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 600 900" width="600" height="900">
    <defs>${template.defs}</defs>
    ${markup}
    ${timeMarkup}
    ${ufcLogoMarkup}
  </svg>`;

  res.setHeader('Content-Type', 'image/svg+xml');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.send(svg);
});

function getPosterTemplateInline() {
  const filePath = path.join(__dirname, 'assets', 'posters', 'poster_template.svg');
  return getInlineSvgOverlay(filePath, 'poster-template');
}

app.get('/poster/:sport/:homeId/:awayId.svg', async (req, res) => {
  const { sport, homeId, awayId } = req.params;
  const gameUtcDate = req.query.date || null;
  const userTz = req.query.tz || 'America/New_York';
  const homeName = req.query.home || 'Home';
  const awayName = req.query.away || 'Away';
  const sportKey = sport.toUpperCase();
  const league = getTeamLogoBucket(sportKey);
  const theme = SPORT_THEMES[sportKey] || SPORT_THEMES.MLB;

  // Using each team's primary color - alternate color was tried and
  // reverted. Falls back to alternate, then the sport's generic theme
  // color, if a team is missing a primary color.
  const homeColor = req.query.homeColor ? `#${req.query.homeColor}`
    : req.query.homeAltColor ? `#${req.query.homeAltColor}`
    : theme.secondary;
  const awayColor = req.query.awayColor ? `#${req.query.awayColor}`
    : req.query.awayAltColor ? `#${req.query.awayAltColor}`
    : theme.primary;
  const homeAbbr = (req.query.homeAbbr || '').toLowerCase();
  const awayAbbr = (req.query.awayAbbr || '').toLowerCase();

  // Scoreboard-optimized logo first, full standard logo as fallback if the
  // scoreboard variant isn't available. Both are guessed from the sport's
  // usual CDN pattern (bucket/500/{id}.png), which most sports follow -
  // but not all (confirmed live: AFL keys its logos by lowercase
  // abbreviation, not numeric team id, and has no /scoreboard/ variant at
  // all, so both guesses above 404 for it). homeLogoUrl/awayLogoUrl - the
  // exact URL ESPN's own scoreboard data already gave for this team,
  // passed through from fetchTodayGames - is the last resort for exactly
  // that case, so a sport with a non-standard CDN layout still gets its
  // real logo instead of falling all the way back to buildLogoFallback.
  const homeScoreboardUrl = homeAbbr ? `https://a.espncdn.com/i/teamlogos/${league}/500/scoreboard/${homeAbbr}.png` : '';
  const awayScoreboardUrl = awayAbbr ? `https://a.espncdn.com/i/teamlogos/${league}/500/scoreboard/${awayAbbr}.png` : '';
  const homeStandardUrl = `https://a.espncdn.com/i/teamlogos/${league}/500/${homeId}.png`;
  const awayStandardUrl = `https://a.espncdn.com/i/teamlogos/${league}/500/${awayId}.png`;
  const homeLogoUrlParam = req.query.homeLogoUrl || '';
  const awayLogoUrlParam = req.query.awayLogoUrl || '';

  const [homeLogoData, awayLogoData] = await Promise.all([
    getBase64ImageWithFallback([homeScoreboardUrl, homeStandardUrl, homeLogoUrlParam]),
    getBase64ImageWithFallback([awayScoreboardUrl, awayStandardUrl, awayLogoUrlParam])
  ]);

  const template = getPosterTemplateInline();

  // away_logo/home_logo/time are placement markers only, never meant to
  // actually render - their rects just define exactly where and how
  // large to place the real, dynamic content instead. Bounds extracted
  // from the original markup before any modifications, since hiding a
  // group doesn't touch its inner coordinates either way.
  const homeLogoBounds = getSvgGroupBounds(template.markup, 'home_logo');
  const awayLogoBounds = getSvgGroupBounds(template.markup, 'away_logo');
  const timeBounds = getSvgGroupBounds(template.markup, 'time');

  let markup = template.markup;
  markup = recolorSvgGroup(markup, 'away_color', awayColor);
  markup = recolorSvgGroup(markup, 'home_color', homeColor);
  markup = hideSvgGroup(markup, 'away_logo');
  markup = hideSvgGroup(markup, 'home_logo');
  markup = hideSvgGroup(markup, 'time');

  const homeLogoMarkup = homeLogoBounds
    ? (homeLogoData
        ? `<image href="${homeLogoData}" x="${homeLogoBounds.x}" y="${homeLogoBounds.y}" width="${homeLogoBounds.width}" height="${homeLogoBounds.height}" preserveAspectRatio="xMidYMid meet" />`
        : buildLogoFallback(homeLogoBounds.x, homeLogoBounds.y, homeLogoBounds.width, homeName, homeColor))
    : '';
  const awayLogoMarkup = awayLogoBounds
    ? (awayLogoData
        ? `<image href="${awayLogoData}" x="${awayLogoBounds.x}" y="${awayLogoBounds.y}" width="${awayLogoBounds.width}" height="${awayLogoBounds.height}" preserveAspectRatio="xMidYMid meet" />`
        : buildLogoFallback(awayLogoBounds.x, awayLogoBounds.y, awayLogoBounds.width, awayName, awayColor))
    : '';

  const timeLine = gameUtcDate ? (formatTeamTime(gameUtcDate, userTz) || 'TBD') : 'GAME TIME TBD';
  // Target width matches the same "most of the box, not edge to edge"
  // ratio our previous plaque used, scaled to this marker's own width.
  const timeFontSize = timeBounds
    ? Math.max(24, Math.min(timeBounds.height * 0.9, Math.round(estimateTimeFontSize(timeLine, timeBounds.width * 0.85))))
    : 36;
  const timeMarkup = timeBounds
    ? `<text x="${timeBounds.x + timeBounds.width / 2}" y="${timeBounds.y + timeBounds.height / 2 + timeFontSize * 0.35}" font-family="'Trebuchet MS', Verdana, sans-serif" font-size="${timeFontSize}" font-weight="700" fill="#ffffff" text-anchor="middle" letter-spacing="0.5">${timeLine}</text>`
    : '';

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 600 900" width="600" height="900">
    <defs>${template.defs}</defs>
    ${markup}
    ${homeLogoMarkup}
    ${awayLogoMarkup}
    ${timeMarkup}
  </svg>`;

  res.setHeader('Content-Type', 'image/svg+xml');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.send(svg);
});

const SPORT_THEMES = {
  NBA: { primary: '#1D428A', secondary: '#C8102E' },
  WNBA: { primary: '#FF6900', secondary: '#1D1160' },
  NFL: { primary: '#013369', secondary: '#D50A0A' },
  MLB: { primary: '#0C2340', secondary: '#BA0C2F' },
  NHL: { primary: '#000000', secondary: '#41B6E6' },
  NCAAMB: { primary: '#041E42', secondary: '#C8102E' },
  NCAAWB: { primary: '#041E42', secondary: '#C8102E' },
  NCAAFB: { primary: '#013369', secondary: '#D50A0A' },
  EPL: { primary: '#3D195B', secondary: '#00FF85' },
  MLS: { primary: '#0B1F41', secondary: '#EE3524' },
  LALIGA: { primary: '#EE8707', secondary: '#000000' },
  WORLDCUP: { primary: '#326295', secondary: '#C8A951' },
  UFC: { primary: '#000000', secondary: '#D20A0A' },
  AFL: { primary: '#1B1B1B', secondary: '#E4002B' },
  URC: { primary: '#003087', secondary: '#FFB81C' },
  PREM: { primary: '#00205B', secondary: '#C8102E' },
  IPL: { primary: '#004C8C', secondary: '#F6A100' }
};

// Primary accent used for the subtle poster background gradient per sport.
function getSportMotif(sportKey, accentColor) {
  switch (sportKey) {
    case 'NBA':
    case 'WNBA':
    case 'NCAAMB':
    case 'NCAAWB':
      return `
        <g transform="translate(1500,540)" opacity="0.16" stroke="${accentColor}" stroke-width="6" fill="none">
          <circle r="380" />
          <path d="M -380,0 A 380,380 0 0,1 380,0" />
          <path d="M -380,0 A 380,380 0 0,0 380,0" />
          <line x1="0" y1="-380" x2="0" y2="380" />
        </g>`;
    case 'NFL':
    case 'NCAAFB':
      return `
        <g transform="translate(1500,540)" opacity="0.16" stroke="${accentColor}" stroke-width="10">
          <line x1="-420" y1="-300" x2="420" y2="-300" />
          <line x1="-420" y1="-150" x2="420" y2="-150" />
          <line x1="-420" y1="0" x2="420" y2="0" />
          <line x1="-420" y1="150" x2="420" y2="150" />
          <line x1="-420" y1="300" x2="420" y2="300" />
        </g>`;
    case 'MLB':
      return `
        <g transform="translate(1500,540)" opacity="0.18" stroke="${accentColor}" stroke-width="6" fill="none">
          <circle r="380" />
          <path d="M -260,-280 A 380,380 0 0,1 -260,280" stroke-dasharray="14 10" />
          <path d="M 260,-280 A 380,380 0 0,0 260,280" stroke-dasharray="14 10" />
        </g>`;
    case 'NHL':
      return `
        <g transform="translate(1500,540)" opacity="0.18" stroke="${accentColor}" stroke-width="6" fill="none">
          <circle r="380" />
          <circle r="60" fill="${accentColor}" opacity="0.5" stroke="none" />
          <line x1="-460" y1="0" x2="-260" y2="0" stroke-width="14" />
          <line x1="260" y1="0" x2="460" y2="0" stroke-width="14" />
        </g>`;
    default:
      return '';
  }
}

app.get('/landscape/:sport.svg', (req, res) => {
  const sportKey = req.params.sport.toUpperCase();
  const theme = SPORT_THEMES[sportKey] || SPORT_THEMES.MLB;
  const motif = getSportMotif(sportKey, theme.secondary);

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="1920" height="1080">
    <defs>
      <linearGradient id="baseGrad" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="#020617" />
        <stop offset="50%" stop-color="#1e293b" />
        <stop offset="100%" stop-color="#0f172a" />
      </linearGradient>
      <linearGradient id="sweepGrad" x1="100%" y1="0%" x2="35%" y2="100%">
        <stop offset="0%" stop-color="${theme.primary}" stop-opacity="0.85" />
        <stop offset="55%" stop-color="${theme.secondary}" stop-opacity="0.45" />
        <stop offset="100%" stop-color="${theme.secondary}" stop-opacity="0" />
      </linearGradient>
    </defs>
    <rect width="1920" height="1080" fill="url(#baseGrad)" />
    <rect width="1920" height="1080" fill="url(#sweepGrad)" />
    ${motif}
  </svg>`;

  res.setHeader('Content-Type', 'image/svg+xml');
  res.setHeader('Cache-Control', 'public, max-age=86400');
  res.send(svg);
});

// Background art specifically for the "Upcoming Schedule" placeholder
// entry - a static, sport-specific photo served directly (see
// getScheduleBackgroundBuffer for why this isn't SVG-wrapped/base64).
app.get('/background/schedule/:sport.svg', (req, res) => {
  const sportKey = req.params.sport.toUpperCase();
  const buffer = getScheduleBackgroundBuffer(sportKey);
  if (!buffer) {
    res.status(404).send('Not found');
    return;
  }
  res.setHeader('Content-Type', 'image/svg+xml');
  res.setHeader('Cache-Control', 'public, max-age=86400');
  res.send(buffer);
});

// The curved diagonal boundary between the home and away color regions,
// extracted directly from color_ref.png (a 3840x2160 placement guide, not
// shipped with the app) via pixel-by-pixel boundary sampling rather than
// hand-drawn - a dense 109-point polyline, pixel-accurate to the source
// rather than an approximation.
const LANDSCAPE_BOUNDARY_PATH = "M 2393 0 L 2313 20 L 2279 40 L 2256 60 L 2238 80 L 2224 100 L 2213 120 L 2205 140 L 2199 160 L 2193 180 L 2187 200 L 2181 220 L 2175 240 L 2169 260 L 2163 280 L 2156 300 L 2150 320 L 2144 340 L 2138 360 L 2132 380 L 2126 400 L 2120 420 L 2114 440 L 2108 460 L 2102 480 L 2096 500 L 2090 520 L 2083 540 L 2077 560 L 2071 580 L 2065 600 L 2059 620 L 2053 640 L 2047 660 L 2041 680 L 2035 700 L 2029 720 L 2023 740 L 2017 760 L 2010 780 L 2004 800 L 1998 820 L 1992 840 L 1986 860 L 1980 880 L 1974 900 L 1968 920 L 1962 940 L 1956 960 L 1950 980 L 1944 1000 L 1937 1020 L 1931 1040 L 1925 1060 L 1919 1080 L 1913 1100 L 1907 1120 L 1901 1140 L 1895 1160 L 1889 1180 L 1883 1200 L 1877 1220 L 1871 1240 L 1864 1260 L 1858 1280 L 1852 1300 L 1846 1320 L 1840 1340 L 1834 1360 L 1828 1380 L 1822 1400 L 1816 1420 L 1810 1440 L 1804 1460 L 1798 1480 L 1791 1500 L 1785 1520 L 1779 1540 L 1773 1560 L 1767 1580 L 1761 1600 L 1755 1620 L 1749 1640 L 1743 1660 L 1737 1680 L 1731 1700 L 1725 1720 L 1718 1740 L 1712 1760 L 1706 1780 L 1700 1800 L 1694 1820 L 1688 1840 L 1682 1860 L 1676 1880 L 1670 1900 L 1664 1920 L 1658 1940 L 1652 1960 L 1645 1980 L 1640 2000 L 1634 2020 L 1626 2040 L 1615 2060 L 1601 2080 L 1583 2100 L 1560 2120 L 1526 2140 L 1456 2159";

// Registered BEFORE the generic team-based landscape route below, for the
// same routing-order reason as the UFC poster route above.
app.get('/landscape/ufc/:fighterAId/:fighterBId.svg', async (req, res) => {
  const fighterAName = req.query.home || 'Fighter A';
  const fighterBName = req.query.away || 'Fighter B';
  const fighterAFlagUrl = req.query.homeFlagUrl || '';
  const fighterBFlagUrl = req.query.awayFlagUrl || '';
  const { fighterAId, fighterBId } = req.params;

  const [fighterAPhoto, fighterBPhoto, fighterAFlag, fighterBFlag] = await Promise.all([
    getBase64Image(`https://a.espncdn.com/i/headshots/mma/players/full/${fighterAId}.png`),
    getBase64Image(`https://a.espncdn.com/i/headshots/mma/players/full/${fighterBId}.png`),
    fighterAFlagUrl ? getBase64Image(fighterAFlagUrl) : null,
    fighterBFlagUrl ? getBase64Image(fighterBFlagUrl) : null
  ]);

  const fighterAMarkup = fighterAPhoto
    ? `<image href="${fighterAPhoto}" x="360" y="480" width="1200" height="1200" preserveAspectRatio="xMidYMid slice" />`
    : buildLogoFallback(360, 480, 1200, fighterAName, '#c0392b');
  const fighterBMarkup = fighterBPhoto
    ? `<image href="${fighterBPhoto}" x="2280" y="480" width="1200" height="1200" preserveAspectRatio="xMidYMid slice" />`
    : buildLogoFallback(2280, 480, 1200, fighterBName, '#2a2a2a');

  // Fighter A (home) on the left, Fighter B (away) on the right -
  // deliberately flipped from the team-sport version's away-left/home-right
  // convention, per an explicit decision to reconsider what reads more
  // naturally for two fighters rather than just reusing the team layout
  // unchanged. Reuses the exact same diagonal boundary geometry either way.
  // Each region is filled with that fighter's actual country flag, scaled
  // to cover the whole region (preserveAspectRatio="xMidYMid slice"), 
  // rather than a plain team-style color - falls back to a solid theme
  // color if a flag image is unavailable for any reason.
  const fighterAFillMarkup = fighterAFlag
    ? `<image href="${fighterAFlag}" x="0" y="0" width="3840" height="2160" preserveAspectRatio="xMidYMid slice" />`
    : `<rect width="3840" height="2160" fill="#000000" />`;
  const fighterBFillMarkup = fighterBFlag
    ? `<image href="${fighterBFlag}" x="0" y="0" width="3840" height="2160" preserveAspectRatio="xMidYMid slice" />`
    : `<rect width="3840" height="2160" fill="#D20A0A" />`;

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 3840 2160" width="3840" height="2160">
    <defs>
      <clipPath id="ufcFighterAFillClip"><path d="${LANDSCAPE_BOUNDARY_PATH} L 0 2160 L 0 0 Z" /></clipPath>
      <clipPath id="ufcFighterBFillClip"><path d="${LANDSCAPE_BOUNDARY_PATH} L 3840 2160 L 3840 0 Z" /></clipPath>
      <clipPath id="ufcFighterAClip"><rect x="360" y="480" width="1200" height="1200" rx="32" /></clipPath>
      <clipPath id="ufcFighterBClip"><rect x="2280" y="480" width="1200" height="1200" rx="32" /></clipPath>
    </defs>
    <g clip-path="url(#ufcFighterAFillClip)">${fighterAFillMarkup}</g>
    <g clip-path="url(#ufcFighterBFillClip)">${fighterBFillMarkup}</g>
    <g clip-path="url(#ufcFighterAClip)">${fighterAMarkup}</g>
    <g clip-path="url(#ufcFighterBClip)">${fighterBMarkup}</g>
    <rect x="1770" y="1040" width="300" height="80" rx="12" fill="#c0392b" />
    <text x="1920" y="1094" font-family="'Trebuchet MS', Verdana, sans-serif" font-size="48" font-weight="800" fill="#ffffff" text-anchor="middle" letter-spacing="2">VS</text>
    <text x="1920" y="1900" font-family="'Trebuchet MS', Verdana, sans-serif" font-size="72" font-weight="700" fill="#ffffff" text-anchor="middle">${escapeXml(fighterAName)} vs ${escapeXml(fighterBName)}</text>
  </svg>`;

  res.setHeader('Content-Type', 'image/svg+xml');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.send(svg);
});

app.get('/landscape/:sport/:homeId/:awayId.svg', async (req, res) => {
  const { sport, homeId, awayId } = req.params;
  const sportKey = sport.toUpperCase();
  const league = getTeamLogoBucket(sportKey);
  const theme = SPORT_THEMES[sportKey] || SPORT_THEMES.MLB;

  const homeName = req.query.home || 'Home';
  const awayName = req.query.away || 'Away';
  const homeColor = req.query.homeColor ? `#${req.query.homeColor}` : theme.secondary;
  const awayColor = req.query.awayColor ? `#${req.query.awayColor}` : theme.primary;
  const homeAbbr = (req.query.homeAbbr || '').toLowerCase();
  const awayAbbr = (req.query.awayAbbr || '').toLowerCase();

  // Same scoreboard-first, standard-logo-fallback pattern as the poster,
  // plus the same homeLogoUrl/awayLogoUrl last resort for sports whose CDN
  // layout doesn't match either guessed pattern (see the poster route for
  // why - confirmed live against AFL).
  const homeScoreboardUrl = homeAbbr ? `https://a.espncdn.com/i/teamlogos/${league}/500/scoreboard/${homeAbbr}.png` : '';
  const awayScoreboardUrl = awayAbbr ? `https://a.espncdn.com/i/teamlogos/${league}/500/scoreboard/${awayAbbr}.png` : '';
  const homeStandardUrl = `https://a.espncdn.com/i/teamlogos/${league}/500/${homeId}.png`;
  const awayStandardUrl = `https://a.espncdn.com/i/teamlogos/${league}/500/${awayId}.png`;
  const homeLogoUrlParam = req.query.homeLogoUrl || '';
  const awayLogoUrlParam = req.query.awayLogoUrl || '';

  const [homeLogoData, awayLogoData] = await Promise.all([
    getBase64ImageWithFallback([homeScoreboardUrl, homeStandardUrl, homeLogoUrlParam]),
    getBase64ImageWithFallback([awayScoreboardUrl, awayStandardUrl, awayLogoUrlParam])
  ]);

  const overlayInline = getBackgroundOverlayInline();

  // Logo placement, extracted directly from logo_ref.png: away in the
  // left (red) square, home in the right (yellow) square, both 1200x1200,
  // scaled to fit and centered via preserveAspectRatio rather than custom
  // per-orientation sizing math.
  const awayLogoBox = { x: 360, y: 480, size: 1200 };
  const homeLogoBox = { x: 2280, y: 480, size: 1200 };

  const awayLogoMarkup = awayLogoData
    ? `<image href="${awayLogoData}" x="${awayLogoBox.x}" y="${awayLogoBox.y}" width="${awayLogoBox.size}" height="${awayLogoBox.size}" preserveAspectRatio="xMidYMid meet" />`
    : buildLogoFallback(awayLogoBox.x, awayLogoBox.y, awayLogoBox.size, awayName, awayColor);
  const homeLogoMarkup = homeLogoData
    ? `<image href="${homeLogoData}" x="${homeLogoBox.x}" y="${homeLogoBox.y}" width="${homeLogoBox.size}" height="${homeLogoBox.size}" preserveAspectRatio="xMidYMid meet" />`
    : buildLogoFallback(homeLogoBox.x, homeLogoBox.y, homeLogoBox.size, homeName, homeColor);

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 3840 2160" width="3840" height="2160">
    <defs>${overlayInline.defs}</defs>
    <path d="${LANDSCAPE_BOUNDARY_PATH} L 0 2160 L 0 0 Z" fill="${awayColor}" />
    <path d="${LANDSCAPE_BOUNDARY_PATH} L 3840 2160 L 3840 0 Z" fill="${homeColor}" />
    ${overlayInline.markup}
    ${awayLogoMarkup}
    ${homeLogoMarkup}
  </svg>`;

  res.setHeader('Content-Type', 'image/svg+xml');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.send(svg);
});

app.get('/poster/none/:sport.svg', async (req, res) => {
  const sportKey = req.params.sport.toUpperCase();
  const theme = SPORT_THEMES[sportKey] || SPORT_THEMES.MLB;

  const leagueLogoUrl = await getRealLeagueLogoUrl(sportKey);
  const leagueLogoData = leagueLogoUrl ? await getBase64Image(leagueLogoUrl) : null;
  const leagueLogoMarkup = leagueLogoData
    ? `<image href="${leagueLogoData}" x="60" y="60" width="480" height="480" preserveAspectRatio="xMidYMid meet" />`
    : buildLogoFallback(60, 60, 480, sportKey, theme.secondary);

  // One uniform background across every sport - a new league added in the
  // future automatically gets this same background and its own real logo
  // (via getRealLeagueLogoUrl above), with nothing sport-specific left to
  // configure here at all.
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 600 900" width="600" height="900">
    <defs>
      <radialGradient id="scheduleBg" cx="50%" cy="50%" r="70%">
        <stop offset="0%" stop-color="#231f20" />
        <stop offset="100%" stop-color="#000000" />
      </radialGradient>
    </defs>
    <rect width="600" height="900" fill="url(#scheduleBg)" />

    <!-- League Logo (Centerpiece) -->
    ${leagueLogoMarkup}

    <!-- UPCOMING / SCHEDULE, each filling 80% of poster width -->
    <text x="300" y="700" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif" font-size="72" font-weight="800" fill="#f8fafc" text-anchor="middle" textLength="480" lengthAdjust="spacingAndGlyphs" letter-spacing="2">UPCOMING</text>
    <text x="300" y="790" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif" font-size="72" font-weight="800" fill="#f8fafc" text-anchor="middle" textLength="480" lengthAdjust="spacingAndGlyphs" letter-spacing="2">SCHEDULE</text>
  </svg>`;

  res.setHeader('Content-Type', 'image/svg+xml');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.send(svg);
});

// League logos don't follow one consistent CDN URL pattern the way team
// logos mostly do - MLB's real logo lives at
// teamlogos/leagues/500/mlb.png, but EPL's real logo lives at
// leaguelogos/soccer/500/23.png, a completely different base path AND a
// numeric id rather than the league slug. Confirmed live - directly
// contradicted what this route used to assume, which is why soccer and
// NCAA sports were silently getting no logo at all. Rather than hunting
// down and hardcoding the correct pattern per sport (fragile, and would
// need redoing for every sport we ever add), the real logo URL is
// extracted directly from the same live scoreboard data fetchTodayGames
// already uses, for every sport uniformly. Cached long-term since league
// logos essentially never change (full-rebrand territory).
const realLeagueLogoCache = {};
const REAL_LEAGUE_LOGO_CACHE_MS = 14 * 24 * 60 * 60 * 1000;

async function getRealLeagueLogoUrl(sportKey) {
  const cached = realLeagueLogoCache[sportKey];
  if (cached && (Date.now() - cached.fetchedAt) < REAL_LEAGUE_LOGO_CACHE_MS) {
    return cached.url;
  }

  const endpoint = ESPN_ENDPOINTS[sportKey];
  if (!endpoint) return null;

  try {
    const res = await axios.get(endpoint, {
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
      timeout: 7000
    });
    const logos = res.data?.leagues?.[0]?.logos || [];
    const defaultLogo = logos.find(l => l.rel?.includes('default')) || logos[0];
    const url = defaultLogo?.href || null;
    realLeagueLogoCache[sportKey] = { fetchedAt: Date.now(), url };
    return url;
  } catch (err) {
    console.error(`[Logo] Failed to fetch real league logo URL for ${sportKey}:`, err.message);
    // A stale cached URL is still far better than none.
    return cached ? cached.url : null;
  }
}

app.get('/logo/:sport.svg', async (req, res) => {
  const sportKey = req.params.sport.toUpperCase();
  const leagueLogoUrl = await getRealLeagueLogoUrl(sportKey);

  const logoData = leagueLogoUrl ? await getBase64Image(leagueLogoUrl) : null;
  const logoMarkup = logoData
    ? `<image href="${logoData}" x="0" y="0" width="1080" height="1080" preserveAspectRatio="xMidYMid meet" />`
    : '';

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 1080 1080" width="1080" height="1080">
    ${logoMarkup}
  </svg>`;

  res.setHeader('Content-Type', 'image/svg+xml');
  res.setHeader('Cache-Control', 'public, max-age=86400');
  res.send(svg);
});

async function fetchTodayGames(sport, hostUrl, userTimeZone = 'America/New_York') {
  const endpoint = ESPN_ENDPOINTS[sport.toUpperCase()];
  if (!endpoint) return [];

  try {
    const targetDateStr = getLocalDateString(userTimeZone);
    const ncaaParams = NCAA_SPORTS.has(sport.toUpperCase()) ? '&groups=50&limit=500' : '';
    const res = await axios.get(`${endpoint}?dates=${targetDateStr}${ncaaParams}`, {
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
      timeout: 7000
    });

    const events = res.data?.events || [];

    return events.map(event => {
      const competition = event.competitions?.[0] || {};
      const competitors = competition.competitors || [];

      const home = competitors.find(c => c.homeAway === 'home') || {};
      const away = competitors.find(c => c.homeAway === 'away') || {};

      const homeTeam = home.team || {};
      const awayTeam = away.team || {};

      const homeId = homeTeam.id || '0';
      const awayId = awayTeam.id || '0';

      const homeNick = homeTeam.name || homeTeam.shortDisplayName || homeTeam.displayName || 'Home';
      const awayNick = awayTeam.name || awayTeam.shortDisplayName || awayTeam.displayName || 'Away';
      
      const homeFull = homeTeam.displayName || 'Home';
      const awayFull = awayTeam.displayName || 'Away';

      const homeLogoUrl = homeTeam.logo || '';
      const awayLogoUrl = awayTeam.logo || '';
      const homeColor = homeTeam.color || '';
      const awayColor = awayTeam.color || '';
      const homeAltColor = homeTeam.alternateColor || '';
      const awayAltColor = awayTeam.alternateColor || '';
      const homeAbbr = homeTeam.abbreviation || '';
      const awayAbbr = awayTeam.abbreviation || '';

      // Flattened, deduplicated list of every broadcast name ESPN lists for
      // this game across all markets (national/home/away) - a match against
      // any of these counts, per how broadcast rights actually work (a
      // single national feed can carry the game on multiple channels at
      // once, e.g. ["MLB.TV", "FS1"]).
      const broadcastNames = [...new Set(
        (competition.broadcasts || []).flatMap(b => b.names || [])
      )];

      const gameUtcDate = event.date || '';
      const artParams = new URLSearchParams({
        home: homeFull,
        away: awayFull,
        homeLogoUrl,
        awayLogoUrl,
        homeColor,
        awayColor,
        homeAltColor,
        awayAltColor,
        homeAbbr,
        awayAbbr
      }).toString();
      const dateParam = gameUtcDate
        ? `?date=${encodeURIComponent(gameUtcDate)}&tz=${encodeURIComponent(userTimeZone)}&${artParams}`
        : `?tz=${encodeURIComponent(userTimeZone)}&${artParams}`;

      const poster = `${hostUrl}/poster/${sport.toLowerCase()}/${homeId}/${awayId}.svg${dateParam}`;
      const background = `${hostUrl}/landscape/${sport.toLowerCase()}/${homeId}/${awayId}.svg${dateParam}`;
      const logo = `${hostUrl}/logo/${sport.toLowerCase()}.svg`;

      const homeWinLoss = home.records?.[0]?.summary || '0-0';
      const awayWinLoss = away.records?.[0]?.summary || '0-0';
      const statusDetail = event.status?.type?.detail || 'Scheduled';

      const venueName = competition.venue?.fullName || 'the arena';

      let formattedTime = 'TBD';
      let formattedDate = '';
      if (gameUtcDate) {
        formattedTime = formatTeamTime(gameUtcDate, userTimeZone) || 'TBD';
        formattedDate = formatReadableDate(gameUtcDate, userTimeZone) || '';
      }

      const line1 = `${awayNick.toUpperCase()} VS. ${homeNick.toUpperCase()}`;
      const line2 = [formattedDate, venueName, formattedTime].filter(Boolean).join('    ');

      // Home/road split, matched by explicit type rather than array index -
      // already present in the same records array used for the overall
      // record above, so this is free (no extra API call). Folded into the
      // same sentence as the overall record (rather than a separate one)
      // so it doesn't read as two back-to-back sentences both starting
      // with the same team name. Only added if both splits are actually
      // present, so a missing/unusual records shape just falls back to the
      // plain overall-record sentence.
      const homeSplit = home.records?.find(r => r.type === 'home')?.summary;
      const awaySplit = away.records?.find(r => r.type === 'road')?.summary;
      let line3 = (homeSplit && awaySplit)
        ? `${homeNick} enter the matchup at ${homeWinLoss} on the season (${homeSplit} at home), while ${awayNick} come in at ${awayWinLoss} (${awaySplit} on the road).`
        : `${homeNick} enter the matchup at ${homeWinLoss} on the season, while ${awayNick} come in at ${awayWinLoss}.`;

      // Statistical leaders, using whichever categories the sport's own API
      // naturally provides (passing/rushing/receiving for football, points
      // for basketball, etc.) rather than hard-coded per-sport categories,
      // so this works uniformly across every sport without special-casing.
      // Capped at the first 2 categories to stay bite-size. Silently
      // omitted entirely if the game hasn't started and leaders aren't
      // populated yet, or the athlete/team can't be resolved - no partial
      // or malformed sentences.
      const leaderLines = (competition.leaders || []).slice(0, 2).map(category => {
        const top = category.leaders?.[0];
        const athleteName = top?.athlete?.displayName;
        const statLine = top?.displayValue;
        const leaderTeamId = top?.team?.id;
        if (!athleteName || !statLine || !leaderTeamId) return null;
        const teamShortName = leaderTeamId === homeTeam.id ? homeNick : (leaderTeamId === awayTeam.id ? awayNick : null);
        if (!teamShortName) return null;
        const categoryLabel = (category.displayName || category.shortDisplayName || 'stat leader').replace(/\s*leader\s*$/i, '').toLowerCase();
        return `${athleteName} leads in ${categoryLabel} for ${teamShortName} (${statLine})`;
      }).filter(Boolean);

      if (leaderLines.length > 0) {
        line3 += ` ${leaderLines.join('; ')}.`;
      }

      const description = `${line1}\n${line2}\n\n${line3}`;

      return {
        id: String(event.id),
        name: event.name || `${awayTeam.displayName || 'Away'} vs ${homeTeam.displayName || 'Home'}`,
        homeTeam: homeTeam.displayName || '',
        awayTeam: awayTeam.displayName || '',
        // Just the nickname (e.g. "Suns"), not the full "Phoenix Suns" -
        // needed for tier 4's city/state exclusion rule in stream ranking.
        homeNick,
        awayNick,
        homeAbbr,
        awayAbbr,
        broadcastNames,
        poster,
        background,
        logo,
        description,
        status: statusDetail,
        date: event.date
      };
    });
  } catch (err) {
    console.error(`[ESPN] Error fetching scoreboard for ${sport}:`, err.message);
    return [];
  }
}

// UFC events don't map to a single matchup the way every other sport here
// does - one ESPN "event" is a whole fight card of many individual
// fights. This identifies the main event specifically (confirmed live
// against real data: the Core API's matchNumber field marks it as
// matchNumber: 1, corroborated independently by cardSegment and the
// 5-round format used only for main events/title fights) and builds a
// single game-equivalent object around that one fight - that's what
// people will actually recognize the event by when browsing posters.
// Deliberately reuses the homeTeam/awayTeam/homeAbbr/awayAbbr field names
// from fetchTodayGames, even though "home"/"away" isn't semantically
// accurate for two fighters - this lets the existing stream-matching tier
// system and poster route work without needing UFC-specific branches.
async function fetchTodayUFCEvents(hostUrl, userTimeZone = 'America/New_York') {
  try {
    // Without an explicit dates filter, ESPN's scoreboard endpoint doesn't
    // reliably return only today's events the way it does for daily sports
    // like MLB/NBA - UFC events are sparse (not every day), and the
    // unfiltered endpoint was confirmed live to return the NEXT upcoming
    // event regardless of how many days away it is, rather than an empty
    // result on a day with no event. Same date-filtering approach
    // fetchTodayGames already uses for every other sport.
    const targetDateStr = getLocalDateString(userTimeZone);
    const res = await axios.get(`${ESPN_ENDPOINTS.UFC}?dates=${targetDateStr}`, {
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
      timeout: 10000
    });
    const events = res.data?.events || [];

    const games = await Promise.all(events.map(async (event) => {
      // The scoreboard's own competitions array doesn't reliably identify
      // the main event on its own (several fights can share the same
      // broadcast-segment start time), so the Core API's per-event
      // endpoint is fetched specifically for its matchNumber field.
      let mainCompetitionId = null;
      try {
        const coreRes = await axios.get(`${ESPN_CORE_EVENT_ENDPOINTS.UFC}/${event.id}`, {
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
          timeout: 10000
        });
        const competitions = coreRes.data?.competitions || [];
        const mainCompetition = competitions.find(c => c.matchNumber === 1);
        mainCompetitionId = mainCompetition ? mainCompetition.id : null;
      } catch (err) {
        console.error(`[ESPN] Failed to fetch Core API event data for UFC event ${event.id}:`, err.message);
      }

      // Falls back to the scoreboard's own first-listed competition if the
      // Core API call fails or matchNumber isn't found, so a partial
      // outage doesn't drop the whole event - just loses main-event
      // precision for that one event specifically.
      const competition = (mainCompetitionId && event.competitions?.find(c => c.id === mainCompetitionId))
        || event.competitions?.[0];
      if (!competition) return null;

      const [competitorA, competitorB] = competition.competitors || [];
      if (!competitorA || !competitorB) return null;

      const fighterAName = competitorA.athlete?.displayName || 'Fighter A';
      const fighterBName = competitorB.athlete?.displayName || 'Fighter B';
      const fighterAId = competitorA.athlete?.id || competitorA.id || '';
      const fighterBId = competitorB.athlete?.id || competitorB.id || '';
      const fighterAFlagUrl = competitorA.athlete?.flag?.href || '';
      const fighterBFlagUrl = competitorB.athlete?.flag?.href || '';

      const broadcastNames = [...new Set(
        (competition.broadcasts || []).flatMap(b => b.names || [])
      )];

      const artParams = new URLSearchParams({
        home: fighterAName,
        away: fighterBName,
        homeFlagUrl: fighterAFlagUrl,
        awayFlagUrl: fighterBFlagUrl
      }).toString();
      const eventUtcDate = competition.date || event.date || '';
      const dateParam = eventUtcDate ? `?date=${encodeURIComponent(eventUtcDate)}&${artParams}` : `?${artParams}`;

      const poster = `${hostUrl}/poster/ufc/${fighterAId}/${fighterBId}.svg${dateParam}`;
      const background = `${hostUrl}/landscape/ufc/${fighterAId}/${fighterBId}.svg${dateParam}`;
      const logo = `${hostUrl}/logo/ufc.svg`;

      return {
        id: String(event.id),
        name: event.name || `${fighterAName} vs ${fighterBName}`,
        homeTeam: fighterAName,
        awayTeam: fighterBName,
        homeNick: fighterAName,
        awayNick: fighterBName,
        homeAbbr: '',
        awayAbbr: '',
        broadcastNames,
        poster,
        background,
        logo,
        description: event.name || `${fighterAName} vs ${fighterBName}`,
        status: competition.status?.type?.shortDetail || '',
        date: eventUtcDate
      };
    }));

    return games.filter(Boolean);
  } catch (err) {
    console.error('[ESPN] Error fetching UFC scoreboard:', err.message);
    return [];
  }
}

// Single entry point used by the catalog, meta, and stream routes -
// branches to sport-specific fetchers with a fundamentally different data
// shape than fetchTodayGames (e.g. UFC: one event is a whole fight card,
// not a single matchup) rather than having each of the three call sites
// duplicate this branching logic themselves.
//
// CORE REQUIREMENT, NOT OPTIONAL: every branch here must filter results to
// ONLY the user's current local day. This is a fundamental feature of the
// whole app, not a nice-to-have - confirmed the hard way once already (the
// first UFC implementation omitted this and showed tomorrow's event as if
// it were tonight's, since ESPN's scoreboard endpoint doesn't reliably
// return "today only" on its own for sparse, non-daily sports - it can
// default to "the next upcoming event" regardless of how far away). Any
// new sport added here - boxing, F1, or anything else - needs its own
// explicit date filter using the user's own timeZone, the same way
// fetchTodayGames already does via getLocalDateString(userTimeZone). Do
// not assume an unfiltered scoreboard call is safe just because it works
// for daily sports like MLB/NBA.
// Shared across the catalog, meta, and stream routes so a burst of requests
// for the same sport doesn't each hit ESPN independently. Keyed by host and
// timeZone (not just sport) because the returned game objects embed
// host-specific poster/background URLs and timeZone-formatted date/time
// strings baked into their description text - two users in different
// timeZones must not share a cached result. No explicit date in the key:
// the target date is derived from the current time inside the fetchers
// themselves, and the 60s TTL means the only staleness risk is a request
// landing right at a user's local midnight, which is a rare and harmless
// one-cycle delay rather than a correctness issue worth extra key
// complexity.
const gamesCache = new Map(); // `${sport}|${hostUrl}|${userTimeZone}` -> { fetchedAt, games }
const GAMES_CACHE_MS = 60 * 1000;

async function fetchGamesForSport(sport, hostUrl, userTimeZone = 'America/New_York') {
  const cacheKey = `${sport}|${hostUrl}|${userTimeZone}`;
  const cached = gamesCache.get(cacheKey);
  if (cached && (Date.now() - cached.fetchedAt) < GAMES_CACHE_MS) {
    return cached.games;
  }

  const games = sport === 'UFC'
    ? await fetchTodayUFCEvents(hostUrl, userTimeZone)
    : await fetchTodayGames(sport, hostUrl, userTimeZone);

  gamesCache.set(cacheKey, { fetchedAt: Date.now(), games });
  return games;
}

// Fetches the current/upcoming program title+description for a single
// channel via Xtream's short EPG endpoint. Returns '' on any failure
// (missing EPG data, timeout, provider error) - EPG matching is a nice
// enhancement on top of channel-name matching, never a hard requirement,
// so a failure here should never break stream matching for that channel.
async function fetchEpgForStream(user, streamId) {
  const { url, username, password } = user.xtream;
  const baseUrl = url.replace(/\/+$/, '');
  const apiUrl = `${baseUrl}/player_api.php?username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}&action=get_short_epg&stream_id=${streamId}&limit=1`;

  try {
    const res = await axios.get(apiUrl, {
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
      timeout: 4000
    });
    const listings = res.data?.epg_listings || [];
    if (listings.length === 0) return { text: '', startTimestamp: null };

    const decodeBase64 = (value) => {
      try {
        return Buffer.from(value || '', 'base64').toString('utf8');
      } catch (err) {
        return '';
      }
    };

    const entry = listings[0];
    const text = `${decodeBase64(entry.title)} ${decodeBase64(entry.description)}`.trim();
    const startTimestamp = entry.start_timestamp ? Number(entry.start_timestamp) : null;
    return { text, startTimestamp: Number.isFinite(startTimestamp) ? startTimestamp : null };
  } catch (err) {
    return { text: '', startTimestamp: null };
  }
}

// Fetches EPG data for every given stream in parallel, so the total wait
// is roughly bounded by the single slowest channel rather than the sum of
// all of them. Returns a { [stream_id]: { text, startTimestamp } } lookup;
// any channel whose lookup failed or timed out simply gets empty/null values.
async function fetchEpgForStreams(user, streams) {
  const results = await Promise.allSettled(
    streams.map(s => fetchEpgForStream(user, s.stream_id))
  );

  const epgByStreamId = {};
  streams.forEach((s, i) => {
    epgByStreamId[s.stream_id] = results[i].status === 'fulfilled' ? results[i].value : { text: '', startTimestamp: null };
  });
  return epgByStreamId;
}

// Extracts the sport "family" (basketball, football, baseball, hockey,
// soccer) from an already-known ESPN scoreboard URL, so it doesn't need its
// own separate hardcoded mapping.
function getSportFamily(sportKey) {
  const endpoint = ESPN_ENDPOINTS[sportKey];
  if (!endpoint) return null;
  const match = endpoint.match(/\/sports\/([^/]+)\/([^/]+)\/scoreboard/);
  return match ? match[1] : null;
}

// Team rosters change extremely rarely (essentially only at trade
// deadlines/relocations, not week to week), so a full day's cache is safe
// and avoids hitting ESPN on every single stream request.
const teamNameCache = new Map(); // sportKey -> { fetchedAt, names }
const TEAM_NAME_CACHE_MS = 24 * 60 * 60 * 1000;

async function fetchAllTeamNamesForSport(sportKey) {
  // UFC has fighters, not teams - there's no equivalent "teams" endpoint to
  // call at all, so skip straight to an empty list rather than always
  // failing a doomed request. An empty list also correctly means no
  // foreign-team exclusion applies, which is the right behavior here -
  // that concept doesn't really translate to a single fighter-vs-fighter
  // matchup anyway.
  if (sportKey === 'UFC') return [];

  // Confirmed live - ESPN's /teams endpoint 404s for cricket/8048 (IPL),
  // unlike every other league here. Skip straight to an empty list for the
  // same reason as UFC above, rather than hitting a request that can never
  // succeed on every single IPL stream lookup.
  if (sportKey === 'IPL') return [];

  const cached = teamNameCache.get(sportKey);
  if (cached && (Date.now() - cached.fetchedAt) < TEAM_NAME_CACHE_MS) {
    return cached.names;
  }

  const family = getSportFamily(sportKey);
  const league = ESPN_LEAGUES[sportKey];
  if (!family || !league) return cached ? cached.names : [];

  try {
    const res = await axios.get(`https://site.api.espn.com/apis/site/v2/sports/${family}/${league}/teams`, {
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
      timeout: 8000
    });
    const teams = res.data?.sports?.[0]?.leagues?.[0]?.teams || [];
    const names = teams.map(t => t.team?.displayName).filter(Boolean);
    teamNameCache.set(sportKey, { fetchedAt: Date.now(), names });
    return names;
  } catch (err) {
    console.error(`[ESPN] Failed to fetch team list for ${sportKey}:`, err.message);
    // A stale cached list is still far better than an empty one.
    return cached ? cached.names : [];
  }
}

async function fetchXtreamCategories(user) {
  const { url, username, password } = user.xtream;
  const baseUrl = url.replace(/\/+$/, '');
  const apiUrl = `${baseUrl}/player_api.php?username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}&action=get_live_categories`;
  try {
    const res = await axios.get(apiUrl, {
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
      timeout: 10000
    });
    return Array.isArray(res.data) ? res.data : [];
  } catch (err) {
    console.error('[Xtream] Failed to fetch categories for stream naming:', err.message);
    return [];
  }
}

// Builds a category_id -> category_name lookup, then returns a function that
// resolves a given stream's folder name (handling both the older single
// category_id field and the newer category_ids array some providers use).
function buildCategoryNameLookup(categories) {
  const byId = {};
  categories.forEach(c => {
    byId[String(c.category_id)] = c.category_name;
  });

  return (stream) => {
    const catId = stream.category_id ?? stream.category_ids?.[0];
    return byId[String(catId)] || 'Live TV';
  };
}

async function fetchXtreamLiveStreams(user, categoryIds = []) {
  if (!categoryIds || categoryIds.length === 0) return [];
  const { url, username, password } = user.xtream;
  const baseUrl = url.replace(/\/+$/, '');

  let allStreams = [];
  for (const catId of categoryIds) {
    const apiUrl = `${baseUrl}/player_api.php?username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}&action=get_live_streams&category_id=${catId}`;
    try {
      const res = await axios.get(apiUrl, {
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
        timeout: 8000
      });
      if (Array.isArray(res.data)) {
        allStreams = allStreams.concat(res.data);
      }
    } catch (e) {
      console.error(`[Xtream] Failed to fetch category ${catId}:`, e.message);
    }
  }
  return allStreams;
}

app.post('/api/xtream/categories', async (req, res) => {
  const { url, username, password } = req.body;
  if (!url || !username || !password) return res.status(400).json({ error: 'Missing credentials' });

  const baseUrl = url.replace(/\/+$/, '');
  const apiUrl = `${baseUrl}/player_api.php?username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}&action=get_live_categories`;

  try {
    const response = await axios.get(apiUrl, {
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
      timeout: 10000
    });
    if (Array.isArray(response.data)) {
      return res.json({ success: true, categories: response.data });
    }
    console.error(`[Xtream] get_live_categories for ${baseUrl} returned non-array data:`, JSON.stringify(response.data).slice(0, 300));
    return res.status(401).json({ error: 'Invalid Xtream credentials.' });
  } catch (err) {
    const status = err.response?.status;
    const code = err.code;
    console.error(`[Xtream] Failed to fetch categories from ${baseUrl}. HTTP status: ${status || 'n/a'}, error code: ${code || 'n/a'}, message: ${err.message}`);
    return res.status(500).json({ error: 'Unable to connect to IPTV server.' });
  }
});

// M3U's equivalent of /api/xtream/categories above - the wizard calls this
// once, with both URLs, showing "Importing. Please wait." while it runs.
// Unlike Xtream there's no separate auth to test - this fetch+parse IS the
// test. On success, also seeds the shared source cache immediately (rather
// than waiting for the next scheduled background refresh), so the very
// first user of a brand-new source doesn't hit an empty cache right after
// finishing setup.
app.post('/api/m3u/import', async (req, res) => {
  const { playlistUrl, epgUrl } = req.body;
  if (!playlistUrl || !epgUrl) {
    return res.status(400).json({ error: 'Both a playlist URL and an EPG URL are required.' });
  }

  try {
    const parsed = await m3u.refreshM3USource(playlistUrl, epgUrl);
    return res.json({ success: true, categories: parsed.categoryList });
  } catch (err) {
    console.error(`[M3U] Failed to import from playlistUrl=${playlistUrl}, epgUrl=${epgUrl}:`, err.message);
    // Distinguish which URL was the problem where possible, so the wizard
    // can point the user at the right one rather than a generic failure.
    if (err.playlistFailed && err.epgFailed) {
      return res.status(400).json({ error: 'Both URLs failed to load. Please double-check them.', playlistFailed: true, epgFailed: true });
    }
    if (err.playlistFailed) {
      return res.status(400).json({ error: 'The playlist URL failed to load or contained no usable channels.', playlistFailed: true, epgFailed: false });
    }
    if (err.epgFailed) {
      return res.status(400).json({ error: 'The EPG URL failed to load.', playlistFailed: false, epgFailed: true });
    }
    return res.status(500).json({ error: 'Unable to import from the provided URLs.' });
  }
});

// Lightweight companion to /api/m3u/import above - reads whatever the
// background scheduler already has cached, rather than re-fetching and
// re-parsing the entire source (a real, measured ~5-6 second operation
// for a full-size source). Used wherever an M3U account's categories
// need to be shown without the user explicitly re-entering/re-importing
// their URLs - on login, and for the dashboard's "Refresh Categories"
// button - since the scheduler is already responsible for keeping this
// cache fresh in the background; a user-facing request has no reason to
// duplicate that work itself.
app.post('/api/m3u/categories', async (req, res) => {
  const { uuid, password, providerId } = req.body;
  const ip = req.ip;

  if (isRateLimited(ip)) {
    const retryAfterSec = getRetryAfterSeconds(ip);
    res.setHeader('Retry-After', retryAfterSec);
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${Math.ceil(retryAfterSec / 60)} minute(s).` });
  }
  const user = userConfigs[uuid];
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    recordFailedAttempt(ip);
    return res.status(401).json({ error: 'Invalid UUID or password.' });
  }
  clearFailedAttempts(ip);

  // An account can have several M3U providers now, so the request has to
  // say which one it means - falling back to the first provider on the
  // account keeps this working for older single-provider callers that
  // don't send providerId yet.
  const provider = (user.providers || []).find(p => p.id === providerId) || (user.providers || [])[0];
  if (!provider || provider.connectionType !== 'm3u' || !provider.m3u || !provider.m3u.playlistUrl) {
    return res.status(400).json({ error: 'This provider is not configured for M3U.' });
  }

  const source = m3u.getCachedM3USource(provider.m3u.playlistUrl);
  if (!source) {
    // A brand-new source the scheduler hasn't completed its first fetch
    // for yet, or a genuinely failed/unreachable source - either way,
    // there's honestly nothing to show right now, not an error to hide.
    return res.json({ success: true, categories: [], notReady: true });
  }

  return res.json({ success: true, categories: source.categoryList });
});

// Companion to /api/m3u/categories above, same auth/lookup pattern - but
// returns individual channels (id/name/logo/categories) rather than just
// the category folder list, for the Channel EPG picker to browse and
// search. Scoped to whatever categories the provider already has selected
// across all its sports (GLOBAL included) - a full unscoped channel list
// could be thousands of entries from categories this account doesn't even
// use, and none of that is relevant to an EPG override for THIS account.
// Falls back to every channel only when nothing's been selected yet
// (a brand-new provider, so there's nothing to scope down to).
app.post('/api/m3u/channels', async (req, res) => {
  const { uuid, password, providerId } = req.body;
  const ip = req.ip;

  if (isRateLimited(ip)) {
    const retryAfterSec = getRetryAfterSeconds(ip);
    res.setHeader('Retry-After', retryAfterSec);
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${Math.ceil(retryAfterSec / 60)} minute(s).` });
  }
  const user = userConfigs[uuid];
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    recordFailedAttempt(ip);
    return res.status(401).json({ error: 'Invalid UUID or password.' });
  }
  clearFailedAttempts(ip);

  const provider = (user.providers || []).find(p => p.id === providerId) || (user.providers || [])[0];
  if (!provider || provider.connectionType !== 'm3u' || !provider.m3u || !provider.m3u.playlistUrl) {
    return res.status(400).json({ error: 'This provider is not configured for M3U.' });
  }

  const source = m3u.getCachedM3USource(provider.m3u.playlistUrl);
  if (!source) {
    return res.json({ success: true, channels: [], notReady: true });
  }

  const categorySet = new Set(Object.values(provider.sportCategories || {}).flat());
  const channels = categorySet.size > 0
    ? source.channels.filter(ch => ch.categories.some(c => categorySet.has(c)))
    : source.channels;

  return res.json({ success: true, channels: channels.map(ch => ({ id: ch.id, name: ch.name, logo: ch.logo, categories: ch.categories })) });
});

// Xtream's equivalent of /api/m3u/channels above - there's no cached
// source to read here (Xtream is always a live API call), so this takes
// the category ids to fetch directly rather than looking them up from a
// stored provider, mirroring /api/xtream/categories' raw-credentials
// pattern. The caller (Channel EPG picker) is expected to pass the same
// selected-categories union /api/m3u/channels derives server-side itself.
app.post('/api/xtream/streams', async (req, res) => {
  const { url, username, password, categoryIds } = req.body;
  if (!url || !username || !password) return res.status(400).json({ error: 'Missing credentials' });
  if (!Array.isArray(categoryIds) || categoryIds.length === 0) {
    return res.json({ success: true, streams: [] });
  }

  const pseudoUser = { xtream: { url, username, password } };
  const streams = await fetchXtreamLiveStreams(pseudoUser, categoryIds);
  return res.json({
    success: true,
    // category_id (single) and category_ids (some providers use an array
    // instead) are both passed through as-is - the Channel EPG picker
    // groups by whichever one a given stream actually has, same fallback
    // buildCategoryNameLookup already relies on elsewhere.
    streams: streams.map(s => ({
      stream_id: s.stream_id,
      name: s.name,
      epg_channel_id: s.epg_channel_id || '',
      category_id: s.category_id ?? null,
      category_ids: Array.isArray(s.category_ids) ? s.category_ids : null
    }))
  });
});

// Lists every channel id available, grouped by source, across the
// sources an admin has actually enabled and that are already cached (see
// epgshare.getEnabledChannelCatalog) - the browsable catalog the Channel
// EPG picker searches (optionally scoped to one source) to pick an
// override target. Any logged-in user can call
// this (it's read-only, public EPGShare01 metadata, not account-specific)
// - the uuid/password check here is just to keep it consistent with every
// other user-facing route rather than leaving one route as a genuine
// exception.
app.post('/api/epgshare/channels', async (req, res) => {
  const { uuid, password } = req.body;
  const ip = req.ip;

  if (isRateLimited(ip)) {
    const retryAfterSec = getRetryAfterSeconds(ip);
    res.setHeader('Retry-After', retryAfterSec);
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${Math.ceil(retryAfterSec / 60)} minute(s).` });
  }
  const user = userConfigs[uuid];
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    recordFailedAttempt(ip);
    return res.status(401).json({ error: 'Invalid UUID or password.' });
  }
  clearFailedAttempts(ip);

  return res.json({ success: true, sources: epgshare.getEnabledChannelCatalog(epgShareSettings.enabledSources) });
});

// The dashboard's Presets/Configs panel browsing list - read-only,
// account-agnostic content (an admin-curated preset is never
// account-specific and never carries credentials), so any logged-in
// user can call this. Requiring {uuid, password} anyway keeps it
// consistent with every other user-facing route rather than leaving
// this one a genuine exception - same reasoning as
// /api/epgshare/channels just above.
app.post('/api/presets', async (req, res) => {
  const { uuid, password } = req.body;
  const ip = req.ip;

  if (isRateLimited(ip)) {
    const retryAfterSec = getRetryAfterSeconds(ip);
    res.setHeader('Retry-After', retryAfterSec);
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${Math.ceil(retryAfterSec / 60)} minute(s).` });
  }
  const user = userConfigs[uuid];
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    recordFailedAttempt(ip);
    return res.status(401).json({ error: 'Invalid UUID or password.' });
  }
  clearFailedAttempts(ip);

  // Unreviewed presets (brand new or edited since a shipped update, not yet
  // looked at by this admin - see isPresetReviewed above) are withheld
  // entirely rather than shown with a caveat, since an unreviewed preset
  // may reference an EPG source this admin hasn't enabled yet.
  return res.json({ success: true, presets: getAllPresets().filter(isPresetReviewed) });
});

// Same read-only, account-agnostic preset list as /api/presets above, but
// reachable before an account exists - the setup wizard needs to offer
// presets between the connection step and account creation, and there's no
// uuid/password yet at that point. No credentials ever live on a preset, so
// there's nothing here worth gating behind auth; same reasoning as the
// wizard's own pre-account /api/xtream/categories and /api/m3u/import.
app.post('/api/presets/public', (req, res) => {
  return res.json({ success: true, presets: getAllPresets().filter(isPresetReviewed) });
});

app.post('/api/user/register', async (req, res) => {
  if (!ENCRYPTION_KEY_CONFIGURED) {
    return res.status(503).json({ error: 'Encryption key not configured yet. See the homepage for setup instructions.' });
  }
  const { xtream, m3u, connectionType, selectedSports, sportCategories, epgOverrides, password, timeZone, sportOrder } = req.body;
  if (!password || typeof password !== 'string' || password.length === 0) {
    return res.status(400).json({ error: 'A password is required.' });
  }
  const uuid = uuidv4();
  const passwordHash = await bcrypt.hash(password, 10);

  userConfigs[uuid] = {
    uuid,
    passwordHash,
    // The wizard only ever creates one provider - additional providers are
    // added later from the dashboard, never at registration. Explicitly
    // stored rather than inferred from which of xtream/m3u is present - an
    // individual provider should only ever have exactly one populated, and
    // every downstream route needs a reliable, unambiguous field to branch
    // on, the same way sport itself is used to branch fetchGamesForSport.
    providers: [{
      id: 'provider-1',
      label: 'Provider 1',
      connectionType: connectionType || 'xtream',
      xtream,
      m3u,
      selectedSports,
      sportCategories,
      // Only ever populated when the wizard's preset step resolved one -
      // the manual leagues/categories path never sets this at registration,
      // same as before this field existed.
      epgOverrides: epgOverrides && typeof epgOverrides === 'object' ? epgOverrides : {}
    }],
    timeZone: timeZone || 'America/New_York',
    sportOrder,
    createdAt: new Date().toISOString()
  };
  saveUserConfigs();

  return res.json({ success: true, uuid, manifestUrl: `/user/${uuid}/manifest.json` });
});

app.post('/api/user/login', async (req, res) => {
  if (!ENCRYPTION_KEY_CONFIGURED) {
    return res.status(503).json({ error: 'Encryption key not configured yet. See the homepage for setup instructions.' });
  }
  const { uuid, password } = req.body;
  const ip = req.ip;

  if (isRateLimited(ip)) {
    const retryAfterSec = getRetryAfterSeconds(ip);
    res.setHeader('Retry-After', retryAfterSec);
    return res.status(429).json({ error: `Too many login attempts. Try again in ${Math.ceil(retryAfterSec / 60)} minute(s).` });
  }

  const user = userConfigs[uuid];
  const passwordOk = user && (await bcrypt.compare(password, user.passwordHash));

  if (!passwordOk) {
    recordFailedAttempt(ip);
    return res.status(401).json({ error: 'Invalid UUID or password.' });
  }

  clearFailedAttempts(ip);
  return res.json({
    success: true,
    uuid: user.uuid,
    providers: user.providers || [],
    timeZone: user.timeZone || 'America/New_York',
    sportOrder: user.sportOrder || [],
    nameFormat: user.nameFormat || DEFAULT_NAME_FORMAT,
    titleFormat: user.titleFormat || DEFAULT_TITLE_FORMAT,
    manifestUrl: `/user/${uuid}/manifest.json`
  });
});

app.post('/api/user/update', async (req, res) => {
  const { uuid, password, providers, timeZone, sportOrder, nameFormat, titleFormat } = req.body;
  const ip = req.ip;

  if (isRateLimited(ip)) {
    const retryAfterSec = getRetryAfterSeconds(ip);
    res.setHeader('Retry-After', retryAfterSec);
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${Math.ceil(retryAfterSec / 60)} minute(s).` });
  }

  const user = userConfigs[uuid];
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    recordFailedAttempt(ip);
    return res.status(401).json({ error: 'Invalid UUID or password.' });
  }
  clearFailedAttempts(ip);

  if (providers !== undefined) {
    // The dashboard always sends the complete, current providers array in
    // one shot (same "one big save" pattern the account already used for
    // its single provider) - but a malformed or replayed request must
    // never be allowed to leave an account with zero working providers,
    // regardless of what the client's own UI does to prevent that.
    if (!Array.isArray(providers) || providers.length === 0) {
      return res.status(400).json({ error: 'An account must have at least one provider.' });
    }
    user.providers = providers;
  }
  if (timeZone) user.timeZone = timeZone;
  if (sportOrder !== undefined) user.sportOrder = sportOrder;
  // Blank/whitespace-only is treated as "go back to default" rather than
  // saved literally - an empty template would otherwise render every
  // stream's name/title as a blank string, which is never actually what
  // someone clearing the field out wants.
  if (nameFormat !== undefined) user.nameFormat = nameFormat.trim() || undefined;
  if (titleFormat !== undefined) user.titleFormat = titleFormat.trim() || undefined;
  saveUserConfigs();

  return res.json({ success: true, uuid: user.uuid, manifestUrl: `/user/${uuid}/manifest.json` });
});

// Permanently removes a user's entire record - their Xtream credentials,
// selected leagues, category mappings, timezone, and manifest UUID all
// live under this one object, so deleting it is a complete, irreversible
// wipe with nothing left behind elsewhere to separately clean up.
app.post('/api/user/delete', async (req, res) => {
  const { uuid, password } = req.body;
  const ip = req.ip;

  if (isRateLimited(ip)) {
    const retryAfterSec = getRetryAfterSeconds(ip);
    res.setHeader('Retry-After', retryAfterSec);
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${Math.ceil(retryAfterSec / 60)} minute(s).` });
  }

  const user = userConfigs[uuid];
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    recordFailedAttempt(ip);
    return res.status(401).json({ error: 'Invalid UUID or password.' });
  }
  clearFailedAttempts(ip);
  delete userConfigs[uuid];
  saveUserConfigs();

  return res.json({ success: true });
});

// Admin credentials can live in two places, checked in this order:
// 1. .env (ADMIN_USERNAME/ADMIN_PASSWORD) - the original, still-supported
//    approach. Same trust boundary as ENCRYPTION_KEY. Always takes
//    priority if set, so any existing deployment that already configured
//    these keeps working exactly as before - this addition changes
//    nothing for them.
// 2. The app-managed store (admin-config.json) - lets a fresh install,
//    with no env vars set yet, configure an admin password through the
//    UI itself instead of requiring a manual file edit and restart
//    before the admin panel is usable at all.
// This app is a single-operator, self-hosted tool, not a multi-admin
// platform, so a simple operator credential (whichever source is active)
// is the right fit, not a full database-backed admin account system.
async function isValidAdmin(username, password) {
  if (process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD) {
    return username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD;
  }
  if (adminConfig) {
    return username === adminConfig.username && (await bcrypt.compare(password, adminConfig.passwordHash));
  }
  return false;
}

function isAdminConfigured() {
  return !!(process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD) || !!adminConfig;
}

// Lets the landing page know whether to show the Admin button at all,
// without exposing the actual credential values to the client.
app.get('/api/admin/enabled', (req, res) => {
  return res.json({ enabled: isAdminConfigured() });
});

// Drives the first-run setup flow on the homepage - lets the frontend
// know which of the two setup screens (if any) to show before the
// normal landing page.
app.get('/api/setup/status', (req, res) => {
  return res.json({
    adminConfigured: isAdminConfigured(),
    encryptionKeyConfigured: ENCRYPTION_KEY_CONFIGURED
  });
});

// Only allowed when NO admin credentials are configured anywhere yet
// (neither env vars nor a previous app-managed setup) - this is
// deliberately a one-time, unauthenticated bootstrap action for a truly
// fresh install, not a way to reset an already-configured admin account.
// Once real credentials exist, this endpoint refuses to do anything at
// all, admin or not.
app.post('/api/setup/admin', async (req, res) => {
  if (isAdminConfigured()) {
    return res.status(403).json({ error: 'Admin credentials are already configured.' });
  }
  const { username, password } = req.body;
  if (!username || typeof username !== 'string' || username.length < 3) {
    return res.status(400).json({ error: 'Username must be at least 3 characters.' });
  }
  if (!password || typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  adminConfig = { username, passwordHash };
  saveAdminConfig(adminConfig);

  return res.json({ success: true });
});

// A random key generator, not tied to any particular request's
// eventual use - deliberately not gated behind admin auth, since
// generating a random value and displaying it isn't itself a security
// action (the key only matters once actually placed into the real
// environment config and used). Still refuses once a real key is already
// configured, though - there's no legitimate reason to expose a
// key-generator once the app is already properly set up, and no reason
// to invite confusion about whether generating a new one here would
// somehow replace the active one (it doesn't - env vars are only ever
// read once, at container startup).
app.get('/api/setup/generate-encryption-key', (req, res) => {
  if (ENCRYPTION_KEY_CONFIGURED) {
    return res.status(403).json({ error: 'An encryption key is already configured.' });
  }
  return res.json({ key: crypto.randomBytes(32).toString('hex') });
});

app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip;

  if (isRateLimited(ip)) {
    const retryAfterSec = getRetryAfterSeconds(ip);
    res.setHeader('Retry-After', retryAfterSec);
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${Math.ceil(retryAfterSec / 60)} minute(s).` });
  }

  if (!(await isValidAdmin(username, password))) {
    recordFailedAttempt(ip);
    return res.status(401).json({ error: 'Invalid admin credentials.' });
  }
  clearFailedAttempts(ip);
  return res.json({ success: true });
});

// No server-side sessions anywhere else in this app either - the regular
// dashboard passes credentials on every save rather than using a session
// cookie, so the admin page follows the same stateless pattern: every
// admin request re-validates the credentials it's sent, rather than
// trusting a token from an earlier login.
app.post('/api/admin/users', async (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip;

  if (isRateLimited(ip)) {
    const retryAfterSec = getRetryAfterSeconds(ip);
    res.setHeader('Retry-After', retryAfterSec);
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${Math.ceil(retryAfterSec / 60)} minute(s).` });
  }
  if (!(await isValidAdmin(username, password))) {
    recordFailedAttempt(ip);
    return res.status(401).json({ error: 'Invalid admin credentials.' });
  }
  clearFailedAttempts(ip);

  // Deliberately excludes passwordHash and xtream/m3u credentials - the
  // admin page only needs enough to identify, sort, and delete accounts,
  // not a reason to expose every user's stored secrets in one list.
  // connectionType itself isn't a secret, just tells the admin which kind
  // of account this is.
  const users = Object.values(userConfigs).map(user => ({
    uuid: user.uuid,
    connectionTypes: (user.providers || []).map(p => p.connectionType || 'xtream'),
    createdAt: user.createdAt || null,
    lastAccessedAt: user.lastAccessedAt || null
  }));

  return res.json({ success: true, users });
});

app.post('/api/admin/m3u-settings', async (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip;

  if (isRateLimited(ip)) {
    const retryAfterSec = getRetryAfterSeconds(ip);
    res.setHeader('Retry-After', retryAfterSec);
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${Math.ceil(retryAfterSec / 60)} minute(s).` });
  }
  if (!(await isValidAdmin(username, password))) {
    recordFailedAttempt(ip);
    return res.status(401).json({ error: 'Invalid admin credentials.' });
  }
  clearFailedAttempts(ip);

  return res.json({ success: true, settings: m3uSettings });
});

// Takes effect on the scheduler's very next cycle, not requiring a
// restart - the scheduler re-reads m3uSettings live each time it
// reschedules itself, rather than capturing a snapshot once at startup.
app.post('/api/admin/m3u-settings/update', async (req, res) => {
  const { username, password, daysOfWeek, times, timeZone } = req.body;
  const ip = req.ip;

  if (isRateLimited(ip)) {
    const retryAfterSec = getRetryAfterSeconds(ip);
    res.setHeader('Retry-After', retryAfterSec);
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${Math.ceil(retryAfterSec / 60)} minute(s).` });
  }
  if (!(await isValidAdmin(username, password))) {
    recordFailedAttempt(ip);
    return res.status(401).json({ error: 'Invalid admin credentials.' });
  }
  clearFailedAttempts(ip);

  const validDayNames = new Set(['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat']);
  if (!Array.isArray(daysOfWeek) || daysOfWeek.length === 0 || !daysOfWeek.every(d => validDayNames.has(d))) {
    return res.status(400).json({ error: 'At least one valid day of the week is required.' });
  }
  const validTimePattern = /^([01]\d|2[0-3]):([0-5]\d)$/;
  if (!Array.isArray(times) || times.length === 0 || !times.every(t => validTimePattern.test(t))) {
    return res.status(400).json({ error: 'At least one valid time (HH:MM, 24-hour) is required.' });
  }
  if (!timeZone || typeof timeZone !== 'string') {
    return res.status(400).json({ error: 'A timezone is required.' });
  }

  m3uSettings = { daysOfWeek, times: [...new Set(times)], timeZone };
  saveM3uSettings(m3uSettings);

  return res.json({ success: true, settings: m3uSettings });
});

// Manual out-of-cycle refresh - empties the shared cache first so a stale
// entry can never be served while the fresh fetch is in flight, then
// re-fetches every currently active source the same way the scheduler
// does. Awaited so the admin gets a definitive success/failure response
// rather than firing this and hoping.
app.post('/api/admin/m3u-cache/recache', async (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip;

  if (isRateLimited(ip)) {
    const retryAfterSec = getRetryAfterSeconds(ip);
    res.setHeader('Retry-After', retryAfterSec);
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${Math.ceil(retryAfterSec / 60)} minute(s).` });
  }
  if (!(await isValidAdmin(username, password))) {
    recordFailedAttempt(ip);
    return res.status(401).json({ error: 'Invalid admin credentials.' });
  }
  clearFailedAttempts(ip);

  m3u.m3uSourceCache.clear();
  await m3u.refreshAllM3USources(getActiveM3uSources);

  // Recache every admin-enabled EPGShare01 source too - an empty
  // enabledSources list (the default) means this is just a no-op loop,
  // not a skipped step, so no separate "is EPGShare enabled" branch is
  // needed here.
  epgshare.clearEpgShareCache();
  const epgShareResults = await epgshare.refreshEnabledSources(epgShareSettings.enabledSources);
  const epgShareRefreshedCount = epgShareResults.filter(r => r.success).length;

  return res.json({
    success: true,
    cachedSources: m3u.m3uSourceCache.size,
    epgShareRefreshed: epgShareRefreshedCount,
    epgShareFailed: epgShareResults.length - epgShareRefreshedCount,
    // Per-source detail (file + error) so a failure is diagnosable from
    // the admin page itself, not just an aggregate "N failed" count.
    epgShareResults
  });
});

// Lists every EPGShare01 source file available to enable, with its
// compressed and (exact, via gzip's ISIZE trailer - see epgshare01.js)
// decompressed size, for the admin picker's column view. This is just
// metadata about what's available - fetching it never fetches or parses
// any source's actual EPG data. Cached after the first call (the full
// listing + ~100 tiny range requests takes a few seconds); pass
// { refresh: true } to force a re-fetch instead of serving the cache.
app.post('/api/admin/epgshare-catalog', async (req, res) => {
  const { username, password, refresh } = req.body;
  const ip = req.ip;

  if (isRateLimited(ip)) {
    const retryAfterSec = getRetryAfterSeconds(ip);
    res.setHeader('Retry-After', retryAfterSec);
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${Math.ceil(retryAfterSec / 60)} minute(s).` });
  }
  if (!(await isValidAdmin(username, password))) {
    recordFailedAttempt(ip);
    return res.status(401).json({ error: 'Invalid admin credentials.' });
  }
  clearFailedAttempts(ip);

  try {
    const catalog = (!refresh && epgshare.getCachedCatalog()) || await epgshare.refreshCatalog();
    return res.json({ success: true, fetchedAt: catalog.fetchedAt, sources: catalog.sources });
  } catch (err) {
    console.error('[EPGShare01] Failed to fetch source catalog:', err.message);
    return res.status(502).json({ error: 'Failed to fetch the EPGShare01 source list. Try again shortly.' });
  }
});

app.post('/api/admin/epgshare-settings', async (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip;

  if (isRateLimited(ip)) {
    const retryAfterSec = getRetryAfterSeconds(ip);
    res.setHeader('Retry-After', retryAfterSec);
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${Math.ceil(retryAfterSec / 60)} minute(s).` });
  }
  if (!(await isValidAdmin(username, password))) {
    recordFailedAttempt(ip);
    return res.status(401).json({ error: 'Invalid admin credentials.' });
  }
  clearFailedAttempts(ip);

  return res.json({ success: true, settings: epgShareSettings });
});

// Takes effect on the shared scheduler's very next cycle - no restart
// needed, same as the M3U settings update route. Note this only controls
// which sources are FETCHED AND AVAILABLE, not who's actually using them -
// there's no per-request behavior change from this route at all, that
// only happens once the (separate, not yet built) per-channel picker
// reads from whatever ends up cached here.
app.post('/api/admin/epgshare-settings/update', async (req, res) => {
  const { username, password, enabledSources } = req.body;
  const ip = req.ip;

  if (isRateLimited(ip)) {
    const retryAfterSec = getRetryAfterSeconds(ip);
    res.setHeader('Retry-After', retryAfterSec);
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${Math.ceil(retryAfterSec / 60)} minute(s).` });
  }
  if (!(await isValidAdmin(username, password))) {
    recordFailedAttempt(ip);
    return res.status(401).json({ error: 'Invalid admin credentials.' });
  }
  clearFailedAttempts(ip);

  if (!Array.isArray(enabledSources) || !enabledSources.every(f => epgshare.isKnownSourceFile(f))) {
    return res.status(400).json({ error: 'enabledSources must be a list of valid EPGShare01 source filenames.' });
  }

  const previouslyEnabled = new Set(epgShareSettings.enabledSources);
  const newlyEnabled = enabledSources.filter(f => !previouslyEnabled.has(f));
  epgShareSettings = { enabledSources: [...new Set(enabledSources)] };
  saveEpgShareSettings(epgShareSettings);

  // Fetch newly-enabled sources immediately rather than leaving them
  // cache-empty until the next scheduled run - mirrors the M3U
  // scheduler's "fetch on startup" reasoning. Sources that were already
  // enabled keep whatever's already cached; sources that got disabled are
  // simply left in cache until the next full recache (no urgency to evict
  // them early - they're just unused, not harmful).
  if (newlyEnabled.length > 0) {
    epgshare.refreshEnabledSources(newlyEnabled).catch(err => {
      console.error('[EPGShare01] Initial fetch for newly-enabled sources failed:', err.message);
    });
  }

  return res.json({ success: true, settings: epgShareSettings });
});

app.post('/api/admin/presets', async (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip;

  if (isRateLimited(ip)) {
    const retryAfterSec = getRetryAfterSeconds(ip);
    res.setHeader('Retry-After', retryAfterSec);
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${Math.ceil(retryAfterSec / 60)} minute(s).` });
  }
  if (!(await isValidAdmin(username, password))) {
    recordFailedAttempt(ip);
    return res.status(401).json({ error: 'Invalid admin credentials.' });
  }
  clearFailedAttempts(ip);

  // Unlike the user-facing /api/presets, the admin's own list shows
  // everything including unreviewed presets - reviewed/missingSources are
  // computed per preset so admin.html can flag which ones still need a
  // look without a second round trip.
  return res.json({
    success: true,
    presets: getAllPresets().map(p => ({ ...p, isStock: stockPresets.some(sp => sp.id === p.id), reviewed: isPresetReviewed(p), missingSources: computeMissingSourcesForPreset(p) }))
  });
});

// Takes the exact payload exportProviderSettings() (index.html) produces
// - only those known fields are ever persisted, so a hand-edited upload
// can't smuggle extra data (credentials were never in the export shape to
// begin with) into what gets committed to the repo.
app.post('/api/admin/presets/create', async (req, res) => {
  const { username, password, name, icon, config, onMissingSources } = req.body;
  const ip = req.ip;

  if (isRateLimited(ip)) {
    const retryAfterSec = getRetryAfterSeconds(ip);
    res.setHeader('Retry-After', retryAfterSec);
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${Math.ceil(retryAfterSec / 60)} minute(s).` });
  }
  if (!(await isValidAdmin(username, password))) {
    recordFailedAttempt(ip);
    return res.status(401).json({ error: 'Invalid admin credentials.' });
  }
  clearFailedAttempts(ip);

  const trimmedName = typeof name === 'string' ? name.trim() : '';
  if (!trimmedName || trimmedName.length > PRESET_NAME_MAX_LENGTH) {
    return res.status(400).json({ error: `Name must be 1-${PRESET_NAME_MAX_LENGTH} characters.` });
  }
  if (!ALLOWED_PRESET_ICONS.has(icon)) {
    return res.status(400).json({ error: 'Choose an icon from the picker.' });
  }
  if (!config || typeof config !== 'object' || config.sportioExportVersion !== 1
    || typeof config.sportCategories !== 'object' || config.sportCategories === null
    || typeof config.epgOverrides !== 'object' || config.epgOverrides === null) {
    return res.status(400).json({ error: "That doesn't look like a settings export file." });
  }

  const validEpgSources = Array.isArray(config.epgSources)
    ? config.epgSources.filter(f => epgshare.isKnownSourceFile(f))
    : [];

  // The export names which EPGShare01 source(s) its overrides actually
  // need - if this admin hasn't enabled one, those overrides would
  // silently never resolve to anything (findOverrideProgramme only
  // searches enabled+cached sources). Surfaced as a distinct response
  // shape (not a hard error) so the client can offer a real choice
  // instead of either silently shipping dead overrides or blocking
  // creation outright.
  const missingSources = validEpgSources.filter(f => !epgShareSettings.enabledSources.includes(f));
  if (missingSources.length > 0 && !onMissingSources) {
    return res.json({ success: false, needsConfirmation: true, missingSources });
  }

  if (onMissingSources === 'enable' && missingSources.length > 0) {
    epgShareSettings = { enabledSources: [...new Set([...epgShareSettings.enabledSources, ...missingSources])] };
    saveEpgShareSettings(epgShareSettings);
    epgshare.refreshEnabledSources(missingSources).catch(err => {
      console.error('[EPGShare01] Initial fetch for newly-enabled sources failed:', err.message);
    });
  }

  const preset = {
    id: uuidv4(),
    name: trimmedName,
    icon,
    connectionType: config.connectionType === 'm3u' ? 'm3u' : 'xtream',
    selectedSports: Array.isArray(config.selectedSports) ? config.selectedSports.filter(s => typeof s === 'string') : [],
    sportCategories: Object.fromEntries(
      Object.entries(config.sportCategories).filter(([, names]) => Array.isArray(names))
        .map(([sport, names]) => [sport, names.filter(n => typeof n === 'string')])
    ),
    epgOverrides: Object.fromEntries(
      Object.entries(config.epgOverrides).filter(([, v]) => typeof v === 'string')
    ),
    epgSources: validEpgSources,
    createdAt: new Date().toISOString()
  };

  // Written to LOCAL_PRESETS_FILE, never PRESETS_FILE - this is this
  // instance's own preset, not something this deployment ships to anyone
  // else. To make a preset part of the stock set distributed with the repo,
  // it has to be added to presets/presets.json by hand and committed.
  localPresets = [...localPresets, preset];
  saveLocalPresets(localPresets);
  // Created right here through this form, missing-source prompt included -
  // that already is the review, so this doesn't also need to sit in the
  // pending queue.
  markPresetReviewed(preset);

  return res.json({ success: true, preset, epgShareSettings });
});

// Renames one of this instance's own local presets. Stock presets can only
// be renamed by editing presets/presets.json and shipping an update, same
// as removing one (see /api/admin/presets/delete) - there is no in-place
// edit path for content shipped via the repo.
app.post('/api/admin/presets/rename', async (req, res) => {
  const { username, password, id, name } = req.body;
  const ip = req.ip;

  if (isRateLimited(ip)) {
    const retryAfterSec = getRetryAfterSeconds(ip);
    res.setHeader('Retry-After', retryAfterSec);
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${Math.ceil(retryAfterSec / 60)} minute(s).` });
  }
  if (!(await isValidAdmin(username, password))) {
    recordFailedAttempt(ip);
    return res.status(401).json({ error: 'Invalid admin credentials.' });
  }
  clearFailedAttempts(ip);

  const trimmedName = typeof name === 'string' ? name.trim() : '';
  if (!trimmedName || trimmedName.length > PRESET_NAME_MAX_LENGTH) {
    return res.status(400).json({ error: `Name must be 1-${PRESET_NAME_MAX_LENGTH} characters.` });
  }

  if (stockPresets.some(p => p.id === id)) {
    return res.status(400).json({ error: 'This is a built-in preset - it can only be renamed by shipping a code update, not from an instance admin panel.' });
  }

  const preset = localPresets.find(p => p.id === id);
  if (!preset) {
    return res.status(404).json({ error: 'Preset not found.' });
  }

  preset.name = trimmedName;
  saveLocalPresets(localPresets);
  // The admin performing the rename has already seen the result, same
  // reasoning as create - no need to also bounce it into the pending
  // review queue just because the name change flipped its content hash.
  markPresetReviewed(preset);

  return res.json({ success: true, preset });
});

app.post('/api/admin/presets/review', async (req, res) => {
  const { username, password, id, action } = req.body;
  const ip = req.ip;

  if (isRateLimited(ip)) {
    const retryAfterSec = getRetryAfterSeconds(ip);
    res.setHeader('Retry-After', retryAfterSec);
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${Math.ceil(retryAfterSec / 60)} minute(s).` });
  }
  if (!(await isValidAdmin(username, password))) {
    recordFailedAttempt(ip);
    return res.status(401).json({ error: 'Invalid admin credentials.' });
  }
  clearFailedAttempts(ip);

  if (action !== 'publish' && action !== 'publish-and-enable') {
    return res.status(400).json({ error: 'Invalid action.' });
  }
  const preset = getAllPresets().find(p => p.id === id);
  if (!preset) {
    return res.status(404).json({ error: 'Preset not found.' });
  }

  if (action === 'publish-and-enable') {
    const missingSources = computeMissingSourcesForPreset(preset);
    if (missingSources.length > 0) {
      epgShareSettings = { enabledSources: [...new Set([...epgShareSettings.enabledSources, ...missingSources])] };
      saveEpgShareSettings(epgShareSettings);
      epgshare.refreshEnabledSources(missingSources).catch(err => {
        console.error('[EPGShare01] Initial fetch for newly-enabled sources failed:', err.message);
      });
    }
  }

  markPresetReviewed(preset);

  return res.json({ success: true, epgShareSettings });
});

app.post('/api/admin/presets/delete', async (req, res) => {
  const { username, password, id } = req.body;
  const ip = req.ip;

  if (isRateLimited(ip)) {
    const retryAfterSec = getRetryAfterSeconds(ip);
    res.setHeader('Retry-After', retryAfterSec);
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${Math.ceil(retryAfterSec / 60)} minute(s).` });
  }
  if (!(await isValidAdmin(username, password))) {
    recordFailedAttempt(ip);
    return res.status(401).json({ error: 'Invalid admin credentials.' });
  }
  clearFailedAttempts(ip);

  // Stock presets ship with the repo and are only ever removed by editing
  // presets/presets.json and shipping an update - this endpoint can only
  // remove this instance's own local presets.
  if (stockPresets.some(p => p.id === id)) {
    return res.status(400).json({ error: 'This is a built-in preset - it can only be removed by shipping a code update, not from an instance admin panel.' });
  }
  const beforeCount = localPresets.length;
  localPresets = localPresets.filter(p => p.id !== id);
  if (localPresets.length === beforeCount) {
    return res.status(404).json({ error: 'Preset not found.' });
  }
  saveLocalPresets(localPresets);
  if (Object.prototype.hasOwnProperty.call(reviewedPresets, id)) {
    const { [id]: _removed, ...rest } = reviewedPresets;
    reviewedPresets = rest;
    saveReviewedPresets(reviewedPresets);
  }

  return res.json({ success: true });
});

app.post('/api/admin/user/delete', async (req, res) => {
  const { username, password, targetUuid } = req.body;
  const ip = req.ip;

  if (isRateLimited(ip)) {
    const retryAfterSec = getRetryAfterSeconds(ip);
    res.setHeader('Retry-After', retryAfterSec);
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${Math.ceil(retryAfterSec / 60)} minute(s).` });
  }
  if (!(await isValidAdmin(username, password))) {
    recordFailedAttempt(ip);
    return res.status(401).json({ error: 'Invalid admin credentials.' });
  }
  clearFailedAttempts(ip);
  if (!userConfigs[targetUuid]) {
    return res.status(404).json({ error: 'No account found with that UUID.' });
  }

  delete userConfigs[targetUuid];
  saveUserConfigs();

  return res.json({ success: true });
});

app.get('/user/:uuid/manifest.json', (req, res) => {
  const user = userConfigs[req.params.uuid];
  if (!user) return res.status(404).json({ error: 'Invalid manifest UUID' });

  // Used by the admin page to show which accounts are actually in active
  // use. Nuvio re-fetches the manifest periodically (not just once at
  // install), so this is a reasonable proxy for real activity without
  // needing to instrument every catalog/stream route too.
  user.lastAccessedAt = new Date().toISOString();
  saveUserConfigs();

  const targetDateStr = getLocalDateDash(user.timeZone);

  // A sport only appears as a catalog if at least one category folder has
  // been mapped to it in AT LEAST ONE provider - this keeps unconfigured
  // sports out of Nuvio while letting different providers each contribute
  // different leagues (or the same league redundantly) to the same account.
  // GLOBAL is a special key (categories that apply to every real sport's
  // search automatically, scoped to that one provider) and is never itself
  // a browsable catalog.
  const activeSportsSet = new Set();
  for (const provider of user.providers || []) {
    for (const [sport, categoryIds] of Object.entries(provider.sportCategories || {})) {
      if (sport !== 'GLOBAL' && Array.isArray(categoryIds) && categoryIds.length > 0) {
        activeSportsSet.add(sport);
      }
    }
  }
  const activeSports = [...activeSportsSet];

  // Catalog order reflects the user's own drag-and-drop ordering of the
  // Category Search accordions, not raw object insertion order (which
  // isn't a meaningful order at all - just whatever sequence categories
  // happened to get saved in over time). Anything not yet given an
  // explicit position (e.g. a league added after the order was last set)
  // falls back to alphabetical, sorting after everything explicitly ordered.
  const sportOrder = user.sportOrder || [];
  const orderedActiveSports = [...activeSports].sort((a, b) => {
    const idxA = sportOrder.indexOf(a);
    const idxB = sportOrder.indexOf(b);
    if (idxA === -1 && idxB === -1) return getSportDisplayName(a).localeCompare(getSportDisplayName(b));
    if (idxA === -1) return 1;
    if (idxB === -1) return -1;
    return idxA - idxB;
  });

  const catalogs = orderedActiveSports.map(sport => ({
    type: 'sports',
    id: `sb_${sport.toLowerCase()}_${targetDateStr}`,
    name: `${getSportDisplayName(sport)} Live Games`
  }));

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');

  res.json({
    id: `org.sportballio.${user.uuid}`,
    version: '2.2.8',
    name: 'Sportio Live',
    description: 'Live sports addon for Stremio/Nuvio. Powered by your IPTV.',
    resources: ['catalog', 'meta', 'stream'],
    types: ['sports'],
    catalogs
  });
});

app.get('/user/:uuid/catalog/sports/:id.json', async (req, res) => {
  const user = userConfigs[req.params.uuid];
  if (!user) return res.json({ metas: [] });

  const hostUrl = `${req.protocol}://${req.get('host')}`;
  // Catalog ids are always constructed as sb_{sport}_{date} (see the
  // manifest route), and the date portion uses dashes rather than
  // underscores, so splitting on "_" and taking the second segment
  // reliably extracts the sport for every league - no need to maintain a
  // hardcoded, easily-incomplete list of substring checks here, which is
  // exactly what caused several leagues to silently fall back to MLB
  // before this fix.
  const sport = (req.params.id.split('_')[1] || 'mlb').toUpperCase();

  const userTz = user.timeZone || 'America/New_York';
  const games = await fetchGamesForSport(sport, hostUrl, userTz);

  const metas = games.map(game => ({
    id: `sb:${sport.toLowerCase()}:${game.id}`,
    type: 'sports',
    name: game.name,
    poster: game.poster,
    background: game.background,
    logo: game.logo,
    description: game.description
  }));

  metas.push({
    id: `sb:${sport.toLowerCase()}:none`,
    type: 'sports',
    name: 'Upcoming Schedule',
    poster: `${hostUrl}/poster/none/${sport.toLowerCase()}.svg`,
    background: `${hostUrl}/background/schedule/${sport.toLowerCase()}.svg`,
    logo: `${hostUrl}/logo/${sport.toLowerCase()}.svg`,
    description: games.length > 0
      ? `See the full upcoming ${getSportDisplayName(sport)} schedule.`
      : `No ${getSportDisplayName(sport)} games today. Tap to see the upcoming schedule.`
  });

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.json({ metas });
});

app.get('/user/:uuid/meta/sports/:id.json', async (req, res) => {
  const user = userConfigs[req.params.uuid];
  if (!user) return res.json({ meta: {} });

  const hostUrl = `${req.protocol}://${req.get('host')}`;
  // Every meta id this route ever receives is shaped sb:{sport}:{gameId} or
  // sb:{sport}:none (see the catalog route above) - the dead
  // non-"sb"-prefixed branch (unreachable - nothing in the app ever
  // constructed that shape of id) has been removed, matching the
  // equivalent cleanup already done on the stream route below.
  const [, sport, idVal] = req.params.id.split(':');

  if (idVal === 'none') {
    const userTz = user.timeZone || 'America/New_York';
    const upcoming = await fetchUpcomingGames(sport, userTz, 20);
    const description = upcoming.length > 0
      ? `Upcoming ${getSportDisplayName(sport)} Games:\n\n${upcoming.join('\n')}`
      : 'No Games Scheduled';

    return res.json({
      meta: {
        id: req.params.id,
        type: 'sports',
        name: 'Upcoming Schedule',
        poster: `${hostUrl}/poster/none/${sport.toLowerCase()}.svg`,
        background: `${hostUrl}/background/schedule/${sport.toLowerCase()}.svg`,
        logo: `${hostUrl}/logo/${sport.toLowerCase()}.svg`,
        description
      }
    });
  }

  const userTz = user.timeZone || 'America/New_York';
  const games = await fetchGamesForSport(sport.toUpperCase(), hostUrl, userTz);
  const game = games.find(g => g.id === idVal);
  if (!game) return res.json({ meta: {} });

  return res.json({
    meta: {
      id: req.params.id,
      type: 'sports',
      name: game.name,
      poster: game.poster,
      background: game.background,
      logo: game.logo,
      description: game.description
    }
  });
});

// What every account gets until it opts into something custom via the
// Formatter panel - an account that's never touched it sees this, not a
// blank/raw fallback.
const DEFAULT_NAME_FORMAT = '{homeNick} vs. {awayNick}\n{status}';
const DEFAULT_TITLE_FORMAT = '📁 {category}  | 📺 {channelName}\nℹ️ {epgDescription}';

// Deliberately plain {placeholder} substitution, not a templating engine -
// an unrecognized placeholder (a typo) is left as literal text rather than
// silently vanishing, so a mistake is obvious in the rendered result
// instead of just quietly missing. A recognized placeholder with no value
// for this particular stream (e.g. {epgDescription} when the channel has
// no EPG data) renders as empty, not "undefined".
function applyFormatter(template, fields) {
  return template.replace(/\{(\w+)\}/g, (match, key) => {
    return Object.prototype.hasOwnProperty.call(fields, key) ? (fields[key] || '') : match;
  });
}

// Builds the placeholder value set for one candidate stream - deliberately
// a curated subset of everything technically available (game venue,
// records, stat leaders, team colors, etc. all exist upstream but aren't
// included here), since the Formatter is meant for naming/labeling a
// stream, not reproducing the full game-description blurb already shown
// elsewhere.
function buildFormatterFields(game, stream) {
  return {
    channelName: stream.name || '',
    category: stream.categoryLabel || '',
    epgDescription: stream.description || '',
    provider: stream.providerLabel || '',
    homeTeam: game.homeTeam || '',
    awayTeam: game.awayTeam || '',
    homeNick: game.homeNick || '',
    awayNick: game.awayNick || '',
    status: game.status || ''
  };
}

// Reserved provider.epgOverrides value meaning "use this channel's own
// (live) name as its description" instead of an EPGShare01 channel id -
// mirrored exactly in public/index.html, which is the only other place
// this string is written or compared. Safe to reserve: real EPGShare01
// ids look like "365BLK.us2"/"NBA-BostonCeltics.us", never
// double-underscore-wrapped. See applyChannelEpgOverrides below for
// where it's actually resolved.
const EPG_OVERRIDE_SELF_NAME = '__CHANNEL_NAME__';

app.get('/user/:uuid/stream/sports/:id.json', async (req, res) => {
  const user = userConfigs[req.params.uuid];
  if (!user) return res.json({ streams: [] });

  // Every id this route ever receives is shaped sb:{sport}:{gameId} - the
  // first segment no longer needs to be captured now that the dead
  // sbstream-prefixed branch (unreachable - nothing in the app ever
  // constructed that shape of id) has been removed.
  const [, sport, idVal] = req.params.id.split(':');
  if (idVal === 'none') return res.json({ streams: [] });

  const hostUrl = `${req.protocol}://${req.get('host')}`;
  const upperSport = sport.toUpperCase();

  // Every provider that has this sport (or its own GLOBAL) mapped to at
  // least one category folder contributes its own candidate streams below -
  // category folder ids are provider-specific numbers/strings with no
  // cross-provider meaning, so each provider's ids are only ever matched
  // against that same provider's own source, never against another
  // provider's source.
  const contributingProviders = (user.providers || [])
    .map(provider => {
      const sportCategoryIds = provider.sportCategories?.[upperSport] || [];
      const globalCategoryIds = provider.sportCategories?.GLOBAL || [];
      const configuredCategoryIds = [...new Set([...sportCategoryIds, ...globalCategoryIds])];
      return { provider, configuredCategoryIds };
    })
    .filter(({ configuredCategoryIds }) => configuredCategoryIds.length > 0);

  if (contributingProviders.length === 0) return res.json({ streams: [] });

  const userTz = user.timeZone || 'America/New_York';
  const games = await fetchGamesForSport(upperSport, hostUrl, userTz);
  const game = games.find(g => g.id === idVal);

  if (!game) return res.json({ streams: [] });

  // Recency anchor for tie-breaking within any tier: the game's own
  // scheduled start, in unix seconds. Computed early (not just before the
  // tie-break step below) because the M3U branch also needs it up front,
  // to pick which single programme entry represents each channel's
  // description in the first place - see getCandidateStreamsForGame.
  const gameTimestampMs = game.date ? new Date(game.date).getTime() : null;
  const gameTimestamp = gameTimestampMs && !isNaN(gameTimestampMs) ? gameTimestampMs / 1000 : null;

  // Depends only on the sport, not on which or how many providers are
  // contributing - fetched once up front rather than once per provider.
  const allTeamNames = await fetchAllTeamNamesForSport(upperSport);

  // Only worth labeling which provider a stream came from once there's
  // more than one provider on the account at all - keeps single-provider
  // accounts (the common case) visually identical to before this feature.
  const showProviderLabel = (user.providers || []).length > 1;

  // Each contributing provider builds its own candidate list independently
  // and in PARALLEL (not sequentially) - Xtream is a real network round
  // trip per provider, and one slow provider shouldn't stack its latency
  // onto every other provider's response time. Every candidate, regardless
  // of source, is normalized into the same {name, description,
  // startTimestamp, streamUrl, categoryLabel} shape the matching/ranking
  // logic below already expects - that normalization is what lets this
  // loop grow the candidate pool without touching the ranking logic at all.
  // A user's per-channel EPG override (provider.epgOverrides: {providerChannelId
  // -> epgShareChannelId}, set from the dashboard's Channel EPG picker) is
  // applied here, right where `provider` is still in scope - joined by the
  // same provider-native channel id (tvg-id / epg_channel_id) every
  // candidate stream already carries. A stream with no override for its
  // channel, or whose override target isn't in any currently cached
  // admin-enabled source, passes through completely unchanged - this never
  // blanks out a description that would otherwise have come from the
  // provider's own EPG.
  const applyChannelEpgOverrides = (streams, provider) => {
    const overrides = provider.epgOverrides;
    if (!overrides || Object.keys(overrides).length === 0) return streams;
    return streams.map(s => {
      const targetChannelId = overrides[s.channelId];
      if (!targetChannelId) return s;
      // No external source involved at all - reads the channel's current
      // name fresh off this candidate on every request, so it tracks the
      // channel's own name automatically as it changes, with no caching.
      if (targetChannelId === EPG_OVERRIDE_SELF_NAME) {
        return { ...s, description: s.name };
      }
      const override = epgshare.findOverrideProgramme(targetChannelId, epgShareSettings.enabledSources, gameTimestamp);
      if (!override) return s;
      // description, not title - findOverrideProgramme already falls back
      // to the EPGShare01 entry's title when that specific entry has no
      // <desc> of its own, so this is never blanked out even then.
      return { ...s, description: override.description, startTimestamp: override.startTimestamp };
    });
  };

  const perProviderResults = await Promise.allSettled(
    contributingProviders.map(async ({ provider, configuredCategoryIds }) => {
      if (provider.connectionType === 'm3u') {
        if (!provider.m3u || !provider.m3u.playlistUrl) return [];
        const m3uSource = m3u.getCachedM3USource(provider.m3u.playlistUrl);
        if (!m3uSource) return [];
        const streams = applyChannelEpgOverrides(m3u.getCandidateStreamsForGame(m3uSource, configuredCategoryIds, gameTimestamp), provider);
        return showProviderLabel ? streams.map(s => ({ ...s, providerLabel: provider.label })) : streams;
      }

      if (!provider.xtream || !provider.xtream.url) return [];
      // fetchXtreamLiveStreams/fetchXtreamCategories/fetchEpgForStreams only
      // ever read the `.xtream` field off whatever's passed in, so a
      // provider-scoped credential set stands in for the "user" they expect
      // without needing those functions to know providers exist at all.
      const pseudoUser = { xtream: provider.xtream };
      const xtreamStreams = await fetchXtreamLiveStreams(pseudoUser, configuredCategoryIds);
      const categories = await fetchXtreamCategories(pseudoUser);
      const getCategoryName = buildCategoryNameLookup(categories);
      const epgByStreamId = await fetchEpgForStreams(pseudoUser, xtreamStreams);
      const xtreamCandidates = xtreamStreams.map(s => {
        const epg = epgByStreamId[s.stream_id] || { text: '', startTimestamp: null };
        return {
          name: s.name,
          description: epg.text,
          startTimestamp: epg.startTimestamp,
          streamUrl: `${provider.xtream.url.replace(/\/+$/, '')}/live/${encodeURIComponent(provider.xtream.username)}/${encodeURIComponent(provider.xtream.password)}/${s.stream_id}.m3u8`,
          categoryLabel: getCategoryName(s),
          // stream_id, not epg_channel_id - confirmed against real
          // provider data that epg_channel_id is frequently empty AND,
          // worse, sometimes identical across genuinely different
          // channels on the same account (some providers just don't
          // populate it meaningfully). stream_id is the one field Xtream
          // guarantees is present and unique per channel, so it's the
          // only safe join key for a per-channel override - not used by
          // anything Xtream-specific here, only kept so the EPGShare01
          // override above can join against it.
          channelId: String(s.stream_id),
          ...(showProviderLabel ? { providerLabel: provider.label } : {})
        };
      });
      return applyChannelEpgOverrides(xtreamCandidates, provider);
    })
  );

  // A provider that failed (dead server, bad credentials, network error)
  // contributes nothing rather than aborting the whole request - a healthy
  // provider's streams must never be lost just because a different one on
  // the same account is down.
  const candidateStreams = perProviderResults.flatMap(result => {
    if (result.status === 'rejected') {
      console.error('[Stream] A provider failed to produce candidate streams:', result.reason?.message || result.reason);
      return [];
    }
    return result.value;
  });

  const homeKw = (game.homeTeam || '').toLowerCase().split(' ').filter(w => w.length > 2);
  const awayKw = (game.awayTeam || '').toLowerCase().split(' ').filter(w => w.length > 2);
  // Also match on each team's short abbreviation (e.g. "LAL"), which some
  // channels/EPG data use instead of the full team name. Only included when
  // at least 3 characters, to avoid an overly-short string causing
  // false-positive substring matches elsewhere.
  const homeAbbr = (game.homeAbbr || '').toLowerCase();
  const awayAbbr = (game.awayAbbr || '').toLowerCase();
  if (homeAbbr.length > 2) homeKw.push(homeAbbr);
  if (awayAbbr.length > 2) awayKw.push(awayAbbr);

  // Nickname-only keywords (e.g. just "suns", not "phoenix suns") - used
  // specifically for tier 4's requirement that a city/state-only match
  // doesn't count. Kept separate from homeKw/awayKw above, which stay
  // city-inclusive for tiers 1-3 (a much stronger "both teams" signal
  // where a city match is far less likely to be a coincidence).
  const homeNickKw = (game.homeNick || '').toLowerCase().split(' ').filter(w => w.length > 2);
  const awayNickKw = (game.awayNick || '').toLowerCase().split(' ').filter(w => w.length > 2);
  if (homeAbbr.length > 2) homeNickKw.push(homeAbbr);
  if (awayAbbr.length > 2) awayNickKw.push(awayAbbr);

  // Every team in the league, not just teams playing today - so a channel
  // whose EPG mentions a team that isn't even playing today (a genuinely
  // stale/outdated listing) still gets caught, not just a same-day mix-up.
  const foreignKw = new Set();
  allTeamNames.forEach(name => {
    (name || '').toLowerCase().split(' ').filter(w => w.length > 2).forEach(w => foreignKw.add(w));
  });
  [...homeKw, ...awayKw].forEach(w => foreignKw.delete(w));

  // Word-boundary matching, not plain substring - a short keyword like
  // "red" (from "Red Sox") must appear as its own word, not as a
  // fragment inside an unrelated word like "Reds" (Cincinnati Reds).
  // Confirmed as a real false-positive against actual provider data
  // during design (a Reds/Marlins channel incorrectly matched a Red
  // Sox/Blue Jays game). Same reasoning has4K below already uses \b
  // boundaries for - this makes every matcher here consistent with it,
  // rather than just the one. Compiled once per game (not per-candidate,
  // which would be wasteful across potentially hundreds of streams).
  function escapeRegex(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
  function buildWordBoundaryMatcher(keywords) {
    if (keywords.length === 0) return () => false;
    const pattern = new RegExp('\\b(' + keywords.map(escapeRegex).join('|') + ')\\b', 'i');
    return (text) => pattern.test(text);
  }

  const matchesHome = buildWordBoundaryMatcher(homeKw);
  const matchesAway = buildWordBoundaryMatcher(awayKw);
  const matchesHomeNickOnly = buildWordBoundaryMatcher(homeNickKw);
  const matchesAwayNickOnly = buildWordBoundaryMatcher(awayNickKw);
  const mentionsForeignTeam = buildWordBoundaryMatcher([...foreignKw]);

  // "4k" as a distinct word, not just any substring - avoids a channel
  // name like "ESPN4Kids" accidentally counting.
  const has4K = (text) => /\b4k\b/i.test(text);

  // Four tiers, most confident first. A stream is assigned to the FIRST
  // tier it qualifies for, checked in priority order - see the ranking
  // logic reference doc for the full rationale behind this ordering. Tier
  // 5 (EPG-verified broadcaster match) was deliberately removed - the
  // provider's own Xtream EPG data wasn't judged reliable enough as a
  // matching signal. Revisit once M3U support lands with a more trustworthy
  // EPG source (e.g. epg6-style data), as its own dedicated tier rather
  // than reusing this same slot.
  const tiers = [[], [], [], []];
  candidateStreams.forEach(s => {
    const name = (s.name || '').toLowerCase();
    // "Description" specifically means the provider's own EPG/programme
    // text here - Xtream's get_short_epg for Xtream users, or the
    // closest-to-game-time programme entry from the paired EPG file for
    // M3U users (see getCandidateStreamsForGame) - not some other,
    // external source. See the ranking logic reference doc for why that
    // scope was chosen deliberately.
    const description = (s.description || '').toLowerCase();
    const combined = `${name} ${description}`;

    const homeInName = matchesHome(name);
    const awayInName = matchesAway(name);
    const homeInDesc = matchesHome(description);
    const awayInDesc = matchesAway(description);
    const bothInEither = (homeInName || homeInDesc) && (awayInName || awayInDesc);
    const bothInNameAlone = homeInName && awayInName;
    const bothInDescAlone = homeInDesc && awayInDesc;

    const entry = { stream: s, startTimestamp: s.startTimestamp };

    // Tier 1: 4K, plus both teams confirmed somewhere (name and/or
    // description). Foreign-team exclusion doesn't apply - both teams
    // being independently confirmed is a strong anchor on its own.
    if (has4K(combined) && bothInEither) {
      tiers[0].push(entry);
      return;
    }

    // Tier 2: both teams confirmed in EACH field independently (name
    // alone has both, description alone also has both) - stricter than
    // tier 3 below, so checked first.
    if (bothInNameAlone && bothInDescAlone) {
      tiers[1].push(entry);
      return;
    }

    // Tier 3: both teams confirmed across the combined text, not
    // necessarily within a single field.
    if (bothInEither) {
      tiers[2].push(entry);
      return;
    }

    // Tier 4: one team's actual nickname (not just its city/state) in the
    // channel name specifically. The one tier without a strong
    // independent anchor, so foreign-team exclusion applies here only.
    if (matchesHomeNickOnly(name) || matchesAwayNickOnly(name)) {
      if (mentionsForeignTeam(combined)) return;
      tiers[3].push(entry);
    }
  });

  // Break ties within any tier by recency - the EPG entry whose start
  // time sits closest to the game's own scheduled start wins. Streams
  // with no EPG timestamp available sort last within their tier, not
  // excluded. Applied uniformly across all 5 tiers, not just specific
  // ones - every tier could plausibly have multiple qualifying streams.
  if (gameTimestamp !== null) {
    const byRecency = (a, b) => {
      const distA = a.startTimestamp !== null ? Math.abs(a.startTimestamp - gameTimestamp) : Infinity;
      const distB = b.startTimestamp !== null ? Math.abs(b.startTimestamp - gameTimestamp) : Infinity;
      return distA - distB;
    };
    tiers.forEach(tier => tier.sort(byRecency));
  }

  // Every stream that qualified for ANY tier is included - tier number
  // controls display order only, not inclusion. A stream in tier 4 doesn't
  // get discarded just because some other stream also qualified for tier 1.
  // If nothing cleared any tier at all, the flattened result is naturally
  // empty - no separate fallback needed.
  const streamsToReturn = tiers.flat().map(e => e.stream);

  // Confirmed via direct testing in Nuvio that a forced rank-prefix isn't
  // actually needed - Nuvio respects our intended order as returned.
  const nameFormat = user.nameFormat || DEFAULT_NAME_FORMAT;
  const titleFormat = user.titleFormat || DEFAULT_TITLE_FORMAT;
  const streams = streamsToReturn.map((s) => {
    const fields = buildFormatterFields(game, s);
    const name = applyFormatter(nameFormat, fields);
    const title = applyFormatter(titleFormat, fields);
    return {
      name,
      title,
      // `description` is Stremio's modern replacement for the deprecated
      // `title` field - some meta-addons (e.g. AIOStreams) read it as a
      // fallback text source, so mirroring it here costs nothing and helps
      // those aggregators surface our labeling instead of showing blank.
      description: title,
      // Aggregators like AIOStreams run their own quality/resolution
      // parser over each stream and check behaviorHints.filename first,
      // before name/title/description - since our streams are plain-text
      // labeled (no torrent-style quality tags to find), that parser comes
      // up empty and the stream shows no text unless we hand it something
      // here directly.
      behaviorHints: {
        filename: `${name} - ${title}`
      },
      url: s.streamUrl
    };
  });

  res.setHeader('Content-Type', 'application/json');
  res.json({ streams });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Sportio Live running at http://0.0.0.0:${PORT}`);
});

// Collects every M3U user's {playlistUrl, epgUrl} pair - deduplication
// across users who happen to share the same provider is handled inside
// refreshAllM3USources itself, not here.
function getActiveM3uSources() {
  return Object.values(userConfigs)
    .flatMap(u => u.providers || [])
    .filter(p => p.connectionType === 'm3u' && p.m3u)
    .map(p => ({ playlistUrl: p.m3u.playlistUrl, epgUrl: p.m3u.epgUrl }));
}

m3u.startM3uScheduler(getActiveM3uSources, () => m3uSettings);

// Runs every admin-enabled EPGShare01 source through the exact same
// schedule as the M3U cache above (computeNextScheduledRun, reused from
// m3u.js rather than duplicated) - deliberately a separate, independent
// setTimeout loop rather than teaching m3u.js about EPGShare01, so that
// module stays self-contained. An empty enabledSources list (the default)
// just means refreshEnabledSources has nothing to do on a given tick, not
// that the tick is skipped - so enabling sources takes effect on the very
// next tick without needing to restart any timer.
let epgShareSchedulerTimeoutHandle = null;

function startEpgShareScheduler() {
  async function runAndReschedule() {
    await epgshare.refreshEnabledSources(epgShareSettings.enabledSources);
    const nextRun = m3u.computeNextScheduledRun(m3uSettings.daysOfWeek, m3uSettings.times, m3uSettings.timeZone);
    const delay = nextRun ? nextRun.getTime() - Date.now() : 60 * 60 * 1000;
    epgShareSchedulerTimeoutHandle = setTimeout(runAndReschedule, delay);
  }

  // Immediate first attempt on startup, same reasoning as the M3U
  // scheduler - runAndReschedule itself already no-ops when there's
  // nothing enabled.
  runAndReschedule();
}

startEpgShareScheduler();