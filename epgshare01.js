// EPGShare01 support - lets an admin choose which of EPGShare01's
// community-maintained XMLTV feeds (https://epgshare01.online/) are made
// available as EPG sources on this server.
//
// Important scope note: enabling a source here does NOT override anyone's
// EPG by itself. This module only fetches, caches, and exposes programme
// data by channel id - it's the raw material a later per-channel picker
// (a user choosing, for one of their own channels, "use this EPGShare01
// channel's guide instead of my provider's") will read from. Admin control
// exists because fetching+parsing even one of these XMLTV files is real,
// avoidable load a small VPS may not want to carry - see epgShareSettings
// in server.js for where that opt-in list is stored.
//
// Deliberately a standalone module (like m3u.js) with no dependency on the
// caller's internal state.

const axios = require('axios');
const zlib = require('zlib');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { parseXmltvTimestamp } = require('./m3u.js');

const EPGSHARE_BASE_URL = 'https://epgshare01.online/epgshare01/';

// Restricts admin-supplied source identifiers to this exact, known
// naming convention (confirmed against the real directory listing) before
// they're ever concatenated into a URL this server fetches server-side -
// not just an admin-page nicety, but the thing standing between
// epgshare-settings.json and an arbitrary outbound request built from
// whatever ends up in that file.
const EPGSHARE_FILENAME_PATTERN = /^epg_ripper_[A-Za-z0-9_.-]+\.xml\.gz$/;

function isKnownSourceFile(file) {
  return typeof file === 'string' && EPGSHARE_FILENAME_PATTERN.test(file);
}

function sourceFileToUrl(file) {
  return EPGSHARE_BASE_URL + file;
}

// ---------------------------------------------------------------------
// XMLTV parsing
// ---------------------------------------------------------------------

// Same regex-based approach as m3u.js's parseXMLTVEpg (a full DOM parse of
// a large XMLTV file is unnecessarily slow/memory-hungry for the flat,
// simple structure actually used here), with a few deliberate differences
// confirmed against real epg_ripper_*.xml.gz files: <title> carries a
// `lang` attribute (`<title lang="en">`), and - unlike the
// provider-specific EPG m3u.js's parser was validated against - it's on
// its own indented line, not immediately adjacent to the closing `>` of
// <programme>, so whitespace between them has to be tolerated rather than
// assumed away.
//
// Critically, <programme>'s own attribute ORDER is NOT consistent across
// sources - confirmed directly: epg_ripper_US_SPORTS1 writes
// `start="..." stop="..." channel="..."`, but epg_ripper_RAKUTEN1 writes
// `channel="..." start="..." stop="..."` instead. An earlier version of
// this regex baked in one fixed order and silently parsed zero programmes
// (not an error - just an empty result) for every source using the other
// one. Fixed by capturing the whole opening tag's raw attribute text
// first, then pulling start/channel out of THAT with their own
// order-independent sub-patterns.
//
// <desc> (the actual programme description/synopsis, distinct from
// <title>) is captured too where present, tolerating an optional
// <sub-title> element in between - confirmed necessary against real data:
// epg_ripper_PLEX1 puts <sub-title> between <title> and <desc> for
// essentially every entry, and without accounting for it the desc capture
// below would silently miss almost all of that source's descriptions
// (339 out of 4010 matched vs. 4009 out of 4010 once <sub-title> is
// tolerated). <desc> itself isn't universal even so - confirmed present
// on anywhere from ~50% (AL1) to 100% (US_SPORTS1) of entries depending
// on the source - so it's captured as optional, not required.
const PROGRAMME_TAG_PATTERN = /<programme\s+([^>]*)>\s*<title[^>]*>([^<]*)<\/title>(?:\s*<sub-title[^>]*>[^<]*<\/sub-title>)?(?:\s*<desc[^>]*>([^<]*)<\/desc>)?/g;
const START_ATTR_PATTERN = /\bstart="(\d{14})/;
const CHANNEL_ATTR_PATTERN = /\bchannel="([^"]*)"/;

function parseEpgShareXmltv(content, relevantChannelIds) {
  const programmesByChannel = new Map();

  let match;
  while ((match = PROGRAMME_TAG_PATTERN.exec(content)) !== null) {
    const [, attrs, title, desc] = match;
    const startMatch = attrs.match(START_ATTR_PATTERN);
    const channelMatch = attrs.match(CHANNEL_ATTR_PATTERN);
    if (!startMatch || !channelMatch) continue;

    const channel = channelMatch[1];
    if (relevantChannelIds && !relevantChannelIds.has(channel)) continue;
    if (!programmesByChannel.has(channel)) {
      programmesByChannel.set(channel, []);
    }
    // title is kept on its own (not just folded into description) since
    // it's always present even when desc isn't, and there may be uses for
    // it distinct from description later.
    programmesByChannel.get(channel).push({
      start: startMatch[1],
      title: title.trim(),
      description: desc ? desc.trim() : ''
    });
  }

  return programmesByChannel;
}

// ---------------------------------------------------------------------
// Source catalog - what's available to enable, with real sizes
// ---------------------------------------------------------------------

// EPGShare01's index is a plain Apache-style directory listing - each row
// is `<a href="FILENAME">...</a>  DD-Mon-YYYY  HH:MM  SIZE`. Only the
// *.xml.gz rows matter here (each has .pdf/.txt companions listed
// alongside it, deliberately ignored).
function parseDirectoryListing(html) {
  const pattern = /<a href="(epg_ripper_[^"]+\.xml\.gz)">[^<]*<\/a>\s+\d{2}-\w{3}-\d{4}\s+\d{2}:\d{2}\s+(\d+)/g;
  const entries = [];
  let match;
  while ((match = pattern.exec(html)) !== null) {
    entries.push({ file: match[1], compressedBytes: Number(match[2]) });
  }
  return entries;
}

// The gzip format stores the uncompressed size as a 4-byte little-endian
// trailer (RFC 1952's ISIZE field) - an HTTP Range request for just the
// last 4 bytes gets the EXACT decompressed size without downloading or
// decompressing the file at all. Confirmed against real files during
// design: compression ratio varies wildly across sources (10x on one,
// 45x on another), so this is the only way to show an honest number
// rather than a guessed multiplier. (ISIZE wraps at 4GB, but nothing in
// this catalog is remotely close to that.) Returns null - not a thrown
// error - on any failure, since this only feeds a display column and one
// slow/unreachable file shouldn't break the whole catalog fetch.
async function fetchDecompressedSize(url) {
  try {
    const res = await axios.get(url, { timeout: 15000, responseType: 'arraybuffer', headers: { Range: 'bytes=-4' } });
    if (res.status !== 206 || res.data.length !== 4) return null;
    return Buffer.from(res.data).readUInt32LE(0);
  } catch (err) {
    return null;
  }
}

// Runs `fn` over `items` with at most `limit` in flight at once -
// 100+ tiny range requests are cheap individually, but firing them all
// at once isn't a polite way to treat someone else's free file server.
async function mapWithConcurrency(items, limit, fn) {
  const results = new Array(items.length);
  let nextIndex = 0;
  async function worker() {
    while (nextIndex < items.length) {
      const i = nextIndex++;
      results[i] = await fn(items[i], i);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

// The catalog itself (which sources exist, and their sizes) is metadata
// for the admin picker - separate from, and far cheaper than, actually
// fetching+parsing any given source's EPG data. Cached module-level since
// it changes rarely and is shared across all admin sessions.
let catalogCache = null; // { fetchedAt, sources: [{file, url, compressedBytes, decompressedBytes}] }

async function refreshCatalog() {
  const res = await axios.get(EPGSHARE_BASE_URL, { timeout: 30000 });
  const entries = parseDirectoryListing(res.data);
  const sources = await mapWithConcurrency(entries, 8, async (entry) => {
    const url = sourceFileToUrl(entry.file);
    const decompressedBytes = await fetchDecompressedSize(url);
    // Every *.xml.gz entry has a same-named *.txt companion listing that
    // source's channel names (confirmed against the real directory
    // listing) - surfaced so the admin can sanity-check what's actually
    // in a source before enabling it, without downloading the XMLTV file.
    const txtUrl = url.replace(/\.xml\.gz$/, '.txt');
    return { file: entry.file, url, txtUrl, compressedBytes: entry.compressedBytes, decompressedBytes };
  });
  sources.sort((a, b) => a.file.localeCompare(b.file));
  catalogCache = { fetchedAt: Date.now(), sources };
  return catalogCache;
}

function getCachedCatalog() {
  return catalogCache;
}

// ---------------------------------------------------------------------
// Fetch + parse a source
// ---------------------------------------------------------------------

// V8 hard-caps a single JS string at ~536,870,888 characters
// (0x1fffffe8) - confirmed directly against a real source: EPGShare01's
// largest files (epg_ripper_US_LOCALS1, epg_ripper_ALL_SOURCES1)
// decompress to 700MB-1.8GB, so decoding the whole buffer to one string
// via .toString('utf8') throws outright for those specifically, even
// though the gunzip step itself succeeds fine (Buffers aren't
// string-length-limited). Fixed by scanning the decompressed buffer in
// overlapping byte-range chunks instead, each decoded to its own
// (comfortably-under-the-limit) string. The overlap is generously larger
// than any single matched <programme ...>...</title> span can plausibly
// be, so a match straddling a chunk boundary still lands fully inside the
// next chunk's overlap region and gets picked up there - a programme
// entry counted twice in that tiny overlap is a harmless duplicate array
// entry, so no de-duplication bookkeeping is needed.
const PARSE_CHUNK_BYTES = 200 * 1024 * 1024;
const PARSE_CHUNK_OVERLAP_BYTES = 64 * 1024;

function parseEpgShareXmltvBuffer(buf, relevantChannelIds) {
  if (buf.length <= PARSE_CHUNK_BYTES) {
    return parseEpgShareXmltv(buf.toString('utf8'), relevantChannelIds);
  }

  const programmesByChannel = new Map();
  for (let offset = 0; offset < buf.length; offset += PARSE_CHUNK_BYTES) {
    const end = Math.min(offset + PARSE_CHUNK_BYTES + PARSE_CHUNK_OVERLAP_BYTES, buf.length);
    const chunkResult = parseEpgShareXmltv(buf.subarray(offset, end).toString('utf8'), relevantChannelIds);
    for (const [channel, programmes] of chunkResult) {
      if (!programmesByChannel.has(channel)) programmesByChannel.set(channel, []);
      programmesByChannel.get(channel).push(...programmes);
    }
  }
  return programmesByChannel;
}

// EPGShare01's files are published as gzip (.xml.gz), but this sniffs the
// gzip magic bytes rather than trusting the URL's file extension - an
// admin pointing this at some other, already-uncompressed XMLTV source
// (their own provider's EPG URL, for instance) should still work.
async function fetchAndParseEpgShareSource(url, relevantChannelIds) {
  const res = await axios.get(url, { timeout: 120000, responseType: 'arraybuffer' });
  const buf = Buffer.from(res.data);
  const isGzip = buf.length > 2 && buf[0] === 0x1f && buf[1] === 0x8b;
  const decompressed = isGzip ? zlib.gunzipSync(buf) : buf;

  const programmesByChannel = parseEpgShareXmltvBuffer(decompressed, relevantChannelIds);
  if (programmesByChannel.size === 0) {
    throw new Error('EPGShare01 source parsed but contained no usable programme data');
  }

  return { programmesByChannel, fetchedAt: Date.now() };
}

// ---------------------------------------------------------------------
// Cache store
// ---------------------------------------------------------------------

// Programme data is kept on disk, not in memory - EPGShare01's largest
// sources decompress to 700MB-1.8GB (see fetchAndParseEpgShareSource above)
// and, unlike m3u.js's paired EPG cache, there's no natural way to filter
// this down to "just the channels in use": this catalog is meant to be
// fully browsable (see getEnabledChannelCatalog) before anyone's picked
// anything from it, so every channel a source offers needs real data
// available, not just ones already referenced by an override. One JSON
// file per channel, split into a per-source subdirectory (named by a hash
// of the source URL) so an entire source's old files can be dropped in one
// shot on refresh without touching any other source's files.
const EPG_CACHE_DIR = path.join(__dirname, 'data', 'epg-cache');
if (!fs.existsSync(EPG_CACHE_DIR)) {
  fs.mkdirSync(EPG_CACHE_DIR, { recursive: true });
}

function sourceCacheDir(sourceUrl) {
  const hash = crypto.createHash('sha256').update(sourceUrl).digest('hex').slice(0, 16);
  return path.join(EPG_CACHE_DIR, hash);
}

function channelCacheFilePath(sourceUrl, channelId) {
  const hash = crypto.createHash('sha256').update(channelId).digest('hex');
  return path.join(sourceCacheDir(sourceUrl), `${hash}.json`);
}

async function readChannelProgrammes(sourceUrl, channelId) {
  try {
    const raw = await fs.promises.readFile(channelCacheFilePath(sourceUrl, channelId), 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }
}

async function writeChannelProgrammes(sourceUrl, channelId, programmes) {
  await fs.promises.writeFile(channelCacheFilePath(sourceUrl, channelId), JSON.stringify(programmes));
}

async function clearSourceCacheDir(sourceUrl) {
  await fs.promises.rm(sourceCacheDir(sourceUrl), { recursive: true, force: true });
}

// Keyed by source URL, same shape/reasoning as m3u.js's m3uSourceCache -
// shared across all admins/users, since this is a single admin-configured
// source, not a per-user one. Unlike before, the cached value here is
// deliberately lightweight - just the sorted list of channel ids a source
// offers (needed instantly for the picker, see getEnabledChannelCatalog)
// plus the source's own URL (so a lookup later knows which on-disk
// subdirectory to read from) - the actual programme data lives on disk,
// read one channel at a time, only when something actually asks for it.
const epgShareCache = new Map(); // sourceUrl -> { url, channelIds, fetchedAt }

// Fetches+parses the whole source (still one full pass over the whole
// file - there's no way around that, it's the only way to discover what
// channels/programmes exist at all), then immediately spills every
// channel's programme array out to its own file and lets the full
// in-memory Map fall out of scope. Memory briefly reflects the whole
// parsed source while this runs (same "temporary spike during a refresh,
// not a standing cost" shape as the art warm-up's rendering pass), but
// nothing from it stays resident afterward.
async function refreshEpgShareSource(url) {
  const parsed = await fetchAndParseEpgShareSource(url);
  await clearSourceCacheDir(url);
  await fs.promises.mkdir(sourceCacheDir(url), { recursive: true });
  const channelIds = [...parsed.programmesByChannel.keys()].sort();
  await Promise.all(channelIds.map(channelId =>
    writeChannelProgrammes(url, channelId, parsed.programmesByChannel.get(channelId))
  ));
  const cached = { url, channelIds, fetchedAt: parsed.fetchedAt };
  epgShareCache.set(url, cached);
  return cached;
}

function getCachedEpgShareSource(url) {
  return epgShareCache.get(url) || null;
}

// Counterpart to refreshEpgShareSource's per-source disk write: drops
// every source's on-disk files, not just the in-memory channel-id lists -
// a source that gets disabled and never refreshed again would otherwise
// leave its old files on disk forever, since refreshEnabledSources only
// ever touches sources that are still enabled.
async function clearEpgShareCache() {
  epgShareCache.clear();
  await fs.promises.rm(EPG_CACHE_DIR, { recursive: true, force: true });
  await fs.promises.mkdir(EPG_CACHE_DIR, { recursive: true });
}

// Refreshes every admin-enabled source, independently - one bad/slow
// source (dead link, malformed XML) doesn't block the others, same
// reasoning as m3u.js's refreshAllM3USources. Takes filenames (as stored
// in epgShareSettings.enabledSources), not full URLs, and resolves each
// through sourceFileToUrl itself.
// Returns one result per file - {file, success, channelCount} on success,
// {file, success: false, error} on failure - rather than raw
// Promise.allSettled entries, so a caller can surface exactly which
// source(s) failed and why (the admin recache route does) without having
// to separately re-derive the valid/ordered file list itself.
async function refreshEnabledSources(files) {
  const validFiles = (files || []).filter(isKnownSourceFile);
  const settled = await Promise.allSettled(
    validFiles.map(file => refreshEpgShareSource(sourceFileToUrl(file)))
  );
  const results = settled.map((result, i) => {
    const file = validFiles[i];
    if (result.status === 'rejected') {
      console.error(`[EPGShare01] Failed to refresh ${file}:`, result.reason.message);
      return { file, success: false, error: result.reason.message };
    }
    console.log(`[EPGShare01] Refreshed ${file}: ${result.value.channelIds.length} channels`);
    return { file, success: true, channelCount: result.value.channelIds.length };
  });

  // Confirmed via /api/admin/diagnostics: parsing a source (gunzipping a
  // file that can decompress to 700MB-1.8GB, then regex-scanning it - see
  // fetchAndParseEpgShareSource) balloons Node's "external" native memory
  // far more than it grows the actual JS heap, so V8's heap-pressure-driven
  // GC scheduling has little reason to collect it - it can sit around
  // fully reclaimable but uncollected indefinitely. Forcing a collection
  // right here, once every source in this batch has finished, reclaims it
  // immediately. A no-op unless the process was started with --expose-gc
  // (see package.json's start script).
  if (typeof global.gc === 'function') global.gc();

  return results;
}

// ---------------------------------------------------------------------
// Programme lookup
// ---------------------------------------------------------------------

// Picks the single programme entry for one channel id whose start time
// sits closest to the game's own scheduled time - same "closest in time
// wins" approach as m3u.js's getCandidateStreamsForGame. Unlike that
// function, this does NOT run extractRealDate's title-based date recovery
// - that quirk (real date hidden in the title, XMLTV start/stop just
// padding) was confirmed against one specific provider's own EPG, not
// EPGShare01's, whose start/stop timestamps are the actual schedule data.
//
// The override this feeds is specifically a DESCRIPTION override - falls
// back to the programme's title when that particular entry has no <desc>
// (not every source populates it for every entry - see the parser above),
// so an override still produces something rather than an empty string.
async function getBestProgrammeForChannel(source, channelId, gameTimestampSec) {
  if (!source || !channelId) return null;
  const programmes = await readChannelProgrammes(source.url, channelId);
  if (!programmes || programmes.length === 0) return null;

  let best = null;
  let bestDist = Infinity;
  for (const p of programmes) {
    const startTimestamp = parseXmltvTimestamp(p.start).getTime() / 1000;
    const dist = gameTimestampSec !== null ? Math.abs(startTimestamp - gameTimestampSec) : 0;
    if (dist < bestDist) {
      bestDist = dist;
      best = { title: p.title, description: p.description || p.title, startTimestamp };
    }
  }
  return best;
}

// Lists every admin-enabled source's channel ids, grouped by source file -
// this is the browsable catalog a user's per-channel picker searches
// against, kept source-scoped (rather than flattened into one merged list)
// so the picker can offer "search within just this source" as well as
// "search everything". Only draws from sources that are both enabled AND
// already cached (a source the scheduler hasn't fetched yet just
// contributes nothing, same as everywhere else this cache is read) -
// never triggers a fetch itself, since this can be called from a
// user-facing request and must stay cheap.
function getEnabledChannelCatalog(enabledFiles) {
  const result = [];
  for (const file of enabledFiles || []) {
    if (!isKnownSourceFile(file)) continue;
    const source = getCachedEpgShareSource(sourceFileToUrl(file));
    if (!source) continue;
    result.push({ file, channelIds: source.channelIds });
  }
  return result;
}

// Looks up one EPGShare01 channel id's best-matching programme across
// every admin-enabled source, stopping at the first source that has it -
// a user's per-channel override is stored as just a channel id (not
// "channel id + which source"), since the same id could plausibly appear
// in more than one enabled source and there's no reason to force a
// specific one.
async function findOverrideProgramme(epgShareChannelId, enabledFiles, gameTimestampSec) {
  if (!epgShareChannelId) return null;
  for (const file of enabledFiles || []) {
    if (!isKnownSourceFile(file)) continue;
    const source = getCachedEpgShareSource(sourceFileToUrl(file));
    if (!source) continue;
    const result = await getBestProgrammeForChannel(source, epgShareChannelId, gameTimestampSec);
    if (result) return result;
  }
  return null;
}

module.exports = {
  EPGSHARE_BASE_URL,
  EPGSHARE_FILENAME_PATTERN,
  isKnownSourceFile,
  sourceFileToUrl,
  parseDirectoryListing,
  fetchDecompressedSize,
  refreshCatalog,
  getCachedCatalog,
  parseEpgShareXmltv,
  fetchAndParseEpgShareSource,
  refreshEpgShareSource,
  refreshEnabledSources,
  getCachedEpgShareSource,
  clearEpgShareCache,
  getBestProgrammeForChannel,
  getEnabledChannelCatalog,
  findOverrideProgramme,
  epgShareCache
};
