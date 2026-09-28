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
const { Readable } = require('stream');
const { pipeline } = require('stream/promises');
const { StringDecoder } = require('string_decoder');
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

    // Forces a real, independent copy of a regex-extracted substring
    // rather than whatever representation V8 chose for the match -
    // confirmed via a real repro (parsing the actual ALL_SOURCES1 file,
    // 1.77GB decompressed) as the cause of catastrophic memory retention
    // that an explicit global.gc() could NOT reclaim on its own: V8 can
    // implement a substring of a huge string (content here is a multi-MB
    // batch of the source - see streamSourceToDir) as a "sliced
    // string" that internally still points at the ENTIRE parent chunk's
    // backing memory. channel is the one field that gets kept alive
    // forever (as part of epgShareCache's channelIds list, see
    // refreshEpgShareSource); start/title/description are only held
    // until they're written to disk, but an uncopied one of these can
    // just as easily keep its whole parent batch pinned in memory until
    // then - confirmed directly: leaving these three uncopied alone
    // left ~340MB of otherwise-dead memory unreclaimable even after
    // forcing a collection, on top of what copying just the channel id
    // already fixed.
    const channel = Buffer.from(channelMatch[1]).toString('utf8');
    if (relevantChannelIds && !relevantChannelIds.has(channel)) continue;
    if (!programmesByChannel.has(channel)) {
      programmesByChannel.set(channel, []);
    }
    // title is kept on its own (not just folded into description) since
    // it's always present even when desc isn't, and there may be uses for
    // it distinct from description later.
    programmesByChannel.get(channel).push({
      start: Buffer.from(startMatch[1]).toString('utf8'),
      title: Buffer.from(title.trim()).toString('utf8'),
      description: desc ? Buffer.from(desc.trim()).toString('utf8') : ''
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

// Sources are processed as a stream: download, gunzip, and the regex scan
// all proceed a few MB at a time, and parsed programmes are appended to
// their per-channel cache files as they accumulate (see
// streamSourceToDir). The previous design downloaded the whole file,
// decompressed it into one buffer (700MB-1.8GB for the largest sources),
// and built every channel's programme list in memory before writing
// anything - so a refresh's memory spike scaled with the size of the
// source. Now it's bounded by roughly PARSE_BATCH_CHARS plus
// PENDING_FLUSH_CHARS regardless of source size. Parsing in batches also
// means no single string ever approaches V8's ~536M-character string
// limit, which the old whole-buffer version had to work around with
// overlapping chunks.
const PARSE_BATCH_CHARS = 4 * 1024 * 1024;
const PENDING_FLUSH_CHARS = 16 * 1024 * 1024;
const PROGRAMME_END_TAG = '</programme>';

// Yields the response body's chunks, gunzipped if it starts with the gzip
// magic bytes. EPGShare01's files are published as gzip (.xml.gz), but
// this sniffs the bytes rather than trusting the URL's file extension - an
// admin pointing this at some other, already-uncompressed XMLTV source
// (their own provider's EPG URL, for instance) should still work.
async function* decodedBodyChunks(body) {
  const iterator = body[Symbol.asyncIterator]();
  const first = await iterator.next();
  if (first.done) return;
  const head = first.value;
  const raw = Readable.from((async function* () {
    yield head;
    for (let r = await iterator.next(); !r.done; r = await iterator.next()) yield r.value;
  })());
  if (head.length > 1 && head[0] === 0x1f && head[1] === 0x8b) {
    const gunzipStream = zlib.createGunzip();
    // A failure anywhere upstream destroys gunzipStream with that error,
    // which then surfaces from the iteration below - nothing to handle here.
    pipeline(raw, gunzipStream).catch(() => {});
    yield* gunzipStream;
  } else {
    yield* raw;
  }
}

// Streams one source into stagingDir as one NDJSON file per channel (one
// programme per line, appended as they're parsed), returning the sorted
// list of channel ids found. Text is only handed to the parser up to the
// last complete </programme>, so no programme is ever split across two
// parse calls; the incomplete tail carries over to the next batch.
async function streamSourceToDir(url, stagingDir) {
  const res = await axios.get(url, { timeout: 120000, responseType: 'stream' });
  const decoder = new StringDecoder('utf8');
  const channelIds = new Set();
  let pending = new Map(); // channel -> [NDJSON lines not yet written]
  let pendingChars = 0;
  let carry = '';

  const flush = async () => {
    const batch = pending;
    pending = new Map();
    pendingChars = 0;
    await mapWithConcurrency([...batch.entries()], EPG_WRITE_CONCURRENCY, ([channel, lines]) =>
      fs.promises.appendFile(path.join(stagingDir, channelCacheFileName(channel)), lines.join('\n') + '\n')
    );
  };

  const parseBatch = async (text) => {
    for (const [channel, programmes] of parseEpgShareXmltv(text)) {
      channelIds.add(channel);
      let lines = pending.get(channel);
      if (!lines) pending.set(channel, (lines = []));
      for (const programme of programmes) {
        const line = JSON.stringify(programme);
        lines.push(line);
        pendingChars += line.length;
      }
    }
    if (pendingChars >= PENDING_FLUSH_CHARS) await flush();
  };

  try {
    for await (const chunk of decodedBodyChunks(res.data)) {
      carry += decoder.write(chunk);
      if (carry.length < PARSE_BATCH_CHARS) continue;
      const cut = carry.lastIndexOf(PROGRAMME_END_TAG);
      if (cut === -1) continue;
      const end = cut + PROGRAMME_END_TAG.length;
      await parseBatch(carry.slice(0, end));
      carry = carry.slice(end);
    }
    carry += decoder.end();
    await parseBatch(carry);
    carry = '';
    await flush();
  } finally {
    res.data.destroy();
  }

  return [...channelIds].sort();
}

// ---------------------------------------------------------------------
// Cache store
// ---------------------------------------------------------------------

// Programme data is kept on disk, not in memory - EPGShare01's largest
// sources decompress to 700MB-1.8GB (see streamSourceToDir above)
// and, unlike m3u.js's paired EPG cache, there's no natural way to filter
// this down to "just the channels in use": this catalog is meant to be
// fully browsable (see getEnabledChannelCatalog) before anyone's picked
// anything from it, so every channel a source offers needs real data
// available, not just ones already referenced by an override. One NDJSON
// file per channel (one programme per line), split into a per-source subdirectory (named by a hash
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

function channelCacheFileName(channelId) {
  return `${crypto.createHash('sha256').update(channelId).digest('hex')}.json`;
}

function channelCacheFilePath(sourceUrl, channelId) {
  return path.join(sourceCacheDir(sourceUrl), channelCacheFileName(channelId));
}

async function readChannelProgrammes(sourceUrl, channelId) {
  try {
    const raw = await fs.promises.readFile(channelCacheFilePath(sourceUrl, channelId), 'utf8');
    // Files written before streaming refreshes existed hold one JSON array
    // rather than NDJSON lines - still readable until the first refresh
    // after an update replaces them.
    if (raw.startsWith('[')) return JSON.parse(raw);
    return raw.split('\n').filter(Boolean).map(line => JSON.parse(line));
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }
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

// Streams the whole source through once (the only way to discover what
// channels/programmes exist at all), spilling programmes to disk as it
// goes - see streamSourceToDir - so only the channel-id list stays in
// memory afterward.
// A handful of enabled sources can add up to tens of thousands of
// channels (confirmed against the real ALL_SOURCES1 file) - writing every
// channel's file with unbounded Promise.all concurrency exhausts the
// process's open-file-descriptor limit (confirmed directly: a real EMFILE
// crash mid-refresh). mapWithConcurrency (already used above for the
// catalog's decompressed-size lookups) caps how many writes are ever
// in flight at once.
const EPG_WRITE_CONCURRENCY = 50;

//
// The new files are written into a scratch directory and only swapped in
// once every one is written - previously the live directory was emptied
// first, so any override lookup during the (multi-second, tens-of-thousands-
// of-files) write saw a half-empty cache, and a failure partway through
// left it that way until the next refresh.
async function refreshEpgShareSource(url) {
  const liveDir = sourceCacheDir(url);
  const stagingDir = `${liveDir}.staging`;
  await fs.promises.rm(stagingDir, { recursive: true, force: true });
  await fs.promises.mkdir(stagingDir, { recursive: true });
  let channelIds;
  try {
    channelIds = await streamSourceToDir(url, stagingDir);
    if (channelIds.length === 0) {
      throw new Error('EPGShare01 source parsed but contained no usable programme data');
    }
    await clearSourceCacheDir(url);
    await fs.promises.rename(stagingDir, liveDir);
  } catch (err) {
    await fs.promises.rm(stagingDir, { recursive: true, force: true });
    throw err;
  }
  const cached = { url, channelIds, fetchedAt: Date.now() };
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
//
// One source at a time: each one briefly holds its entire decompressed
// file (up to ~1.8GB) plus everything parsed from it, so refreshing several
// in parallel stacked those peaks - enabling two big sources could double
// the container's memory spike for no benefit on a background schedule.
async function refreshEnabledSources(files) {
  const validFiles = (files || []).filter(isKnownSourceFile);
  const results = [];
  for (const file of validFiles) {
    try {
      const refreshed = await refreshEpgShareSource(sourceFileToUrl(file));
      console.log(`[EPGShare01] Refreshed ${file}: ${refreshed.channelIds.length} channels`);
      results.push({ file, success: true, channelCount: refreshed.channelIds.length });
    } catch (err) {
      console.error(`[EPGShare01] Failed to refresh ${file}:`, err.message);
      results.push({ file, success: false, error: err.message });
    }
    // Confirmed via /api/admin/diagnostics: parsing a source (gunzipping a
    // file that can decompress to 700MB-1.8GB, then regex-scanning it - see
    // streamSourceToDir) balloons Node's "external" native memory
    // far more than it grows the actual JS heap, so V8's heap-pressure-driven
    // GC scheduling has little reason to collect it - it can sit around
    // fully reclaimable but uncollected indefinitely. Forcing a collection
    // after each source reclaims it before the next one's download and
    // decompression can stack on top of it. A no-op unless the process was
    // started with --expose-gc (see package.json's start script).
    if (typeof global.gc === 'function') global.gc();
  }

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
  streamSourceToDir,
  channelCacheFileName,
  refreshEpgShareSource,
  refreshEnabledSources,
  getCachedEpgShareSource,
  clearEpgShareCache,
  getBestProgrammeForChannel,
  getEnabledChannelCatalog,
  findOverrideProgramme,
  epgShareCache
};
