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
// simple structure actually used here), but with two deliberate
// differences confirmed against a real epg_ripper_*.xml.gz file's actual
// structure: <title> carries a `lang` attribute (`<title lang="en">`), and
// - unlike the provider-specific EPG m3u.js's parser was validated
// against - it's on its own indented line, not immediately adjacent to
// the closing `>` of <programme>, so whitespace between them has to be
// tolerated rather than assumed away.
function parseEpgShareXmltv(content, relevantChannelIds) {
  const programmesByChannel = new Map();
  const pattern = /<programme start="(\d{14}) [^"]*" stop="(\d{14}) [^"]*" channel="([^"]*)">\s*<title[^>]*>([^<]*)<\/title>/g;

  let match;
  while ((match = pattern.exec(content)) !== null) {
    const [, start, stop, channel, title] = match;
    if (relevantChannelIds && !relevantChannelIds.has(channel)) continue;
    if (!programmesByChannel.has(channel)) {
      programmesByChannel.set(channel, []);
    }
    programmesByChannel.get(channel).push({ start, stop, title: title.trim() });
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

// EPGShare01's files are published as gzip (.xml.gz), but this sniffs the
// gzip magic bytes rather than trusting the URL's file extension - an
// admin pointing this at some other, already-uncompressed XMLTV source
// (their own provider's EPG URL, for instance) should still work.
async function fetchAndParseEpgShareSource(url, relevantChannelIds) {
  const res = await axios.get(url, { timeout: 120000, responseType: 'arraybuffer' });
  const buf = Buffer.from(res.data);
  const isGzip = buf.length > 2 && buf[0] === 0x1f && buf[1] === 0x8b;
  const xml = (isGzip ? zlib.gunzipSync(buf) : buf).toString('utf8');

  const programmesByChannel = parseEpgShareXmltv(xml, relevantChannelIds);
  if (programmesByChannel.size === 0) {
    throw new Error('EPGShare01 source parsed but contained no usable programme data');
  }

  return { programmesByChannel, fetchedAt: Date.now() };
}

// ---------------------------------------------------------------------
// Cache store
// ---------------------------------------------------------------------

// Keyed by source URL, same shape/reasoning as m3u.js's m3uSourceCache -
// a shared, in-memory cache since this is a single admin-configured
// source, not a per-user one.
const epgShareCache = new Map(); // sourceUrl -> { programmesByChannel, fetchedAt }

async function refreshEpgShareSource(url) {
  const parsed = await fetchAndParseEpgShareSource(url);
  epgShareCache.set(url, parsed);
  return parsed;
}

function getCachedEpgShareSource(url) {
  return epgShareCache.get(url) || null;
}

function clearEpgShareCache() {
  epgShareCache.clear();
}

// Refreshes every admin-enabled source, independently - one bad/slow
// source (dead link, malformed XML) doesn't block the others, same
// reasoning as m3u.js's refreshAllM3USources. Takes filenames (as stored
// in epgShareSettings.enabledSources), not full URLs, and resolves each
// through sourceFileToUrl itself.
async function refreshEnabledSources(files) {
  const validFiles = (files || []).filter(isKnownSourceFile);
  const results = await Promise.allSettled(
    validFiles.map(file => refreshEpgShareSource(sourceFileToUrl(file)))
  );
  results.forEach((result, i) => {
    if (result.status === 'rejected') {
      console.error(`[EPGShare01] Failed to refresh ${validFiles[i]}:`, result.reason.message);
    } else {
      console.log(`[EPGShare01] Refreshed ${validFiles[i]}: ${result.value.programmesByChannel.size} channels`);
    }
  });
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
function getBestProgrammeForChannel(source, channelId, gameTimestampSec) {
  if (!source || !channelId) return null;
  const programmes = source.programmesByChannel.get(channelId);
  if (!programmes || programmes.length === 0) return null;

  let best = null;
  let bestDist = Infinity;
  for (const p of programmes) {
    const startTimestamp = parseXmltvTimestamp(p.start).getTime() / 1000;
    const dist = gameTimestampSec !== null ? Math.abs(startTimestamp - gameTimestampSec) : 0;
    if (dist < bestDist) {
      bestDist = dist;
      best = { title: p.title, startTimestamp };
    }
  }
  return best;
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
  epgShareCache
};
