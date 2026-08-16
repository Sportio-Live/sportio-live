// M3U support - parsing and caching layer.
//
// This is the foundation everything else (wizard setup, Category Search,
// catalog/stream routes) builds on. Design was validated against a real
// provider's actual playlist + EPG file pair before any of this was
// written - see sportio-live-todo.md for the full research history
// (97.9% tvg-id-to-EPG match rate, confirmed multi-category channel
// membership, confirmed EPG timestamp padding quirk, etc).
//
// A note on scale: parsing a real ~150MB EPG file takes roughly 2-3
// seconds end to end. That's far too slow to ever run on a live user
// request - this is why the design settled on a periodically-refreshed,
// shared background cache rather than fetching/parsing on demand. See
// scheduleM3URefresh() below.

const axios = require('axios');

// ---------------------------------------------------------------------
// Playlist parsing
// ---------------------------------------------------------------------

// Parses raw M3U playlist text into:
// - channels: array of { id, name, logo, streamUrl, categories: [...] }
//   (categories is always an array - a channel can genuinely belong to
//   more than one group-title at once, confirmed against real data: 903
//   such channels in the file used to validate this design)
// - categoryList: array of { name, channelCount }, sorted alphabetically
//
// Deliberately not a full M3U-spec parser - just enough structure
// extraction for the fields actually used, matching the real-world
// format confirmed during design against actual provider output.
function parseM3UPlaylist(content) {
  const blocks = content.split(/(?=#EXTINF:)/);
  const channelsById = new Map();

  for (const block of blocks) {
    if (!block.startsWith('#EXTINF:')) continue;

    const idMatch = block.match(/tvg-id="([^"]*)"/);
    const logoMatch = block.match(/tvg-logo="([^"]*)"/);
    const groupMatch = block.match(/group-title="([^"]*)"/);
    const extinfLine = block.split('\n')[0];
    const nameMatch = extinfLine.match(/,([^,]*)$/);
    const urlMatch = block.match(/\n(https?:\/\/\S+)/);

    // Skip malformed entries rather than let one bad line break the whole
    // parse - a missing id or stream URL means the entry isn't usable
    // anyway.
    if (!idMatch || !urlMatch) continue;

    const id = idMatch[1];
    const name = (nameMatch ? nameMatch[1] : id).trim();
    const logo = logoMatch ? logoMatch[1] : '';
    const streamUrl = urlMatch[1].trim();
    const group = groupMatch ? groupMatch[1] : '';

    if (!channelsById.has(id)) {
      channelsById.set(id, { id, name, logo, streamUrl, categories: new Set() });
    }
    if (group) {
      channelsById.get(id).categories.add(group);
    }
  }

  const channels = [...channelsById.values()].map(ch => ({
    ...ch,
    categories: [...ch.categories]
  }));

  const categoryCounts = new Map();
  for (const ch of channels) {
    for (const cat of ch.categories) {
      categoryCounts.set(cat, (categoryCounts.get(cat) || 0) + 1);
    }
  }
  const categoryList = [...categoryCounts.entries()]
    .map(([name, channelCount]) => ({ name, channelCount }))
    .sort((a, b) => a.name.localeCompare(b.name));

  return { channels, categoryList };
}

// ---------------------------------------------------------------------
// EPG (XMLTV) parsing
// ---------------------------------------------------------------------

// Parses raw XMLTV text into a Map of channel_id -> array of
// { start, stop, title } programme entries.
//
// Deliberately regex-based rather than a full XML DOM parse - the
// confirmed real-world structure here is simple and flat (no nesting to
// worry about), and a full DOM parse of a 150MB+ file would be far
// slower and more memory-hungry than needed. relevantChannelIds (from
// the paired playlist) is used to skip storing programme data for
// channels that aren't even in this provider's playlist - the shared EPG
// source covers more channels than any one playlist actually uses.
function parseXMLTVEpg(content, relevantChannelIds) {
  const programmesByChannel = new Map();
  const pattern = /<programme start="(\d{14}) [^"]*" stop="(\d{14}) [^"]*" channel="([^"]*)"><title>([^<]*)<\/title>/g;

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
// Real-date extraction from title text
// ---------------------------------------------------------------------

// Confirmed during design: many EPG entries pad the same event across
// many consecutive, identically-titled fixed-length time blocks rather
// than giving one precise start/stop range - the REAL scheduled
// date/time is often embedded in the title text itself instead. This
// extracts that real date where possible, falling back to the XMLTV
// start field otherwise. Two known real formats, confirmed against
// actual provider data during design:
//   "(2026-08-19 01:00:05)" - ISO-style, in parens
//   "8/15 1pm"              - M/D + hour+ampm, no explicit year
const ISO_DATE_PATTERN = /\((\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})\)/;
const MD_DATE_PATTERN = /(\d{1,2})\/(\d{1,2})\s+(\d{1,2})(am|pm)/i;

function parseXmltvTimestamp(ts) {
  const y = ts.slice(0, 4), mo = ts.slice(4, 6), d = ts.slice(6, 8);
  const h = ts.slice(8, 10), mi = ts.slice(10, 12), s = ts.slice(12, 14);
  return new Date(Date.UTC(+y, +mo - 1, +d, +h, +mi, +s));
}

function extractRealDate(title, fallbackStartTs, assumedYear) {
  const isoMatch = title.match(ISO_DATE_PATTERN);
  if (isoMatch) {
    const [, y, mo, d, h, mi, s] = isoMatch;
    return { date: new Date(Date.UTC(+y, +mo - 1, +d, +h, +mi, +s)), source: 'title-iso' };
  }

  const mdMatch = title.match(MD_DATE_PATTERN);
  if (mdMatch) {
    const [, month, day, hour, ampm] = mdMatch;
    let h24 = (+hour) % 12;
    if (ampm.toLowerCase() === 'pm') h24 += 12;
    return { date: new Date(Date.UTC(assumedYear, +month - 1, +day, h24, 0, 0)), source: 'title-md' };
  }

  return { date: parseXmltvTimestamp(fallbackStartTs), source: 'xmltv-fallback' };
}

// Builds the candidate stream list for one specific game, from a parsed
// M3U source - normalized into the exact same {name, description,
// startTimestamp, streamUrl} shape the existing Xtream-based tier-
// matching logic already expects, so that logic can run completely
// unchanged regardless of which source produced the candidates.
//
// For each relevant channel, picks the ONE programme entry whose real,
// extracted date/time (not the possibly-padded XMLTV start field - see
// extractRealDate above) sits closest to the game's own scheduled time.
// This single choice is what actually solves the "same channel has many
// duplicate padded programme blocks" problem for this use case - since
// only one programme per channel is ever considered here, the duplicates
// never even get compared against each other. Verified against real
// provider data during design (correctly picks a genuine, close-to-game
// entry over hours of generic padding noise on either side of it).
function getCandidateStreamsForGame(source, configuredCategoryIds, gameTimestampSec) {
  const categorySet = new Set(configuredCategoryIds);
  const relevantChannels = source.channels.filter(ch => ch.categories.some(c => categorySet.has(c)));

  return relevantChannels.map(ch => {
    const programmes = source.programmesByChannel.get(ch.id) || [];
    let bestTitle = '';
    let bestStartTimestamp = null;
    let bestDist = Infinity;

    for (const p of programmes) {
      const { date } = extractRealDate(p.title, p.start, new Date().getFullYear());
      const startTimestamp = date.getTime() / 1000;
      const dist = gameTimestampSec !== null ? Math.abs(startTimestamp - gameTimestampSec) : 0;
      if (dist < bestDist) {
        bestDist = dist;
        bestTitle = p.title;
        bestStartTimestamp = startTimestamp;
      }
    }

    return {
      name: ch.name,
      description: bestTitle,
      startTimestamp: bestStartTimestamp,
      streamUrl: ch.streamUrl,
      categoryLabel: ch.categories[0] || ''
    };
  });
}

// ---------------------------------------------------------------------
// Fetch + parse a full source
// ---------------------------------------------------------------------

// Fetches and parses one playlist+EPG pair end to end. This is the
// expensive, slow operation (seconds, not milliseconds, for a real-sized
// EPG file) that must never run on a live user request - only from the
// background refresh scheduler.
//
// Uses Promise.allSettled rather than Promise.all specifically so a
// failure can be attributed to the correct URL - Promise.all would fail
// fast and lose which one was actually the problem, but the wizard needs
// to tell the user which of their two URLs is bad.
async function fetchAndParseM3USource(playlistUrl, epgUrl) {
  const [playlistResult, epgResult] = await Promise.allSettled([
    axios.get(playlistUrl, { timeout: 30000, responseType: 'text', transformResponse: [d => d] }),
    axios.get(epgUrl, { timeout: 60000, responseType: 'text', transformResponse: [d => d] })
  ]);

  if (playlistResult.status === 'rejected' || epgResult.status === 'rejected') {
    const err = new Error('Failed to fetch M3U source');
    err.playlistFailed = playlistResult.status === 'rejected';
    err.epgFailed = epgResult.status === 'rejected';
    err.playlistError = playlistResult.status === 'rejected' ? playlistResult.reason.message : null;
    err.epgError = epgResult.status === 'rejected' ? epgResult.reason.message : null;
    throw err;
  }

  const { channels, categoryList } = parseM3UPlaylist(playlistResult.value.data);
  if (channels.length === 0) {
    const err = new Error('Playlist parsed but contained no usable channels');
    err.playlistFailed = true;
    err.epgFailed = false;
    throw err;
  }

  const relevantIds = new Set(channels.map(c => c.id));
  const programmesByChannel = parseXMLTVEpg(epgResult.value.data, relevantIds);

  return {
    channels,
    categoryList,
    programmesByChannel,
    fetchedAt: Date.now()
  };
}

// ---------------------------------------------------------------------
// Cache store
// ---------------------------------------------------------------------

// Keyed by playlistUrl - the natural unique identifier for a source,
// since different users can each bring their own, completely different
// provider. This is a shared, in-memory cache: the heavy parsed catalog
// data is never stored per-user (a user's own stored data stays tiny -
// just their two URLs), matching the settled design. Refresh cadence
// itself is a single global admin setting (built separately, in the
// scheduler) - this map just holds whatever the most recent successful
// parse produced, independent of how the refresh was triggered.
const m3uSourceCache = new Map(); // playlistUrl -> parsed source result

async function refreshM3USource(playlistUrl, epgUrl) {
  const parsed = await fetchAndParseM3USource(playlistUrl, epgUrl);
  m3uSourceCache.set(playlistUrl, parsed);
  return parsed;
}

function getCachedM3USource(playlistUrl) {
  return m3uSourceCache.get(playlistUrl) || null;
}

// ---------------------------------------------------------------------
// Scheduler
// ---------------------------------------------------------------------

// Finds the next actual UTC instant matching one of the configured
// day-of-week + clock-time combinations, in the given timezone.
// Deliberately computes the UTC offset separately for EACH candidate day
// (via noon UTC on that specific date as an anchor) rather than reusing
// "now's" offset - the two can genuinely differ across a DST transition,
// and a schedule spanning one needs the correct offset for the actual
// candidate day, not whatever offset happened to be in effect when this
// function was called. Verified against real test cases during design,
// including a DST-fallback transition specifically (confirmed it
// correctly used the post-transition offset, not a stale pre-transition
// one) and multi-time-per-day rollover within the same day.
const DAY_NAMES = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'];

function getOffsetMinutesAt(dateUtcNoon, timeZone) {
  const formatter = new Intl.DateTimeFormat('en-US', { timeZone, timeZoneName: 'shortOffset' });
  const parts = formatter.formatToParts(dateUtcNoon);
  const offsetPart = parts.find(p => p.type === 'timeZoneName').value; // e.g. 'GMT-4' or 'GMT+9'
  const match = offsetPart.match(/GMT([+-]\d+)(?::(\d+))?/);
  if (!match) return 0;
  const hours = parseInt(match[1], 10);
  const minutes = match[2] ? parseInt(match[2], 10) : 0;
  return hours * 60 + (hours < 0 ? -minutes : minutes);
}

// daysOfWeek: array of 'sun'..'sat' (any subset). times: array of 'HH:MM'
// 24-hour strings (any subset, one schedule can have several times per
// day). Searches up to 8 days ahead - always finds a match given at
// least one day and one time are configured.
function computeNextScheduledRun(daysOfWeek, times, timeZone, now = new Date()) {
  const daySet = new Set(daysOfWeek.map(d => d.toLowerCase()));
  const sortedTimes = [...times].sort();

  const nowFormatter = new Intl.DateTimeFormat('en-US', {
    timeZone, year: 'numeric', month: '2-digit', day: '2-digit', hourCycle: 'h23'
  });
  const nowParts = nowFormatter.formatToParts(now);
  const get = (type) => nowParts.find(p => p.type === type).value;
  const todayY = parseInt(get('year'), 10), todayM = parseInt(get('month'), 10), todayD = parseInt(get('day'), 10);

  for (let dayOffset = 0; dayOffset <= 7; dayOffset++) {
    const candidateUtcNoon = new Date(Date.UTC(todayY, todayM - 1, todayD + dayOffset, 12, 0, 0));
    const candidateDayName = DAY_NAMES[candidateUtcNoon.getUTCDay()];
    if (!daySet.has(candidateDayName)) continue;

    const offsetMinutes = getOffsetMinutesAt(candidateUtcNoon, timeZone);

    for (const t of sortedTimes) {
      const [hh, mm] = t.split(':').map(Number);
      const candidateUtcMs = Date.UTC(todayY, todayM - 1, todayD + dayOffset, hh, mm, 0) - offsetMinutes * 60000;
      const candidateDate = new Date(candidateUtcMs);
      if (candidateDate > now) {
        return candidateDate;
      }
    }
  }
  return null; // shouldn't happen with at least one day and one time configured
}

// Refreshes every distinct M3U source currently in use, given a getter
// function returning [{playlistUrl, epgUrl}, ...] - deliberately a
// callback rather than this module reaching into server.js's userConfigs
// directly, so m3u.js stays a self-contained module with no dependency
// on the caller's internal state (matching how the rest of this module
// is structured and independently testable). Sources are deduplicated by
// playlistUrl first, since multiple users can genuinely share the exact
// same provider - no reason to fetch and parse the same ~150MB file
// twice in the same refresh cycle. Each source refreshes independently;
// one failing (bad URL, provider down, etc) doesn't block the others.
async function refreshAllM3USources(getActiveSources) {
  const sources = getActiveSources();
  const uniqueByPlaylistUrl = new Map();
  for (const s of sources) {
    if (s && s.playlistUrl && s.epgUrl) uniqueByPlaylistUrl.set(s.playlistUrl, s);
  }

  const results = await Promise.allSettled(
    [...uniqueByPlaylistUrl.values()].map(({ playlistUrl, epgUrl }) => refreshM3USource(playlistUrl, epgUrl))
  );

  results.forEach((result, i) => {
    const { playlistUrl } = [...uniqueByPlaylistUrl.values()][i];
    if (result.status === 'rejected') {
      console.error(`[M3U scheduler] Failed to refresh source ${playlistUrl}:`, result.reason.message);
    } else {
      console.log(`[M3U scheduler] Refreshed ${playlistUrl}: ${result.value.channels.length} channels, ${result.value.categoryList.length} categories`);
    }
  });
}

// Starts the self-rescheduling background refresh loop. Fetches
// immediately on startup (so the app isn't empty for hours after a fresh
// deploy - a settled design decision, not an afterthought), then
// schedules itself for the next slot based on whatever the current
// admin-configured cadence is at the time each refresh fires - so a
// settings change takes effect on the very next cycle, not requiring a
// restart. getSettings returns the current {refreshesPerDay, timeZone}
// live (not a snapshot taken once at startup), for exactly this reason.
let schedulerTimeoutHandle = null;

function startM3uScheduler(getActiveSources, getSettings) {
  async function runAndReschedule() {
    await refreshAllM3USources(getActiveSources);
    const { daysOfWeek, times, timeZone } = getSettings();
    const nextRun = computeNextScheduledRun(daysOfWeek, times, timeZone);
    if (!nextRun) {
      console.error('[M3U scheduler] Could not compute next run - check daysOfWeek/times settings. Retrying in 1 hour.');
      schedulerTimeoutHandle = setTimeout(runAndReschedule, 60 * 60 * 1000);
      return;
    }
    const delay = nextRun.getTime() - Date.now();
    console.log(`[M3U scheduler] Next refresh at ${nextRun.toISOString()} (in ${(delay / 1000 / 60).toFixed(1)} minutes)`);
    schedulerTimeoutHandle = setTimeout(runAndReschedule, delay);
  }

  // Immediate first fetch, not scheduled - a brand-new deploy shouldn't
  // wait up to a full refresh interval before having any M3U data at all.
  runAndReschedule();
}

function stopM3uScheduler() {
  if (schedulerTimeoutHandle) {
    clearTimeout(schedulerTimeoutHandle);
    schedulerTimeoutHandle = null;
  }
}

module.exports = {
  parseM3UPlaylist,
  parseXMLTVEpg,
  extractRealDate,
  parseXmltvTimestamp,
  getCandidateStreamsForGame,
  fetchAndParseM3USource,
  refreshM3USource,
  getCachedM3USource,
  computeNextScheduledRun,
  refreshAllM3USources,
  startM3uScheduler,
  stopM3uScheduler,
  m3uSourceCache
};