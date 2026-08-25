// Network Links registry - see network-links-spec.md §2 for the full
// reasoning behind why neither half of this is a hand-typed list.
//
// Two genuinely different kinds of "network" a user can map a channel to:
//
// - Affiliate networks (FOX/CBS/NBC/ABC): a fixed 4-entry classification
//   rule, not a discovered list. ESPN reports a local affiliate broadcast
//   as the actual station's own name/call sign ("KTRK (ABC)", "Fox 5
//   Vegas"), not as "FOX" - and confirmed live, roughly half of real local
//   station names give no hint of their network at all ("KING 5" is NBC,
//   "KPIX" is CBS). Full classification of every station would need an
//   outside call-sign reference ESPN doesn't provide, so this only
//   classifies the names that plainly say which network they are.
//
// - National/single networks (ESPN, FOX, NBC, NFL Network, etc.): grown
//   automatically from live ESPN data, never hand-typed. Confirmed live
//   that ESPN reuses these names consistently and exactly across games.

const fs = require('fs');

const AFFILIATE_NETWORKS = [
  { key: 'fox', label: 'FOX' },
  { key: 'cbs', label: 'CBS' },
  { key: 'nbc', label: 'NBC' },
  { key: 'abc', label: 'ABC' }
];

// Case-insensitive substring match against the fixed affiliate names -
// e.g. "FOX59", "KTRK (ABC)", "CBS2", "NBC 10" all classify correctly.
// Anything that doesn't contain one of these four words (including
// non-affiliate entries ESPN sometimes lists here, like a team's own
// preseason channel) returns null rather than guessing - see spec §2.
function classifyAffiliateName(rawName) {
  const lower = (rawName || '').toLowerCase();
  for (const network of AFFILIATE_NETWORKS) {
    if (lower.includes(network.key)) return network.key;
  }
  return null;
}

// Registry key for an auto-discovered national network - lowercase,
// letters/digits only, so lookups never depend on incidental spelling
// differences in capitalization/punctuation. Two genuinely different
// spellings of the same real network (e.g. "NFL Net" vs "NFL Network")
// still normalize to two different keys - see spec §2's "known rough
// edge" note. That's an accepted, occasional manual-merge situation, not
// something this function tries to solve.
function normalizeNetworkName(name) {
  return (name || '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

// --- Auto-discovered national/single networks ---
//
// Grown automatically as the app fetches live ESPN game data for
// schedules/artwork - see recordNationalNetworkSighting below, called
// from server.js's fetchTodayGames/fetchTodayUFCEvents. Persisted so the
// registry survives a restart; only written on a genuinely new name, not
// on every sighting of one already known.

let discoveredNetworksFile = null;
let discovered = {}; // normalizedKey -> { name, firstSeen, lastSeen, timesSeen }

function loadDiscovered() {
  if (!discoveredNetworksFile || !fs.existsSync(discoveredNetworksFile)) return {};
  try {
    const raw = JSON.parse(fs.readFileSync(discoveredNetworksFile, 'utf8'));
    return raw && typeof raw === 'object' ? raw : {};
  } catch (err) {
    console.error('[Networks] Error loading discovered-networks.json, starting empty:', err.message);
    return {};
  }
}

function saveDiscovered() {
  if (!discoveredNetworksFile) return;
  try {
    fs.writeFileSync(discoveredNetworksFile, JSON.stringify(discovered, null, 2), 'utf8');
  } catch (err) {
    console.error('[Networks] Failed to save discovered-networks.json:', err.message);
  }
}

// Must be called once at startup (server.js) before any sightings are
// recorded, same pattern as the app's other persisted stores.
function initDiscoveredNetworksStore(filePath) {
  discoveredNetworksFile = filePath;
  discovered = loadDiscovered();
}

function recordNationalNetworkSighting(rawName) {
  const key = normalizeNetworkName(rawName);
  if (!key) return;
  const now = Date.now();
  if (discovered[key]) {
    discovered[key].lastSeen = now;
    discovered[key].timesSeen += 1;
  } else {
    discovered[key] = { name: rawName, firstSeen: now, lastSeen: now, timesSeen: 1 };
    saveDiscovered();
  }
}

function getDiscoveredNationalNetworks() {
  return Object.entries(discovered).map(([key, entry]) => ({ key, label: entry.name }));
}

// --- Broadcaster extraction from a game's ESPN competition object ---

// TV-only allow-list, not an exclusion list - see spec §2 for why this
// replaces a hand-typed streaming-service exclusion set entirely.
// geoBroadcasts[].type.shortName already distinguishes "TV" from
// "Streaming"/"Radio"; confirmed live that geoBroadcasts and broadcasts
// are empty/populated together in every case checked, so the broadcasts
// fallback below is a defensive, not-yet-observed edge case.
function extractTvBroadcastEntries(competition) {
  const geo = competition?.geoBroadcasts || [];
  const broadcasts = competition?.broadcasts || [];

  if (geo.length === 0 && broadcasts.length > 0) {
    // No type tag available in this fallback path - market alone decides
    // national vs local.
    return broadcasts.flatMap(b => (b.names || []).map(name => ({
      name,
      marketType: b.market === 'national' ? 'National' : 'Local'
    })));
  }

  return geo
    .filter(g => g?.type?.shortName === 'TV')
    .map(g => ({
      name: g.media?.shortName || '',
      marketType: g.market?.type === 'National' ? 'National' : 'Local'
    }));
}

// Called for every game fetched (see server.js), regardless of whether
// Network Links match-time resolution runs for it - this is what makes
// the national registry "auto-discovered" rather than static.
function recordSightingsFromCompetition(competition) {
  for (const { name, marketType } of extractTvBroadcastEntries(competition)) {
    if (name && marketType === 'National') recordNationalNetworkSighting(name);
  }
}

// Given one game's competition object, returns the set of registry keys
// (fixed affiliate keys or normalized discovered-network keys) its TV
// broadcasters resolve to. Records any new national sightings as a side
// effect. Used by the match-time resolution path (spec §8) - not wired
// into candidate matching yet at this stage of the build.
function resolveNetworkKeysForCompetition(competition) {
  const keys = new Set();
  for (const { name, marketType } of extractTvBroadcastEntries(competition)) {
    if (!name) continue;
    if (marketType === 'National') {
      recordNationalNetworkSighting(name);
      keys.add(normalizeNetworkName(name));
    } else {
      const affiliateKey = classifyAffiliateName(name);
      if (affiliateKey) keys.add(affiliateKey);
    }
  }
  return keys;
}

// Union of the fixed affiliate list and whatever's been auto-discovered
// so far - this is what the network-mapping dropdown (spec §5) reads from.
function getAllNetworks() {
  return [...AFFILIATE_NETWORKS, ...getDiscoveredNationalNetworks()];
}

module.exports = {
  AFFILIATE_NETWORKS,
  classifyAffiliateName,
  normalizeNetworkName,
  initDiscoveredNetworksStore,
  recordNationalNetworkSighting,
  getDiscoveredNationalNetworks,
  extractTvBroadcastEntries,
  recordSightingsFromCompetition,
  resolveNetworkKeysForCompetition,
  getAllNetworks
};
