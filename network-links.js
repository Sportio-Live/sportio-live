// Network Links slot resolution/healing - network-links-spec.md §4.
//
// Keeps a saved slot's status up to date against the current channel
// list, since a provider's stream URLs (M3U) can drift when the playlist
// regenerates, or a channel can simply disappear (either source). Pure
// functions - no I/O, no persistence - so they're testable the same way
// m3u.js's parsing functions are.
//
// Callers are responsible for the "orphaned provider" case (spec §0): if
// a slot's providerId no longer matches any of the user's connected
// providers, there's no channel/stream list to even pass in here - resolve
// straight to 'broken' without calling into this module at all.

// M3U: try progressively weaker signals against the current playlist,
// first hit wins.
function resolveM3uSlot(slot, channels) {
  const list = channels || [];

  const exact = list.find(ch => ch.streamUrl === slot.url);
  if (exact) return { status: 'ok', channel: exact };

  // "+ group" means membership in the channel's current categories array,
  // not exact equality against the slot's single stored group - a channel
  // picking up an unrelated additional category later shouldn't break
  // healing for the one group membership that never actually went away.
  // Where more than one channel matches (e.g. two quality variants of the
  // same network in the same group), the first match wins, same
  // first-listed-wins convention used elsewhere for this kind of tie
  // (see m3u.js's dedup fix).
  const byTvgIdAndGroup = list.find(ch => ch.id === slot.tvgId && ch.categories.includes(slot.group));
  if (byTvgIdAndGroup) return { status: 'healed', channel: byTvgIdAndGroup };

  const byNameAndGroup = list.find(ch => ch.name === slot.name && ch.categories.includes(slot.group));
  if (byNameAndGroup) return { status: 'healed', channel: byNameAndGroup };

  const byTvgIdAlone = list.find(ch => ch.id === slot.tvgId);
  if (byTvgIdAlone) return { status: 'healed', channel: byTvgIdAlone };

  return { status: 'broken', channel: null };
}

// Xtream: no healing chain needed - stream_id is a stable, provider-
// assigned identifier (unlike an M3U stream's URL), so it's either still
// in the provider's current channel list or it isn't. See spec §3 for why
// an Xtream slot never stores a URL to fall back on in the first place.
function resolveXtreamSlot(slot, xtreamStreams) {
  const list = xtreamStreams || [];
  const match = list.find(s => String(s.stream_id) === String(slot.streamId));
  return match ? { status: 'ok', stream: match } : { status: 'broken', stream: null };
}

// Dispatches on slot.type - the one place callers need to know about,
// rather than branching on type themselves everywhere a slot gets
// resolved (the save-slot API route, match-time resolution, the status
// chips in §5/§7).
function resolveSlot(slot, { channels, xtreamStreams } = {}) {
  if (slot.type === 'm3u') return resolveM3uSlot(slot, channels);
  if (slot.type === 'xtream') return resolveXtreamSlot(slot, xtreamStreams);
  return { status: 'broken' };
}

module.exports = {
  resolveM3uSlot,
  resolveXtreamSlot,
  resolveSlot
};
