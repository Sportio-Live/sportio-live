const test = require('node:test');
const assert = require('node:assert');
const m3u = require('../m3u.js');

test('parseM3UPlaylist keeps every distinct stream URL and merges categories', () => {
  const playlist = [
    '#EXTM3U',
    '#EXTINF:-1 tvg-id="espn.us" tvg-logo="http://logo/espn.png" group-title="US Sports",ESPN',
    'http://provider/live/u/p/1.ts',
    '#EXTINF:-1 tvg-id="espn.us" group-title="US Sports",ESPN Backup',
    'http://provider/live/u/p/2.ts',
    '#EXTINF:-1 tvg-id="espn.us" group-title="Favorites",ESPN',
    'http://provider/live/u/p/1.ts',
    '#EXTINF:-1 group-title="Broken",No tvg-id',
    'http://provider/live/u/p/3.ts'
  ].join('\n');
  const { channels, categoryList } = m3u.parseM3UPlaylist(playlist);
  assert.strictEqual(channels.length, 2, 'two distinct URLs, malformed entry skipped');
  const first = channels.find(c => c.streamUrl.endsWith('/1.ts'));
  assert.deepStrictEqual(first.categories.sort(), ['Favorites', 'US Sports']);
  assert.strictEqual(first.logo, 'http://logo/espn.png');
  assert.deepStrictEqual(categoryList, [
    { name: 'Favorites', channelCount: 1 },
    { name: 'US Sports', channelCount: 2 }
  ]);
});

test('parseXMLTVEpg filters to relevant channels and stores only start/title', () => {
  const xml = [
    '<programme start="20260927180000 +0000" stop="20260927200000 +0000" channel="espn.us"><title>NFL: Bills at Jets</title></programme>',
    '<programme start="20260927180000 +0000" stop="20260927200000 +0000" channel="other.us"><title>Ignored</title></programme>'
  ].join('\n');
  const result = m3u.parseXMLTVEpg(xml, new Set(['espn.us']));
  assert.deepStrictEqual([...result.keys()], ['espn.us']);
  assert.deepStrictEqual(result.get('espn.us'), [{ start: '20260927180000', title: 'NFL: Bills at Jets' }]);
});

test('extractRealDate prefers dates embedded in the title', () => {
  const iso = m3u.extractRealDate('Game (2026-08-19 01:00:05)', '20260818000000', 2026);
  assert.strictEqual(iso.source, 'title-iso');
  assert.strictEqual(iso.date.toISOString(), '2026-08-19T01:00:05.000Z');

  const md = m3u.extractRealDate('Yankees vs Red Sox 8/15 1pm', '20260801000000', 2026);
  assert.strictEqual(md.source, 'title-md');
  assert.strictEqual(md.date.toISOString(), '2026-08-15T13:00:00.000Z');

  const fallback = m3u.extractRealDate('Plain title', '20260801123000', 2026);
  assert.strictEqual(fallback.source, 'xmltv-fallback');
  assert.strictEqual(fallback.date.toISOString(), '2026-08-01T12:30:00.000Z');
});

test('computeNextScheduledRun picks the next slot in the configured timezone', () => {
  const now = new Date('2026-09-27T12:00:00Z'); // Sunday 08:00 in New York (EDT, UTC-4)
  const next = m3u.computeNextScheduledRun(['sun', 'mon'], ['06:00', '18:00'], 'America/New_York', now);
  assert.strictEqual(next.toISOString(), '2026-09-27T22:00:00.000Z'); // Sunday 18:00 EDT

  const skipDays = m3u.computeNextScheduledRun(['wed'], ['06:00'], 'America/New_York', now);
  assert.strictEqual(skipDays.toISOString(), '2026-09-30T10:00:00.000Z');
});

test('computeNextScheduledRun uses the post-DST offset across a transition', () => {
  // US DST ends Sunday 2026-11-01; Monday 06:00 is then EST (UTC-5).
  const now = new Date('2026-10-31T12:00:00Z');
  const next = m3u.computeNextScheduledRun(['mon'], ['06:00'], 'America/New_York', now);
  assert.strictEqual(next.toISOString(), '2026-11-02T11:00:00.000Z');
});

test('describeUrlForLog never includes credentials', () => {
  const out = m3u.describeUrlForLog('http://host.example:8080/get.php?username=alice&password=secret&type=m3u');
  assert.strictEqual(out, 'http://host.example:8080/...');
  assert.ok(!out.includes('secret'));
  assert.strictEqual(m3u.describeUrlForLog('not a url'), '(invalid URL)');
});
