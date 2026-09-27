const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const zlib = require('zlib');
const epgshare = require('../epgshare01.js');

test('parseEpgShareXmltv handles either attribute order, sub-title, and missing desc', () => {
  const xml = `
  <programme start="20260927180000 +0000" stop="20260927190000 +0000" channel="A.us">
    <title lang="en">First</title>
    <sub-title lang="en">Episode</sub-title>
    <desc lang="en">Has a description</desc>
  </programme>
  <programme channel="B.us" start="20260927190000 +0000" stop="20260927200000 +0000">
    <title lang="en">Second</title>
  </programme>`;
  const result = epgshare.parseEpgShareXmltv(xml);
  assert.deepStrictEqual(result.get('A.us'), [{ start: '20260927180000', title: 'First', description: 'Has a description' }]);
  assert.deepStrictEqual(result.get('B.us'), [{ start: '20260927190000', title: 'Second', description: '' }]);
});

test('isKnownSourceFile only accepts the EPGShare01 naming convention', () => {
  assert.ok(epgshare.isKnownSourceFile('epg_ripper_US2.xml.gz'));
  assert.ok(!epgshare.isKnownSourceFile('../../etc/passwd'));
  assert.ok(!epgshare.isKnownSourceFile('http://evil/epg_ripper_US2.xml.gz'));
  assert.ok(!epgshare.isKnownSourceFile(null));
});

// Big enough (~6MB of XML) to span several parse batches and many network
// chunks, so programmes straddle the boundaries the streaming parser has to
// stitch back together. Its output must match a plain whole-file parse.
function buildLargeXmltv() {
  const parts = ['<?xml version="1.0"?>\n<tv>\n'];
  for (let i = 0; i < 24000; i++) {
    const channel = `Channel${i % 300}.us`;
    const hh = String(i % 24).padStart(2, '0');
    parts.push(`  <programme start="202609${String(1 + (i % 28)).padStart(2, '0')}${hh}0000 +0000" stop="202609${String(1 + (i % 28)).padStart(2, '0')}${hh}3000 +0000" channel="${channel}">\n` +
      `    <title lang="en">Programme ${i} été – café</title>\n` +
      `    <desc lang="en">${'Description text for the programme. '.repeat(5)}#${i}</desc>\n  </programme>\n`);
  }
  parts.push('</tv>\n');
  return parts.join('');
}

function readNdjsonDir(dir, channelIds) {
  const out = new Map();
  for (const id of channelIds) {
    const raw = fs.readFileSync(path.join(dir, epgshare.channelCacheFileName(id)), 'utf8');
    out.set(id, raw.split('\n').filter(Boolean).map(line => JSON.parse(line)));
  }
  return out;
}

for (const gzipped of [true, false]) {
  test(`streamSourceToDir matches a whole-file parse (${gzipped ? 'gzip' : 'plain'} body)`, async () => {
    const xml = buildLargeXmltv();
    const body = gzipped ? zlib.gzipSync(Buffer.from(xml)) : Buffer.from(xml);
    const server = http.createServer((req, res) => {
      // Small, odd-sized writes so chunk boundaries land mid-tag and mid-character.
      let offset = 0;
      const writeNext = () => {
        if (offset >= body.length) return res.end();
        const next = body.subarray(offset, offset + 7777);
        offset += next.length;
        if (res.write(next)) setImmediate(writeNext); else res.once('drain', writeNext);
      };
      writeNext();
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sportio-epg-test-'));
    try {
      const channelIds = await epgshare.streamSourceToDir(`http://127.0.0.1:${server.address().port}/src.xml.gz`, dir);
      const expected = epgshare.parseEpgShareXmltv(xml);
      assert.deepStrictEqual(channelIds, [...expected.keys()].sort());
      const actual = readNdjsonDir(dir, channelIds);
      for (const id of channelIds) {
        assert.deepStrictEqual(actual.get(id), expected.get(id), `programmes for ${id}`);
      }
    } finally {
      server.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
}
