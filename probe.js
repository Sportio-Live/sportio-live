// Stream quality probing - runs ffprobe against a stream URL to measure
// its actual resolution/fps, and turns that into a quality tier.
//
// Deliberately reads only real technical properties (resolution, frame
// rate), not bitrate or codec - see project design notes for why those
// were left out of v1. A probe is a brief, light metadata read (a handful
// of frames via tight analyzeduration/probesize caps below), not a real
// playback session or transcode.

const { execFile } = require('child_process');
const fs = require('fs');

// Hard ceiling on how long a single probe may run before being killed
// outright. Serial probing means one unresponsive channel must never be
// able to stall everything queued behind it.
const PROBE_TIMEOUT_MS = 10000;

// Caps how much of the stream ffprobe is willing to buffer/analyze before
// reporting whatever it has. Kept small on purpose - a live stream with no
// cap here can have ffprobe buffer indefinitely trying to get a fully
// confident read, which defeats the point of the hard timeout above.
const ANALYZE_DURATION_US = 3000000; // 3 seconds
const PROBE_SIZE_BYTES = 5000000; // 5MB

// Runs ffprobe against streamUrl and resolves to either
// { status: 'alive', width, height, fps } or { status: 'dead' }.
// Never rejects - a probe failure is a normal, expected outcome here, not
// an exceptional one, so callers never need a try/catch around this.
function probeStream(streamUrl) {
  return new Promise((resolve) => {
    const args = [
      '-v', 'quiet',
      '-print_format', 'json',
      '-show_streams',
      '-analyzeduration', String(ANALYZE_DURATION_US),
      '-probesize', String(PROBE_SIZE_BYTES),
      streamUrl
    ];

    execFile('ffprobe', args, {
      timeout: PROBE_TIMEOUT_MS,
      killSignal: 'SIGKILL',
      maxBuffer: 10 * 1024 * 1024
    }, (err, stdout) => {
      // Covers both a hard timeout (child_process kills the process and
      // still calls back with an error) and any non-zero exit - stream
      // unreachable, connection refused, malformed URL, etc. Either way
      // this channel reads as dead here; the retry mechanic (T+7 after
      // the batch) that decides whether a single dead reading actually
      // means "confirmed dead" lives at the call site, not in here.
      if (err) {
        resolve({ status: 'dead' });
        return;
      }

      let parsed;
      try {
        parsed = JSON.parse(stdout);
      } catch (parseErr) {
        resolve({ status: 'dead' });
        return;
      }

      const videoStream = (parsed.streams || []).find(s => s.codec_type === 'video');
      if (!videoStream || !videoStream.width || !videoStream.height) {
        resolve({ status: 'dead' });
        return;
      }

      // r_frame_rate (the container's nominal rate) tried first -
      // avg_frame_rate is computed from observed packet timestamps, which
      // often can't be resolved reliably within our deliberately short
      // analyzeduration window and comes back as "0/0" (missing) more
      // often than r_frame_rate does under the same tight cap.
      const fps = parseFrameRate(videoStream.r_frame_rate) || parseFrameRate(videoStream.avg_frame_rate);

      resolve({
        status: 'alive',
        width: videoStream.width,
        height: videoStream.height,
        fps
      });
    });
  });
}

// ffprobe reports frame rate as a fraction string like "30000/1001" or
// "60/1", and as "0/0" when it genuinely couldn't determine one - which
// must resolve to undefined (missing fps), not a divide-by-zero NaN
// masquerading as a real value.
function parseFrameRate(fraction) {
  if (!fraction) return undefined;
  const [num, den] = fraction.split('/').map(Number);
  if (!den) return undefined;
  const fps = num / den;
  return Number.isFinite(fps) && fps > 0 ? fps : undefined;
}

// ---------------------------------------------------------------------
// Tier computation
// ---------------------------------------------------------------------

// Ordered best-to-worst - callers doing ranking comparisons index into
// this rather than compare tier strings directly.
const TIER_ORDER = ['2160p', '1080p60', '1080p30', '720p60', '720p30', 'SD'];

const HIGH_FPS_THRESHOLD = 45;

// Pure function: { height, fps } -> one of TIER_ORDER. Bucketed by height
// (not width) with tolerance for non-standard encoder output (e.g. 1078 or
// 1088 instead of exactly 1080). fps only distinguishes within 1080p/720p -
// not worth the extra granularity at 4K (rare either way) or SD (already
// the bottom tier regardless of frame rate). Missing fps defaults to the
// standard (not high) bucket rather than leaving the tier unclassified.
function computeTier({ height, fps }) {
  if (!height || height < 500) return 'SD';
  if (height >= 1600) return '2160p';

  const isHighFps = typeof fps === 'number' && fps >= HIGH_FPS_THRESHOLD;

  if (height >= 900) return isHighFps ? '1080p60' : '1080p30';
  return isHighFps ? '720p60' : '720p30'; // height >= 500 && height < 900
}

// ---------------------------------------------------------------------
// Results storage - same flat-JSON-in-DATA_DIR pattern as every other
// piece of instance state in this app (see loadAdminConfig/saveAdminConfig
// in server.js). Keyed by a (categoryFolderName, channelName) compound
// key, not raw stream identity (streamUrl/stream_id aren't portable across
// the probing account and an arbitrary user's own account) and not bare
// channel name alone (collides across independently-sourced probing
// accounts - see project design notes). The key is JSON.stringify'd rather
// than joined with a delimiter, since real category names have been
// observed containing colons/pipes (e.g. "US: WILLOW CRICKET HD"), so no
// plain-text delimiter is safe to assume absent from either field.
// ---------------------------------------------------------------------

function makeResultKey(categoryFolderName, channelName) {
  return JSON.stringify([categoryFolderName, channelName]);
}

function loadProbeResults(filePath) {
  if (!fs.existsSync(filePath)) return {};
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (err) {
    console.error('[Probe] Error loading stream-probe-results.json:', err.message);
    return {};
  }
}

function saveProbeResults(filePath, results) {
  try {
    fs.writeFileSync(filePath, JSON.stringify(results, null, 2), 'utf8');
  } catch (err) {
    console.error('[Probe] Failed to save stream-probe-results.json:', err.message);
  }
}

function getProbeResult(results, categoryFolderName, channelName) {
  return results[makeResultKey(categoryFolderName, channelName)];
}

function setProbeResult(results, categoryFolderName, channelName, data) {
  results[makeResultKey(categoryFolderName, channelName)] = data;
}

module.exports = {
  probeStream,
  parseFrameRate,
  PROBE_TIMEOUT_MS,
  computeTier,
  TIER_ORDER,
  HIGH_FPS_THRESHOLD,
  makeResultKey,
  loadProbeResults,
  saveProbeResults,
  getProbeResult,
  setProbeResult
};
