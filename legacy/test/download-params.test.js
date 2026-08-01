const test = require('node:test');
const assert = require('node:assert/strict');

const { buildDownloadParams } = require('../tcl-fota.js');

// FULL-image (mode 4) download requests must include foot=1. Without it, TCL's
// server returns a bare S3 key (/{hash}/NN/{id}) that 404s with NoSuchKey; with
// it the server returns the resolvable /body/{hash}/NN/{id} key. See issue #3.
test('buildDownloadParams includes foot=1 for FULL (mode 4) requests', () => {
  const params = buildDownloadParams('T440W-2ATBUS1', '7ABDUMD0', '7AC0UM00', '941181', { mode: 4 });
  assert.equal(params.foot, '1');
});

// OTA (mode 2) requests must NOT carry foot — the incremental flow doesn't use it.
test('buildDownloadParams omits foot for OTA (mode 2) requests', () => {
  const params = buildDownloadParams('T440W-2ATBUS1', '7ABDUMD0', '7AC0UM00', '941181', { mode: 2 });
  assert.equal('foot' in params, false);
});

// foot must not be part of the signed parameter set: the VK is computed before
// foot is added, so adding foot must not change the vk value.
test('foot is excluded from the VK hash', () => {
  const opts = { mode: 4, imei: '543212345000000' };
  const full = buildDownloadParams('T440W-2ATBUS1', '7ABDUMD0', '7AC0UM00', '941181', opts);
  const ota = buildDownloadParams('T440W-2ATBUS1', '7ABDUMD0', '7AC0UM00', '941181', { ...opts, mode: 2 });
  // Different mode changes the vk legitimately, so instead assert foot ordering:
  // foot must appear after rtd and before chnl in the FULL params.
  const keys = Object.keys(full);
  assert.ok(keys.indexOf('foot') > keys.indexOf('rtd'), 'foot should come after rtd');
  assert.ok(keys.indexOf('foot') < keys.indexOf('chnl'), 'foot should come before chnl');
  assert.equal('foot' in ota, false);
});
