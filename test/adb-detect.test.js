const test = require('node:test');
const assert = require('node:assert/strict');

const { listAdbDevices, detectDeviceProps } = require('../tcl-fota.js');

// These tests exercise the parsing/fallback logic without needing real
// hardware: they confirm the tool never throws and returns sensible
// "not available" / "no props" shapes when adb calls fail, by pointing
// detectDeviceProps/listAdbDevices at a nonexistent device serial (findAdbPath
// prefers the bundled platform-tools/adb.exe when present on this machine, so
// we can't rely on clearing PATH here — but adb will still fail cleanly
// against a serial that isn't connected).

test('listAdbDevices does not throw and returns an array (possibly empty)', async () => {
  const result = await listAdbDevices();
  assert.equal(typeof result.available, 'boolean');
  assert.ok(Array.isArray(result.devices));
});

test('detectDeviceProps never throws for a nonexistent device serial', async () => {
  const props = await detectDeviceProps('definitely-not-a-real-serial-0000');
  assert.equal(props.curef, null);
  assert.equal(props.fv, null);
});
