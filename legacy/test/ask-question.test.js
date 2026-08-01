const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

// Regression test for a crash found while testing runInteractive with a real
// connected device: piping stdin (non-TTY) causes Node's readline interface
// to close after the first line is consumed, even if more lines are buffered
// in the pipe. Any askQuestion() call after that point used to throw
// "readline was closed" and crash the whole process instead of degrading to
// an empty answer. A real user typing at a terminal never hits this (a TTY
// doesn't EOF between keystrokes) — this only affects piped/non-interactive
// input, but it should degrade gracefully rather than crash either way.

test('interactive mode does not crash when stdin ends mid-flow', () => {
  const cliPath = path.join(__dirname, '..', 'tcl-fota.js');
  // "n" (skip auto-detect) then EOF — readline will close before the next
  // question (device selection) is asked.
  const result = spawnSync(process.execPath, [cliPath, 'interactive'], {
    input: 'n\n',
    encoding: 'utf8',
    timeout: 15000,
  });

  assert.equal(result.status, 0, `expected clean exit, got status ${result.status}\nstderr: ${result.stderr}`);
  assert.ok(!/readline was closed/.test(result.stderr || ''), 'should not crash with readline error');
  assert.ok(!/Fatal error/.test(result.stdout || ''), 'should not print a fatal error');
});
