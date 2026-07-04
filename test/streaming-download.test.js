const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const { httpDownload, downloadWithRetry, sha1File } = require('../tcl-fota.js');

test('httpDownload streams a large plain response to disk without buffering it whole', async () => {
  const payload = crypto.randomBytes(5 * 1024 * 1024); // 5MB
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': String(payload.length) });
    res.end(payload);
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tcl-fota-test-'));
  const dest = path.join(tempDir, 'body.bin');

  try {
    const result = await httpDownload(`http://127.0.0.1:${port}/big`, dest, () => {});
    assert.equal(result.size, payload.length);
    assert.ok(Buffer.from(fs.readFileSync(dest)).equals(payload));
  } finally {
    server.close();
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('httpDownload resumes from a Range offset and appends to the existing file', async () => {
  const payload = crypto.randomBytes(1024);
  const server = http.createServer((req, res) => {
    const range = req.headers['range'];
    if (range) {
      const start = parseInt(range.match(/bytes=(\d+)-/)[1], 10);
      const slice = payload.subarray(start);
      res.writeHead(206, { 'Content-Type': 'application/octet-stream', 'Content-Length': String(slice.length) });
      res.end(slice);
    } else {
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': String(payload.length) });
      res.end(payload);
    }
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tcl-fota-test-'));
  const dest = path.join(tempDir, 'resume.bin');

  try {
    fs.writeFileSync(dest, payload.subarray(0, 512));
    const result = await httpDownload(`http://127.0.0.1:${port}/r`, dest, () => {}, { resumeFrom: 512 });
    assert.equal(result.size, payload.length);
    assert.ok(Buffer.from(fs.readFileSync(dest)).equals(payload));
  } finally {
    server.close();
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('downloadWithRetry succeeds after transient failures using resume', async () => {
  const payload = crypto.randomBytes(2048);
  let attempts = 0;
  const server = http.createServer((req, res) => {
    attempts++;
    const range = req.headers['range'];
    const start = range ? parseInt(range.match(/bytes=(\d+)-/)[1], 10) : 0;

    if (attempts <= 2) {
      // Simulate a dropped connection partway through.
      res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
      res.write(payload.subarray(start, start + 100));
      res.destroy();
      return;
    }

    const slice = payload.subarray(start);
    res.writeHead(start > 0 ? 206 : 200, { 'Content-Type': 'application/octet-stream', 'Content-Length': String(slice.length) });
    res.end(slice);
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tcl-fota-test-'));
  const dest = path.join(tempDir, 'retry.bin');

  try {
    const result = await downloadWithRetry(`http://127.0.0.1:${port}/flaky`, dest, () => {}, { maxRetries: 5 });
    assert.ok(attempts > 2, 'expected at least one simulated failure before success');
    assert.equal(fs.statSync(dest).size, result.size);
  } finally {
    server.close();
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('sha1File matches crypto hash of the same buffer', async () => {
  const payload = crypto.randomBytes(64 * 1024);
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tcl-fota-test-'));
  const dest = path.join(tempDir, 'hashme.bin');

  try {
    fs.writeFileSync(dest, payload);
    const expected = crypto.createHash('sha1').update(payload).digest('hex');
    const actual = await sha1File(dest);
    assert.equal(actual, expected);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});
