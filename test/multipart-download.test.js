const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { httpDownload } = require('../tcl-fota.js');

test('httpDownload handles 207 multipart responses', async () => {
  const server = http.createServer((req, res) => {
    const body = Buffer.from('--test-boundary\r\nContent-Type: application/octet-stream\r\n\r\nABC\r\n--test-boundary\r\nContent-Type: application/octet-stream\r\n\r\nDEF\r\n--test-boundary--\r\n');
    res.writeHead(207, {
      'Content-Type': 'multipart/related; boundary="test-boundary"',
      'Content-Length': String(body.length),
    });
    res.end(body);
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tcl-fota-test-'));
  const dest = path.join(tempDir, 'payload.bin');

  try {
    const result = await httpDownload(`http://127.0.0.1:${port}/payload`, dest, () => {});
    assert.equal(result.size, 6);
    assert.equal(fs.readFileSync(dest, 'utf8'), 'ABCDEF');
  } finally {
    server.close();
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});
