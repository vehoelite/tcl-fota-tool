const test = require('node:test');
const assert = require('node:assert/strict');

const { buildFullUrls, parseDownloadResponse, parseCheckResponse } = require('../tcl-fota.js');

const SAMPLE_DL = `<?xml version="1.0" encoding="utf-8"?>
<GOTU><FILE_LIST>
<FILE><FILE_ID>1201948</FILE_ID><DOWNLOAD_URL>/HASH/48/1201948</DOWNLOAD_URL></FILE>
<FILE><FILE_ID>1201923</FILE_ID><DOWNLOAD_URL>/HASH/23/1201923</DOWNLOAD_URL></FILE>
</FILE_LIST><SLAVE_LIST>
<SLAVE>g2slave-ap-north-01.tclcom.com</SLAVE>
<SLAVE>g2slave-us-east-01.tclcom.com</SLAVE>
<ENCRYPT_SLAVE>54.238.56.196</ENCRYPT_SLAVE>
<S3_SLAVE>g2slave-us-east-01.tclcom.com</S3_SLAVE>
</SLAVE_LIST></GOTU>`;

test('buildFullUrls (single-arg, backwards compatible) uses DOWNLOAD_URL verbatim per slave', () => {
  const dl = parseDownloadResponse(SAMPLE_DL);
  // Old call shape — single argument — must still work and behave like before.
  const urls = buildFullUrls(dl);
  assert.deepEqual(urls, [
    'https://g2slave-ap-north-01.tclcom.com/HASH/48/1201948',
    'https://g2slave-us-east-01.tclcom.com/HASH/48/1201948',
  ]);
});

test('buildFullUrls does not double-prefix a /body path (server already adds it under foot=1)', () => {
  const dlWithBody = parseDownloadResponse(
    SAMPLE_DL.replace(/\/HASH\/48\/1201948/g, '/body/HASH/48/1201948')
  );
  const urls = buildFullUrls(dlWithBody, dlWithBody.downloadUrl);
  assert.ok(urls.every((u) => u.includes('/body/HASH/')));
  assert.ok(urls.every((u) => !u.includes('/body/body/')), 'must not double /body');
});

test('buildFullUrls can target a specific file from the FILE_LIST', () => {
  const dl = parseDownloadResponse(SAMPLE_DL);
  const urls = buildFullUrls(dl, dl.files[1].downloadUrl);
  assert.ok(urls[0].endsWith('/HASH/23/1201923'));
});

test('parseDownloadResponse captures every file and all slave types', () => {
  const dl = parseDownloadResponse(SAMPLE_DL);
  assert.equal(dl.files.length, 2);
  assert.equal(dl.files[1].downloadUrl, '/HASH/23/1201923');
  assert.equal(dl.encSlaves.length, 1);
  assert.equal(dl.s3Slaves.length, 1);
  // Backwards-compatible first-file fields still populated.
  assert.equal(dl.downloadUrl, '/HASH/48/1201948');
});

test('parseCheckResponse captures the full fileset for FULL images', () => {
  const xml = `<GOTU><CUREF>T440W-2ATBUS1</CUREF><VERSION><FV>A</FV><TV>B</TV></VERSION>
    <FIRMWARE><FW_ID>941181</FW_ID><FILESET>
    <FILE><FILENAME>U7AC0000EC00.mbn</FILENAME><FILE_ID>1201948</FILE_ID><SIZE>10318188</SIZE><CHECKSUM>abc</CHECKSUM><INDEX>0</INDEX></FILE>
    <FILE><FILENAME>B7AC0000EC00.mbn</FILENAME><FILE_ID>1201923</FILE_ID><SIZE>100663296</SIZE><CHECKSUM>def</CHECKSUM><INDEX>1</INDEX></FILE>
    </FILESET></FIRMWARE></GOTU>`;
  const info = parseCheckResponse(xml);
  assert.equal(info.fileset.length, 2);
  assert.equal(info.fileset[0].filename, 'U7AC0000EC00.mbn');
  // First-file fields remain for the single-file OTA summary UI.
  assert.equal(info.filename, 'U7AC0000EC00.mbn');
});
