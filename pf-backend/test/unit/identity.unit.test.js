'use strict';
// TDD: identity validators (PAN / Aadhaar / IFSC / bank account) and gateway signature
const test = require('node:test');
const assert = require('node:assert/strict');
const os = require('os'), path = require('path'), fs = require('fs'), crypto = require('crypto');
process.env.DB_PATH = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'pfs-id-')), 'u.db');
const { panCheck, aadhaarCheck, ifscCheck, acctCheck, gatewaySigOk } = require('../../server.js');

test('PAN: format, entity type, normalisation, surname-initial hint', () => {
  assert.deepEqual({ ok: true, type: 'Individual', pan: 'ABCPK1234F' }, (({ ok, type, pan }) => ({ ok, type, pan }))(panCheck(' abcpk1234f ')));
  assert.equal(panCheck('ABCDE1234F').ok, false, '4th letter D is not a valid holder type');
  for (const bad of ['', 'ABCPK12345', 'ABCP1234F', 'ABCPK1234', 'ABCPK1234FF', '12345ABCDE', 'ABC@K1234F', null, undefined, 42, {}, ['ABCPK1234F']]) assert.equal(panCheck(bad).ok, false, String(bad));
  assert.equal(panCheck('AAACP1234F').type, 'Company'); assert.equal(panCheck('AAAHP1234F').type, 'HUF'); assert.equal(panCheck('AAAFP1234F').type, 'Firm');
  assert.equal(panCheck('ABCPK1234F', 'Ramesh Kumar').name_hint, 'match'); assert.equal(panCheck('ABCPK1234F', 'Ramesh Sharma').name_hint, 'mismatch');
});
test('Aadhaar: 12 digits, first digit 2-9, Verhoeff checksum (spaces allowed)', () => {
  const mk = base => { for (let d = 0; d < 10; d++) if (aadhaarCheck(base + d).ok) return base + d; throw new Error('no check digit'); };
  const good = mk('23456789012'); assert.equal(aadhaarCheck(good).ok, true); assert.equal(aadhaarCheck(good.replace(/(\d{4})(\d{4})(\d{4})/, '$1 $2 $3')).ok, true);
  const wrong = good.slice(0, 11) + ((+good[11] + 1) % 10); assert.equal(aadhaarCheck(wrong).ok, false);
  for (const bad of ['', '12345678901', '1234567890123', '0000 0000 0000', '123456789012', 'abcdefghijkl', null, undefined, {}, 5]) assert.equal(aadhaarCheck(bad).ok, false, String(bad));
  assert.equal(aadhaarCheck(good).masked, 'XXXX XXXX ' + good.slice(8));
});
test('IFSC and bank account number', () => {
  assert.equal(ifscCheck('sbin0004521').ok, true); assert.equal(ifscCheck('sbin0004521').ifsc, 'SBIN0004521');
  for (const bad of ['SBIN1004521', 'SBI0004521', 'SBIN000452', '', null, 'SBIN0004521X']) assert.equal(ifscCheck(bad).ok, false, String(bad));
  assert.equal(acctCheck('32145698701').ok, true); assert.equal(acctCheck('1234 5678 9012').ok, true);
  for (const bad of ['12345678', '1234567890123456789', 'abc', '', null, '0000000000']) assert.equal(acctCheck(bad).ok, false, String(bad));
});
test('gateway signature: HMAC-SHA256 hex over the raw body, constant-time, rejects everything else', () => {
  const body = Buffer.from('{"event":"payment.captured"}'), sec = 'whsec_test_1234567890';
  const sig = crypto.createHmac('sha256', sec).update(body).digest('hex');
  assert.equal(gatewaySigOk(body, sig, sec), true);
  for (const bad of [sig.slice(1), sig.toUpperCase() + 'x', '', null, undefined, 'zz', sig.replace(/./, c => c === 'a' ? 'b' : 'a')]) assert.equal(gatewaySigOk(body, bad, sec), false, String(bad));
  assert.equal(gatewaySigOk(Buffer.from('{"event":"payment.captured "}'), sig, sec), false, 'tampered body');
  assert.equal(gatewaySigOk(body, sig, ''), false, 'no secret configured');
  assert.equal(gatewaySigOk(body, sig, undefined), false);
});
