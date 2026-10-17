'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const License = require('..');
const keys = () => crypto.generateKeyPairSync('rsa', {modulusLength: 2048, privateKeyEncoding: {type: 'pkcs8', format: 'pem'}, publicKeyEncoding: {type: 'spki', format: 'pem'}});
const {privateKey, publicKey} = keys();
const template = 'BEGIN (license).\n{{&name}}\n{{&serial}}\nEND';
const generate = (data, extra = {}) => License.generate({privateKey, template, data, ...extra});
const parse = (licenseFile, extra = {}) => License.parse({publicKey, template, licenseFile, ...extra});

test('legacy round trip is repeatable, immutable and preserves replacement syntax', () => {
    const data = Object.freeze({name: '$& $$ $` $\' {{&serial}} é'});
    const first = generate(data);
    assert.equal(generate(data), first);
    assert.deepEqual(parse(first).data, data);
    assert.equal(parse(first).valid, true);
    assert.deepEqual(Object.keys(data), ['name']);
});
test('strings and primitive fields round trip', () => {
    const t = '{{&string}}\n{{&serial}}';
    assert.equal(parse(generate('Alice', {template: t}), {template: t}).valid, true);
    const other = '{{&number}}\n{{&boolean}}\n{{&serial}}';
    assert.deepEqual(parse(generate({number: 0, boolean: false}, {template: other}), {template: other}).data, {number: '0', boolean: 'false'});
});
test('strict literal matching, full file matching and CRLF support', () => {
    const file = generate({name: 'Alice'});
    assert.equal(parse(file.replace(/\n/g, '\r\n')).valid, true);
    for (const changed of ['extra' + file, file + '\n', file.replace('BEGIN (license).', 'BEGIN (license)!')]) assert.throws(() => parse(changed), /corrupted/);
});
test('tampering and wrong public key fail verification', () => {
    const file = generate({name: 'Alice'});
    assert.equal(parse(file.replace('Alice', 'Bobby')).valid, false);
    assert.equal(parse(file, {publicKey: keys().publicKey}).valid, false);
});
test('invalid inputs and ambiguous templates are rejected', () => {
    for (const data of [null, [], {name: {}}, {name: NaN}, {name: 'a\nb'}, {name: 'a', serial: 'b'}, {name: 'a', extra: 'b'}]) assert.throws(() => generate(data));
    for (const t of ['{{&name}}', '{{&name}}{{&serial}}', '{{&name}}\n{{&name}}\n{{&serial}}', '{{&__proto__}}\n{{&serial}}', '{{&bad-name}}\n{{&serial}}']) assert.throws(() => generate({name: 'a'}, {template: t}));
    assert.throws(() => License.generate());
    assert.throws(() => License.parse());
    assert.throws(() => parse(generate({name: 'a'}).replace(/\n[^\n]+\nEND$/, '\n!!!\nEND')), /signature/);
});
test('null-prototype input and shadowed hasOwnProperty work', () => {
    const data = Object.assign(Object.create(null), {hasOwnProperty: 'safe'});
    const t = '{{&hasOwnProperty}}\n{{&serial}}';
    assert.equal(parse(generate(data, {template: t}), {template: t}).valid, true);
});
test('JSON v2 preserves structure and signs the version and payload', () => {
    const data = {nested: {z: null, a: [true, 42, 'a\nb']}, string: '$&', expirationDate: '2030-01-01T00:00:00.000Z'};
    const file = generate(data, {format: 'json'});
    assert.deepEqual(parse(file, {format: 'json'}).data, data);
    assert.equal(parse(file, {format: 'json'}).valid, true);
    const envelope = JSON.parse(file);
    envelope.data.nested.a[1] = 43;
    assert.equal(parse(JSON.stringify(envelope), {format: 'json'}).valid, false);
    envelope.version = 3;
    assert.throws(() => parse(JSON.stringify(envelope), {format: 'json'}));
});
test('JSON v2 rejects lossy values and cycles', () => {
    const circular = {}; circular.self = circular;
    for (const data of [{a: undefined}, {a: new Date()}, {a: Infinity}, {a: BigInt(1)}, {a: new Array(1)}, circular]) assert.throws(() => generate(data, {format: 'json'}));
});
test('legacy signatures retain sorted-key canonicalization', () => {
    const data = {'2': 'two', '10': 'ten', name: 'Alice'};
    const sorted = '{"10":"ten","2":"two","name":"Alice"}';
    const serial = crypto.sign('RSA-SHA256', Buffer.from(sorted), privateKey).toString('base64');
    const t = '{{&name}}\n{{&2}}\n{{&10}}\n{{&serial}}';
    assert.equal(parse(`Alice\ntwo\nten\n${serial}`, {template: t}).valid, true);
    assert.equal(parse(generate(data, {template: t}), {template: t}).valid, true);
});
test('business rules distinguish authenticity, expiry and compatibility', () => {
    const data = {product: 'app', applicationVersion: '1.0', expirationDate: '2030-01-01T00:00:00.000Z'};
    const licenseFile = generate(data, {format: 'json'});
    const validate = policy => License.validate({publicKey, licenseFile, format: 'json', policy});
    assert.equal(validate({now: '2029-01-01T00:00:00.000Z', product: 'app', applicationVersion: '1.0'}).valid, true);
    const expired = validate({now: '2030-01-01T00:00:00.000Z'});
    assert.equal(expired.signatureValid, true);
    assert.equal(expired.valid, false);
    assert.deepEqual(expired.reasons, ['expired']);
    assert.equal(validate({now: '2029-01-01T00:00:00.000Z', product: 'other'}).compatible, false);
    assert.throws(() => validate({now: '2029-02-30T00:00:00.000Z'}), /Invalid/);
    assert.throws(() => validate({unknown: true}), /Unknown/);
    const missing = License.validate({publicKey, licenseFile: generate({}, {format: 'json'}), format: 'json', policy: {requireExpiration: true}});
    assert.deepEqual(missing.reasons, ['missing_expiration']);
    const invalid = License.validate({publicKey, licenseFile: licenseFile.replace('"app"', '"bad"'), format: 'json'});
    assert.deepEqual(invalid.reasons, ['invalid_signature']);
    assert.equal(invalid.expired, null);
});
test('ambiguous same-line fields are rejected before returning a license', () => {
    assert.throws(() => generate({a: 'left|middle', b: 'right'}, {template: '{{&a}}|{{&b}}\n{{&serial}}'}), /ambiguous/);
});
test('file inputs work and inline content takes precedence', () => {
    const fs = require('node:fs');
    const os = require('node:os');
    const path = require('node:path');
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-licensing-test-'));
    try {
        const privateKeyPath = path.join(directory, 'private.pem');
        const publicKeyPath = path.join(directory, 'public.pem');
        const licenseFilePath = path.join(directory, 'license.txt');
        fs.writeFileSync(privateKeyPath, privateKey);
        fs.writeFileSync(publicKeyPath, publicKey);
        const file = License.generate({privateKeyPath, template, data: {name: 'Alice'}});
        fs.writeFileSync(licenseFilePath, file);
        assert.equal(License.parse({publicKeyPath, licenseFilePath, template}).valid, true);
        assert.equal(parse(file, {publicKeyPath: 'missing', licenseFilePath: 'missing'}).valid, true);
        assert.throws(() => License.parse({publicKeyPath: path.join(directory, 'missing'), licenseFilePath, template}), /ENOENT/);
        assert.throws(() => parse(file, {publicKey: 'not a key'}));
    } finally {
        fs.rmSync(directory, {recursive: true, force: true});
    }
});
test('policy rejects malformed authenticated expiration dates', () => {
    for (const expirationDate of ['12/10/2025', '2030-02-30T00:00:00.000Z', null]) {
        const licenseFile = generate({expirationDate}, {format: 'json'});
        assert.throws(() => License.validate({publicKey, licenseFile, format: 'json'}), /expirationDate/);
    }
});
