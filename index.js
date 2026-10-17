'use strict';

const fs = require('node:fs');
const crypto = require('node:crypto');
const hasOwn = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
const plain = value => value !== null && typeof value === 'object' &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
const fail = message => { throw new TypeError(message); };

// Sort keys explicitly: JSON.stringify's property ordering treats integer keys specially.
function canonical(value) {
    if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
    if (plain(value)) return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
    return JSON.stringify(value);
}

function validateJSON(value, ancestors = new Set()) {
    if (value === null || typeof value === 'string' || typeof value === 'boolean') return;
    if (typeof value === 'number' && Number.isFinite(value)) return;
    if (!plain(value) && !Array.isArray(value)) fail('Data must contain only JSON values');
    if (ancestors.has(value)) fail('Circular data is not supported');
    ancestors.add(value);
    if (Object.getOwnPropertySymbols(value).length) fail('Symbol keys are not supported');
    if (Array.isArray(value)) {
        if (Object.keys(value).length !== value.length) fail('Array properties are not supported');
        for (let i = 0; i < value.length; i++) {
            if (!hasOwn(value, i)) fail('Sparse arrays are not supported');
            validateJSON(value[i], ancestors);
        }
    } else {
        for (const key of Object.keys(value)) validateJSON(value[key], ancestors);
    }
    ancestors.delete(value);
}

function optionsObject(options) {
    if (!plain(options)) fail('options must be an object');
}

function content(options, field) {
    if (typeof options[field] === 'string') return options[field];
    if (typeof options[field + 'Path'] === 'string') return fs.readFileSync(options[field + 'Path'], 'utf8');
    fail(`${field} or ${field}Path is required`);
}

function legacyData(data) {
    if (typeof data === 'string') data = {string: data};
    if (!plain(data)) fail('Legacy data must be a plain object or string');
    const result = Object.create(null);
    for (const key of Object.keys(data)) {
        if (!/^\w+$/.test(key) || ['serial', '__proto__', 'constructor', 'prototype'].includes(key)) fail(`Invalid or reserved field: ${key}`);
        const value = data[key];
        if (!['string', 'number', 'boolean'].includes(typeof value) ||
            (typeof value === 'number' && !Number.isFinite(value))) fail(`Field ${key} must be a string, finite number or boolean`);
        result[key] = String(value);
        if (/[\r\n]/.test(result[key])) fail(`Field ${key} cannot contain newlines in the legacy format`);
    }
    return result;
}

function compile(template) {
    if (typeof template !== 'string' || !template.length) fail('template is required');
    const normalized = template.replace(/\r\n/g, '\n');
    if (/\r/.test(normalized)) fail('Unsupported line ending');
    const tokens = [];
    const parts = [];
    let offset = 0;
    for (const match of normalized.matchAll(/{{&(\w+)}}/g)) {
        const literal = normalized.slice(offset, match.index);
        if (literal.includes('{{&')) fail('Malformed template token');
        if (tokens.includes(match[1])) fail(`Duplicate template token: ${match[1]}`);
        if (['__proto__', 'constructor', 'prototype'].includes(match[1])) fail('Reserved template token');
        if (tokens.length && literal.length === 0) fail('Adjacent template tokens are ambiguous');
        parts.push(literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), '([^\\r\\n]*?)');
        tokens.push(match[1]);
        offset = match.index + match[0].length;
    }
    const tail = normalized.slice(offset);
    if (tail.includes('{{&')) fail('Malformed template token');
    parts.push(tail.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
    if (!tokens.includes('serial')) fail('template must contain {{&serial}}');
    return {template: normalized, tokens, regex: new RegExp('^' + parts.join('') + '(?![\\s\\S])')};
}

function signature(data, privateKey) {
    return crypto.sign('RSA-SHA256', Buffer.from(data), privateKey).toString('base64');
}
function verify(data, serial, publicKey) {
    if (typeof serial !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(serial) || !serial.length) {
        fail('Malformed base64 signature');
    }
    return crypto.verify('RSA-SHA256', Buffer.from(data), publicKey, Buffer.from(serial, 'base64'));
}
function timestamp(value, field) {
    if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) fail(`${field} must use UTC ISO format YYYY-MM-DDTHH:mm:ss.sssZ`);
    const time = Date.parse(value);
    if (!Number.isFinite(time) || new Date(time).toISOString() !== value) fail(`Invalid ${field}`);
    return time;
}

class LicenseFile {
    static generate(options) {
        optionsObject(options);
        const privateKey = content(options, 'privateKey');
        if (options.format === 'json') {
            if (!plain(options.data)) fail('JSON license data must be a plain object');
            validateJSON(options.data);
            const payload = {version: 2, data: options.data};
            return JSON.stringify({...payload, serial: signature(canonical(payload), privateKey)});
        }
        if (options.format !== undefined && options.format !== 'legacy') fail('Unsupported format');
        const data = legacyData(options.data);
        const compiled = compile(options.template);
        const fields = compiled.tokens.filter(token => token !== 'serial');
        if (fields.length !== Object.keys(data).length || fields.some(key => !hasOwn(data, key))) fail('Template fields must match data fields exactly');
        const serial = signature(canonical(data), privateKey);
        const rendered = compiled.template.replace(/{{&(\w+)}}/g, (_, key) => key === 'serial' ? serial : data[key]);
        const extracted = compiled.regex.exec(rendered);
        if (!extracted || compiled.tokens.some((key, i) => extracted[i + 1] !== (key === 'serial' ? serial : data[key]))) {
            fail('Field values are ambiguous for this template; use one field per line');
        }
        return rendered;
    }

    static parse(options) {
        optionsObject(options);
        const publicKey = content(options, 'publicKey');
        const file = content(options, 'licenseFile');
        let data, serial, signed;
        if (options.format === 'json') {
            const envelope = JSON.parse(file);
            if (!plain(envelope) || envelope.version !== 2 || !plain(envelope.data) ||
                Object.keys(envelope).sort().join(',') !== 'data,serial,version') fail('Invalid JSON license envelope');
            validateJSON(envelope.data);
            data = envelope.data;
            serial = envelope.serial;
            signed = canonical({version: 2, data});
        } else {
            if (options.format !== undefined && options.format !== 'legacy') fail('Unsupported format');
            const compiled = compile(options.template);
            const match = compiled.regex.exec(file.replace(/\r\n/g, '\n'));
            if (!match) fail('License file corrupted');
            data = {};
            compiled.tokens.forEach((token, i) => {
                if (token === 'serial') serial = match[i + 1];
                else data[token] = match[i + 1];
            });
            signed = canonical(data);
        }
        return {valid: verify(signed, serial, publicKey), serial, data};
    }

    // Business rules are explicit and separate from signature verification.
    static validate(options) {
        optionsObject(options);
        const policy = options.policy === undefined ? {} : options.policy;
        if (!plain(policy)) fail('policy must be an object');
        if (Object.keys(policy).some(key => !['now', 'product', 'applicationVersion', 'requireExpiration'].includes(key))) fail('Unknown policy option');
        if (policy.requireExpiration !== undefined && typeof policy.requireExpiration !== 'boolean') fail('requireExpiration must be a boolean');
        for (const key of ['product', 'applicationVersion']) {
            if (policy[key] !== undefined && typeof policy[key] !== 'string') fail(`${key} must be a string`);
        }
        const now = policy.now === undefined ? Date.now() : timestamp(policy.now, 'now');
        const result = LicenseFile.parse(options);
        if (!result.valid) return {...result, signatureValid: false, expired: null, compatible: null, reasons: ['invalid_signature']};
        const reasons = [];
        let expired = false;
        if (hasOwn(result.data, 'expirationDate')) {
            expired = timestamp(result.data.expirationDate, 'expirationDate') <= now;
            if (expired) reasons.push('expired');
        } else if (policy.requireExpiration) reasons.push('missing_expiration');
        const compatible = ['product', 'applicationVersion'].every(key => policy[key] === undefined || result.data[key] === policy[key]);
        if (!compatible) reasons.push('incompatible');
        return {...result, valid: reasons.length === 0, signatureValid: true, expired, compatible, reasons};
    }
}

module.exports = LicenseFile;
