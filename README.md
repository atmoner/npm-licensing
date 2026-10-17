# npm-licensing

Generate and verify RSA-SHA256 signed licenses for Node.js and Electron. No runtime dependencies. Requires Node.js 22 or newer.

```sh
npm install npm-licensing
```

## Keys

Generate keys in your license issuance environment:

```sh
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in private_key.pem -out public_key.pem
```

Keep the private key in the issuance environment. Distribute only the public key with your application. Signing authenticates data; it does not encrypt it. A client-side check can be modified by someone who controls the application.

## Legacy text licenses

```js
const LicenseFile = require('npm-licensing');
const template = [
    '====BEGIN LICENSE====',
    '{{&product}}',
    '{{&applicationVersion}}',
    '{{&expirationDate}}',
    '{{&serial}}',
    '=====END LICENSE====='
].join('\n');

const licenseFile = LicenseFile.generate({
    privateKeyPath: 'private_key.pem',
    template,
    data: {
        product: 'my-app',
        applicationVersion: '1.0.0',
        expirationDate: '2030-01-01T00:00:00.000Z'
    }
});

const result = LicenseFile.parse({
    publicKeyPath: 'public_key.pem',
    licenseFile,
    template
});
console.log(result.valid, result.data);
```

`generate()` returns text and does not write files or change its input. `parse()` returns `{valid, serial, data}`. Here, `valid` checks the signature only, including for expired licenses.

A template is required; there is no default template. Every data field must appear exactly once, alongside `{{&serial}}`. Field names use letters, digits and underscores. `serial`, `__proto__`, `constructor` and `prototype` are reserved. Adjacent tokens without a separator are rejected. Use one field per line to avoid ambiguous values containing field separators.

Legacy input accepts a plain object with string, finite number or boolean values, or a string represented by `{{&string}}`. Values are converted to strings. Nested objects, arrays, null and multiline values are rejected. Literal template punctuation is preserved. LF and CRLF are accepted; all other content, including leading/trailing whitespace, must match the template exactly.

## Versioned JSON licenses

Use `format: 'json'` on both generation and parsing to preserve JSON types, nested objects, arrays, null and multiline strings. Templates are not used in this format.

```js
const jsonLicense = LicenseFile.generate({
    privateKeyPath: 'private_key.pem',
    format: 'json',
    data: {
        product: 'my-app',
        applicationVersion: '1.0.0',
        expirationDate: '2030-01-01T00:00:00.000Z',
        features: ['export', 'reports'],
        limits: {seats: 5}
    }
});
const parsed = LicenseFile.parse({
    publicKeyPath: 'public_key.pem',
    licenseFile: jsonLicense,
    format: 'json'
});
```

The envelope is `{version: 2, data: {...}, serial: "base64..."}`. The signature covers canonical JSON of `{version: 2, data}` with recursively sorted object keys and preserved array order. There are no optional envelope fields. Unknown versions are rejected. Non-JSON values, circular references, sparse arrays and non-finite numbers are rejected. The top-level data must be a plain object. JSON format selection is explicit; it is not auto-detected.

## Business validation

`validate()` accepts the same inputs as `parse()` plus `policy`:

```js
const decision = LicenseFile.validate({
    publicKeyPath: 'public_key.pem',
    licenseFile: jsonLicense,
    format: 'json',
    policy: {
        product: 'my-app',
        applicationVersion: '1.0.0',
        requireExpiration: true
    }
});
console.log(decision.valid, decision.reasons);
```

The result adds `signatureValid`, `expired`, `compatible` and `reasons`. In this method, `valid` is true only if the signature and all requested rules pass. Reasons are `invalid_signature`, `expired`, `missing_expiration`, or `incompatible`. Business rules are not evaluated for an invalid signature; `expired` and `compatible` are then null.

When present, `expirationDate` must use exact UTC ISO format `YYYY-MM-DDTHH:mm:ss.sssZ`. Expiration is exclusive: the license is expired at that instant. `requireExpiration` defaults to false. Product and application version comparisons are exact strings, not semantic version ranges. Optional `policy.now` accepts the same date format for deterministic checks; otherwise the system clock is used. Offline checks depend on the device clock and do not provide revocation.

## API and errors

- `generate({data, template?, format?, privateKey?, privateKeyPath?})`
- `parse({template?, format?, publicKey?, publicKeyPath?, licenseFile?, licenseFilePath?})`
- `validate({...parseOptions, policy?})`

`format` is `legacy` (default) or `json`. Inline string keys/content take precedence over paths. Paths use synchronous file reads; load content once and pass inline values when verifying frequently or on Electron's UI path.

Malformed inputs, templates, signatures, JSON, dates and unsupported formats throw. Filesystem and key errors propagate. A well-formed signature that does not match returns `valid: false`. Catch errors at your application boundary and only grant access when `valid === true`. Do not use unauthenticated returned data to grant features.

## Compatibility

Existing correctly generated object-based text licenses retain their canonical signing representation. Parsing now rejects extra surrounding content, malformed templates and duplicate tokens that were previously tolerated. Remove incidental whitespace from legacy files deliberately before calling the API if your application requires that behavior.

String generation is fixed, input data is no longer mutated, and ambiguous/lossy data is rejected. The JSON v2 format is opt-in and does not replace existing text licenses. The previous unsupported `engine` declaration has been replaced by `engines.node: >=22`; consumers on older runtimes need to upgrade before adopting these changes. See CHANGELOG.md.

## Development

```sh
npm run check
npm test
npm pack --dry-run
```

Tests use Node's built-in runner. CI covers Node 22 and 24 on Linux and Windows. No dependency installation is required to run the tests.

## License

MIT. See LICENSE.
