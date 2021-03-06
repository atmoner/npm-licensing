# npm-licensing

[![NPM version](https://img.shields.io/npm/v/npm-licensing.svg?style=flat)](https://www.npmjs.com/package/npm-licensing) [![NPM monthly downloads](https://img.shields.io/npm/dm/npm-licensing.svg?style=flat)](https://www.npmjs.com/package/npm-licensing) 

A lightweight License file generator and parser for ElectronJs and NodeJs.

## Generate a keypair using OpenSSL

1. Generate an RSA 2048 bit private key

    `openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048`

2. Extract the public key from an RSA keypair

    `openssl rsa -pubout -in private_key.pem -out public_key.pem`

## Generating license file

```javascript
const licenseFile = require('npm-licensing');

const template = [
    '====BEGIN LICENSE====',
    '{{&licenseVersion}}',
    '{{&applicationVersion}}',
    '{{&firstName}}',
    '{{&lastName}}',
    '{{&email}}',
    '{{&expirationDate}}',
    '{{&serial}}',
    '=====END LICENSE====='
].join('\n');

try {
 
    const licenseFileContent = licenseFile.generate({
        privateKeyPath: 'private_key.pem',
        template,
        data: {
            licenseVersion: '1',
            applicationVersion: '1.0.0',
            firstName: 'Name',
            lastName: 'Last Name',
            email: 'some@email.com',
            expirationDate: '12/10/2025'
        }
    });
    
    console.log(licenseFileContent);

} catch (err) {
    
    console.log(err);
}
```

This will produce a license key, which uses the default template and will look similar to this:
```
====BEGIN LICENSE====
1
1.0.0
Name
Last Name
some@email.com
12/10/2025
xxxxxxxxxxxxxxxxxxxxx
=====END LICENSE=====
```

## Parse and verify license file

```javascript
const licenseFile = require('npm-licensing');

try {
 
    const data = licenseFile.parse({
        publicKeyPath: 'public_key.pem',
        licenseFilePath: 'user.lic',
        template
    });
    
    console.log(data);
    
} catch (err) {
    
    console.log(err);
}
```

There is an execution result:
```
{
    valid: true,
    serial: 'oZDqoEr2avwhAqwV4HInq9otNzeBeD/azq2yn2jA ...',
    data: {
        licenseVersion: '1',
        applicationVersion: '1.0.0',
        firstName: 'Name',
        lastName: 'Last Name',
        email: 'some@email.com',
        expirationDate: '12/10/2025'
    }
}
```

NOTICE: All numeric data will be converted to strings after parsing. You need to take care of a parsed data types.

## Parse and verify license string

```javascript
const licenseFile = require('npm-licensing');

try {

    const licence = `
====BEGIN LICENSE====
1
1.0.0
Name
Last Name
some@email.com
12/10/2025
xxxxxxxxxxxxxxxxxxxxx
=====END LICENSE=====
    `;
 
    const data = licenseFile.parse({
        publicKeyPath: 'path/to/key.pub',
        licenseFile: licence,
        template
    });
    
    console.log(data);
    
} catch (err) {
    
    console.log(err);
}
```

There is an execution result:
```
{
    valid: true,
    serial: 'oZDqoEr2avwhAqwV4HInq9otNzeBeD/azq2yn2jA ...',
    data: {
        licenseVersion: '1',
        applicationVersion: '1.0.0',
        firstName: 'Name',
        lastName: 'Last Name',
        email: 'some@email.com',
        expirationDate: '12/10/2025'
    }
}
```

NOTICE: All numeric data will be converted to strings after parsing. You need to take care of a parsed data types.
